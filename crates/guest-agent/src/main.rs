//! guest-agent: the only thing that runs inside a VM-tier sandbox.
//!
//! Two shapes, one binary:
//!   * Firecracker microVM — PID 1 with euid 0, so it does `init::boot()` first.
//!   * podman container    — PID 1 but uid 1000, no CAP_SYS_ADMIN: boot is skipped.
//!
//! Everything it serves comes from `agent-core` (D17); this crate is init plus
//! the two listeners.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("guest-agent is Linux-only; build with --target <arch>-unknown-linux-musl");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod init;
#[cfg(target_os = "linux")]
mod serve;

/// The log goes to stdout, which in a microVM is the serial console, through
/// one thread that does the writing. A Firecracker snapshot taken while the
/// UART is still sending can restore into a console that never drains again;
/// writing there directly, every thread that logs blocks for good once the tty
/// buffer is full (measured: a clone's second exec never answered, its bpftrace
/// alerts stopped). Here only the writer thread blocks.
/// ponytail: lines are dropped, not queued, once 1024 are waiting — on a dead
/// console forever, on a slow one (115200 baud) during a burst.
#[cfg(target_os = "linux")]
#[derive(Clone)]
struct LossyStdout {
    /// The writer thread's queue; `None` when that thread could not be started
    /// and the lines go straight to `fd` instead.
    queue: Option<std::sync::mpsc::SyncSender<Vec<u8>>>,
    /// Lines queued and not yet written, so `drain` can tell when the queue is empty.
    pending: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    fd: libc::c_int,
}

/// How long `main` waits for the writer thread before it lets the process go.
#[cfg(target_os = "linux")]
const LOG_DRAIN: std::time::Duration = std::time::Duration::from_millis(200);

#[cfg(target_os = "linux")]
impl LossyStdout {
    fn start() -> Self {
        Self::start_with(std::io::stdout(), 2)
    }

    fn start_with<W: std::io::Write + Send + 'static>(mut out: W, fallback_fd: libc::c_int) -> Self {
        use std::sync::atomic::Ordering::SeqCst;
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1024);
        let pending = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let spawned = std::thread::Builder::new().name("log".into()).spawn({
            let pending = pending.clone();
            move || {
                for line in rx {
                    let _ = out.write_all(&line);
                    let _ = out.flush();
                    pending.fetch_sub(1, SeqCst);
                }
            }
        });
        match spawned {
            Ok(_) => Self { queue: Some(tx), pending, fd: fallback_fd },
            Err(_) => Self::direct(fallback_fd),
        }
    }

    /// No writer thread (it could not be spawned): each line is one write to
    /// `fd`, which is made non-blocking so a full tty drops the line instead of
    /// stopping whoever logged it. Losing lines beats losing the log.
    /// ponytail: `O_NONBLOCK` is a flag of the open file description, so it
    /// reaches every process that shares this stderr; the agent's children get
    /// their own pipes, so today that is only the agent. Upgrade: reopen the
    /// device with its own description once /dev is mounted.
    fn direct(fd: libc::c_int) -> Self {
        // SAFETY: fcntl on a descriptor number; no memory is involved.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        Self { queue: None, pending: Default::default(), fd }
    }

    /// Waits up to `within` for every queued line to be written. A console that
    /// has stopped draining costs the whole wait and loses what is stuck behind
    /// it, which is the bargain this writer is built on. Whether it emptied.
    fn drain(&self, within: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + within;
        while self.pending.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        true
    }
}

/// One event's line, handed to the writer thread when the formatter is done.
#[cfg(target_os = "linux")]
struct LogLine(Vec<u8>, LossyStdout);

#[cfg(target_os = "linux")]
impl std::io::Write for LogLine {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for LogLine {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering::SeqCst;
        let line = std::mem::take(&mut self.0);
        if line.is_empty() {
            return;
        }
        let log = &self.1;
        match &log.queue {
            Some(tx) => {
                // Counted before it is queued: the writer may finish the line
                // before this thread gets to count it.
                log.pending.fetch_add(1, SeqCst);
                if tx.try_send(line).is_err() {
                    log.pending.fetch_sub(1, SeqCst);
                }
            }
            None => {
                // SAFETY: `line` is a live buffer of the length passed.
                let _ = unsafe { libc::write(log.fd, line.as_ptr().cast(), line.len()) };
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LossyStdout {
    type Writer = LogLine;
    fn make_writer(&'a self) -> LogLine {
        LogLine(Vec::new(), self.clone())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tracing_subscriber::fmt::MakeWriter;

    /// A console that never drains costs log lines, never the thread logging:
    /// with nobody reading, the queue keeps what fits and drops the rest.
    #[test]
    fn a_full_log_queue_drops_lines_instead_of_blocking() {
        let (tx, rx) = std::sync::mpsc::sync_channel(2);
        let log = super::LossyStdout { queue: Some(tx), pending: Default::default(), fd: 2 };
        for i in 0..10 {
            writeln!(log.make_writer(), "line {i}").unwrap();
        }
        assert_eq!(rx.try_iter().collect::<Vec<_>>(), vec![b"line 0\n".to_vec(), b"line 1\n".to_vec()]);
        assert_eq!(log.pending.load(std::sync::atomic::Ordering::SeqCst), 2, "the dropped ones are not counted");
    }

    /// A sink that takes `.1` per write and keeps what it was given.
    struct Slow(Arc<Mutex<Vec<u8>>>, Duration);
    impl Write for Slow {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            std::thread::sleep(self.1);
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// As PID 1, the last lines before an init failure are the ones that matter,
    /// and they are exactly the ones still queued when `main` returns. `drain`
    /// is what holds the exit for them.
    #[test]
    fn exit_waits_for_the_queued_lines_to_be_written() {
        let got = Arc::new(Mutex::new(Vec::new()));
        let log = super::LossyStdout::start_with(Slow(got.clone(), Duration::from_millis(20)), 2);
        for i in 0..5 {
            writeln!(log.make_writer(), "line {i}").unwrap();
        }
        assert!(got.lock().unwrap().len() < 5 * 7, "the writer is slower than the producer: not all written yet");
        assert!(log.drain(Duration::from_secs(5)));
        assert_eq!(String::from_utf8(got.lock().unwrap().clone()).unwrap(), "line 0\nline 1\nline 2\nline 3\nline 4\n");
        assert!(log.drain(Duration::ZERO), "and an empty queue is drained at once");
    }

    /// A console that has stopped draining must not hold the exit for more than
    /// the bound, however many lines are stuck behind it.
    #[test]
    fn a_dead_console_costs_the_bound_and_no_more() {
        // The sink blocks until the test lets it go.
        struct Stuck(std::sync::mpsc::Receiver<()>);
        impl Write for Stuck {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                let _ = self.0.recv();
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (release, stuck) = std::sync::mpsc::channel();
        let log = super::LossyStdout::start_with(Stuck(stuck), 2);
        for i in 0..3 {
            writeln!(log.make_writer(), "line {i}").unwrap();
        }
        let t = Instant::now();
        assert!(!log.drain(Duration::from_millis(150)));
        assert!(t.elapsed() >= Duration::from_millis(150) && t.elapsed() < Duration::from_secs(2));
        drop(release);
    }

    /// With no writer thread the lines still go somewhere: straight to the
    /// descriptor, and a descriptor nobody reads (a full pipe) costs lines, not
    /// the caller.
    #[test]
    fn without_a_writer_thread_lines_go_straight_to_the_descriptor_without_blocking() {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` holds the two descriptors pipe(2) fills in.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let log = super::LossyStdout::direct(fds[1]);
        writeln!(log.make_writer(), "first").unwrap();
        // The pipe holds 64 KiB; far more than that cannot fit, and must not block.
        let big = "x".repeat(4096);
        for _ in 0..100 {
            writeln!(log.make_writer(), "{big}").unwrap();
        }
        let mut buf = [0u8; 6];
        // SAFETY: reads at most `buf.len()` bytes into `buf`.
        let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(&buf[..n as usize], b"first\n");
        // SAFETY: closing the two descriptors this test opened.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    let log = LossyStdout::start();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(log.clone())
        .init();

    let r = run();
    // As PID 1 the exit takes the VM down with it, and the writer thread dies
    // with the process: what is still queued is the explanation of why we are
    // leaving. Bounded, because a console that stopped draining never empties.
    log.drain(LOG_DRAIN);
    r
}

#[cfg(target_os = "linux")]
fn run() -> anyhow::Result<()> {
    // Mounting, hostname and the NIC are the microVM path only. As a
    // container entrypoint we are uid 1000 without CAP_SYS_ADMIN and the
    // runtime has already done all of it.
    if std::process::id() == 1 && nix::unistd::geteuid().is_root() {
        init::boot();
    }

    // Build the seccomp programs once, in the parent, so `pre_exec` only has to
    // call prctl(2) on already-allocated BPF.
    agent_core::harden::init_filter();

    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(async {
        // Whoever is PID 1 inherits orphans and has to reap them. Started inside
        // the runtime because the reaper waits on SIGCHLD.
        if std::process::id() == 1 {
            init::start_reaper();
        }
        serve::run().await
    })
}
