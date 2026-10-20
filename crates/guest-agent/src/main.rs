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
struct LossyStdout(std::sync::mpsc::SyncSender<Vec<u8>>);

#[cfg(target_os = "linux")]
impl LossyStdout {
    fn start() -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1024);
        let _ = std::thread::Builder::new().name("log".into()).spawn(move || {
            for line in rx {
                let _ = std::io::Write::write_all(&mut std::io::stdout(), &line);
            }
        });
        Self(tx)
    }
}

/// One event's line, handed to the writer thread when the formatter is done.
#[cfg(target_os = "linux")]
struct LogLine(Vec<u8>, std::sync::mpsc::SyncSender<Vec<u8>>);

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
        let _ = self.1.try_send(std::mem::take(&mut self.0));
    }
}

#[cfg(target_os = "linux")]
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LossyStdout {
    type Writer = LogLine;
    fn make_writer(&'a self) -> LogLine {
        LogLine(Vec::new(), self.0.clone())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::io::Write;
    use tracing_subscriber::fmt::MakeWriter;

    /// A console that never drains costs log lines, never the thread logging:
    /// with nobody reading, the queue keeps what fits and drops the rest.
    #[test]
    fn a_full_log_queue_drops_lines_instead_of_blocking() {
        let (tx, rx) = std::sync::mpsc::sync_channel(2);
        let log = super::LossyStdout(tx);
        for i in 0..10 {
            writeln!(log.make_writer(), "line {i}").unwrap();
        }
        assert_eq!(rx.try_iter().collect::<Vec<_>>(), vec![b"line 0\n".to_vec(), b"line 1\n".to_vec()]);
    }
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(LossyStdout::start())
        .init();

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
