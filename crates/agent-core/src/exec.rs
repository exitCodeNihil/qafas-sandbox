//! `POST /exec` (buffered) and `GET /exec/ws` (streaming, optionally on a PTY).
//! Frame protocol: docs/protocol.md §2.1.
//!
//! Every exec is a process group. That is what makes a timeout able to kill the
//! whole tree, and what lets `procmon` attribute a grandchild spawned two
//! minutes later back to the tool call that started it.

use std::collections::{BTreeMap, HashSet};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures_util::{SinkExt, StreamExt};
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;
use proto::{rules as R, ExecFrame, ExecReq, ExecResp, PtySize, Severity};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Child;
use tokio::sync::mpsc;

use crate::{Corr, Ctx};

pub(crate) const CAP: usize = 1024 * 1024;
const DEFAULT_BUFFERED_MS: u64 = 120_000;
const DEFAULT_WS_MS: u64 = 600_000;

/// Root pids we are `wait()`ing on. guest-agent's PID-1 reaper consults this so
/// it never steals an exit status tokio is waiting for.
static TRACKED: Mutex<Option<HashSet<i32>>> = Mutex::new(None);

pub fn is_tracked(pid: i32) -> bool {
    TRACKED.lock().unwrap().as_ref().is_some_and(|s| s.contains(&pid))
}

fn track(ctx: &Arc<Ctx>, pid: u32, corr: &Corr) {
    TRACKED.lock().unwrap().get_or_insert_with(HashSet::new).insert(pid as i32);
    ctx.mon.watch(pid, corr.clone());
    // v5.1: something is running, so the sandbox starts reporting its own usage.
    crate::limits::start_usage_push(ctx);
}

/// The exec root is the one process whose status we waited for ourselves, so
/// report it here rather than leaving `process.exit` with a null `exit` for
/// whichever kernel feed notices the death first (a no-op if it already did).
fn untrack(ctx: &Ctx, corr: &Corr, pid: u32, code: i32, sig: Option<&str>) {
    if let Some(s) = TRACKED.lock().unwrap().as_mut() {
        s.remove(&(pid as i32));
    }
    ctx.mon.note_exit(pid, Some(code), sig.map(str::to_string));
    // Before `unwatch`: the sample is this exec's, and `unwatch` forgets whose.
    crate::limits::push_usage(ctx, corr);
    ctx.mon.unwatch(pid);
}

/// `"KILL"`, `"SIGKILL"` and `"9"` all mean SIGKILL.
fn parse_signal(s: &str) -> Option<Signal> {
    if let Ok(n) = s.parse::<i32>() {
        return Signal::try_from(n).ok();
    }
    let full = if s.starts_with("SIG") { s.to_string() } else { format!("SIG{s}") };
    full.parse().ok()
}

/// bash reports a child killed by the seccomp filter as "Bad system call" on
/// stderr (the strsignal text for SIGSYS) and carries on, so the shell's own
/// exit status may hide the kill. This is the one string the kernel guarantees.
fn sniff_sigsys(bytes: &[u8]) -> bool {
    bytes.windows(15).any(|w| w == b"Bad system call")
}

/// Alerts that can only be read off the way a process died (D18: this is a
/// boundary signal — the kernel stopped it, we are only reporting).
fn post_mortem(ctx: &Ctx, corr: &Corr, cmd: &str, pid: u32, code: i32, sig: Option<&str>, sigsys_seen: bool) {
    // The command runs under `bash -lc`; when a *grandchild* is killed, bash
    // exits 128+signal instead of dying itself. Map that back to the signal.
    let sig = match (sig, code) {
        (Some(s), _) => Some(s),
        (None, _) if sigsys_seen => Some("SYS"),
        (None, 159) => Some("SYS"),
        (None, 152) => Some("XCPU"),
        (None, 153) => Some("XFSZ"),
        _ => None,
    };
    // v5 §3a. A cgroup OOM kill reaches userspace as a plain SIGKILL, so the
    // only honest evidence is the cgroup's own `oom_kill` counter moving. Asked
    // once, after the kill, rather than watched from a thread.
    if matches!(sig, Some("KILL")) || code == 137 {
        if crate::limits::oom_kills_since_last_check() > 0 {
            let mib = crate::limits::mem_limit_mib(ctx);
            ctx.ev.alert(
                corr,
                Severity::Low,
                R::RESOURCE_LIMIT,
                format!("memory limit {mib} MiB hit (oom_kill)"),
                json!({"pid": pid, "evidence": {"cmd": cmd, "signal": "SIGKILL"}}),
            );
        }
    }
    match sig {
        Some("SYS") => ctx.ev.alert(
            corr,
            Severity::High,
            R::SECCOMP_VIOLATION,
            "process killed by the seccomp filter",
            json!({"pid": pid, "evidence": {"cmd": cmd, "signal": "SIGSYS"}}),
        ),
        Some("XCPU") | Some("XFSZ") => ctx.ev.alert(
            corr,
            Severity::Low,
            R::RESOURCE_LIMIT,
            format!("process hit a resource limit (SIG{})", sig.unwrap_or("")),
            json!({"pid": pid, "evidence": {"cmd": cmd}}),
        ),
        _ => {}
    }
}

/// Command-line rules, run before the process exists so an alert precedes the
/// damage in the timeline.
fn pre_flight(ctx: &Ctx, corr: &Corr, cmd: &str) {
    for h in ctx.rules.scan(cmd) {
        ctx.ev.alert(
            corr,
            h.severity,
            h.rule,
            format!("command references {}", h.path),
            json!({"path": h.path, "evidence": {"cmd": cmd}}),
        );
    }
}

/// Waits for the child, killing its whole process group on timeout.
/// Returns `(exit_code, signal_name, timed_out)`.
async fn wait_child(child: &mut Child, pgid: Pid, timeout: Duration) -> (i32, Option<String>, bool) {
    let timed_out = tokio::time::timeout(timeout, child.wait()).await.is_err();
    if timed_out {
        let r = killpg(pgid, Signal::SIGKILL);
        tracing::warn!(pgid = pgid.as_raw(), ?r, "timeout: killing the process group");
    }
    let st = child.wait().await.ok();
    let code = st.and_then(|s| s.code()).unwrap_or(-1);
    let sig = st
        .and_then(|s| s.signal())
        .and_then(|n| Signal::try_from(n).ok())
        .map(|s| s.as_str().trim_start_matches("SIG").to_string());
    (code, sig, timed_out)
}

/// Reads to EOF but only keeps the first `CAP` bytes; the rest is drained so the
/// child never blocks on a full pipe.
async fn read_capped<R: AsyncRead + Unpin>(mut r: R) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    let mut truncated = false;
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if out.len() < CAP {
                    let take = n.min(CAP - out.len());
                    out.extend_from_slice(&buf[..take]);
                    truncated |= take < n;
                } else {
                    truncated = true;
                }
            }
        }
    }
    (out, truncated)
}

/// The cwd a request should actually run in: its own if it exists, else the
/// sandbox's home. A non-existent cwd is a client bug that used to surface as an
/// opaque "spawn failed".
fn resolve_cwd(ctx: &Ctx, cwd: &str) -> String {
    if !cwd.is_empty() && std::path::Path::new(cwd).is_dir() {
        cwd.to_string()
    } else {
        ctx.spawner.home()
    }
}

// ------------------------------------------------------------------ buffered

pub async fn buffered(ctx: &Arc<Ctx>, corr: Corr, req: ExecReq) -> std::io::Result<ExecResp> {
    let started = Instant::now();
    pre_flight(ctx, &corr, &req.cmd);
    let cwd = resolve_cwd(ctx, &req.cwd);
    let mut cmd = ctx.spawner.command(&req.cmd, &cwd, &ctx.env_with_defaults(&req.env));
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let pid = child.id().unwrap_or(0);
    track(ctx, pid, &corr);

    let out = read_capped(child.stdout.take().unwrap());
    let err = read_capped(child.stderr.take().unwrap());
    let timeout = Duration::from_millis(req.timeout_ms.unwrap_or(DEFAULT_BUFFERED_MS));
    let ((o, ot), (e, et), (code, sig, _to)) =
        tokio::join!(out, err, wait_child(&mut child, Pid::from_raw(pid as i32), timeout));
    post_mortem(ctx, &corr, &req.cmd, pid, code, sig.as_deref(), sniff_sigsys(&e));
    untrack(ctx, &corr, pid, code, sig.as_deref());

    Ok(ExecResp {
        exit: code,
        stdout: String::from_utf8_lossy(&o).into_owned(),
        stderr: String::from_utf8_lossy(&e).into_owned(),
        duration_ms: started.elapsed().as_millis() as u64,
        truncated: ot || et,
    })
}

// ------------------------------------------------------------------ streaming

fn set_winsize(fd: i32, sz: PtySize) {
    let ws = libc::winsize { ws_row: sz.rows, ws_col: sz.cols, ws_xpixel: 0, ws_ypixel: 0 };
    unsafe { libc::ioctl(fd, libc::TIOCSWINSZ as _, &ws) };
}

/// The PTY master, driven by the reactor. A `tokio::fs::File` would work too,
/// but every read of one parks a blocking-pool thread until the child writes,
/// so a sandbox holding several PTY sessions would hold a thread each.
struct Pty(tokio::io::unix::AsyncFd<OwnedFd>);

impl Pty {
    fn new(fd: OwnedFd) -> std::io::Result<Self> {
        // Without O_NONBLOCK the "ready" fd would still block the reactor.
        nix::fcntl::fcntl(fd.as_raw_fd(), nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK))
            .map_err(std::io::Error::other)?;
        Ok(Self(tokio::io::unix::AsyncFd::new(fd)?))
    }
}

impl tokio::io::AsyncRead for Pty {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.0.poll_read_ready(cx) {
                std::task::Poll::Ready(r) => r?,
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };
            let out = buf.initialize_unfilled();
            let r = guard.try_io(|fd| {
                let n = unsafe { libc::read(fd.get_ref().as_raw_fd(), out.as_mut_ptr().cast(), out.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match r {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return std::task::Poll::Ready(Ok(()));
                }
                // A master whose last slave is gone reads EIO. That is this
                // side's EOF, not a failure.
                Ok(Err(e)) if e.raw_os_error() == Some(libc::EIO) => return std::task::Poll::Ready(Ok(())),
                Ok(Err(e)) => return std::task::Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl tokio::io::AsyncWrite for Pty {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let mut guard = match this.0.poll_write_ready(cx) {
                std::task::Poll::Ready(r) => r?,
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };
            let r = guard.try_io(|fd| {
                let n = unsafe { libc::write(fd.get_ref().as_raw_fd(), data.as_ptr().cast(), data.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match r {
                Ok(v) => return std::task::Poll::Ready(v),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// stdin/stdout for the child: one PTY master, or three pipes.
enum Io {
    Pty {
        read: Pty,
        write: Pty,
    },
    Pipes {
        stdin: tokio::process::ChildStdin,
        stdout: tokio::process::ChildStdout,
        stderr: tokio::process::ChildStderr,
    },
}

fn spawn_session(
    ctx: &Ctx,
    cmd: &str,
    cwd: &str,
    env: &BTreeMap<String, String>,
    pty: Option<PtySize>,
) -> std::io::Result<(Child, Io)> {
    let mut c = ctx.spawner.command(cmd, cwd, &ctx.env_with_defaults(env));
    match pty {
        None => {
            c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
            let mut child = c.spawn()?;
            let io = Io::Pipes {
                stdin: child.stdin.take().unwrap(),
                stdout: child.stdout.take().unwrap(),
                stderr: child.stderr.take().unwrap(),
            };
            Ok((child, io))
        }
        Some(size) => {
            let ws = libc::winsize { ws_row: size.rows, ws_col: size.cols, ws_xpixel: 0, ws_ypixel: 0 };
            let pty = nix::pty::openpty(Some(&ws), None).map_err(|e| std::io::Error::other(e.to_string()))?;
            let (master, slave): (OwnedFd, OwnedFd) = (pty.master, pty.slave);
            let dup = |fd: &OwnedFd| -> std::io::Result<Stdio> { Ok(Stdio::from(fd.try_clone()?)) };
            c.stdin(dup(&slave)?).stdout(dup(&slave)?).stderr(dup(&slave)?);
            unsafe {
                // Runs after the Spawner's own pre_exec, which already made this
                // a session leader (`own_process_group`). TIOCSCTTY then claims
                // the slave — fd 0 by now — as the controlling terminal, which is
                // what makes job control and Ctrl-C work.
                c.pre_exec(|| {
                    if libc::getsid(0) != libc::getpid() && libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::ioctl(0, libc::TIOCSCTTY as _, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let child = c.spawn()?;
            // The parent's copy of the slave must go, or the master never sees EOF.
            drop(slave);
            let write = master.try_clone()?;
            Ok((child, Io::Pty { read: Pty::new(master)?, write: Pty::new(write)? }))
        }
    }
}

/// Pumps a child output stream to the client as `stdout`/`stderr` frames.
fn pump<R: AsyncRead + Unpin + Send + 'static>(
    mut r: R,
    is_err: bool,
    tx: mpsc::Sender<ExecFrame>,
    sigsys: Arc<std::sync::atomic::AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = [0u8; 32 * 1024];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if sniff_sigsys(&buf[..n]) {
                        sigsys.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    let data = B64.encode(&buf[..n]);
                    let f = if is_err { ExecFrame::Stderr { data } } else { ExecFrame::Stdout { data } };
                    if tx.send(f).await.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

pub async fn ws(ctx: Arc<Ctx>, corr: Corr, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();

    // Frame 1 must be `start` (protocol §2.1).
    let start = loop {
        match stream.next().await {
            Some(Ok(Message::Text(t))) => match serde_json::from_str::<ExecFrame>(&t) {
                Ok(f @ ExecFrame::Start { .. }) => break f,
                _ => {
                    let _ = sink.close().await;
                    return;
                }
            },
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            _ => {
                let _ = sink.close().await;
                return;
            }
        }
    };
    let ExecFrame::Start { cmd, cwd, env, pty, timeout_ms } = start else { unreachable!() };

    let started = Instant::now();
    pre_flight(&ctx, &corr, &cmd);
    let cwd = resolve_cwd(&ctx, &cwd);
    let (mut child, io) = match spawn_session(&ctx, &cmd, &cwd, &env, pty) {
        Ok(v) => v,
        Err(e) => {
            let f = ExecFrame::Exit { code: 127, signal: None, duration_ms: 0, timed_out: false };
            tracing::warn!(error = %e, cmd, cwd, "spawn failed");
            let _ = sink.send(Message::Text(json(&f).into())).await;
            let _ = sink.close().await;
            return;
        }
    };
    let pid = child.id().unwrap_or(0);
    let pgid = Pid::from_raw(pid as i32);
    track(&ctx, pid, &corr);

    let (tx, mut rx) = mpsc::channel::<ExecFrame>(64);
    let writer = tokio::spawn(async move {
        while let Some(f) = rx.recv().await {
            if sink.send(Message::Text(json(&f).into())).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
        sink
    });

    // Output pumps + the client→child task, which also handles resize/signal.
    let sigsys = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let pumps: Vec<_> = match io {
        Io::Pty { read, write } => {
            let fd = write.0.as_raw_fd();
            let p = vec![pump(read, false, tx.clone(), sigsys.clone())];
            tokio::spawn(client_loop(stream, Some(write), None, fd, pgid));
            p
        }
        Io::Pipes { stdin, stdout, stderr } => {
            let p =
                vec![pump(stdout, false, tx.clone(), sigsys.clone()), pump(stderr, true, tx.clone(), sigsys.clone())];
            tokio::spawn(client_loop(stream, None, Some(stdin), -1, pgid));
            p
        }
    };

    let timeout = Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_WS_MS));
    let (code, sig, timed_out) = wait_child(&mut child, pgid, timeout).await;
    untrack(&ctx, &corr, pid, code, sig.as_deref());

    // Let the pumps drain what is already buffered, then stop waiting on them: a
    // grandchild holding the PTY slave open would otherwise keep them alive.
    for p in pumps {
        if tokio::time::timeout(Duration::from_millis(200), p).await.is_err() {
            break;
        }
    }
    post_mortem(&ctx, &corr, &cmd, pid, code, sig.as_deref(), sigsys.load(std::sync::atomic::Ordering::Relaxed));
    let _ = tx
        .send(ExecFrame::Exit {
            code,
            signal: if timed_out { Some("KILL".into()) } else { sig },
            duration_ms: started.elapsed().as_millis() as u64,
            timed_out,
        })
        .await;
    drop(tx);
    let _ = writer.await;
}

fn json(f: &ExecFrame) -> String {
    serde_json::to_string(f).expect("ExecFrame always serializes")
}

/// client → child: `stdin`, `resize`, `signal`.
async fn client_loop(
    mut stream: futures_util::stream::SplitStream<WebSocket>,
    mut pty_write: Option<Pty>,
    mut pipe_write: Option<tokio::process::ChildStdin>,
    pty_fd: i32,
    pgid: Pid,
) {
    while let Some(Ok(msg)) = stream.next().await {
        let Message::Text(t) = msg else { continue };
        let Ok(frame) = serde_json::from_str::<ExecFrame>(&t) else { continue };
        match frame {
            ExecFrame::Stdin { data } => {
                let Ok(bytes) = B64.decode(data.as_bytes()) else { continue };
                let ok = match (&mut pty_write, &mut pipe_write) {
                    (Some(w), _) => w.write_all(&bytes).await.and(w.flush().await).is_ok(),
                    (_, Some(w)) => w.write_all(&bytes).await.and(w.flush().await).is_ok(),
                    _ => false,
                };
                if !ok {
                    break;
                }
            }
            ExecFrame::Resize { cols, rows } if pty_fd >= 0 => {
                set_winsize(pty_fd, PtySize { cols, rows });
                let _ = killpg(pgid, Signal::SIGWINCH);
            }
            ExecFrame::Signal { sig } => {
                if let Some(s) = parse_signal(&sig) {
                    let _ = killpg(pgid, s);
                }
            }
            _ => {}
        }
    }
    // Client hung up or stopped sending: close the child's stdin so `cat` ends.
    drop(pipe_write);
    drop(pty_write);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spawn::{Hardened, Limits};
    use crate::{rules::Rules, Emitter};

    #[test]
    fn signal_names() {
        assert_eq!(parse_signal("KILL"), Some(Signal::SIGKILL));
        assert_eq!(parse_signal("SIGTERM"), Some(Signal::SIGTERM));
        assert_eq!(parse_signal("9"), Some(Signal::SIGKILL));
        assert_eq!(parse_signal("NOPE"), None);
    }

    #[tokio::test]
    async fn capped_read_truncates_and_still_drains() {
        let big = vec![b'x'; CAP + 4096];
        let (out, truncated) = read_capped(&big[..]).await;
        assert_eq!(out.len(), CAP);
        assert!(truncated);
        let (out, truncated) = read_capped(&b"short"[..]).await;
        assert_eq!(out, b"short");
        assert!(!truncated);
    }

    #[test]
    fn start_must_be_first_frame() {
        let f: ExecFrame = serde_json::from_str(r#"{"type":"stdin","data":"aGk="}"#).unwrap();
        assert!(!matches!(f, ExecFrame::Start { .. }));
    }

    /// A whole exec end to end: the command runs, `process.start` names it, the
    /// sensitive path on its command line alerts, and a bad cwd does not fail.
    #[tokio::test]
    async fn exec_runs_and_reports() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let ev = Emitter::new("h", "sbx", Arc::new(move |e| s.lock().unwrap().push(e)));
        let ctx = Ctx::new(Hardened { limits: Limits::default() }, ev, Rules::guest("/tmp", "/tmp/nohome"));

        let r = buffered(
            &ctx,
            Corr { pi_session: "p".into(), tool_call_id: "t".into() },
            ExecReq {
                cmd: "echo hi; cat /proc/1/environ 2>/dev/null; true".into(),
                cwd: "/definitely/not/here".into(),
                env: BTreeMap::new(),
                timeout_ms: Some(10_000),
            },
        )
        .await
        .expect("exec");
        assert_eq!(r.exit, 0, "a missing cwd falls back to home instead of failing");
        assert!(r.stdout.starts_with("hi"));

        let evs = seen.lock().unwrap();
        assert!(
            evs.iter().any(|e| e.data["rule"] == R::SENSITIVE_PATH_READ && e.pi_session == "p"),
            "the /proc/1/environ read should have alerted: {evs:?}",
        );

        // v5.1 §1: the exec ends with a usage sample on the stream, carrying the
        // tool call that caused it. That is what `SandboxInfo.usage` follows
        // between the daemon's 5 s pulls.
        let u = evs
            .iter()
            .find(|e| e.r#type == proto::EventType::SandboxUsage)
            .unwrap_or_else(|| panic!("no sandbox.usage: {evs:?}"));
        assert_eq!((u.pi_session.as_str(), u.tool_call_id.as_str()), ("p", "t"));
        assert!(u.data["ts"].as_str().is_some_and(|t| t.ends_with('Z')), "{}", u.data);
        assert!(u.data.get("mem_bytes").is_some(), "the payload is a SandboxUsage: {}", u.data);
    }

    /// The PTY master is driven by the reactor, not a blocking-pool thread: it
    /// still has to read and write like a terminal. `cat` on a pty answers twice
    /// — once from the line discipline's echo, once from `cat` itself.
    #[tokio::test]
    async fn a_pty_master_reads_and_writes_through_the_reactor() {
        let ctx = Ctx::new(Hardened::default(), Emitter::null(), Rules::guest("/tmp", "/tmp/nohome"));
        let (mut child, io) =
            spawn_session(&ctx, "cat", "/tmp", &BTreeMap::new(), Some(PtySize { cols: 80, rows: 24 }))
                .expect("pty session");
        let Io::Pty { mut read, mut write } = io else { panic!("asked for a pty") };

        write.write_all(b"ping\n").await.expect("write to the master");
        let mut got = String::new();
        let mut buf = [0u8; 256];
        while got.matches("ping").count() < 2 {
            let n = tokio::time::timeout(Duration::from_secs(5), read.read(&mut buf))
                .await
                .expect("the pty must not block the reactor")
                .expect("read");
            assert_ne!(n, 0, "EOF before `cat` answered: {got:?}");
            got.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        let _ = child.kill().await;
    }

    #[tokio::test]
    async fn timeout_kills_the_group_and_reports_it() {
        let ctx = Ctx::new(Hardened::default(), Emitter::null(), Rules::guest("/tmp", "/tmp/nohome"));
        let r = buffered(
            &ctx,
            Corr::default(),
            ExecReq { cmd: "sleep 30".into(), cwd: "/tmp".into(), env: BTreeMap::new(), timeout_ms: Some(300) },
        )
        .await
        .expect("exec");
        assert_eq!(r.exit, -1, "killed, so no exit code");
        assert!(r.duration_ms < 5_000);
    }
}
