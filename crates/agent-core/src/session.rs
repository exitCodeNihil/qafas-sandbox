//! v3 persistent shells (protocol §3a "Sessions").
//!
//! One `bash` per session, spawned through the same `Spawner` as `/exec`, so it
//! gets the identical uid drop / seccomp / Landlock / `PROTECTED_ENV` treatment.
//! Commands are fed to its stdin and delimited by a marker the shell prints
//! after each one:
//!
//! ```text
//! { <cmd>
//! }; printf '\n__SBX_EXIT_<cid>_%d__\n' $?
//! ```
//!
//! Splitting stdout on that marker is what gives every command an exit code
//! without losing the state (`cd`, `export`, shell functions) between them.
//!
//! `POST .../input` writes to the same pipe, which is why `read v` works: the
//! shell reads the next line of its own stdin.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures_util::SinkExt;
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;
use proto::{
    CommandState, CreateSessionReq, EventType, ExecFrame, SessionCommand, SessionExecReq, SessionInfo, SessionInputReq,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{broadcast, watch};

use crate::exec::CAP;
use crate::{now_rfc3339, Corr, Ctx};

/// How long a command gets to die of SIGINT before we kill the whole session.
const SIGINT_GRACE_MS: u64 = 500;
const DEFAULT_TIMEOUT_MS: u64 = 120_000;
const MARK: &[u8] = b"\n__SBX_EXIT_";

pub type Registry = Arc<Mutex<BTreeMap<String, Arc<Session>>>>;

// ------------------------------------------------------------------ marker

/// What the stdout reader may do with `buf` right now:
/// `(bytes safe to forward, the command that just ended, bytes to consume)`.
///
/// A marker can straddle two reads, so when none is complete we hold back the
/// longest tail that could still become one.
fn scan(buf: &[u8]) -> (usize, Option<(String, i32)>, usize) {
    if let Some(i) = find(buf, MARK) {
        let body = &buf[i + MARK.len()..];
        return match find(body, b"__\n") {
            Some(j) => {
                let end = i + MARK.len() + j + 3;
                let txt = String::from_utf8_lossy(&body[..j]);
                match txt.rsplit_once('_').and_then(|(c, n)| Some((c.to_string(), n.parse().ok()?))) {
                    Some(fin) => (i, Some(fin), end),
                    // Not our marker after all: forward it verbatim.
                    None => (end, None, end),
                }
            }
            // The marker started but has not finished arriving.
            None => (i, None, i),
        };
    }
    let keep = buf.len() - partial_tail(buf);
    (keep, None, keep)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Length of the suffix of `buf` that is a proper prefix of `MARK`.
fn partial_tail(buf: &[u8]) -> usize {
    (1..MARK.len().min(buf.len() + 1)).rev().find(|k| buf.ends_with(&MARK[..*k])).unwrap_or(0)
}

// ------------------------------------------------------------------ state

struct Out {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit: Option<i32>,
    ended_at: Option<String>,
    duration_ms: u64,
}

struct Cmd {
    id: String,
    cmd: String,
    started_at: String,
    started: Instant,
    corr: Corr,
    out: Mutex<Out>,
    /// Live frames for `logs/ws`. Subscribed to under the `out` lock so a
    /// replay of the buffer plus the stream is exactly the whole output.
    tx: broadcast::Sender<ExecFrame>,
    done: watch::Sender<bool>,
}

impl Cmd {
    fn new(id: String, cmd: String, corr: Corr, stderr: Vec<u8>) -> Self {
        Self {
            id,
            cmd,
            started_at: now_rfc3339(),
            started: Instant::now(),
            corr,
            out: Mutex::new(Out { stdout: Vec::new(), stderr, exit: None, ended_at: None, duration_ms: 0 }),
            tx: broadcast::channel(256).0,
            done: watch::channel(false).0,
        }
    }

    fn info(&self, with_output: bool) -> SessionCommand {
        let o = self.out.lock().unwrap();
        SessionCommand {
            command_id: self.id.clone(),
            cmd: self.cmd.clone(),
            state: if o.exit.is_some() { CommandState::Done } else { CommandState::Running },
            exit: o.exit,
            started_at: self.started_at.clone(),
            ended_at: o.ended_at.clone(),
            stdout: with_output.then(|| String::from_utf8_lossy(&o.stdout).into_owned()),
            stderr: with_output.then(|| String::from_utf8_lossy(&o.stderr).into_owned()),
        }
    }
}

struct Inner {
    history: Vec<Arc<Cmd>>,
    running: Option<Arc<Cmd>>,
    /// stderr that arrived with no command running (a background job's). It is
    /// attributed to the next command — see the §3a ponytail note.
    orphan_stderr: Vec<u8>,
    alive: bool,
}

pub struct Session {
    pub id: String,
    cwd: String,
    created_at: String,
    /// The shell, and therefore the process group everything it starts joins.
    pid: u32,
    stdin: tokio::sync::Mutex<Option<tokio::process::ChildStdin>>,
    inner: Mutex<Inner>,
}

impl Session {
    fn info(&self) -> SessionInfo {
        SessionInfo {
            id: self.id.clone(),
            cwd: self.cwd.clone(),
            created_at: self.created_at.clone(),
            commands: self.inner.lock().unwrap().history.iter().map(|c| c.info(false)).collect(),
        }
    }

    fn running(&self) -> Option<Arc<Cmd>> {
        self.inner.lock().unwrap().running.clone()
    }

    fn find_cmd(&self, cid: &str) -> Option<Arc<Cmd>> {
        self.inner.lock().unwrap().history.iter().find(|c| c.id == cid).cloned()
    }

    /// Appends to the running command's buffer and wakes every `logs/ws`.
    /// Capped like `/exec`: past `CAP` the bytes are still streamed live, only
    /// the replay buffer stops growing.
    fn push(&self, is_err: bool, bytes: &[u8]) {
        let Some(cmd) = self.running() else {
            if is_err {
                let mut i = self.inner.lock().unwrap();
                if i.orphan_stderr.len() < CAP {
                    i.orphan_stderr.extend_from_slice(bytes);
                }
            }
            return;
        };
        let mut o = cmd.out.lock().unwrap();
        let buf = if is_err { &mut o.stderr } else { &mut o.stdout };
        if buf.len() < CAP {
            let take = bytes.len().min(CAP - buf.len());
            buf.extend_from_slice(&bytes[..take]);
        }
        let data = B64.encode(bytes);
        let _ = cmd.tx.send(if is_err { ExecFrame::Stderr { data } } else { ExecFrame::Stdout { data } });
    }

    /// The marker for `cid` arrived (or the shell died): close the command out.
    fn finish(&self, ctx: &Ctx, cid: Option<&str>, exit: i32) {
        let cmd = {
            let mut i = self.inner.lock().unwrap();
            let mine = match (i.running.as_ref(), cid) {
                (Some(c), Some(cid)) => c.id == cid,
                (Some(_), None) => true,
                (None, _) => false,
            };
            if !mine {
                return;
            }
            i.running.take().unwrap()
        };
        let duration_ms = cmd.started.elapsed().as_millis() as u64;
        {
            let mut o = cmd.out.lock().unwrap();
            o.exit = Some(exit);
            o.ended_at = Some(now_rfc3339());
            o.duration_ms = duration_ms;
            let bytes_out = o.stdout.len() + o.stderr.len();
            let _ = cmd.tx.send(ExecFrame::Exit { code: exit, signal: None, duration_ms, timed_out: false });
            ctx.ev.emit(
                &cmd.corr,
                EventType::ExecEnd,
                json!({"exit": exit, "duration_ms": duration_ms, "bytes_out": bytes_out}),
            );
        }
        let _ = cmd.done.send(true);
    }

    /// SIGKILL the shell's process group. Everything it started dies with it.
    fn kill(&self, ctx: &Ctx) {
        self.inner.lock().unwrap().alive = false;
        let _ = killpg(Pid::from_raw(self.pid as i32), Signal::SIGKILL);
        ctx.mon.unwatch(self.pid);
    }
}

// ------------------------------------------------------------------ spawn

fn new_id() -> String {
    ulid::Ulid::new().to_string()
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({"error": msg.into()}))).into_response()
}

async fn spawn(ctx: &Arc<Ctx>, req: &CreateSessionReq) -> std::io::Result<Arc<Session>> {
    let cwd = match req.cwd.as_deref() {
        Some(c) if !c.is_empty() && std::path::Path::new(c).is_dir() => c.to_string(),
        _ => ctx.spawner.home(),
    };
    // `exec` so the pid we hold is the shell that reads stdin, not a wrapper.
    let mut c = ctx.spawner.command("exec /bin/bash", &cwd, &ctx.env_with_defaults(&req.env));
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn()?;
    let pid = child.id().unwrap_or(0);
    let (stdin, stdout, stderr) =
        (child.stdin.take().unwrap(), child.stdout.take().unwrap(), child.stderr.take().unwrap());

    let session = Arc::new(Session {
        id: req.id.clone().unwrap_or_else(new_id),
        cwd,
        created_at: now_rfc3339(),
        pid,
        stdin: tokio::sync::Mutex::new(Some(stdin)),
        inner: Mutex::new(Inner { history: Vec::new(), running: None, orphan_stderr: Vec::new(), alive: true }),
    });

    // A handler (not SIG_IGN) so the shell survives the SIGINT a timeout sends
    // to its process group, while the command's own children — which reset
    // trapped signals across exec — still die of it.
    if let Some(w) = session.stdin.lock().await.as_mut() {
        w.write_all(b"trap ':' INT\n").await?;
        w.flush().await?;
    }

    tokio::spawn(read_stdout(session.clone(), ctx.clone(), stdout));
    tokio::spawn(read_stderr(session.clone(), stderr));
    // Reap the shell; `kill_on_drop` handles the rest.
    tokio::spawn(async move {
        let _ = child.wait().await;
    });
    Ok(session)
}

async fn read_stdout(session: Arc<Session>, ctx: Arc<Ctx>, mut out: tokio::process::ChildStdout) {
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = [0u8; 32 * 1024];
    loop {
        match out.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => pending.extend_from_slice(&buf[..n]),
        }
        loop {
            let (emit, fin, consumed) = scan(&pending);
            if emit > 0 {
                session.push(false, &pending[..emit]);
            }
            pending.drain(..consumed);
            match fin {
                Some((cid, code)) => session.finish(&ctx, Some(&cid), code),
                None => break,
            }
        }
    }
    // The shell is gone: whatever was running never gets a marker.
    session.inner.lock().unwrap().alive = false;
    session.finish(&ctx, None, -1);
    ctx.mon.unwatch(session.pid);
    ctx.sessions.lock().unwrap().remove(&session.id);
}

async fn read_stderr(session: Arc<Session>, mut err: tokio::process::ChildStderr) {
    let mut buf = [0u8; 32 * 1024];
    while let Ok(n) = err.read(&mut buf).await {
        if n == 0 {
            break;
        }
        session.push(true, &buf[..n]);
    }
}

// ------------------------------------------------------------------ handlers

pub async fn create(State(ctx): State<Arc<Ctx>>, body: axum::body::Bytes) -> Response {
    let req: CreateSessionReq = if body.is_empty() {
        CreateSessionReq::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()),
        }
    };
    if let Some(id) = &req.id {
        if !valid_id(id) {
            return err(StatusCode::BAD_REQUEST, "id must be [A-Za-z0-9_-]{1,64}");
        }
        if ctx.sessions.lock().unwrap().contains_key(id) {
            return err(StatusCode::CONFLICT, format!("session {id} exists"));
        }
    }
    match spawn(&ctx, &req).await {
        Ok(s) => {
            let id = s.id.clone();
            ctx.sessions.lock().unwrap().insert(id.clone(), s);
            (StatusCode::CREATED, Json(json!({"id": id}))).into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub async fn list(State(ctx): State<Arc<Ctx>>) -> Json<Vec<SessionInfo>> {
    let all: Vec<Arc<Session>> = ctx.sessions.lock().unwrap().values().cloned().collect();
    Json(all.iter().map(|s| s.info()).collect())
}

fn lookup(ctx: &Ctx, id: &str) -> Option<Arc<Session>> {
    ctx.sessions.lock().unwrap().get(id).cloned()
}

pub async fn get(State(ctx): State<Arc<Ctx>>, Path(id): Path<String>) -> Response {
    match lookup(&ctx, &id) {
        Some(s) => Json(s.info()).into_response(),
        None => err(StatusCode::NOT_FOUND, "no such session"),
    }
}

pub async fn delete(State(ctx): State<Arc<Ctx>>, Path(id): Path<String>) -> Response {
    let Some(s) = ctx.sessions.lock().unwrap().remove(&id) else {
        return err(StatusCode::NOT_FOUND, "no such session");
    };
    s.kill(&ctx);
    StatusCode::NO_CONTENT.into_response()
}

pub async fn exec(
    State(ctx): State<Arc<Ctx>>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let req: SessionExecReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()),
    };
    if req.cmd.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "cmd is empty");
    }
    let Some(session) = lookup(&ctx, &id) else {
        return err(StatusCode::NOT_FOUND, "no such session");
    };
    let corr = Corr::from_headers(&headers);
    let cid = new_id();

    // Claim the one running slot before anything can block.
    let cmd = {
        let mut i = session.inner.lock().unwrap();
        if !i.alive {
            return err(StatusCode::GONE, "the session shell has exited");
        }
        if i.running.is_some() {
            return err(StatusCode::CONFLICT, "a command is already running in this session");
        }
        let orphan = std::mem::take(&mut i.orphan_stderr);
        let cmd = Arc::new(Cmd::new(cid.clone(), req.cmd.clone(), corr.clone(), orphan));
        i.running = Some(cmd.clone());
        i.history.push(cmd.clone());
        cmd
    };

    ctx.ev.emit(&corr, EventType::ExecStart, json!({"cmd": req.cmd, "cwd": session.cwd, "pty": false}));
    // Re-point procmon at the shell for this tool call, so the children it
    // spawns from now on are attributed to the command that asked for them.
    ctx.mon.watch(session.pid, corr);
    // v5.1: a session command is an exec too, so the sandbox reports its usage
    // for as long as one is running.
    crate::limits::start_usage_push(&ctx);

    // `{ … }` groups the command so `$?` is the group's, and multi-line input
    // works; the marker rides on the same logical line so it always runs.
    let line = format!("{{ {}\n}}; printf '\\n__SBX_EXIT_{cid}_%d__\\n' $?\n", req.cmd);
    let write = {
        let mut guard = session.stdin.lock().await;
        match guard.as_mut() {
            Some(w) => w.write_all(line.as_bytes()).await.and(w.flush().await),
            None => Err(std::io::Error::other("session stdin closed")),
        }
    };
    if let Err(e) = write {
        session.finish(&ctx, Some(&cid), -1);
        return err(StatusCode::GONE, e.to_string());
    }

    let timeout = Duration::from_millis(req.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS));
    tokio::spawn(enforce_timeout(session.clone(), ctx.clone(), cmd.clone(), timeout));

    if req.r#async {
        return (StatusCode::ACCEPTED, Json(json!({"command_id": cid}))).into_response();
    }
    let mut done = cmd.done.subscribe();
    let _ = done.wait_for(|v| *v).await;
    Json(cmd.info(true)).into_response()
}

/// SIGINT to the shell's process group kills the foreground job but not the
/// shell (it traps INT). If that is not enough the whole session goes.
async fn enforce_timeout(session: Arc<Session>, ctx: Arc<Ctx>, cmd: Arc<Cmd>, timeout: Duration) {
    let mut done = cmd.done.subscribe();
    if tokio::time::timeout(timeout, done.wait_for(|v| *v)).await.is_ok() {
        return;
    }
    tracing::warn!(session = session.id, cid = cmd.id, "session command timed out");
    // The command's processes, never the shell: a timeout that fired before the
    // shell had read its `trap ':' INT` (a login shell on a busy host) used to
    // take the whole session down with it.
    for pid in crate::procmon::group_pids(session.pid).into_iter().filter(|p| *p != session.pid) {
        let _ = nix::sys::signal::kill(Pid::from_raw(pid as i32), Signal::SIGINT);
    }
    let grace = Duration::from_millis(SIGINT_GRACE_MS);
    if tokio::time::timeout(grace, done.wait_for(|v| *v)).await.is_ok() {
        return;
    }
    // The command ignores SIGINT. Everything it started is in the shell's process
    // group, and the shell is that group's leader, so killing every member *but*
    // the leader kills the command alone: bash reaps the job, prints its marker,
    // and the session keeps its cwd, exports and functions.
    let strays: Vec<u32> = crate::procmon::group_pids(session.pid).into_iter().filter(|p| *p != session.pid).collect();
    for pid in &strays {
        let _ = nix::sys::signal::kill(Pid::from_raw(*pid as i32), Signal::SIGKILL);
    }
    // An empty list means "not forked yet" as often as "a bash builtin": one
    // grace either way before the session itself is given up on.
    if tokio::time::timeout(grace, done.wait_for(|v| *v)).await.is_ok() {
        return;
    }
    // Nothing left to kill but the shell itself — a builtin spinning in bash's
    // own process (`while :; do :; done`). Only then does the session go.
    ctx.sessions.lock().unwrap().remove(&session.id);
    session.kill(&ctx);
    session.finish(&ctx, Some(&cmd.id), -1);
}

pub async fn command(State(ctx): State<Arc<Ctx>>, Path((id, cid)): Path<(String, String)>) -> Response {
    match lookup(&ctx, &id).and_then(|s| s.find_cmd(&cid)) {
        Some(c) => Json(c.info(true)).into_response(),
        None => err(StatusCode::NOT_FOUND, "no such command"),
    }
}

pub async fn input(
    State(ctx): State<Arc<Ctx>>,
    Path((id, cid)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Response {
    let req: SessionInputReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let Some(session) = lookup(&ctx, &id) else {
        return err(StatusCode::NOT_FOUND, "no such session");
    };
    // Input goes to the shell's stdin, which only the running command reads.
    match session.running() {
        Some(c) if c.id == cid => {}
        _ => return err(StatusCode::CONFLICT, "that command is not running"),
    }
    let mut guard = session.stdin.lock().await;
    let r = match guard.as_mut() {
        Some(w) => w.write_all(req.data.as_bytes()).await.and(w.flush().await),
        None => Err(std::io::Error::other("session stdin closed")),
    };
    match r {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(StatusCode::GONE, e.to_string()),
    }
}

pub async fn logs_ws(
    State(ctx): State<Arc<Ctx>>,
    Path((id, cid)): Path<(String, String)>,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(cmd) = lookup(&ctx, &id).and_then(|s| s.find_cmd(&cid)) else {
        return err(StatusCode::NOT_FOUND, "no such command");
    };
    ws.on_upgrade(move |sock| stream_logs(cmd, sock))
}

async fn stream_logs(cmd: Arc<Cmd>, mut sock: WebSocket) {
    // Subscribing under the buffer lock is what makes "replay then live" exact:
    // no frame is both replayed and streamed, and none is missed.
    let (replay, mut rx) = {
        let o = cmd.out.lock().unwrap();
        let mut f: Vec<ExecFrame> = Vec::new();
        if !o.stdout.is_empty() {
            f.push(ExecFrame::Stdout { data: B64.encode(&o.stdout) });
        }
        if !o.stderr.is_empty() {
            f.push(ExecFrame::Stderr { data: B64.encode(&o.stderr) });
        }
        if let Some(code) = o.exit {
            f.push(ExecFrame::Exit { code, signal: None, duration_ms: o.duration_ms, timed_out: false });
        }
        (f, cmd.tx.subscribe())
    };
    let done = replay.iter().any(|f| matches!(f, ExecFrame::Exit { .. }));
    for f in replay {
        if send(&mut sock, &f).await.is_err() {
            return;
        }
    }
    if !done {
        while let Ok(f) = rx.recv().await {
            let last = matches!(f, ExecFrame::Exit { .. });
            if send(&mut sock, &f).await.is_err() || last {
                break;
            }
        }
    }
    let _ = sock.close().await;
}

async fn send(sock: &mut WebSocket, f: &ExecFrame) -> Result<(), axum::Error> {
    let txt = serde_json::to_string(f).expect("ExecFrame always serializes");
    sock.send(Message::Text(txt.into())).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rules;
    use crate::spawn::Hardened;
    use crate::Emitter;

    fn ctx() -> Arc<Ctx> {
        Ctx::new(Hardened::default(), Emitter::null(), Rules::guest("/tmp", "/tmp/nohome"))
    }

    async fn run_for(ctx: &Arc<Ctx>, s: &Arc<Session>, cmd: &str, ms: u64) -> SessionCommand {
        let r = exec(
            State(ctx.clone()),
            Path(s.id.clone()),
            axum::http::HeaderMap::new(),
            serde_json::to_vec(&json!({"cmd": cmd, "timeout_ms": ms})).unwrap().into(),
        )
        .await;
        let (parts, body) = r.into_parts();
        assert_eq!(parts.status, StatusCode::OK, "exec {cmd:?}");
        serde_json::from_slice(&axum::body::to_bytes(body, 1 << 20).await.unwrap()).unwrap()
    }

    async fn run(ctx: &Arc<Ctx>, s: &Arc<Session>, cmd: &str) -> SessionCommand {
        run_for(ctx, s, cmd, DEFAULT_TIMEOUT_MS).await
    }

    #[test]
    fn markers_survive_being_split_across_reads() {
        // Whole marker in one buffer.
        let (emit, fin, consumed) = scan(b"hi\n__SBX_EXIT_c1_7__\nrest");
        assert_eq!(&b"hi\n__SBX_EXIT_c1_7__\nrest"[..emit], b"hi");
        assert_eq!(fin, Some(("c1".to_string(), 7)));
        assert_eq!(consumed, 21);
        // Split in the middle: nothing past the partial marker is forwarded.
        let (emit, fin, consumed) = scan(b"out\n__SBX_EX");
        assert_eq!((emit, fin, consumed), (3, None, 3));
        // A tail that could still become a marker is held back.
        assert_eq!(scan(b"abc\n").0, 3);
        assert_eq!(scan(b"abc").0, 3);
        // A ULID command id round-trips.
        let (_, fin, _) = scan(b"\n__SBX_EXIT_01J8Z3N4K6P7Q9R2S5T8V1W3X6_130__\n");
        assert_eq!(fin, Some(("01J8Z3N4K6P7Q9R2S5T8V1W3X6".to_string(), 130)));
    }

    /// One session, three commands: state carries over, stdin reaches `read`,
    /// and the history is what `GET /sessions/{id}` will report.
    #[tokio::test]
    async fn a_session_keeps_its_shell_state() {
        let ctx = ctx();
        let s = spawn(&ctx, &CreateSessionReq::default()).await.expect("bash");
        ctx.sessions.lock().unwrap().insert(s.id.clone(), s.clone());

        let c = run(&ctx, &s, "cd /tmp && export X=1").await;
        assert_eq!(c.exit, Some(0));
        let c = run(&ctx, &s, "echo $X && pwd").await;
        assert_eq!(c.exit, Some(0));
        let out = c.stdout.unwrap();
        assert!(out.starts_with("1\n") && out.contains("/tmp"), "{out:?}");
        assert_eq!(c.stderr.as_deref(), Some(""));

        // A subshell, because a bare `exit` in the group would end the session.
        let c = run(&ctx, &s, "echo oops 1>&2; (exit 3)").await;
        assert_eq!(c.exit, Some(3), "the group's exit status, not the shell's");
        assert_eq!(c.stderr.as_deref(), Some("oops\n"));

        assert_eq!(s.info().commands.len(), 3);
        assert!(s.info().commands.iter().all(|c| c.state == CommandState::Done));
    }

    #[tokio::test]
    async fn async_commands_stream_and_take_input() {
        let ctx = ctx();
        let s = spawn(&ctx, &CreateSessionReq::default()).await.expect("bash");
        ctx.sessions.lock().unwrap().insert(s.id.clone(), s.clone());

        // async: 202 with the id, output arrives later.
        let r = exec(
            State(ctx.clone()),
            Path(s.id.clone()),
            axum::http::HeaderMap::new(),
            serde_json::to_vec(&json!({"cmd": "sleep 1; echo done", "async": true})).unwrap().into(),
        )
        .await;
        assert_eq!(r.status(), StatusCode::ACCEPTED);
        let cid = {
            let b = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&b).unwrap()["command_id"].as_str().unwrap().to_string()
        };

        // A second command while that one runs is a 409.
        let r = exec(
            State(ctx.clone()),
            Path(s.id.clone()),
            axum::http::HeaderMap::new(),
            serde_json::to_vec(&json!({"cmd": "true"})).unwrap().into(),
        )
        .await;
        assert_eq!(r.status(), StatusCode::CONFLICT);

        // The logs the ws would replay-then-stream.
        let cmd = s.find_cmd(&cid).expect("command");
        let mut done = cmd.done.subscribe();
        done.wait_for(|v| *v).await.unwrap();
        let c = cmd.info(true);
        assert_eq!(c.exit, Some(0));
        assert_eq!(c.stdout.as_deref(), Some("done\n"));

        // stdin to a running command.
        let r = exec(
            State(ctx.clone()),
            Path(s.id.clone()),
            axum::http::HeaderMap::new(),
            serde_json::to_vec(&json!({"cmd": "read v; echo got $v", "async": true})).unwrap().into(),
        )
        .await;
        let cid = {
            let b = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&b).unwrap()["command_id"].as_str().unwrap().to_string()
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        let r = input(
            State(ctx.clone()),
            Path((s.id.clone(), cid.clone())),
            serde_json::to_vec(&json!({"data": "hello\n"})).unwrap().into(),
        )
        .await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        let cmd = s.find_cmd(&cid).unwrap();
        cmd.done.subscribe().wait_for(|v| *v).await.unwrap();
        assert_eq!(cmd.info(true).stdout.as_deref(), Some("got hello\n"));
    }

    /// The routes as they are actually mounted, and `logs/ws` replaying then
    /// streaming an async command to its `exit` frame.
    #[tokio::test]
    async fn logs_ws_replays_then_streams() {
        let ctx = ctx();
        let app = crate::router(ctx);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });

        let post = |path: String, body: serde_json::Value| async move {
            let s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let (mut send, conn) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(s)).await.unwrap();
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let req = axum::http::Request::builder()
                .method("POST")
                .uri(path)
                .header("host", "x")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap();
            let r = send.send_request(req).await.unwrap();
            let st = r.status();
            let b = axum::body::to_bytes(axum::body::Body::new(r.into_body()), 1 << 20).await.unwrap();
            (st, serde_json::from_slice::<serde_json::Value>(&b).unwrap_or(json!(null)))
        };

        let (st, v) = post("/sessions".into(), json!({})).await;
        assert_eq!(st, StatusCode::CREATED);
        let sid = v["id"].as_str().unwrap().to_string();

        let (st, v) = post(format!("/sessions/{sid}/exec"), json!({"cmd": "sleep 1; echo done", "async": true})).await;
        assert_eq!(st, StatusCode::ACCEPTED);
        let cid = v["command_id"].as_str().unwrap().to_string();

        let url = format!("ws://127.0.0.1:{port}/sessions/{sid}/commands/{cid}/logs/ws");
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await.expect("logs ws");
        let mut out = String::new();
        let mut exit = None;
        while let Some(Ok(m)) = futures_util::StreamExt::next(&mut ws).await {
            let tokio_tungstenite::tungstenite::Message::Text(t) = m else { continue };
            match serde_json::from_str::<ExecFrame>(&t).unwrap() {
                ExecFrame::Stdout { data } => out.push_str(&String::from_utf8_lossy(&B64.decode(data).unwrap())),
                ExecFrame::Exit { code, .. } => {
                    exit = Some(code);
                    break;
                }
                _ => {}
            }
        }
        assert_eq!((out.as_str(), exit), ("done\n", Some(0)));
    }

    #[tokio::test]
    async fn timeout_interrupts_the_command_and_keeps_the_session() {
        let ctx = ctx();
        let s = spawn(&ctx, &CreateSessionReq::default()).await.expect("bash");
        ctx.sessions.lock().unwrap().insert(s.id.clone(), s.clone());

        let started = Instant::now();
        let r = exec(
            State(ctx.clone()),
            Path(s.id.clone()),
            axum::http::HeaderMap::new(),
            serde_json::to_vec(&json!({"cmd": "sleep 30", "timeout_ms": 1000})).unwrap().into(),
        )
        .await;
        let b = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
        let c: SessionCommand = serde_json::from_slice(&b).unwrap();
        assert_eq!(c.exit, Some(130), "SIGINT'd, so 128+2");
        assert!(started.elapsed() < Duration::from_secs(5));

        // The shell trapped the INT, so the session is still usable.
        let c = run(&ctx, &s, "echo alive").await;
        assert_eq!(c.stdout.as_deref(), Some("alive\n"));

        delete(State(ctx.clone()), Path(s.id.clone())).await;
        assert!(lookup(&ctx, &s.id).is_none());
    }

    /// The escalation path: a command that *ignores* SIGINT still has to die on
    /// its own, leaving the session — and its state — alive.
    #[tokio::test]
    async fn a_command_that_ignores_sigint_dies_alone() {
        let ctx = ctx();
        let s = spawn(&ctx, &CreateSessionReq::default()).await.expect("bash");
        ctx.sessions.lock().unwrap().insert(s.id.clone(), s.clone());
        run(&ctx, &s, "export KEEP=me").await;

        let started = Instant::now();
        let c = run_for(&ctx, &s, r#"bash -c 'trap "" INT; while :; do sleep 1; done'"#, 2000).await;
        assert_ne!(c.exit, Some(0), "the stuck command must not report success");
        assert!(started.elapsed() < Duration::from_secs(10), "it must not wait out `sleep`");

        assert!(lookup(&ctx, &s.id).is_some(), "the session survives its stuck command");
        let c = run(&ctx, &s, "echo ok $KEEP").await;
        assert_eq!(c.stdout.as_deref(), Some("ok me\n"), "and keeps the shell's state");
    }
}
