//! Rust client for [Qafas Sandbox](https://github.com/exitCodeNihil/qafas-sandbox): the control
//! plane (`:7800`), which places the sandbox and hands back the worker to use, or one worker
//! (`:7700`) directly. Async on tokio, rustls for https/wss. Wire types come from the daemon's
//! own `proto` crate and are re-exported, so there is one definition of the contract.
//!
//! ```no_run
//! # async fn demo() -> qafas_sandbox::Result<()> {
//! use qafas_sandbox::{Sandbox, AcquireOptions, ExecOptions};
//! let sb = Sandbox::create(Some("http://127.0.0.1:7800"), None, Some("my-session"),
//!                          AcquireOptions::new().runtime("docker")).await?;
//! let r = sb.exec_buffered("echo hi", &ExecOptions::default()).await?;
//! println!("{} {}", r.stdout, r.exit);
//! sb.destroy().await?;
//! # Ok(()) }
//! ```

mod client;
mod image;
mod net;
mod pack;

pub use client::{
    acquire, control_plane_token, isolation_to_runtime, runtime_to_isolation, snapshots, AcquireOptions, EventStream,
    ExecOptions, Sandbox, Session, SnapshotSpec, Snapshots,
};
pub use image::Image;
pub use pack::{pack_workspace, unpack_tar, DEFAULT_IGNORE};

// The wire types the daemon already defines, reused as they are.
pub use proto::sizes::{default_table as default_sizes, DEFAULT as DEFAULT_SIZE};
pub use proto::{
    CommandState, Event, EventType, FsStat, PreviewInfo, SandboxInfo, SandboxLimits, SandboxState, SandboxUsage,
    SessionInfo, SnapshotInfo, SnapshotSource, SnapshotState, HDR_PI_SESSION, HDR_TOOL_CALL_ID,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SIZE_NAMES: [&str; 4] = ["micro", "mini", "medium", "high"];

pub type Result<T> = std::result::Result<T, Error>;

/// Which pipe a chunk of streamed output came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// Result of `exec` / `exec_buffered`. `proto::ExecResp` has no `timed_out` (the `/exec/ws`
/// exit frame does), so this is the SDK's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    pub exit: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub truncated: bool,
    pub timed_out: bool,
}

/// A session command. Not `proto::SessionCommand`: the daemon answers a sync exec with
/// `{command_id, exit, stdout, stderr}` and an async one with `{command_id}` only
/// (docs/protocol.md section 3a), and that type requires `cmd`, `state` and `started_at`.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
pub struct SessionCommand {
    pub command_id: String,
    #[serde(default)]
    pub cmd: String,
    /// Absent on the exec replies, present on `command()`.
    #[serde(default)]
    pub state: Option<CommandState>,
    #[serde(default)]
    pub started_at: String,
    #[serde(default)]
    pub exit: Option<i32>,
    #[serde(default)]
    pub ended_at: Option<String>,
    #[serde(default)]
    pub stdout: Option<String>,
    #[serde(default)]
    pub stderr: Option<String>,
}

/// Everything that can go wrong. A non-2xx answer is `Http`; a 404 from the fs reads is the
/// distinct `NotFound` (the Python SDK's `FileNotFoundError`).
#[derive(Debug)]
pub enum Error {
    /// Non-2xx response, with the server's `{"error"}` text when it sent one.
    Http {
        status: u16,
        body: String,
    },
    /// `read_file` / `stat` / `listdir` on a path that does not exist.
    NotFound(String),
    /// A bad argument or an unsafe path (invalid runtime, outside the workspace, tar escape).
    Invalid(String),
    /// A deadline passed (`Snapshots::wait_ready`).
    Timeout(String),
    /// The workspace upload after a `remote` create failed; the sandbox was destroyed.
    Upload(String),
    /// Connect, TLS or WebSocket failure.
    Transport(String),
    Json(serde_json::Error),
    Io(std::io::Error),
}

impl Error {
    pub(crate) fn http(status: u16, body: &[u8]) -> Error {
        Error::Http { status, body: String::from_utf8_lossy(body).into_owned() }
    }

    /// The server's `{"error": "..."}` text, if `body` is that.
    fn extract(body: &str) -> Option<String> {
        let v: serde_json::Value = serde_json::from_str(body).ok()?;
        v.get("error")?.as_str().filter(|s| !s.is_empty()).map(str::to_owned)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Http { status, body } => {
                write!(f, "HTTP {status}: {}", Error::extract(body).as_deref().unwrap_or(body))
            }
            Error::NotFound(p) => write!(f, "not found: {p}"),
            Error::Invalid(m) | Error::Timeout(m) | Error::Upload(m) | Error::Transport(m) => f.write_str(m),
            Error::Json(e) => write!(f, "invalid JSON: {e}"),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Json(e) => Some(e),
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_message_prefers_the_server_error_text() {
        let e = Error::http(409, br#"{"error":"sandbox is paused"}"#);
        assert_eq!(e.to_string(), "HTTP 409: sandbox is paused");
        assert!(matches!(e, Error::Http { status: 409, .. }));
        // No `error` key, or not JSON at all: the raw body.
        assert_eq!(Error::http(500, br#"{"x":1}"#).to_string(), r#"HTTP 500: {"x":1}"#);
        assert_eq!(Error::http(502, b"bad gateway").to_string(), "HTTP 502: bad gateway");
        assert_eq!(Error::http(400, br#"{"error":7}"#).to_string(), r#"HTTP 400: {"error":7}"#);
    }

    #[test]
    fn sizes_match_the_contract() {
        let t = default_sizes();
        assert_eq!(t.keys().map(String::as_str).collect::<Vec<_>>(), {
            let mut n = SIZE_NAMES.to_vec();
            n.sort();
            n
        });
        assert_eq!(DEFAULT_SIZE, "medium");
        assert_eq!(t["medium"].mem_mib, 2048);
        assert_eq!(VERSION, proto::VERSION);
    }
}
