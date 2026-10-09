//! One trait, two implementations, one connector type. The connector is what
//! the agent reverse proxy dials: a published loopback port (podman), the egress
//! proxy's relay onto the sandbox network (rootful podman on Linux) or a
//! Firecracker vsock UDS (firecracker).

pub mod native;
pub mod podman;

#[cfg(target_os = "linux")]
pub mod firecracker;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type Conn = Box<dyn Io>;
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One HTTP/1 connection to a guest, kept open between requests. Only the vsock
/// path has one: TCP already goes through the shared pooled client, while every
/// vsock request would otherwise pay for a fresh socket plus the `CONNECT`/`OK`
/// handshake. A pool of exactly one — a second concurrent request opens its own
/// rather than queueing behind a 120 s exec — and it is per *sandbox*, because
/// that is what a vsock is.
#[derive(Clone, Default)]
pub struct Keepalive(Arc<tokio::sync::Mutex<Option<hyper::client::conn::http1::SendRequest<axum::body::Body>>>>);

impl Keepalive {
    /// The kept connection, if there is one and it can take a request right now.
    /// `is_ready` is false while a response is still streaming, which is what
    /// makes handing it straight back safe.
    pub async fn take(&self) -> Option<hyper::client::conn::http1::SendRequest<axum::body::Body>> {
        self.0.try_lock().ok()?.take().filter(|s| s.is_ready())
    }

    pub async fn put(&self, s: hyper::client::conn::http1::SendRequest<axum::body::Body>) {
        if let Ok(mut g) = self.0.try_lock() {
            *g = Some(s);
        }
    }
}

impl std::fmt::Debug for Keepalive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keepalive")
    }
}

/// Container name → its current address on the sandbox network, kept by the
/// podman backend, so a `Relay` connector follows a container across stop/start
/// without the sandbox record ever changing.
pub type RelayTable = Arc<std::sync::Mutex<std::collections::HashMap<String, IpAddr>>>;

#[derive(Debug, Clone)]
pub enum Connector {
    Tcp(SocketAddr),
    /// Through the egress proxy container's relay listener: an HTTP CONNECT to
    /// the container's address on the sandbox network, looked up in `table` at
    /// connect time. Used where the host has no route onto that network.
    Relay {
        via: SocketAddr,
        name: String,
        port: u16,
        table: RelayTable,
    },
    /// The native tier's shim, on a unix socket in the sandbox's scratch dir.
    Unix(PathBuf),
    /// Firecracker's host-side vsock UDS. Connecting means writing
    /// `CONNECT <port>\n` and reading back `OK <n>\n`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Vsock {
        uds: PathBuf,
        port: u32,
        keepalive: Keepalive,
    },
}

impl Connector {
    pub async fn connect(&self) -> anyhow::Result<Conn> {
        match self {
            Connector::Tcp(addr) => Ok(Box::new(tokio::net::TcpStream::connect(addr).await?)),
            Connector::Relay { via, name, port, table } => {
                let ip = table.lock().unwrap().get(name).copied();
                let Some(ip) = ip else { anyhow::bail!("{name} has no address on the sandbox network") };
                let mut s = tokio::net::TcpStream::connect(via).await?;
                s.write_all(format!("CONNECT {ip}:{port} HTTP/1.1\r\nHost: {ip}:{port}\r\n\r\n").as_bytes()).await?;
                let mut r = BufReader::new(&mut s);
                let mut line = String::new();
                r.read_line(&mut line).await?;
                if !line.starts_with("HTTP/1.1 200") {
                    anyhow::bail!("relay refused {ip}:{port}: {line:?}");
                }
                while line != "\r\n" && !line.is_empty() {
                    line.clear();
                    r.read_line(&mut line).await?;
                }
                Ok(Box::new(s))
            }
            Connector::Unix(path) => Ok(Box::new(tokio::net::UnixStream::connect(path).await?)),
            Connector::Vsock { uds, port, .. } => {
                let mut s = tokio::net::UnixStream::connect(uds).await?;
                s.write_all(format!("CONNECT {port}\n").as_bytes()).await?;
                let mut r = BufReader::new(&mut s);
                let mut line = String::new();
                r.read_line(&mut line).await?;
                if !line.starts_with("OK") {
                    anyhow::bail!("vsock handshake refused: {line:?}");
                }
                Ok(Box::new(s))
            }
        }
    }

    /// Host:port form for the pooled HTTP client. `None` for vsock and the
    /// relay, which have to use a per-request handshake.
    pub fn tcp_authority(&self) -> Option<String> {
        match self {
            Connector::Tcp(a) => Some(a.to_string()),
            _ => None,
        }
    }

    /// The kept-open connection for this sandbox, where the tier has one.
    pub fn keepalive(&self) -> Option<&Keepalive> {
        match self {
            Connector::Vsock { keepalive, .. } => Some(keepalive),
            _ => None,
        }
    }
}

/// v3. The snapshot a `template` resolved to (`crate::snapshots`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct SnapshotRef {
    /// Everything a create needs: `dir/rootfs.ext4` to boot from, plus
    /// `dir/{vmstate,mem}` to restore from when the template has a capture.
    pub dir: PathBuf,
}

impl SnapshotRef {
    /// v4 §3a "start is a restore": an `image` template also restores once the
    /// daemon has captured its memory, so the question is what is on disk, not
    /// which `kind` the record carries.
    pub fn is_restore(&self) -> bool {
        crate::snapshots::has_memory(&self.dir)
    }
}

/// What the caller asks for.
#[derive(Debug, Clone)]
pub struct Spec {
    pub id: String,
    pub template: String,
    /// Mounted (podman) or extracted (firecracker) at this exact path (D4).
    pub workspace_path: String,
    /// v2. Extra egress allow globs for this sandbox, from the harness (D22).
    /// Honoured by the native tier, which gives every sandbox its own proxy
    /// listener; the vm tier shares one proxy container and ignores them.
    pub egress_allow: Vec<String>,
    /// v2. Image the requested tools resolve to (`images/templates.json`).
    /// Empty means the configured default.
    pub image: String,
    /// v3. Set when `template` named a snapshot on this host.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub snapshot: Option<SnapshotRef>,
    /// v3. `POST /sandboxes {env}`: handed to the guest with the workspace, or
    /// applied to the shim's environment on the native tier.
    pub env: std::collections::BTreeMap<String, String>,
    /// The creating session (§1). Empty for a warm sandbox nobody claimed yet.
    /// The native tier stamps it on the `egress.*` events its own proxy emits;
    /// the shared proxy container is attributed by peer IP instead.
    pub pi_session: String,
    /// v5 §3a. Resolved ceilings. A pool create uses `medium`; `apply_limits`
    /// re-applies the request's when a warm sandbox is handed out.
    pub limits: proto::SandboxLimits,
}

/// What a backend hands back.
#[derive(Debug, Clone)]
pub struct Sandbox {
    pub id: String,
    pub template: String,
    pub workspace_path: String,
    pub connector: Connector,
    /// v4. The per-sandbox secret every hop to this guest carries as
    /// `X-Sbx-Agent-Token` (protocol §2). `Some` only on the podman tier, whose
    /// agent port is published on the host's loopback; the native tier's unix
    /// socket sits in a `0700` directory and Firecracker's vsock is unreachable
    /// from anywhere but the jailer, so both keep `None`. Never serialised: it
    /// stays out of `SandboxInfo` and out of the logs.
    pub agent_token: Option<String>,
    /// Address the egress proxy sees; used to attribute `egress.*` events.
    pub peer_ip: Option<IpAddr>,
    pub created_at: String,
    pub ready_at: Option<String>,
    pub boot_ms: u64,
}

/// 32 bytes of kernel randomness, hex. Straight from `/dev/urandom` rather than
/// a new dependency: qafas only ever runs on unix, and this happens once per
/// sandbox create.
pub fn mint_agent_token() -> anyhow::Result<String> {
    use std::io::Read;
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(hex(&b))
}

/// Lowercase hex. Two call sites — the per-sandbox agent token and the TLS
/// certificate fingerprint — and both are compared against a string somebody
/// else produced, so there is exactly one spelling of it.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, x| {
        use std::fmt::Write;
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// The lifecycle verbs of §3a. v4: `Stop`/`Start` exist on every tier, the rest
/// stay remote-only, so which of them a backend answers is a per-verb question.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verb {
    Stop,
    Start,
    Pause,
    Resume,
    Archive,
}

impl Verb {
    /// The word the 409 names ("pause needs the remote tier").
    pub fn as_str(self) -> &'static str {
        match self {
            Verb::Stop => "stop",
            Verb::Start => "start",
            Verb::Pause => "pause",
            Verb::Resume => "resume",
            Verb::Archive => "archive",
        }
    }
}

pub trait Backend: Send + Sync {
    fn name(&self) -> &'static str;
    /// Whether a warm sandbox is tied to one workspace (a bind mount decided at
    /// create time). A microVM receives its workspace as a tar after acquire, so
    /// one warm pool per template serves every directory.
    fn pool_by_workspace(&self) -> bool {
        true
    }
    /// A workspace this runtime cannot mount safely, as the reason (a `409`).
    fn refuse_workspace(&self, _path: &str) -> Option<String> {
        None
    }
    fn create(&self, spec: Spec) -> BoxFut<'_, anyhow::Result<Sandbox>>;
    fn destroy(&self, sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>>;

    // ---- v5 sizes and limits (protocol §3a). Applied at create and again when
    // a pooled sandbox is handed out, always from out here: nothing the workload
    // can reach sets its own ceiling.

    /// Re-applies `l` to a sandbox that already exists. The error is a 500 on
    /// the create path, so a tier that cannot enforce must say so here rather
    /// than hand out a sandbox with somebody else's limits.
    fn apply_limits(&self, _sb: &Sandbox, _l: &proto::SandboxLimits) -> BoxFut<'_, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }
    /// One boundary sample, read on the reaper's 5 s tick. `None` when the tier
    /// cannot answer right now (a stopped sandbox, an unreachable guest).
    fn usage(&self, _sb: &Sandbox) -> BoxFut<'_, Option<proto::SandboxUsage>> {
        Box::pin(async { None })
    }
    /// `SandboxInfo.enforcement`: `kernel` where a cgroup holds the line,
    /// `daemon` where qafas's watchdog does (macOS native).
    fn enforcement(&self) -> &'static str {
        "kernel"
    }

    /// Rebuild the `Sandbox` for a record the persisted table kept across a
    /// restart (`livetable::plan` already checked the files are there). Only a
    /// tier that can hold a sandbox with no process of its own answers; the
    /// default is "this record has no owner any more".
    fn adopt(&self, _rec: &crate::livetable::LiveRecord) -> Option<Sandbox> {
        None
    }

    /// Is the thing that runs this sandbox still there? The reaper asks it about
    /// running sandboxes only, so "gone" means the sandbox died under us. It has
    /// to be cheap (one `pgrep`, one API call) and it has to answer `true` when
    /// it cannot tell: destroying a live sandbox on a failed probe is worse than
    /// listing a dead one for another five seconds. A tier with no process of
    /// its own keeps the default.
    fn alive(&self, _sb: &Sandbox) -> BoxFut<'_, bool> {
        Box::pin(async { true })
    }

    // ---- v3 lifecycle (protocol §3a). Only the microVM tier can snapshot RAM,
    // so everything below defaults to "not on this tier" and `api.rs` turns that
    // into the 409 the contract asks for. v4: the native and vm tiers answer
    // `Stop`/`Start` too, which is why this is asked per verb.
    fn supports_lifecycle(&self, _verb: Verb) -> bool {
        false
    }
    /// Pause, full snapshot into the jail, kill the VM. Keeps tap and jail.
    fn stop(&self, _sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        no_lifecycle()
    }
    /// Restore from the snapshot `stop`/`archive` left behind.
    fn start(&self, _sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        no_lifecycle()
    }
    fn pause(&self, _sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        no_lifecycle()
    }
    fn resume(&self, _sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        no_lifecycle()
    }
    /// Move a stopped sandbox's snapshot out of the jail and free the jail.
    fn archive(&self, _sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        no_lifecycle()
    }
    /// `POST /snapshots {source:{sandbox_id}}` on a live sandbox: writes the
    /// snapshot into `dir` and leaves the sandbox running. Returns `bytes`.
    fn snapshot(&self, _sb: &Sandbox, _dir: PathBuf) -> BoxFut<'_, anyhow::Result<u64>> {
        no_lifecycle()
    }
}

fn no_lifecycle<T: Send + 'static>() -> BoxFut<'static, anyhow::Result<T>> {
    Box::pin(async { anyhow::bail!("lifecycle needs the remote tier") })
}

/// Stands in for a pooled backend on a host that serves only the native tier,
/// so the pool and the API do not have to be `Option`-shaped for it.
pub struct Unavailable;

impl Backend for Unavailable {
    fn name(&self) -> &'static str {
        "none"
    }
    fn create(&self, _spec: Spec) -> BoxFut<'_, anyhow::Result<Sandbox>> {
        Box::pin(async { anyhow::bail!("this host serves no container or microVM tier") })
    }
    fn destroy(&self, _sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// Waits for the guest-agent to answer `/healthz` on a fresh sandbox.
pub async fn wait_healthy(conn: &Connector, timeout: std::time::Duration) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    let mut last = String::from("never attempted");
    while std::time::Instant::now() < deadline {
        match probe(conn).await {
            Ok(()) => return Ok(()),
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    anyhow::bail!("guest-agent not healthy within {timeout:?}: {last}")
}

/// One request to the guest agent over the connector, without the hyper client:
/// the connector may be a vsock handshake, and these calls happen once per
/// sandbox. Returns the status code and body.
pub async fn guest_call(
    conn: &Connector,
    token: Option<&str>,
    method: &str,
    path: &str,
    body: &serde_json::Value,
) -> anyhow::Result<(u16, String)> {
    use tokio::io::AsyncReadExt;
    let body = body.to_string();
    let auth = match token {
        Some(t) => format!("{}: {t}\r\n", proto::HDR_AGENT_TOKEN),
        None => String::new(),
    };
    let mut s = conn.connect().await?;
    s.write_all(
        format!("{method} {path} HTTP/1.0\r\nHost: sbx\r\n{auth}content-type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len())
            .as_bytes(),
    )
    .await?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("no status line in {:?}", &text[..text.len().min(60)]))?;
    Ok((status, text))
}

/// `guest_call`, but a non-2xx is an error naming the route. Every caller below
/// wanted exactly that and spelled it out itself.
async fn guest_ok(
    conn: &Connector,
    token: Option<&str>,
    method: &str,
    path: &str,
    body: &serde_json::Value,
) -> anyhow::Result<()> {
    let (status, text) = guest_call(conn, token, method, path, body).await?;
    if (200..300).contains(&status) {
        return Ok(());
    }
    anyhow::bail!("{path} returned {status}: {}", &text[..text.len().min(160)])
}

/// One GET whose body is JSON. Same connector, same one-shot handshake as
/// `guest_call`; only the parsing is different.
pub async fn guest_json<T: serde::de::DeserializeOwned>(
    conn: &Connector,
    method: &str,
    path: &str,
) -> anyhow::Result<T> {
    let (status, text) = guest_call(conn, None, method, path, &serde_json::Value::Null).await?;
    if !(200..300).contains(&status) {
        anyhow::bail!("{path} returned {status}");
    }
    let body = text.split("\r\n\r\n").nth(1).unwrap_or_default();
    Ok(serde_json::from_str(body)?)
}

/// Tells a pooled guest which workspace it now serves (`PUT /workspace`), so
/// its rules know the boundary even for a client that never uploads a tar.
/// v3: `env` rides along and becomes the default environment of every exec.
pub async fn set_workspace(
    conn: &Connector,
    token: Option<&str>,
    path: &str,
    env: &std::collections::BTreeMap<String, String>,
) -> anyhow::Result<()> {
    guest_ok(conn, token, "PUT", "/workspace", &serde_json::json!({"path": path, "env": env})).await
}

/// v5 §3a. `PUT /limits` on the guest agent: the in-guest cgroup (remote, where
/// the agent is root) or the daemon watchdog's budget (native). The vm tier does
/// not use it — podman owns that container's cgroup and `apply_limits` goes
/// through libpod instead.
pub async fn set_limits(conn: &Connector, token: Option<&str>, l: &proto::SandboxLimits) -> anyhow::Result<()> {
    guest_ok(conn, token, "PUT", "/limits", &serde_json::to_value(l)?).await
}

/// v5 §3a. `GET /usage`: the agent reads the cgroup files and `statvfs` itself,
/// so nothing is ever asked of the workload. A guest image without the route
/// answers 404 and the sandbox simply reports no usage.
pub async fn guest_usage(conn: &Connector, token: Option<&str>) -> Option<proto::SandboxUsage> {
    let (status, text) = guest_call(conn, token, "GET", "/usage", &serde_json::Value::Null).await.ok()?;
    if !(200..300).contains(&status) {
        return None;
    }
    serde_json::from_str(text.split("\r\n\r\n").nth(1)?).ok()
}

/// v3. After a restore the guest is a clone: same kernel state, new identity.
/// It re-plants canaries, reconfigures eth0, and sets the clock (which has been
/// frozen since the snapshot). A guest image without the route answers 404 and
/// the restored VM still works, minus those three things.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub async fn restored(
    conn: &Connector,
    token: Option<&str>,
    id: &str,
    ip: &str,
    gw: &str,
    proxy: &str,
    now_ms: i64,
) -> anyhow::Result<()> {
    let body = serde_json::json!({"id": id, "ip": ip, "gw": gw, "proxy": proxy, "now": now_ms});
    // 404 is a guest image without the route: the VM works, minus the three
    // things above, and saying so is better than refusing the restore.
    if guest_call(conn, token, "POST", "/restored", &body).await?.0 == 404 {
        tracing::warn!(sandbox_id = id, "guest image has no POST /restored; clock and identity are stale");
        return Ok(());
    }
    guest_ok(conn, token, "POST", "/restored", &body).await
}

async fn probe(conn: &Connector) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;
    let mut s = conn.connect().await?;
    s.write_all(b"GET /healthz HTTP/1.0\r\nHost: sbx\r\n\r\n").await?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await?;
    if buf.starts_with(b"HTTP/1.0 200") || buf.starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        anyhow::bail!("healthz returned {:?}", String::from_utf8_lossy(&buf[..buf.len().min(40)]))
    }
}
