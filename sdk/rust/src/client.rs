//! `acquire` / `Sandbox` / `Session` / `Snapshots`: the client half of docs/protocol.md,
//! behaviour-for-behaviour the Python SDK (`sdk/python/src/qafas_sandbox/client.py`).

use std::collections::BTreeMap;
use std::path::Path;
use std::pin::Pin;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::{stream, SinkExt, Stream as FuturesStream, StreamExt};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};
use tokio_tungstenite::tungstenite::Message;

use crate::net::{to_ws, transport, Headers, Ws};
use crate::pack::{abspath, pack_workspace, unpack_tar};
use crate::{
    Error, Event, ExecResult, FsStat, Image, PreviewInfo, Result, SandboxInfo, SandboxLimits, SessionCommand,
    SnapshotInfo, Stream, HDR_PI_SESSION, HDR_TOOL_CALL_ID,
};

/// Python's `urllib.parse.quote(s)`: everything but letters, digits, `_.-~` and `/`.
const QUOTE: &AsciiSet = &NON_ALPHANUMERIC.remove(b'_').remove(b'.').remove(b'-').remove(b'~').remove(b'/');

fn quote(s: &str) -> String {
    utf8_percent_encode(s, QUOTE).to_string()
}

fn auth(token: &str) -> Headers {
    vec![("Authorization".into(), format!("Bearer {token}"))]
}

async fn raw(method: &str, url: &str, headers: &[(String, String)], body: Option<Vec<u8>>) -> Result<(u16, Vec<u8>)> {
    transport()?.send(method, url, headers, body).await
}

/// A request whose non-2xx answer is an error; returns the body.
async fn ok(method: &str, url: &str, headers: &[(String, String)], body: Option<Vec<u8>>) -> Result<Vec<u8>> {
    let (status, data) = raw(method, url, headers, body).await?;
    if status >= 400 {
        return Err(Error::http(status, &data));
    }
    Ok(data)
}

/// JSON in, JSON out; an empty answer (204) is `null`.
async fn json_req(method: &str, url: &str, headers: &[(String, String)], obj: Option<&Value>) -> Result<Value> {
    let mut h = headers.to_vec();
    let body = obj.map(|o| {
        h.push(("content-type".into(), "application/json".into()));
        o.to_string().into_bytes()
    });
    let data = ok(method, url, &h, body).await?;
    if data.is_empty() {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_slice(&data)?)
}

async fn typed<T: DeserializeOwned>(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    obj: Option<&Value>,
) -> Result<T> {
    Ok(serde_json::from_value(json_req(method, url, headers, obj).await?)?)
}

/// `.../sandboxes/{id}/agent` -> `.../sandboxes/{id}`: where qafas-level routes live.
fn agent_base(endpoint: &str) -> &str {
    endpoint.strip_suffix("/agent").unwrap_or(endpoint)
}

/// Up to `/sandboxes/`: where `/events/ws` lives.
fn qafas_root(endpoint: &str) -> &str {
    endpoint.find("/sandboxes/").map_or(endpoint, |i| &endpoint[..i])
}

// ------------------------------------------------------------------ runtime naming

const RUNTIME_VALUES: &str = "auto|process|docker|firecracker";

/// Daytona/E2B-style tier name -> this project's `isolation`. Purely a client-side relabelling,
/// never sent on the wire. `auto`/`None` leave tier selection to qafas; anything else is an error
/// naming the accepted values rather than a silently ignored typo.
pub fn runtime_to_isolation(runtime: Option<&str>) -> Result<Option<&'static str>> {
    match runtime {
        None | Some("auto") => Ok(None),
        Some("process") => Ok(Some("native")),
        Some("docker") => Ok(Some("vm")),
        Some("firecracker") => Ok(Some("remote")),
        Some(r) => Err(Error::Invalid(format!("invalid runtime \"{r}\": expected one of {RUNTIME_VALUES}"))),
    }
}

pub fn isolation_to_runtime(isolation: Option<&str>) -> Option<&'static str> {
    match isolation {
        Some("native") => Some("process"),
        Some("vm") => Some("docker"),
        Some("remote") => Some("firecracker"),
        _ => None,
    }
}

/// The bearer for the control plane: an API key identifies the application (protocol section
/// 4b); the admin token is the root credential and the fallback.
pub fn control_plane_token(api_key: Option<&str>) -> String {
    let env = |k| std::env::var(k).ok().filter(|v| !v.is_empty());
    api_key
        .map(str::to_owned)
        .filter(|k| !k.is_empty())
        .or_else(|| env("SBX_API_KEY"))
        .or_else(|| env("SBX_ADMIN_TOKEN"))
        .unwrap_or_default()
}

/// Refuses a remote path outside `workspace_path` unless `allow_outside`: qafas/guest-agent
/// enforce the real boundary, this only catches an obvious typo before a wasted round trip.
/// Purely lexical (Python's `os.path.relpath`).
fn assert_inside_workspace(remote: &str, workspace: &str, allow_outside: bool) -> Result<()> {
    if allow_outside || workspace.is_empty() || abspath(Path::new(remote)).starts_with(abspath(Path::new(workspace))) {
        return Ok(());
    }
    Err(Error::Invalid(format!(
        "{remote} is outside the workspace ({workspace}); pass allow_outside(true) to override"
    )))
}

// ------------------------------------------------------------------ websocket frames

/// Next JSON text/binary frame; `None` when the peer closes. Non-JSON frames are skipped.
async fn next_json(ws: &mut Ws) -> Result<Option<Value>> {
    while let Some(msg) = ws.next().await {
        let bytes = match msg.map_err(|e| Error::Transport(format!("websocket: {e}")))? {
            Message::Text(t) => t.as_bytes().to_vec(),
            Message::Binary(b) => b.to_vec(),
            Message::Close(_) => return Ok(None),
            _ => continue,
        };
        if let Ok(v) = serde_json::from_slice(&bytes) {
            return Ok(Some(v));
        }
    }
    Ok(None)
}

/// A `{"type":"stdout"|"stderr","data":<base64>}` frame, decoded.
fn output_frame(v: &Value) -> Option<(Stream, Vec<u8>)> {
    let stream = match v.get("type")?.as_str()? {
        "stdout" => Stream::Stdout,
        "stderr" => Stream::Stderr,
        _ => return None,
    };
    STANDARD.decode(v.get("data")?.as_str()?).ok().map(|d| (stream, d))
}

/// Live events of one sandbox. Dropping it closes the connection.
pub type EventStream = Pin<Box<dyn FuturesStream<Item = Result<Event>> + Send>>;

// ------------------------------------------------------------------ options

/// Per-call options of `exec` / `exec_buffered`. `cwd` defaults to the sandbox's workspace.
#[derive(Debug, Clone, Default)]
pub struct ExecOptions {
    pub cwd: Option<String>,
    pub env: BTreeMap<String, String>,
    pub timeout: Option<Duration>,
    /// Sent as `x-tool-call-id`; every qafas event of this call carries it.
    pub tool_call_id: String,
}

impl ExecOptions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }
    pub fn env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.insert(k.into(), v.into());
        self
    }
    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }
    pub fn tool_call_id(mut self, id: impl Into<String>) -> Self {
        self.tool_call_id = id.into();
        self
    }
}

/// Everything `acquire` can set beyond `url`/`cwd`/`pi_session`. Unset fields are not sent.
#[derive(Debug, Clone)]
pub struct AcquireOptions {
    pub api_key: Option<String>,
    /// `native|vm|remote` (or `auto`). Loses to `runtime` when both are given.
    pub isolation: Option<String>,
    /// `auto|process|docker|firecracker`, the Daytona/E2B naming; wins over `isolation`.
    pub runtime: Option<String>,
    pub trust: String,
    pub tools: Vec<String>,
    pub egress_allow: Vec<String>,
    pub ttl_secs: Option<u64>,
    /// Bearer for the create call; defaults to `$SBX_TOKEN` (worker) or the control-plane token.
    pub token: Option<String>,
    pub template: String,
    /// A snapshot name; wins over `template`.
    pub snapshot: Option<String>,
    pub name: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub env: BTreeMap<String, String>,
    pub auto_stop_secs: Option<u64>,
    pub auto_archive_secs: Option<u64>,
    pub auto_delete_secs: Option<u64>,
    pub max_age_secs: Option<u64>,
    /// `micro|mini|medium|high`; giving `limits` as well is a 400.
    pub size: Option<String>,
    pub limits: Option<SandboxLimits>,
    /// `remote` tier only: tar the `cwd` up after create (default true).
    pub upload_workspace: bool,
}

impl Default for AcquireOptions {
    fn default() -> Self {
        AcquireOptions {
            api_key: None,
            isolation: None,
            runtime: None,
            trust: "trusted".into(),
            tools: vec![],
            egress_allow: vec![],
            ttl_secs: None,
            token: None,
            template: "base".into(),
            snapshot: None,
            name: None,
            labels: BTreeMap::new(),
            env: BTreeMap::new(),
            auto_stop_secs: None,
            auto_archive_secs: None,
            auto_delete_secs: None,
            max_age_secs: None,
            size: None,
            limits: None,
            upload_workspace: true,
        }
    }
}

impl AcquireOptions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn api_key(mut self, v: impl Into<String>) -> Self {
        self.api_key = Some(v.into());
        self
    }
    pub fn isolation(mut self, v: impl Into<String>) -> Self {
        self.isolation = Some(v.into());
        self
    }
    pub fn runtime(mut self, v: impl Into<String>) -> Self {
        self.runtime = Some(v.into());
        self
    }
    pub fn trust(mut self, v: impl Into<String>) -> Self {
        self.trust = v.into();
        self
    }
    pub fn tools<S: Into<String>>(mut self, v: impl IntoIterator<Item = S>) -> Self {
        self.tools = v.into_iter().map(Into::into).collect();
        self
    }
    pub fn egress_allow<S: Into<String>>(mut self, v: impl IntoIterator<Item = S>) -> Self {
        self.egress_allow = v.into_iter().map(Into::into).collect();
        self
    }
    pub fn ttl_secs(mut self, v: u64) -> Self {
        self.ttl_secs = Some(v);
        self
    }
    pub fn token(mut self, v: impl Into<String>) -> Self {
        self.token = Some(v.into());
        self
    }
    pub fn template(mut self, v: impl Into<String>) -> Self {
        self.template = v.into();
        self
    }
    pub fn snapshot(mut self, v: impl Into<String>) -> Self {
        self.snapshot = Some(v.into());
        self
    }
    pub fn name(mut self, v: impl Into<String>) -> Self {
        self.name = Some(v.into());
        self
    }
    pub fn label(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.labels.insert(k.into(), v.into());
        self
    }
    pub fn env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.insert(k.into(), v.into());
        self
    }
    pub fn auto_stop_secs(mut self, v: u64) -> Self {
        self.auto_stop_secs = Some(v);
        self
    }
    pub fn auto_archive_secs(mut self, v: u64) -> Self {
        self.auto_archive_secs = Some(v);
        self
    }
    pub fn auto_delete_secs(mut self, v: u64) -> Self {
        self.auto_delete_secs = Some(v);
        self
    }
    pub fn max_age_secs(mut self, v: u64) -> Self {
        self.max_age_secs = Some(v);
        self
    }
    pub fn size(mut self, v: impl Into<String>) -> Self {
        self.size = Some(v.into());
        self
    }
    pub fn limits(mut self, v: SandboxLimits) -> Self {
        self.limits = Some(v);
        self
    }
    pub fn upload_workspace(mut self, v: bool) -> Self {
        self.upload_workspace = v;
        self
    }
}

// ------------------------------------------------------------------ Sandbox

/// A single acquired sandbox. Cheap to clone. There is no destroy-on-drop (it would need an
/// async runtime in `Drop`): call `destroy()`.
#[derive(Debug, Clone)]
pub struct Sandbox {
    pub endpoint: String,
    pub token: String,
    pub pi_session: String,
    pub id: String,
    pub backend: String,
    pub workspace_path: String,
    pub isolation: Option<String>,
    pub tools: BTreeMap<String, String>,
    pub missing_tools: Vec<String>,
    /// v5: a named size, or `custom`.
    pub size: Option<String>,
    /// v5: the ceilings actually applied.
    pub limits: Option<SandboxLimits>,
    /// v5.1: the daemon's record right after create. Not called `info`: that is the live refresh.
    pub create_info: Option<SandboxInfo>,
}

impl Sandbox {
    /// A handle to a sandbox you already have the endpoint and token for.
    pub fn new(
        endpoint: impl Into<String>,
        token: impl Into<String>,
        pi_session: impl Into<String>,
        id: impl Into<String>,
        backend: impl Into<String>,
        workspace_path: impl Into<String>,
    ) -> Sandbox {
        Sandbox {
            endpoint: endpoint.into(),
            token: token.into(),
            pi_session: pi_session.into(),
            id: id.into(),
            backend: backend.into(),
            workspace_path: workspace_path.into(),
            isolation: None,
            tools: BTreeMap::new(),
            missing_tools: vec![],
            size: None,
            limits: None,
            create_info: None,
        }
    }

    /// Same as `acquire()`, the Daytona/E2B-style entry point.
    pub async fn create(
        url: Option<&str>,
        cwd: Option<&str>,
        pi_session: Option<&str>,
        opts: AcquireOptions,
    ) -> Result<Sandbox> {
        acquire(url, cwd, pi_session, opts).await
    }

    /// The tier qafas actually picked, in the `runtime` naming.
    pub fn runtime(&self) -> Option<&'static str> {
        isolation_to_runtime(self.isolation.as_deref())
    }

    pub fn cdp_url(&self) -> String {
        to_ws(&self.endpoint) + "/browser/cdp"
    }

    fn headers(&self, tool_call_id: &str) -> Headers {
        let mut h = auth(&self.token);
        h.push((HDR_PI_SESSION.into(), self.pi_session.clone()));
        h.push((HDR_TOOL_CALL_ID.into(), tool_call_id.into()));
        h
    }

    fn url(&self, suffix: &str) -> String {
        format!("{}{suffix}", self.endpoint)
    }

    fn agent_url(&self, suffix: &str) -> String {
        format!("{}{suffix}", agent_base(&self.endpoint))
    }

    // -------------------------------------------------------------- exec

    fn exec_body(&self, cmd: &str, o: &ExecOptions, start: bool) -> Value {
        let mut b = Map::new();
        if start {
            b.insert("type".into(), "start".into());
        }
        b.insert("cmd".into(), cmd.into());
        b.insert(
            "cwd".into(),
            o.cwd.clone().filter(|c| !c.is_empty()).unwrap_or_else(|| self.workspace_path.clone()).into(),
        );
        if !o.env.is_empty() {
            b.insert("env".into(), json!(o.env));
        }
        if let Some(ms) = o.timeout.map(|t| t.as_millis() as u64).filter(|ms| *ms > 0) {
            b.insert("timeout_ms".into(), ms.into());
        }
        Value::Object(b)
    }

    /// `POST /exec`: the whole result at once.
    pub async fn exec_buffered(&self, cmd: &str, o: &ExecOptions) -> Result<ExecResult> {
        let body = self.exec_body(cmd, o, false);
        let r: proto::ExecResp = typed("POST", &self.url("/exec"), &self.headers(&o.tool_call_id), Some(&body)).await?;
        Ok(ExecResult {
            exit: r.exit,
            stdout: r.stdout,
            stderr: r.stderr,
            duration_ms: r.duration_ms,
            truncated: r.truncated,
            timed_out: false,
        })
    }

    /// Runs `cmd` over `/exec/ws`.
    pub async fn exec(&self, cmd: &str, o: &ExecOptions) -> Result<ExecResult> {
        self.exec_with(cmd, o, |_, _| {}).await
    }

    /// Like `exec`, calling `on_output(chunk, stream)` for every frame as it arrives.
    pub async fn exec_with(
        &self,
        cmd: &str,
        o: &ExecOptions,
        mut on_output: impl FnMut(&[u8], Stream),
    ) -> Result<ExecResult> {
        let mut ws =
            transport()?.ws_connect(&(to_ws(&self.endpoint) + "/exec/ws"), &self.headers(&o.tool_call_id)).await?;
        ws.send(Message::Text(self.exec_body(cmd, o, true).to_string().into()))
            .await
            .map_err(|e| Error::Transport(format!("websocket: {e}")))?;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let (mut exit, mut duration_ms, mut timed_out) = (1, 0, false);
        while let Some(f) = next_json(&mut ws).await? {
            if let Some((s, chunk)) = output_frame(&f) {
                match s {
                    Stream::Stdout => out.extend_from_slice(&chunk),
                    Stream::Stderr => err.extend_from_slice(&chunk),
                }
                on_output(&chunk, s);
            } else if f.get("type").and_then(Value::as_str) == Some("exit") {
                exit = f.get("code").and_then(Value::as_i64).unwrap_or(1) as i32;
                duration_ms = f.get("duration_ms").and_then(Value::as_u64).unwrap_or(0);
                timed_out = f.get("timed_out").and_then(Value::as_bool).unwrap_or(false);
                break;
            }
        }
        Ok(ExecResult {
            exit,
            stdout: String::from_utf8_lossy(&out).into_owned(),
            stderr: String::from_utf8_lossy(&err).into_owned(),
            duration_ms,
            truncated: false,
            timed_out,
        })
    }

    // -------------------------------------------------------------- fs

    async fn fs_get(&self, route: &str, path: &str) -> Result<Vec<u8>> {
        let (status, data) =
            raw("GET", &self.url(&format!("/fs/{route}?path={}", quote(path))), &self.headers(""), None).await?;
        match status {
            404 => Err(Error::NotFound(path.to_owned())),
            s if s >= 400 => Err(Error::http(s, &data)),
            _ => Ok(data),
        }
    }

    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        self.fs_get("read", path).await
    }

    pub async fn write_file(&self, path: &str, content: impl AsRef<[u8]>) -> Result<()> {
        ok(
            "PUT",
            &self.url(&format!("/fs/write?path={}", quote(path))),
            &self.headers(""),
            Some(content.as_ref().to_vec()),
        )
        .await?;
        Ok(())
    }

    /// Alias of `write_file`, named for symmetry with `read_file`/`upload`/`download`.
    pub async fn upload_bytes(&self, path: &str, content: impl AsRef<[u8]>) -> Result<()> {
        self.write_file(path, content).await
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        json_req("POST", &self.url("/fs/mkdir"), &self.headers(""), Some(&json!({ "path": path }))).await?;
        Ok(())
    }

    pub async fn stat(&self, path: &str) -> Result<FsStat> {
        Ok(serde_json::from_slice(&self.fs_get("stat", path).await?)?)
    }

    pub async fn listdir(&self, path: &str) -> Result<Vec<String>> {
        Ok(serde_json::from_slice(&self.fs_get("list", path).await?)?)
    }

    pub async fn upload_tar(&self, path: &str, tar: Vec<u8>) -> Result<()> {
        ok("PUT", &self.url(&format!("/fs/tar?path={}", quote(path))), &self.headers(""), Some(tar)).await?;
        Ok(())
    }

    pub async fn download_tar(&self, path: &str) -> Result<Vec<u8>> {
        ok("GET", &self.url(&format!("/fs/tar?path={}", quote(path))), &self.headers(""), None).await
    }

    /// Uploads a local file or directory to `remote`. A directory is packed with the same rules
    /// as a remote-tier workspace upload (`pack_workspace`: `.sbxignore` + `DEFAULT_IGNORE`) and
    /// sent as a tar; a file goes straight through `write_file`. Refuses a `remote` outside this
    /// sandbox's workspace unless `allow_outside`: a client-side guard against a typo'd path.
    pub async fn upload(&self, local: impl AsRef<Path>, remote: &str, allow_outside: bool) -> Result<()> {
        assert_inside_workspace(remote, &self.workspace_path, allow_outside)?;
        let local = local.as_ref().to_path_buf();
        if local.is_dir() {
            let tar = tokio::task::spawn_blocking(move || pack_workspace(local, &[]))
                .await
                .map_err(|e| Error::Transport(e.to_string()))??;
            self.upload_tar(remote, tar).await
        } else {
            self.write_file(remote, tokio::fs::read(local).await?).await
        }
    }

    /// Downloads `remote` (file or directory) to `local`. Same boundary guard as `upload`.
    pub async fn download(&self, remote: &str, local: impl AsRef<Path>, allow_outside: bool) -> Result<()> {
        assert_inside_workspace(remote, &self.workspace_path, allow_outside)?;
        let local = local.as_ref().to_path_buf();
        if self.stat(remote).await?.is_dir {
            let tar = self.download_tar(remote).await?;
            tokio::task::spawn_blocking(move || unpack_tar(&tar, local))
                .await
                .map_err(|e| Error::Transport(e.to_string()))?
        } else {
            let data = self.read_file(remote).await?;
            if let Some(parent) = local.parent().filter(|p| !p.as_os_str().is_empty()) {
                tokio::fs::create_dir_all(parent).await?;
            }
            Ok(tokio::fs::write(local, data).await?)
        }
    }

    // -------------------------------------------------------------- qafas

    /// `GET /sandboxes/{id}/processes`: the live process tree (generic JSON objects).
    pub async fn processes(&self) -> Result<Vec<Value>> {
        typed("GET", &self.agent_url("/processes"), &self.headers(""), None).await
    }

    /// Live events for this sandbox from qafas's `/events/ws` firehose, filtered client-side to
    /// this sandbox id. Connects before returning, so a bad URL or token fails here. A frame of
    /// this sandbox that is not an `Event` the `proto` types know (a newer daemon's event type)
    /// is yielded as an `Err` and the stream goes on.
    pub async fn events(&self) -> Result<EventStream> {
        let url = to_ws(qafas_root(&self.endpoint)) + "/events/ws";
        let ws = transport()?.ws_connect(&url, &auth(&self.token)).await?;
        let id = self.id.clone();
        Ok(Box::pin(stream::unfold(Some(ws), move |st| {
            let id = id.clone();
            async move {
                let mut ws = st?;
                loop {
                    match next_json(&mut ws).await {
                        Ok(Some(v)) if v.get("sandbox_id").and_then(Value::as_str) == Some(id.as_str()) => {
                            return Some((serde_json::from_value::<Event>(v).map_err(Error::from), Some(ws)));
                        }
                        Ok(Some(_)) => {}
                        Ok(None) => return None,
                        Err(e) => return Some((Err(e), None)),
                    }
                }
            }
        })))
    }

    // -------------------------------------------------------------- lifecycle

    /// `GET /sandboxes/{id}`: the current record, including v3 state and timers.
    pub async fn info(&self) -> Result<SandboxInfo> {
        typed("GET", &self.agent_url(""), &self.headers(""), None).await
    }

    async fn lifecycle(&self, verb: &str) -> Result<()> {
        ok("POST", &self.agent_url(&format!("/{verb}")), &self.headers(""), None).await?;
        Ok(())
    }

    /// `remote` tier only; `native`/`vm` answer 409 (docs/protocol.md section 3a "Lifecycle").
    pub async fn stop(&self) -> Result<()> {
        self.lifecycle("stop").await
    }

    pub async fn start(&self) -> Result<SandboxInfo> {
        typed("POST", &self.agent_url("/start"), &self.headers(""), None).await
    }

    pub async fn pause(&self) -> Result<()> {
        self.lifecycle("pause").await
    }

    pub async fn resume(&self) -> Result<()> {
        self.lifecycle("resume").await
    }

    pub async fn archive(&self) -> Result<()> {
        self.lifecycle("archive").await
    }

    /// `DELETE /sandboxes/{id}`; a sandbox that is already gone is success, so calling it twice
    /// is a no-op. "Gone" is a 404, or the worker's 401 `token revoked with its sandbox`: a
    /// worker revokes the sandbox-scoped token on destroy, so the second DELETE answers that
    /// rather than 404 (the Python SDK raises there; protocol section 3 does not list it).
    pub async fn destroy(&self) -> Result<()> {
        let (status, data) = raw("DELETE", &self.agent_url(""), &auth(&self.token), None).await?;
        let revoked = status == 401 && String::from_utf8_lossy(&data).contains("token revoked with its sandbox");
        if status >= 400 && status != 404 && !revoked {
            return Err(Error::http(status, &data));
        }
        Ok(())
    }

    /// Alias of `destroy`, the name Daytona/E2B users expect.
    pub async fn delete(&self) -> Result<()> {
        self.destroy().await
    }

    /// `POST /sandboxes/{id}/preview`: a signed URL for a port inside the sandbox.
    pub async fn preview(&self, port: u16, ttl_secs: Option<u64>) -> Result<PreviewInfo> {
        let mut body = json!({ "port": port });
        if let Some(t) = ttl_secs {
            body["ttl_secs"] = t.into();
        }
        typed("POST", &self.agent_url("/preview"), &self.headers(""), Some(&body)).await
    }

    /// `POST /sessions`: a persistent shell inside this sandbox, alive until deleted or the
    /// sandbox stops.
    pub async fn create_session(
        &self,
        id: Option<&str>,
        cwd: Option<&str>,
        env: &BTreeMap<String, String>,
    ) -> Result<Session> {
        let mut body = Map::new();
        if let Some(id) = id.filter(|s| !s.is_empty()) {
            body.insert("id".into(), id.into());
        }
        if let Some(cwd) = cwd.filter(|s| !s.is_empty()) {
            body.insert("cwd".into(), cwd.into());
        }
        if !env.is_empty() {
            body.insert("env".into(), json!(env));
        }
        let resp = json_req("POST", &self.url("/sessions"), &self.headers(""), Some(&Value::Object(body))).await?;
        let id = resp
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Transport("create session: no id in the reply".into()))?;
        Ok(Session { sb: self.clone(), id: id.to_owned() })
    }
}

// ------------------------------------------------------------------ Session

/// A persistent shell inside a sandbox (docs/protocol.md section 3a "Sessions"). Reached through
/// the owning sandbox's endpoint and token.
#[derive(Debug, Clone)]
pub struct Session {
    sb: Sandbox,
    pub id: String,
}

impl Session {
    fn url(&self, suffix: &str) -> String {
        self.sb.url(&format!("/sessions/{}{suffix}", self.id))
    }

    async fn exec_inner(&self, cmd: &str, is_async: bool, timeout_ms: Option<u64>) -> Result<SessionCommand> {
        let mut body = json!({ "cmd": cmd });
        if is_async {
            body["async"] = true.into();
        }
        if let Some(ms) = timeout_ms {
            body["timeout_ms"] = ms.into();
        }
        typed("POST", &self.url("/exec"), &self.sb.headers(""), Some(&body)).await
    }

    /// `POST /sessions/{id}/exec`, waiting for it: exit/stdout/stderr in the result. Only one
    /// command runs per session at a time.
    pub async fn exec(&self, cmd: &str, timeout_ms: Option<u64>) -> Result<SessionCommand> {
        self.exec_inner(cmd, false, timeout_ms).await
    }

    /// Returns at once with just `command_id` set; poll `command()` or stream `logs()`.
    pub async fn exec_async(&self, cmd: &str, timeout_ms: Option<u64>) -> Result<SessionCommand> {
        self.exec_inner(cmd, true, timeout_ms).await
    }

    /// `GET /sessions/{id}/commands/{cid}`, with stdout/stderr (capped like `/exec`).
    pub async fn command(&self, cid: &str) -> Result<SessionCommand> {
        typed("GET", &self.url(&format!("/commands/{cid}")), &self.sb.headers(""), None).await
    }

    /// Bytes to the shell's stdin while `cid` is the running command.
    pub async fn input(&self, cid: &str, data: &str) -> Result<()> {
        json_req(
            "POST",
            &self.url(&format!("/commands/{cid}/input")),
            &self.sb.headers(""),
            Some(&json!({ "data": data })),
        )
        .await?;
        Ok(())
    }

    /// Streams stdout/stderr of `cid` over WebSocket (buffered output replayed, then live) until
    /// it exits, then returns `command(cid)`: the authoritative final state and output.
    pub async fn logs(&self, cid: &str, mut on_output: impl FnMut(&[u8], Stream)) -> Result<SessionCommand> {
        let url = to_ws(&self.url(&format!("/commands/{cid}/logs/ws")));
        let mut ws = transport()?.ws_connect(&url, &self.sb.headers("")).await?;
        while let Some(f) = next_json(&mut ws).await? {
            if let Some((s, chunk)) = output_frame(&f) {
                on_output(&chunk, s);
            } else if f.get("type").and_then(Value::as_str) == Some("exit") {
                break;
            }
        }
        self.command(cid).await
    }

    /// `DELETE /sessions/{id}`: kills the shell's process group. Already gone (404) is success.
    pub async fn delete(&self) -> Result<()> {
        let (status, data) = raw("DELETE", &self.url(""), &self.sb.headers(""), None).await?;
        if status >= 400 && status != 404 {
            return Err(Error::http(status, &data));
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ acquire

/// `GET {base}/healthz`: a worker (qafas) has a `backend` field, the control plane does not.
async fn is_worker(base: &str) -> Result<bool> {
    let data = ok("GET", &format!("{base}/healthz"), &[], None).await?;
    let v: Value = if data.is_empty() { json!({}) } else { serde_json::from_slice(&data)? };
    Ok(v.get("backend").is_some())
}

/// Acquire a sandbox. `url` may point at the control plane (`:7800`) or, for local/dev use,
/// straight at qafas (`:7700`); it defaults to `$SANDBOX_URL`, then `http://127.0.0.1:7700`.
/// `pi_session` defaults to `sbx-rust-<pid>`.
///
/// `cwd` is optional and never defaulted to the current directory: pass it to mount (`native`,
/// `vm`) or upload (`remote`) a workspace; omit it and the sandbox gets its own `/home/agent`,
/// no workspace sent, nothing uploaded. With neither `runtime` nor `isolation` set the request
/// carries no `isolation` field at all and the control plane picks (Firecracker first, D25).
/// `size` / `limits` are for the harness only: never expose them as a tool parameter a model
/// can set (docs/protocol.md section 3a).
pub async fn acquire(
    url: Option<&str>,
    cwd: Option<&str>,
    pi_session: Option<&str>,
    opts: AcquireOptions,
) -> Result<Sandbox> {
    let base = url
        .map(str::to_owned)
        .or_else(|| std::env::var("SANDBOX_URL").ok().filter(|u| !u.is_empty()))
        .unwrap_or_else(|| "http://127.0.0.1:7700".into());
    let pi_session = pi_session.map(str::to_owned).unwrap_or_else(|| format!("sbx-rust-{}", std::process::id()));
    let worker = is_worker(&base).await?;

    let isolation = match runtime_to_isolation(opts.runtime.as_deref())? {
        Some(i) => Some(i.to_owned()),
        None => opts.isolation.clone(),
    };
    let mut req = Map::new();
    req.insert(
        "template".into(),
        opts.snapshot.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| opts.template.clone()).into(),
    );
    req.insert("pi_session".into(), pi_session.clone().into());
    req.insert("trust".into(), opts.trust.clone().into());
    if let Some(cwd) = cwd {
        req.insert("workspace".into(), json!({ "host_path": cwd }));
    }
    if let Some(i) = isolation {
        req.insert("isolation".into(), i.into());
    }
    if !opts.tools.is_empty() {
        req.insert("tools".into(), json!(opts.tools));
    }
    if !opts.egress_allow.is_empty() {
        req.insert("egress_allow".into(), json!(opts.egress_allow));
    }
    for (k, v) in [
        ("ttl_secs", opts.ttl_secs),
        ("auto_stop_secs", opts.auto_stop_secs),
        ("auto_archive_secs", opts.auto_archive_secs),
        ("auto_delete_secs", opts.auto_delete_secs),
        ("max_age_secs", opts.max_age_secs),
    ] {
        if let Some(v) = v {
            req.insert(k.into(), v.into());
        }
    }
    if let Some(n) = opts.name.as_ref().filter(|n| !n.is_empty()) {
        req.insert("name".into(), json!(n));
    }
    if !opts.labels.is_empty() {
        req.insert("labels".into(), json!(opts.labels));
    }
    if !opts.env.is_empty() {
        req.insert("env".into(), json!(opts.env));
    }
    if let Some(s) = &opts.size {
        req.insert("size".into(), json!(s));
    }
    if let Some(l) = &opts.limits {
        let mut m = json!({ "cpus": l.cpus, "mem_mib": l.mem_mib, "disk_mib": l.disk_mib });
        if l.pids > 0 {
            m["pids"] = l.pids.into();
        }
        req.insert("limits".into(), m);
    }

    let (path, tok) = if worker {
        ("/sandboxes", opts.token.clone().unwrap_or_else(|| std::env::var("SBX_TOKEN").unwrap_or_default()))
    } else {
        ("/api/sandboxes", opts.token.clone().unwrap_or_else(|| control_plane_token(opts.api_key.as_deref())))
    };
    let resp: proto::CreateSandboxResp =
        typed("POST", &format!("{base}{path}"), &auth(&tok), Some(&Value::Object(req))).await?;

    let non_empty = |s: String| Some(s).filter(|s| !s.is_empty());
    let sb = Sandbox {
        endpoint: resp.endpoint,
        token: resp.token,
        pi_session,
        id: resp.id,
        backend: resp.backend,
        workspace_path: resp.workspace_path,
        isolation: non_empty(resp.isolation),
        tools: resp.tools,
        missing_tools: resp.missing_tools,
        size: non_empty(resp.size),
        limits: resp.limits,
        create_info: resp.info.map(|i| *i),
    };
    // A microVM has no bind mount: the cwd travels as a tar, minus build output and credentials.
    // Only when the caller passed a cwd (no cwd means no workspace sent above, nothing to upload).
    if let (Some(cwd), Some("remote"), true) = (cwd, sb.isolation.as_deref(), opts.upload_workspace) {
        let dir = cwd.to_owned();
        let up = async {
            let tar = tokio::task::spawn_blocking(move || pack_workspace(dir, &[]))
                .await
                .map_err(|e| Error::Transport(e.to_string()))??;
            sb.upload_tar(cwd, tar).await
        };
        if let Err(e) = up.await {
            // Don't leak a running sandbox the caller has no handle to.
            let _ = sb.destroy().await;
            return Err(Error::Upload(format!(
                "workspace upload failed ({e}): pass upload_workspace(false) or a smaller directory (.sbxignore)"
            )));
        }
    }
    Ok(sb)
}

// ------------------------------------------------------------------ snapshots

/// What `Snapshots::create` builds a snapshot from, plus its v4 knobs. Give one of `image`
/// (an OCI ref with a tag or digest), `dockerfile` (text, or an `Image`'s output) and
/// `sandbox_id` (capture a live sandbox).
#[derive(Debug, Clone, Default)]
pub struct SnapshotSpec {
    pub image: Option<String>,
    pub dockerfile: Option<String>,
    pub sandbox_id: Option<String>,
    pub warm: Option<u32>,
    pub memory_snapshot: Option<bool>,
}

impl SnapshotSpec {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn image(mut self, v: impl Into<String>) -> Self {
        self.image = Some(v.into());
        self
    }
    /// A `&str`, a `String`, or an `Image` (anything `Display`).
    pub fn dockerfile(mut self, v: impl std::fmt::Display) -> Self {
        self.dockerfile = Some(v.to_string());
        self
    }
    pub fn sandbox_id(mut self, v: impl Into<String>) -> Self {
        self.sandbox_id = Some(v.into());
        self
    }
    pub fn warm(mut self, n: u32) -> Self {
        self.warm = Some(n);
        self
    }
    pub fn memory_snapshot(mut self, v: bool) -> Self {
        self.memory_snapshot = Some(v);
        self
    }
}

impl From<Image> for SnapshotSpec {
    fn from(i: Image) -> Self {
        SnapshotSpec::new().dockerfile(i)
    }
}

/// Snapshots (named images a sandbox can be created from) are top-level, not tied to one
/// sandbox. `url` gets the same worker-vs-control-plane detection as `acquire()` on every call;
/// `token` defaults to `$SBX_TOKEN` (worker) or the control-plane token.
#[derive(Debug, Clone)]
pub struct Snapshots {
    url: String,
    token: Option<String>,
}

pub fn snapshots(url: &str, token: Option<&str>) -> Snapshots {
    Snapshots::new(url, token)
}

/// The control plane fans create/put out to every host: `[SnapshotInfo]`; qafas: `SnapshotInfo`.
fn first(v: Value) -> Result<SnapshotInfo> {
    let v = match v {
        Value::Array(a) => a.into_iter().next().unwrap_or(Value::Null),
        v => v,
    };
    Ok(serde_json::from_value(v)?)
}

impl Snapshots {
    pub fn new(url: &str, token: Option<&str>) -> Snapshots {
        Snapshots { url: url.to_owned(), token: token.map(str::to_owned) }
    }

    async fn root_and_headers(&self) -> Result<(String, Headers)> {
        let worker = is_worker(&self.url).await?;
        let tok = match (&self.token, worker) {
            (Some(t), _) if !t.is_empty() => t.clone(),
            (_, true) => std::env::var("SBX_TOKEN").unwrap_or_default(),
            (_, false) => control_plane_token(None),
        };
        let root = if worker { format!("{}/snapshots", self.url) } else { format!("{}/api/snapshots", self.url) };
        Ok((root, auth(&tok)))
    }

    pub async fn create(&self, name: &str, spec: impl Into<SnapshotSpec>) -> Result<SnapshotInfo> {
        let spec = spec.into();
        let mut source = Map::new();
        for (k, v) in [("image", &spec.image), ("dockerfile", &spec.dockerfile), ("sandbox_id", &spec.sandbox_id)] {
            if let Some(v) = v.as_ref().filter(|v| !v.is_empty()) {
                source.insert(k.into(), json!(v));
            }
        }
        let mut body = json!({ "name": name, "source": source });
        if let Some(w) = spec.warm {
            body["warm"] = w.into();
        }
        if let Some(m) = spec.memory_snapshot {
            body["memory_snapshot"] = m.into();
        }
        let (root, h) = self.root_and_headers().await?;
        first(json_req("POST", &root, &h, Some(&body)).await?)
    }

    pub async fn list(&self) -> Result<Vec<SnapshotInfo>> {
        let (root, h) = self.root_and_headers().await?;
        typed("GET", &root, &h, None).await
    }

    pub async fn get(&self, name: &str) -> Result<SnapshotInfo> {
        let (root, h) = self.root_and_headers().await?;
        typed("GET", &format!("{root}/{}", quote(name)), &h, None).await
    }

    /// A snapshot that is already gone (404) is success.
    pub async fn delete(&self, name: &str) -> Result<()> {
        let (root, h) = self.root_and_headers().await?;
        let (status, data) = raw("DELETE", &format!("{root}/{}", quote(name)), &h, None).await?;
        if status >= 400 && status != 404 {
            return Err(Error::http(status, &data));
        }
        Ok(())
    }

    /// v4 `PUT /snapshots/{name}`: sets the pool's warm target live.
    pub async fn set_warm(&self, name: &str, n: u32) -> Result<SnapshotInfo> {
        let (root, h) = self.root_and_headers().await?;
        first(json_req("PUT", &format!("{root}/{}", quote(name)), &h, Some(&json!({ "warm": n }))).await?)
    }

    /// Polls `get(name)` every second until `state` leaves `building` or `timeout` passes.
    pub async fn wait_ready(&self, name: &str, timeout: Duration) -> Result<SnapshotInfo> {
        let deadline = Instant::now() + timeout;
        loop {
            let info = self.get(name).await?;
            if info.state != proto::SnapshotState::Building {
                return Ok(info);
            }
            if Instant::now() > deadline {
                return Err(Error::Timeout(format!(
                    "snapshot {name} still building after {:?}s",
                    timeout.as_secs_f64()
                )));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

#[cfg(test)]
mod tests;
