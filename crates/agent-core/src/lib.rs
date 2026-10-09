//! The handlers every tier shares (D17): `/exec`, `/exec/ws`, `/fs/*`,
//! `/browser/cdp`, plus the telemetry that watches what they spawn.
//!
//! One `Ctx` per sandbox. `Hardened` decides how a command is confined —
//! `Hardened` drops uid and installs seccomp in `pre_exec` (VM/remote tier),
//! the native tier runs the same handlers in `qafas shim`, wrapped once in the OS sandbox. Everything
//! above that is identical, which is why the harness cannot tell tiers apart.

pub mod browser;
pub mod exec;
pub mod fs;
pub mod limits;
pub mod procmon;
pub mod proxy;
pub mod rules;
pub mod serve;
pub mod session;
pub mod spawn;

#[cfg(target_os = "linux")]
pub mod harden;

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::{any, get, post, put};
use axum::{Json, Router};
use proto::{Event, EventType, ExecReq, Healthz, Severity};
use serde_json::{json, Value};

// ------------------------------------------------------------------ time

pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// RFC 3339 UTC with milliseconds (protocol §1). Hinnant's civil-from-days, so
/// no date crate in a binary that only ever formats "now".
pub fn rfc3339_millis(unix_ms: i64) -> String {
    let (secs, milli) = (unix_ms.div_euclid(1000), unix_ms.rem_euclid(1000));
    let (days, sod) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{milli:03}Z", sod / 3600, (sod % 3600) / 60, sod % 60)
}

pub fn now_rfc3339() -> String {
    rfc3339_millis(now_ms())
}

// ------------------------------------------------------------------ kernel cmdline

/// One `sbx.key=value` value, safe to put on a Linux kernel command line: the
/// kernel splits it on whitespace, so a workspace path with a space in it would
/// otherwise arrive as two tokens and truncate silently. Both halves live here
/// because qafas writes the command line (`backend::firecracker`) and
/// guest-agent reads it (`init::boot`), and an encoder that disagrees with its
/// decoder is worse than neither.
pub fn cmdline_encode(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'/' | b':' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub fn cmdline_decode(v: &str) -> String {
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |k: usize| b.get(k).and_then(|c| (*c as char).to_digit(16));
        match (b[i], hex(i + 1), hex(i + 2)) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            _ => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ------------------------------------------------------------------ correlation

/// `X-Pi-Session` / `X-Tool-Call-Id`, copied verbatim onto every event a request
/// causes — including the ones its grandchildren cause minutes later (§7).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Corr {
    pub pi_session: String,
    pub tool_call_id: String,
}

impl Corr {
    pub fn from_headers(h: &axum::http::HeaderMap) -> Self {
        let get = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        Self { pi_session: get(proto::HDR_PI_SESSION), tool_call_id: get(proto::HDR_TOOL_CALL_ID) }
    }
}

// ------------------------------------------------------------------ events

/// Where an `Event` goes once it is built. guest-agent pushes onto a broadcast
/// that `/events/ws` drains; qafas's native tier pushes straight onto its bus.
#[derive(Clone)]
pub struct Emitter {
    sink: Arc<dyn Fn(Event) + Send + Sync>,
    host_id: String,
    sandbox_id: String,
}

impl Emitter {
    pub fn new(
        host_id: impl Into<String>,
        sandbox_id: impl Into<String>,
        sink: Arc<dyn Fn(Event) + Send + Sync>,
    ) -> Self {
        Self { sink, host_id: host_id.into(), sandbox_id: sandbox_id.into() }
    }

    /// Drops every event. Used by tests and by `qafas bench`.
    pub fn null() -> Self {
        Self::new("", "", Arc::new(|_| {}))
    }

    pub fn sandbox_id(&self) -> &str {
        &self.sandbox_id
    }

    pub fn emit(&self, corr: &Corr, ty: EventType, data: Value) {
        (self.sink)(Event {
            id: ulid::Ulid::new().to_string(),
            ts: now_rfc3339(),
            host_id: self.host_id.clone(),
            sandbox_id: self.sandbox_id.clone(),
            pi_session: corr.pi_session.clone(),
            tool_call_id: corr.tool_call_id.clone(),
            r#type: ty,
            data,
        });
    }

    /// `security.alert` with the protocol §1 payload shape. `extra` is merged in
    /// so callers can add `pid`, `path` or `evidence` without rebuilding the map.
    pub fn alert(&self, corr: &Corr, sev: Severity, rule: &str, msg: impl Into<String>, extra: Value) {
        let mut data = json!({"severity": sev, "rule": rule, "msg": msg.into()});
        if let (Some(d), Some(e)) = (data.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                d.insert(k.clone(), v.clone());
            }
        }
        tracing::warn!(rule, severity = ?sev, sandbox_id = %self.sandbox_id, data = %data, "security alert");
        self.emit(corr, EventType::SecurityAlert, data);
    }
}

// ------------------------------------------------------------------ context

pub struct Ctx {
    pub spawner: spawn::Hardened,
    pub ev: Emitter,
    pub mon: procmon::Monitor,
    pub rules: rules::Rules,
    /// D12. The one Chromium this sandbox runs, and its browser-level DevTools
    /// endpoint. Per sandbox, not per process, because the native tier serves
    /// several sandboxes out of one.
    pub browser: tokio::sync::OnceCell<String>,
    /// v3. Default environment for everything this sandbox runs, set by
    /// `PUT /workspace {env}`. A request's own `env` wins over it.
    pub env: std::sync::RwLock<std::collections::BTreeMap<String, String>>,
    /// v3. Live shells (protocol §3a). They die with the process; nothing here
    /// is persisted.
    pub sessions: session::Registry,
    /// v5. The ceilings `PUT /limits` last set, for the `resource.limit` alert
    /// to name a number. `None` until qafas says (the vm tier never does —
    /// podman owns that cgroup).
    pub limits: std::sync::RwLock<Option<proto::SandboxLimits>>,
    /// v5.1. Whether `limits::start_usage_push` already has its task here.
    pub usage_push: std::sync::atomic::AtomicBool,
}

impl Ctx {
    pub fn new(spawner: spawn::Hardened, ev: Emitter, rules: rules::Rules) -> Arc<Self> {
        let mon = procmon::Monitor::new(ev.clone(), rules.clone());
        Arc::new(Self {
            spawner,
            ev,
            mon,
            rules,
            browser: Default::default(),
            env: Default::default(),
            sessions: Default::default(),
            limits: Default::default(),
            usage_push: Default::default(),
        })
    }

    /// A request's `env` layered over the workspace defaults. `PROTECTED_ENV` is
    /// still dropped later, by the `Spawner`.
    pub fn env_with_defaults(
        &self,
        req: &std::collections::BTreeMap<String, String>,
    ) -> std::collections::BTreeMap<String, String> {
        if req.is_empty() {
            return self.env.read().unwrap().clone();
        }
        let mut m = self.env.read().unwrap().clone();
        m.extend(req.iter().map(|(k, v)| (k.clone(), v.clone())));
        m
    }
}

// ------------------------------------------------------------------ router

async fn healthz() -> Json<Healthz> {
    Json(Healthz { ok: true, uid: nix::unistd::getuid().as_raw(), version: proto::VERSION.to_string() })
}

/// Bodies are parsed by hand, not with `Json`, so a plain `curl -d` with no
/// content-type header still works.
fn parse<T: serde::de::DeserializeOwned>(body: &axum::body::Bytes) -> Result<T, Response> {
    use axum::response::IntoResponse;
    serde_json::from_slice(body).map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()).into_response())
}

async fn exec_buffered(
    State(ctx): State<Arc<Ctx>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    use axum::response::IntoResponse;
    let req: ExecReq = match parse(&body) {
        Ok(r) => r,
        Err(e) => return e,
    };
    match exec::buffered(&ctx, Corr::from_headers(&headers), req).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// v3: `{path}` alone is still the v2 body; `env` is the sandbox's default
/// environment, applied to every later `/exec`, `/exec/ws`, PTY and session.
#[derive(serde::Deserialize)]
struct WorkspaceReq {
    path: String,
    #[serde(default)]
    env: std::collections::BTreeMap<String, String>,
}

/// `PUT /workspace {"path"}`: a pooled guest learns which directory it serves.
/// Creates it (owned by the agent user) so a cwd exists before any tar arrives.
async fn set_workspace(State(ctx): State<Arc<Ctx>>, body: axum::body::Bytes) -> Response {
    use axum::response::IntoResponse;
    let req: WorkspaceReq = match parse(&body) {
        Ok(r) => r,
        Err(e) => return e,
    };
    ctx.rules.set_workspace(&req.path);
    if !req.env.is_empty() {
        // The `Spawner` still drops `PROTECTED_ENV`; filtering here as well keeps
        // the names a caller can never set out of the stored defaults entirely.
        let keep = req.env.into_iter().filter(|(k, _)| spawn::env_allowed(k));
        ctx.env.write().unwrap().extend(keep);
    }
    let _ = std::fs::create_dir_all(&req.path);
    #[cfg(unix)]
    if nix::unistd::geteuid().is_root() {
        let _ = std::os::unix::fs::chown(&req.path, Some(1000), Some(1000));
    }
    axum::http::StatusCode::NO_CONTENT.into_response()
}

/// v5 §3a `PUT /limits`. Only qafas reaches this route (the agent port is a
/// vsock, a unix socket in a `0700` directory, or token-guarded), so applying
/// what it says is not a decision the workload can influence. The reply names
/// the enforcement the sandbox actually got.
async fn set_limits(State(ctx): State<Arc<Ctx>>, body: axum::body::Bytes) -> Response {
    use axum::response::IntoResponse;
    let l = match parse::<proto::SandboxLimits>(&body) {
        Ok(l) => l,
        Err(e) => return e,
    };
    match limits::apply(&ctx, &l) {
        Ok(enforcement) => Json(json!({"enforcement": enforcement})).into_response(),
        // The caller (qafas's `apply_limits`) turns this into a failed
        // acquire. Handing the sandbox over with a cap that did not apply would
        // be worse than refusing it.
        Err(e) => (axum::http::StatusCode::CONFLICT, Json(json!({"error": e}))).into_response(),
    }
}

/// v5 §3a `GET /usage`: the boundary sample qafas polls on its 5 s tick.
async fn usage(State(ctx): State<Arc<Ctx>>) -> Json<proto::SandboxUsage> {
    Json(limits::usage(&ctx))
}

async fn mkdir(body: axum::body::Bytes) -> Response {
    match parse::<proto::MkdirReq>(&body) {
        Ok(r) => fs::mkdir(r).await,
        Err(e) => e,
    }
}

/// `GET /processes` — the live tree (protocol §3 v2). Served here so the native
/// tier and the VM tier answer it identically.
async fn processes(State(ctx): State<Arc<Ctx>>) -> Json<Vec<procmon::ProcInfo>> {
    Json(ctx.mon.snapshot())
}

/// Cap on one upload body, from `SBX_MAX_UPLOAD_MB` (qafas sets it per tier:
/// shim env, container env, `sbx.max_upload_mb` on the kernel command line).
/// Both `/fs/tar` and `/fs/write` buffer the whole body, and on the remote tier
/// the extraction target is a tmpfs, so an unbounded PUT OOMs the microVM.
/// qafas enforces the same number one hop out, on `content-length` and on
/// the stream; this layer stops the bytes that get past it (it trips while
/// reading, so the test for the fast rejection lives in qafas).
pub fn max_upload_bytes() -> usize {
    let mb: usize = std::env::var("SBX_MAX_UPLOAD_MB").ok().and_then(|v| v.parse().ok()).unwrap_or(512);
    mb.saturating_mul(1024 * 1024)
}

// ------------------------------------------------------------------ agent token

/// `SBX_AGENT_TOKEN`, the per-sandbox secret qafas mints at create. Set only
/// on the podman tier, where the agent port is published on the host's loopback
/// and reachability is therefore no longer the boundary (protocol §2). The
/// native tier (unix socket in a `0700` directory) and Firecracker (vsock) leave
/// it unset, and the guard below is then not installed at all.
pub fn agent_token() -> Option<String> {
    let t = std::env::var("SBX_AGENT_TOKEN").ok().filter(|s| !s.is_empty());
    if t.is_some() {
        std::env::remove_var("SBX_AGENT_TOKEN");
        scrub_initial_env("SBX_AGENT_TOKEN=");
    }
    t
}

/// `unsetenv` drops the pointer but leaves the bytes where the kernel placed
/// them at exec, and `/proc/<pid>/environ` reads exactly that range. On the
/// podman tier the agent and the sandboxed processes share a uid, so that file
/// is readable from inside: overwrite the value in place (same length, so the
/// block still parses). Linux only; elsewhere there is nothing to read.
#[cfg(target_os = "linux")]
fn scrub_initial_env(prefix: &str) {
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else { return };
    // Fields after the parenthesised comm; env_start/env_end are fields 50 and 51.
    let Some(rest) = stat.rsplit(')').next() else { return };
    let f: Vec<&str> = rest.split_whitespace().collect();
    let (Some(start), Some(end)) =
        (f.get(47).and_then(|v| v.parse::<usize>().ok()), f.get(48).and_then(|v| v.parse::<usize>().ok()))
    else {
        return;
    };
    if start == 0 || end <= start {
        return;
    }
    // SAFETY: the range is this process's own environment block, mapped
    // read-write on the initial stack; we only overwrite bytes inside it.
    let block = unsafe { std::slice::from_raw_parts_mut(start as *mut u8, end - start) };
    for entry in block.split_mut(|b| *b == 0) {
        if entry.starts_with(prefix.as_bytes()) {
            for b in &mut entry[prefix.len()..] {
                *b = b'x';
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn scrub_initial_env(_prefix: &str) {}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Wraps the whole app: without a matching `X-Sbx-Agent-Token` every route
/// answers `401`. `/healthz` stays open — qafas polls it before it has a
/// sandbox record to carry a token for, and it reports nothing a caller who can
/// already reach the port does not know.
pub fn guard(app: Router, token: Option<String>) -> Router {
    let Some(want) = token.map(Arc::new) else { return app };
    app.layer(axum::middleware::from_fn(move |req: axum::extract::Request, next: axum::middleware::Next| {
        let want = want.clone();
        async move {
            use axum::response::IntoResponse;
            let ok = req.uri().path() == "/healthz"
                || req.headers().get(proto::HDR_AGENT_TOKEN).is_some_and(|v| ct_eq(v.as_bytes(), want.as_bytes()));
            if ok {
                next.run(req).await
            } else {
                axum::http::StatusCode::UNAUTHORIZED.into_response()
            }
        }
    }))
}

pub fn router(ctx: Arc<Ctx>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/exec", post(exec_buffered))
        .route(
            "/exec/ws",
            get(|State(ctx): State<Arc<Ctx>>, headers: axum::http::HeaderMap, ws: WebSocketUpgrade| async move {
                let corr = Corr::from_headers(&headers);
                ws.on_upgrade(move |s| exec::ws(ctx, corr, s))
            }),
        )
        .route("/fs/read", get(fs::read))
        // v4: both upload handlers stream, and `DefaultBodyLimit` does not reach
        // a `Body` extractor — they count the bytes themselves (`fs::capped`).
        // The layer stays for anything that goes back to buffering.
        .route("/fs/write", put(fs::write).layer(DefaultBodyLimit::max(max_upload_bytes())))
        .route("/fs/stat", get(fs::stat))
        .route("/fs/list", get(fs::list))
        .route("/fs/mkdir", post(mkdir))
        .route("/fs/tar", get(fs::tar_get).put(fs::tar_put).layer(DefaultBodyLimit::max(max_upload_bytes())))
        .route("/workspace", put(set_workspace))
        .route("/processes", get(processes))
        // v5 sizes and limits (protocol §3a).
        .route("/limits", put(set_limits))
        .route("/usage", get(usage))
        // v3 sessions (protocol §3a).
        .route("/sessions", post(session::create).get(session::list))
        .route("/sessions/{id}", get(session::get).delete(session::delete))
        .route("/sessions/{id}/exec", post(session::exec))
        .route("/sessions/{id}/commands/{cid}", get(session::command))
        .route("/sessions/{id}/commands/{cid}/logs/ws", get(session::logs_ws))
        .route("/sessions/{id}/commands/{cid}/input", post(session::input))
        // v3 preview: qafas's `/preview/{id}/{port}/…` lands here.
        .route("/proxy/{port}", any(proxy::proxy))
        .route("/proxy/{port}/", any(proxy::proxy))
        .route("/proxy/{port}/{*rest}", any(proxy::proxy))
        .route(
            "/browser/cdp",
            get(|State(ctx): State<Arc<Ctx>>, ws: WebSocketUpgrade| async move {
                ws.on_upgrade(move |s| browser::cdp(ctx, s))
            }),
        )
        // Workspace tars are far bigger than axum's 2 MiB default.
        .layer(DefaultBodyLimit::disable())
        .with_state(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_match_the_protocol_shape() {
        assert_eq!(rfc3339_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_millis(1_757_325_600_123), "2025-09-08T10:00:00.123Z");
        assert_eq!(rfc3339_millis(1_709_164_800_000), "2024-02-29T00:00:00.000Z");
        assert_eq!(rfc3339_millis(-1), "1969-12-31T23:59:59.999Z");
    }

    /// A workspace path the kernel command line would otherwise cut in half.
    #[test]
    fn cmdline_values_round_trip_through_whitespace() {
        for v in ["/Users/me/My Projects/app", "/home/agent", "/w/tab\there", "/w/100%", "/w/ünïcode"] {
            let enc = cmdline_encode(v);
            assert!(!enc.contains(char::is_whitespace), "{enc:?} must be one token");
            assert_eq!(cmdline_decode(&enc), v);
        }
        // A value with no encoding in it is its own plaintext, so an older
        // daemon's command line still decodes to itself.
        assert_eq!(cmdline_decode("/home/agent"), "/home/agent");
        // A stray `%` that is not an escape survives verbatim.
        assert_eq!(cmdline_decode("100%"), "100%");
        assert_eq!(cmdline_decode("%zz"), "%zz");
    }

    #[test]
    fn correlation_headers_default_to_empty() {
        let mut h = axum::http::HeaderMap::new();
        assert_eq!(Corr::from_headers(&h).pi_session, "");
        h.insert(proto::HDR_PI_SESSION, "abc".parse().unwrap());
        h.insert(proto::HDR_TOOL_CALL_ID, "toolu_1".parse().unwrap());
        let c = Corr::from_headers(&h);
        assert_eq!((c.pi_session.as_str(), c.tool_call_id.as_str()), ("abc", "toolu_1"));
    }

    /// Real listener, real router: no token means 401 on every route but the
    /// health probe, the right token means the handler runs, a wrong one of the
    /// same length still fails.
    #[tokio::test]
    async fn agent_token_guards_everything_but_healthz() {
        let ctx = Ctx::new(spawn::Hardened::default(), Emitter::null(), rules::Rules::guest("/tmp", "/tmp/nohome"));
        let app = guard(router(ctx), Some("s3cret".to_string()));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });

        let get = |path: &'static str, token: Option<&'static str>| async move {
            let s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let (mut send, conn) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(s)).await.unwrap();
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let mut b = axum::http::Request::builder().uri(path).header("host", "x");
            if let Some(t) = token {
                b = b.header(proto::HDR_AGENT_TOKEN, t);
            }
            send.send_request(b.body(axum::body::Body::empty()).unwrap()).await.unwrap().status().as_u16()
        };

        assert_eq!(get("/processes", None).await, 401);
        assert_eq!(get("/processes", Some("wrong!")).await, 401);
        assert_eq!(get("/processes", Some("s3cret")).await, 200);
        assert_eq!(get("/healthz", None).await, 200);
    }

    /// No env, no layer: the tiers where reachability is the boundary keep
    /// serving unauthenticated.
    #[tokio::test]
    async fn no_token_means_no_guard() {
        let ctx = Ctx::new(spawn::Hardened::default(), Emitter::null(), rules::Rules::guest("/tmp", "/tmp/nohome"));
        let app = guard(router(ctx), None);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(s)).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = axum::http::Request::builder()
            .uri("/processes")
            .header("host", "x")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(send.send_request(req).await.unwrap().status(), 200);
    }

    #[test]
    fn alerts_carry_the_protocol_payload() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let s = seen.clone();
        let ev = Emitter::new("h", "sbx_1", Arc::new(move |e| s.lock().unwrap().push(e)));
        ev.alert(
            &Corr { pi_session: "p".into(), tool_call_id: "t".into() },
            Severity::Critical,
            proto::rules::CANARY_READ,
            "canary opened",
            json!({"path": "/x", "pid": 5}),
        );
        let e = &seen.lock().unwrap()[0];
        assert_eq!(e.r#type, EventType::SecurityAlert);
        assert_eq!(e.sandbox_id, "sbx_1");
        assert_eq!(e.pi_session, "p");
        assert_eq!(e.data["severity"], "critical");
        assert_eq!(e.data["rule"], "canary.read");
        assert_eq!(e.data["path"], "/x");
        assert_eq!(e.data["pid"], 5);
    }
}
