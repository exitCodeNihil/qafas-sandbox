//! qafas's HTTP surface (protocol §3), including the agent reverse proxy —
//! the one place that sees every tool call and therefore the only place that
//! needs to emit events.
//!
//! The tier is invisible above this layer. A native sandbox's `Connector` is a
//! loopback port this same process serves; a VM sandbox's is a published
//! container port; a remote sandbox's is a vsock socket. Everything below
//! `send()` is identical, which is why `/exec` behaves the same on all three.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use axum::extract::ws::{Message as AxMsg, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Path, Request, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use proto::{
    hmac_token, ClientEvent, CreateSandboxReq, CreateSandboxResp, Event, EventType, ExecFrame, ExecReq, ExecResp,
    Isolation, QafasHealthz, SandboxInfo, SandboxState,
};
use serde_json::json;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message as TgMsg;

use crate::backend::{Backend, Conn, Connector, Sandbox, Spec, Verb};
use crate::config::Config;
#[cfg(test)]
use crate::events::now_rfc3339;
use crate::events::{new_event, now_ms, rfc3339_millis, Bus, Corr};
use crate::metrics::{Gauges, Metrics};
use crate::policy::{self, Caps};
use crate::pool::Pool;
use crate::tools::{self, Templates};

pub type AgentClient = Client<HttpConnector, axum::body::Body>;

pub struct Live {
    pub sb: Sandbox,
    pub pi_session: String,
    pub isolation: Isolation,
    /// The backend that made it, so `destroy` goes to the right one.
    pub backend: Arc<dyn Backend>,
    /// Unix millis of the last request. The reaper reads it; the proxy writes it.
    pub last_activity: AtomicI64,
    pub ttl_secs: u64,
    /// v3.
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub created_ms: i64,
    /// v3 timers, v4-resolved: the request's value, else the daemon default, so
    /// `SandboxInfo` reports a number a client can count down from. `0` disables.
    pub auto_stop_secs: Option<u64>,
    pub auto_archive_secs: Option<u64>,
    pub auto_delete_secs: Option<u64>,
    pub max_age_secs: Option<u64>,
    /// v4. `POST /sandboxes {env}`, kept so a wake can hand it to the guest again.
    pub env: BTreeMap<String, String>,
    /// v4. Highest multiple of `SBX_LONG_RUNNING_SECS` already alerted on, so
    /// the rule fires once per multiple rather than every 5 s.
    pub long_running_fired: std::sync::atomic::AtomicU64,
    /// v5 §3a. The size name (or `custom`), the ceilings it resolved to and who
    /// holds them (`kernel`/`daemon`). Fixed at create: a resize is a new
    /// sandbox, so nothing here changes under a reader.
    pub size: String,
    pub limits: proto::SandboxLimits,
    pub enforcement: String,
    /// v5 §3a. The last boundary sample, refreshed on the reaper's 5 s tick.
    /// `None` until the first one lands.
    pub usage: std::sync::Mutex<Option<proto::SandboxUsage>>,
    /// v3. `ready|busy` while it runs, then `paused|stopped|archived`, with the
    /// unix millis it last changed. A std mutex: every reader is synchronous.
    state: std::sync::Mutex<(SandboxState, i64)>,
    /// v3. Held for the length of a lifecycle verb, so two concurrent `stop`s
    /// cannot snapshot the same VM twice.
    pub op: Mutex<()>,
}

impl Live {
    pub fn state(&self) -> SandboxState {
        self.state.lock().expect("live state").0
    }
    /// Unix millis the state last changed at.
    pub fn changed_ms(&self) -> i64 {
        self.state.lock().expect("live state").1
    }
    pub fn set_state(&self, s: SandboxState) {
        *self.state.lock().expect("live state") = (s, now_ms());
    }
    /// Whether the guest is there to answer. Everything under `/agent` and the
    /// preview routes need this; `DELETE` works from every state (§3a).
    pub fn running(&self) -> bool {
        matches!(self.state(), SandboxState::Ready | SandboxState::Busy | SandboxState::Creating)
    }
    /// v4. Seconds since the last request (§3a).
    pub fn idle_secs(&self, now: i64) -> u64 {
        ((now - self.last_activity.load(Ordering::Relaxed)).max(0) / 1000) as u64
    }
    /// v4. Seconds since the last start or create *while running*: `changed_ms`
    /// is set by every transition, and by create for the first one.
    pub fn running_secs(&self, now: i64) -> u64 {
        match self.running() {
            true => ((now - self.changed_ms()).max(0) / 1000) as u64,
            false => 0,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub pool: Pool,
    pub bus: Bus,
    pub live: Arc<Mutex<HashMap<String, Arc<Live>>>>,
    pub agent: AgentClient,
    pub caps: Caps,
    pub metrics: Arc<Metrics>,
    pub templates: Arc<Templates>,
    /// Present when this host serves the native tier.
    pub native: Option<Arc<crate::backend::native::Native>>,
    /// SHA-256 of the certificate we serve, lowercase hex; empty without TLS.
    pub tls_fingerprint: String,
    /// Sandbox ids destroyed but whose scoped tokens have not expired yet, with
    /// the unix second they can be forgotten at.
    ///
    /// design: an in-memory map, so a restart forgets it — which is safe here
    /// because a restart also forgets every sandbox the tokens could name. Move
    /// it to the store only if sandbox ids ever stop being random.
    pub revoked: Arc<Mutex<HashMap<String, u64>>>,
    /// v3. Named images and VM snapshots this host can create sandboxes from.
    pub snapshots: Arc<crate::snapshots::Store>,
    /// v4c. What `doctor` found: sent at registration, served by `GET /caps`.
    pub host_caps: proto::HostCaps,
}

impl AppState {
    pub fn new(cfg: Arc<Config>, pool: Pool, bus: Bus, caps: Caps) -> Self {
        let templates = Arc::new(Templates::load(&cfg.templates));
        // v4c: every template this host holds is a template of its pooled runtime.
        let runtime = if caps.remote {
            "remote"
        } else if caps.vm {
            "vm"
        } else {
            ""
        };
        let snapshots = Arc::new(crate::snapshots::Store::load(&cfg, runtime));
        Self {
            snapshots,
            cfg,
            pool,
            bus,
            live: Default::default(),
            agent: Client::builder(TokioExecutor::new()).build(HttpConnector::new()),
            caps,
            metrics: Metrics::new(),
            templates,
            native: None,
            tls_fingerprint: String::new(),
            revoked: Default::default(),
            host_caps: Default::default(),
        }
    }

    fn info(&self, l: &Live) -> SandboxInfo {
        SandboxInfo {
            id: l.sb.id.clone(),
            backend: l.backend.name().to_string(),
            template: l.sb.template.clone(),
            state: l.state(),
            workspace_path: l.sb.workspace_path.clone(),
            pi_session: l.pi_session.clone(),
            created_at: l.sb.created_at.clone(),
            ready_at: l.sb.ready_at.clone(),
            endpoint: self.endpoint(&l.sb.id),
            host_id: Some(self.cfg.host_id.clone()),
            isolation: l.isolation.as_str().to_string(),
            last_activity: Some(rfc3339_millis(l.last_activity.load(Ordering::Relaxed))),
            name: l.name.clone(),
            labels: l.labels.clone(),
            state_changed_at: Some(rfc3339_millis(l.changed_ms())),
            auto_stop_secs: l.auto_stop_secs,
            auto_archive_secs: l.auto_archive_secs,
            auto_delete_secs: l.auto_delete_secs,
            max_age_secs: l.max_age_secs,
            idle_secs: l.idle_secs(now_ms()),
            running_secs: l.running_secs(now_ms()),
            size: l.size.clone(),
            limits: Some(l.limits),
            enforcement: l.enforcement.clone(),
            usage: l.usage.lock().expect("usage").clone(),
        }
    }

    /// For `snapshots.rs`, which needs the sandbox a `sandbox_id` source names.
    pub async fn live_get(&self, id: &str) -> Option<Arc<Live>> {
        self.live.lock().await.get(id).cloned()
    }

    /// Write this sandbox's row of the persisted table (`livetable`). Best
    /// effort: a table we cannot write costs a restart its stopped sandboxes,
    /// which is exactly where we were before the table existed — never a 500.
    pub fn persist(&self, l: &Live) {
        if let Err(e) = crate::livetable::write(&self.cfg, l) {
            tracing::warn!(error = %e, sandbox_id = %l.sb.id, "sandbox table write failed");
        }
    }

    pub fn forget(&self, id: &str) {
        if let Err(e) = crate::livetable::forget(&self.cfg, id) {
            tracing::warn!(error = %e, sandbox_id = %id, "sandbox table remove failed");
        }
    }

    /// Startup re-adoption of a record the previous run left behind. The state
    /// and its clock come back unchanged, so `auto_delete` counts from the
    /// original stop and not from the restart; `last_activity` restarts from
    /// now (it is not persisted per request). `false` when the backend cannot
    /// rebuild the sandbox, which leaves the record for the caller to drop.
    pub async fn adopt(&self, rec: &crate::livetable::LiveRecord, backend: Arc<dyn Backend>) -> bool {
        let Some(sb) = backend.adopt(rec) else { return false };
        let enforcement = backend.enforcement().to_string();
        let l = Arc::new(Live {
            sb,
            pi_session: rec.pi_session.clone(),
            isolation: rec.isolation,
            backend,
            last_activity: AtomicI64::new(now_ms()),
            ttl_secs: rec.ttl_secs,
            name: rec.name.clone(),
            labels: rec.labels.clone(),
            created_ms: rec.created_ms,
            auto_stop_secs: rec.auto_stop_secs,
            auto_archive_secs: rec.auto_archive_secs,
            auto_delete_secs: rec.auto_delete_secs,
            max_age_secs: rec.max_age_secs,
            env: rec.env.clone(),
            long_running_fired: Default::default(),
            // v5 §3a: a record from a pre-v5 daemon has no size, so it comes
            // back as the default — which is what it was actually running under.
            size: if rec.size.is_empty() { proto::sizes::DEFAULT.to_string() } else { rec.size.clone() },
            limits: rec.limits.unwrap_or_else(|| self.cfg.default_limits()),
            enforcement,
            usage: Default::default(),
            state: std::sync::Mutex::new((rec.state, rec.state_changed_ms)),
            op: Mutex::new(()),
        });
        self.live.lock().await.insert(rec.id.clone(), l);
        true
    }

    pub fn endpoint(&self, id: &str) -> String {
        format!("{}/sandboxes/{id}/agent", self.cfg.public_base())
    }

    pub async fn list(&self) -> Vec<SandboxInfo> {
        self.live.lock().await.values().map(|l| self.info(l)).collect()
    }

    pub fn emit(&self, sandbox_id: &str, corr: &Corr, ty: EventType, data: serde_json::Value) {
        let _ = self.bus.send(new_event(&self.cfg.host_id, sandbox_id, corr, ty, data));
    }

    async fn touch(&self, id: &str) {
        if let Some(l) = self.live.lock().await.get(id) {
            l.last_activity.store(now_ms(), Ordering::Relaxed);
        }
    }
}

// ------------------------------------------------------------------ auth

/// Static admin token, or an HMAC token scoped to one sandbox (protocol §5).
pub struct Auth {
    admin: bool,
    sandbox: Option<String>,
}

impl Auth {
    pub fn allows(&self, id: &str) -> bool {
        self.admin || self.sandbox.as_deref() == Some(id)
    }
}

/// Host-wide routes. A scoped token speaks for one sandbox, never for the host:
/// `/pool`, `/policy` and the snapshot list name every tenant's templates.
fn admin_only(a: &Auth) -> Option<Response> {
    (!a.admin).then(|| (StatusCode::FORBIDDEN, "admin token required").into_response())
}

fn presented_token(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    if let Some(v) = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(t) = v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")) {
            return Some(t.trim().to_string());
        }
    }
    // WebSocket clients that cannot set headers may pass ?token= instead — and
    // only they: on an ordinary request the token lands in access logs, in
    // `Referer` and in shell history. qafas serves no EventSource route.
    let upgrading =
        headers.get(axum::http::header::UPGRADE).is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
    if !upgrading {
        return None;
    }
    uri.query()?.split('&').find_map(|kv| kv.strip_prefix("token=")).map(|t| t.to_string())
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let deny = || (StatusCode::UNAUTHORIZED, "bad or missing bearer token").into_response();
        let tok = presented_token(&parts.headers, &parts.uri).ok_or_else(deny)?;
        if hmac_token::eq_ct(&state.cfg.token, &tok) {
            return Ok(Auth { admin: true, sandbox: None });
        }
        match hmac_token::verify(&state.cfg.token, &tok, (now_ms() / 1000) as u64) {
            Some(id) if state.revoked.lock().await.contains_key(&id) => {
                Err((StatusCode::UNAUTHORIZED, "token revoked with its sandbox").into_response())
            }
            Some(id) => Ok(Auth { admin: false, sandbox: Some(id) }),
            None => Err(deny()),
        }
    }
}

// ------------------------------------------------------------------ router

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        // Unauthenticated from a loopback peer, bearer `SBX_TOKEN` otherwise (§3 v4).
        .route("/metrics", get(metrics))
        .route("/pool", get(pool_stats))
        .route("/caps", get(caps_h))
        .route("/policy", get(policy))
        .route("/sandboxes", post(create).get(list))
        .route("/sandboxes/{id}", get(get_one).delete(destroy))
        .route("/sandboxes/{id}/events", post(client_event))
        .route("/sandboxes/{id}/processes", get(processes))
        // v3 lifecycle (§3a). Synchronous: the verb returns once the state changed.
        .route("/sandboxes/{id}/stop", post(stop_h))
        .route("/sandboxes/{id}/start", post(start_h))
        .route("/sandboxes/{id}/pause", post(pause_h))
        .route("/sandboxes/{id}/resume", post(resume_h))
        .route("/sandboxes/{id}/archive", post(archive_h))
        .route("/sandboxes/{id}/preview", post(create_preview))
        .route("/snapshots", post(create_snapshot).get(list_snapshots))
        .route("/snapshots/{name}", get(get_snapshot).put(update_snapshot).delete(delete_snapshot))
        .route("/snapshots/{name}/scan", post(scan_snapshot))
        // The WebSocket routes are named explicitly; everything else under
        // /agent/ is plain HTTP.
        .route("/sandboxes/{id}/agent/exec/ws", get(agent_ws))
        .route("/sandboxes/{id}/agent/browser/cdp", get(agent_ws))
        .route("/sandboxes/{id}/agent/sessions/{sid}/commands/{cid}/logs/ws", get(agent_ws))
        .route("/sandboxes/{id}/agent/{*rest}", any(agent_http))
        // Preview: no bearer token, a signed one in the query or a cookie.
        .route("/preview/{id}/{port}", any(preview_proxy))
        .route("/preview/{id}/{port}/", any(preview_proxy))
        .route("/preview/{id}/{port}/{*rest}", any(preview_proxy))
        .route("/events/ws", get(events_ws))
        .route("/internal/events", post(internal_events))
        .fallback(|| async { (StatusCode::NOT_FOUND, "no such route") })
        .with_state(state)
}

async fn healthz(State(st): State<AppState>) -> Json<QafasHealthz> {
    Json(QafasHealthz {
        ok: true,
        backend: st.cfg.primary_backend().to_string(),
        host_id: st.cfg.host_id.clone(),
        tls_fingerprint: st.tls_fingerprint.clone(),
        tiers: st.caps.tiers().iter().map(|t| t.to_string()).collect(),
        version: proto::VERSION.to_string(),
    })
}

/// Prometheus text (§3). v4: unauthenticated from loopback — a scraper on the
/// box — and bearer `SBX_TOKEN` from anywhere else, because a worker that serves
/// the remote tier listens on 0.0.0.0.
async fn metrics(State(st): State<AppState>, req: Request) -> Response {
    // Open only when the daemon itself is bound to loopback (the dev machine). A
    // worker listening on 0.0.0.0 always wants the token: the peer address is
    // not proof of anything once a port forwarder (Lima, `ssh -L`, a reverse
    // proxy) sits in front, because it rewrites the source to loopback.
    let open = st.cfg.listen.ip().is_loopback();
    if !open && !presented_token(req.headers(), &Uri::default()).is_some_and(|t| hmac_token::eq_ct(&st.cfg.token, &t)) {
        return (StatusCode::UNAUTHORIZED, "/metrics needs the admin token on a non-loopback listener").into_response();
    }
    let now = now_ms();
    let mut g = Gauges { tiers: st.caps.tiers().iter().map(|t| t.to_string()).collect(), ..Default::default() };
    for l in st.live.lock().await.values() {
        let tier = l.isolation.as_str().to_string();
        *g.sandboxes.entry((tier.clone(), state_name(l.state()))).or_default() += 1;
        let age = ((now - l.created_ms).max(0) / 1000) as u64;
        let m = g.age_max.entry(tier.clone()).or_default();
        *m = (*m).max(age);
        let m = g.idle_max.entry(tier.clone()).or_default();
        *m = (*m).max(l.idle_secs(now));
        g.per_sandbox.push(crate::metrics::SandboxGauge {
            id: l.sb.id.clone(),
            tier,
            size: l.size.clone(),
            pi_session: l.pi_session.clone(),
            limits: l.limits,
            usage: l.usage.lock().expect("usage").clone(),
        });
    }
    for t in st.caps.tiers() {
        // A tier this host serves reports a zero rather than no series at all,
        // so a dashboard panel exists before the first sandbox does.
        g.sandboxes.entry((t.to_string(), "ready".to_string())).or_default();
        g.age_max.entry(t.to_string()).or_default();
        g.idle_max.entry(t.to_string()).or_default();
    }
    for (k, v) in st.pool.stats().await {
        g.pool.insert(k, v.warm as u64);
    }
    ([(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")], st.metrics.render(&g)).into_response()
}

/// v4c §3a. What `qafas doctor` found on this host — the same struct the
/// registration carries, for an operator who has the host but not the fleet.
/// `/healthz` stays small on purpose; this is the place that answers "why does
/// this host not offer Docker".
async fn caps_h(State(st): State<AppState>, a: Auth) -> Response {
    match admin_only(&a) {
        Some(r) => r,
        None => Json(st.host_caps.clone()).into_response(),
    }
}

async fn pool_stats(State(st): State<AppState>, a: Auth) -> Response {
    match admin_only(&a) {
        Some(r) => r,
        None => Json(st.pool.stats().await).into_response(),
    }
}

/// What this host enforces and watches. The same JSON rides along with the
/// registration so the control plane's Policy page shows it per host.
pub fn policy_summary(cfg: &Config) -> serde_json::Value {
    let egress: proto::EgressPolicy =
        std::fs::read_to_string(&cfg.policy).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    agent_core::rules::policy_summary(&egress)
}

async fn policy(State(st): State<AppState>, a: Auth) -> Response {
    match admin_only(&a) {
        Some(r) => r,
        None => Json(policy_summary(&st.cfg)).into_response(),
    }
}

/// What a `template` on `POST /sandboxes` named.
#[derive(Debug, PartialEq)]
enum Resolved {
    /// `base`: the host's built-in image.
    BuiltIn,
    /// An `active` snapshot on this host.
    Snapshot,
}

/// v4 §3a: `base` is the built-in image, anything else must be an `active`
/// snapshot on this host. Nothing falls back silently — an unknown name is a
/// `404`, not a sandbox quietly built from the wrong image.
fn resolve_template(name: &str, snap: Option<&proto::SnapshotInfo>) -> Result<Resolved, (StatusCode, String)> {
    use proto::SnapshotState as S;
    if name == crate::snapshots::BASE {
        return Ok(Resolved::BuiltIn);
    }
    match snap.map(|s| (&s.state, s.error.as_deref())) {
        Some((S::Active, _)) => Ok(Resolved::Snapshot),
        Some((S::Building, _)) => Err((StatusCode::CONFLICT, format!("snapshot {name} is building"))),
        Some((S::Error, e)) => {
            Err((StatusCode::CONFLICT, format!("snapshot {name} failed: {}", e.unwrap_or("no reason recorded"))))
        }
        None => Err((StatusCode::NOT_FOUND, format!("unknown template \"{name}\""))),
    }
}

async fn create(State(st): State<AppState>, auth: Auth, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    if !auth.admin {
        return (StatusCode::FORBIDDEN, "creating sandboxes needs the admin token").into_response();
    }
    // A client that hangs up mid-create (an SDK timeout, a closed tab) makes
    // axum drop this future at its next await: with the VM acquired but not yet
    // in `live`, nothing would ever destroy it. Spawned, the work runs to the
    // insert whatever the client does, and the timers reap what nobody claims.
    match tokio::spawn(create_inner(st, headers, body)).await {
        Ok(r) => r,
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("create task failed: {e}")).into_response(),
    }
}

async fn create_inner(st: AppState, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    // Parsed by hand rather than with `Json`, so a plain `curl -d` without a
    // content-type header still works (the gate commands are written that way).
    let req: CreateSandboxReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let corr = Corr::from_headers(&headers);
    let mut workspace = req.workspace.as_ref().map(|w| w.host_path.clone()).unwrap_or_else(|| default_workspace(&st));
    let template = if req.template.is_empty() { "base".to_string() } else { req.template.clone() };

    // --- v3 name: unique among this host's live sandboxes (§3a).
    let name = req.name.clone().unwrap_or_default();
    if !name.is_empty() && st.live.lock().await.values().any(|l| l.name == name) {
        return (StatusCode::CONFLICT, format!("a live sandbox is already named {name}")).into_response();
    }

    // --- v4 template resolution (§3a). Nothing falls back silently.
    let found = st.snapshots.get(&template).await;
    // --- v5.2 (security.md M43): untrusted work never lands on a template whose
    // security scan failed a boundary check. Trusted work may; the grade is on
    // the row for whoever made that call.
    if let Some(msg) = insecure_for(req.trust, &template, found.as_ref()) {
        return (StatusCode::CONFLICT, Json(json!({"error": msg}))).into_response();
    }

    let snapshot = match resolve_template(&template, found.as_ref()) {
        Ok(Resolved::BuiltIn) => None,
        Ok(Resolved::Snapshot) => found,
        Err((code, msg)) => return (code, Json(json!({"error": msg}))).into_response(),
    };

    // --- v5 size (§3a). Resolved here even though the control plane already
    // resolved it: a client can reach this daemon directly, and the host
    // ceilings are ours to defend.
    let (size, limits) = match proto::sizes::resolve(req.size.as_deref(), req.limits, &st.cfg.sizes) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    };
    if let Some(msg) = over_ceiling(&limits, &st.cfg.max_limits) {
        return (StatusCode::CONFLICT, Json(json!({"error": msg}))).into_response();
    }

    // --- tier
    let ask = policy::Ask {
        isolation: req.isolation,
        trust: req.trust,
        tools: req.tools.clone(),
        workspace: workspace.clone(),
    };
    let home = std::env::var("HOME").unwrap_or_default();
    let decision = match policy::select(&ask, &st.caps, &home) {
        Ok(d) => d,
        Err(e) => {
            st.emit(
                "",
                &corr,
                EventType::SandboxTierSelected,
                json!({"requested": req.isolation.as_str(), "selected": "none", "reason": e.0}),
            );
            return (StatusCode::CONFLICT, e.0).into_response();
        }
    };

    // The pre-decision default is the image's `/home/agent`, which does not exist
    // on the host: a native sandbox with no workspace runs in its own scratch
    // directory instead — narrowed to `<scratch>/sbx-<id>` once the id exists.
    // Never the scratch root: the profile makes the workspace writable, and the
    // root holds every other native sandbox's unauthenticated `agent.sock`.
    if req.workspace.is_none() && decision.tier == Isolation::Native {
        workspace = st.cfg.scratch_dir.clone();
    }

    if decision.tier == Isolation::Vm {
        if let Some(msg) = st.pool.backend().refuse_workspace(&workspace) {
            return (StatusCode::CONFLICT, Json(json!({"error": msg}))).into_response();
        }
    }

    // §3a: on the remote tier the guest's RAM is the template's, fixed by the
    // memory snapshot, so a bigger `mem_mib` is a 409 and not a silent clamp —
    // clamping would corrupt the control plane's capacity arithmetic.
    if decision.tier == Isolation::Remote && limits.mem_mib > u64::from(st.cfg.fc_mem_mib) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": format!(
                "mem_mib {} exceeds this host's template RAM ({})", limits.mem_mib, st.cfg.fc_mem_mib)})),
        )
            .into_response();
    }

    // §3a: native is `501` for snapshots, so it cannot serve one as a template
    // either — on a host that also serves vm/remote the snapshot exists, the
    // process runtime just has nowhere to put it.
    if decision.tier == Isolation::Native && snapshot.is_some() {
        return (StatusCode::NOT_IMPLEMENTED, Json(json!({"error": "the process runtime has no snapshots"})))
            .into_response();
    }

    // --- tools (D21: probed and reported, never installed, never fatal)
    let resolved = if decision.tier == Isolation::Native {
        tools::resolve_host(&req.tools)
    } else {
        st.templates.resolve(&req.tools)
    };

    // A podman snapshot *is* an image, so it lands in the same field the tool
    // resolution uses; a firecracker one is a directory the backend boots or
    // restores from.
    let image = match (&snapshot, decision.tier) {
        (Some(s), Isolation::Vm) => crate::snapshots::podman_image(&s.name),
        _ => st.templates.image_for(&req.tools, &st.cfg.template_image),
    };
    let snap_ref = match (&snapshot, decision.tier) {
        (Some(s), Isolation::Remote) => Some(crate::backend::SnapshotRef { dir: st.snapshots.dir_of(&s.name) }),
        // v4 §3a: `base` is a restore too once the daemon has captured its
        // memory. Nothing else changes — the backend reads the directory.
        (None, Isolation::Remote) => {
            Some(crate::backend::SnapshotRef { dir: st.snapshots.dir_of(crate::snapshots::BASE) })
                .filter(|r| r.is_restore())
        }
        _ => None,
    };
    let spec_of = |id: String| Spec {
        id,
        template: template.clone(),
        workspace_path: workspace.clone(),
        egress_allow: req.egress_allow.clone(),
        image: image.clone(),
        snapshot: snap_ref.clone(),
        env: req.env.clone(),
        pi_session: req.pi_session.clone(),
        limits,
    };

    let (sb, backend, warm) = match decision.tier {
        Isolation::Native => {
            // No pool: a native sandbox is a directory and a listener, and
            // making one costs about as much as taking one off a queue.
            let Some(native) = st.native.clone() else {
                return (StatusCode::CONFLICT, "native tier not configured").into_response();
            };
            let mut spec = spec_of(crate::pool::new_id());
            let id = spec.id.clone();
            if req.workspace.is_none() {
                spec.workspace_path = native.workspace_of(&id);
            }
            st.emit(
                &id,
                &corr,
                EventType::SandboxCreated,
                json!({"template": template, "backend": "native", "workspace": spec.workspace_path}),
            );
            match native.create(spec).await {
                Ok(sb) => {
                    st.emit(&id, &corr, EventType::SandboxReady, json!({"boot_ms": sb.boot_ms}));
                    spawn_guest_events(st.clone(), sb.id.clone(), sb.connector.clone(), sb.agent_token.clone());
                    (sb, native as Arc<dyn Backend>, false)
                }
                Err(e) => {
                    st.emit(&id, &corr, EventType::Error, json!({"msg": e.to_string()}));
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                }
            }
        }
        _ => match st.pool.acquire(&template, &workspace, &req.egress_allow, &image, snap_ref.clone(), &limits).await {
            Ok((mut sb, warm)) => {
                // A workspace-agnostic pool (microVMs) booted this one with no
                // workspace; the request names it, and the tar lands there. The
                // v3 `env` rides the same call, so a workspace-keyed pool
                // (containers) makes it only when there is something to say.
                if !st.pool.backend().pool_by_workspace() || !req.env.is_empty() {
                    sb.workspace_path = workspace.clone();
                    if let Err(e) =
                        crate::backend::set_workspace(&sb.connector, sb.agent_token.as_deref(), &workspace, &req.env)
                            .await
                    {
                        tracing::warn!(error = %e, sandbox_id = %sb.id, "guest did not take the workspace path");
                    }
                }
                // Pull the guest's own telemetry onto our bus for as long as it
                // lives; it cannot push to us through an internal network (D7).
                spawn_guest_events(st.clone(), sb.id.clone(), sb.connector.clone(), sb.agent_token.clone());
                st.metrics.pool_result(warm);
                (sb, st.pool.backend().clone(), warm)
            }
            Err(e) => {
                st.emit("", &corr, EventType::Error, json!({"msg": e.to_string()}));
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
        },
    };

    st.emit(
        &sb.id,
        &corr,
        EventType::SandboxTierSelected,
        json!({
            "requested": req.isolation.as_str(),
            "selected": decision.tier.as_str(),
            "reason": decision.reason,
        }),
    );
    tracing::info!(
        sandbox_id = sb.id,
        pi_session = req.pi_session,
        warm,
        boot_ms = sb.boot_ms,
        tier = decision.tier.as_str(),
        reason = decision.reason,
        // Self-reported, so it attributes an honest client and nothing more (M33).
        client = headers.get(proto::HDR_CLIENT).and_then(|v| v.to_str().ok()).unwrap_or("unknown"),
        "sandbox acquired",
    );

    let exp = (now_ms() / 1000) as u64 + st.cfg.token_ttl_secs;
    let resp = CreateSandboxResp {
        id: sb.id.clone(),
        endpoint: st.endpoint(&sb.id),
        token: hmac_token::mint(&st.cfg.token, &sb.id, exp),
        backend: backend.name().to_string(),
        workspace_path: sb.workspace_path.clone(),
        expires_at: rfc3339_millis(exp as i64 * 1000),
        host_id: Some(st.cfg.host_id.clone()),
        isolation: decision.tier.as_str().to_string(),
        tools: resolved.tools,
        missing_tools: resolved.missing,
        tls_fingerprint: st.tls_fingerprint.clone(),
        size: size.clone(),
        limits: Some(limits),
        info: None,
    };
    let id = sb.id.clone();
    let live = Arc::new(Live {
        name: if name.is_empty() { id.clone() } else { name },
        labels: req.labels,
        created_ms: now_ms(),
        // v4 §3a: resolved here, once, so every reader (the timers, the API,
        // the dashboard) sees the same concrete numbers.
        auto_stop_secs: Some(req.auto_stop_secs.unwrap_or(st.cfg.auto_stop_secs)),
        auto_archive_secs: req.auto_archive_secs,
        auto_delete_secs: Some(req.auto_delete_secs.unwrap_or(st.cfg.auto_delete_secs)),
        max_age_secs: req.max_age_secs.or(Some(st.cfg.max_age_secs)).filter(|s| *s > 0),
        state: std::sync::Mutex::new((SandboxState::Ready, now_ms())),
        op: Mutex::new(()),
        env: req.env,
        long_running_fired: Default::default(),
        size,
        limits,
        enforcement: backend.enforcement().to_string(),
        usage: Default::default(),
        sb,
        pi_session: req.pi_session,
        isolation: decision.tier,
        backend,
        last_activity: AtomicI64::new(now_ms()),
        ttl_secs: req.ttl_secs.unwrap_or(st.cfg.ttl_secs),
    });
    st.live.lock().await.insert(id, live.clone());
    // From here the sandbox outlives this process: the table is what the next
    // start re-adopts a `stopped` or `archived` one from.
    st.persist(&live);
    // v5.1: the 201 carries the record itself, so the control plane never has to
    // re-derive the name or the timer defaults from what the client sent.
    let resp = CreateSandboxResp { info: Some(Box::new(st.info(&live))), ..resp };
    (StatusCode::CREATED, Json(resp)).into_response()
}

/// v5 §3a. The 409 body for a request that fits no host ceiling, naming the
/// dimension and both numbers. `None` when it fits. Defence in depth: the
/// control plane has already checked the key's own limits, but a compromised key
/// or a client talking to this daemon directly has not been through that.
fn over_ceiling(l: &proto::SandboxLimits, cap: &proto::SandboxLimits) -> Option<String> {
    if proto::sizes::fits(l, cap) {
        return None;
    }
    Some(if l.cpus > cap.cpus {
        format!("cpus {} exceeds this host's ceiling ({})", l.cpus, cap.cpus)
    } else if l.mem_mib > cap.mem_mib {
        format!("mem_mib {} exceeds this host's ceiling ({})", l.mem_mib, cap.mem_mib)
    } else {
        format!("disk_mib {} exceeds this host's ceiling ({})", l.disk_mib, cap.disk_mib)
    })
}

/// A create with no workspace still needs somewhere to run. The VM tier has
/// `/home/agent` in the image; the native tier has no such path on the host, so
/// it falls back to the scratch root.
fn default_workspace(st: &AppState) -> String {
    if st.caps.vm || st.caps.remote {
        "/home/agent".to_string()
    } else {
        st.cfg.scratch_dir.clone()
    }
}

async fn list(State(st): State<AppState>, a: Auth) -> Json<Vec<SandboxInfo>> {
    let mut all = st.list().await;
    // A scoped token sees its own sandbox and nothing else: other tenants' ids,
    // workspace paths and `pi_session` are not its business (§3, §5).
    all.retain(|s| a.allows(&s.id));
    Json(all)
}

async fn get_one(State(st): State<AppState>, auth: Auth, Path(id): Path<String>) -> Response {
    if !auth.allows(&id) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match st.live.lock().await.get(&id) {
        Some(l) => Json(st.info(l)).into_response(),
        None => (StatusCode::NOT_FOUND, "no such sandbox").into_response(),
    }
}

async fn destroy(State(st): State<AppState>, auth: Auth, Path(id): Path<String>) -> Response {
    if !auth.allows(&id) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match destroy_inner(&st, &id, "requested").await {
        true => StatusCode::NO_CONTENT.into_response(),
        false => (StatusCode::NOT_FOUND, "no such sandbox").into_response(),
    }
}

async fn destroy_inner(st: &AppState, id: &str, reason: &str) -> bool {
    let Some(l) = st.live.lock().await.remove(id) else { return false };
    // Belt and braces (M31): ids are random, so a token for a destroyed sandbox
    // has nothing to be replayed against — unless an id is ever reused.
    let now = (now_ms() / 1000) as u64;
    let mut revoked = st.revoked.lock().await;
    revoked.retain(|_, exp| *exp > now);
    revoked.insert(id.to_string(), now + st.cfg.token_ttl_secs);
    drop(revoked);
    if let Err(e) = l.backend.destroy(&l.sb).await {
        tracing::warn!(error = %e, sandbox_id = id, "destroy failed");
    }
    st.forget(id);
    st.emit(id, &Corr::default(), EventType::SandboxDestroyed, json!({"reason": reason}));
    true
}

// ------------------------------------------------------------------ v3 lifecycle

fn state_name(s: SandboxState) -> String {
    serde_json::to_value(s).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

/// The one place a sandbox changes state. Both the API verbs and the reaper's
/// timers go through it, so an `auto_stop` is exactly an API `stop` with a
/// different `reason` on the event.
async fn transition(st: &AppState, l: &Arc<Live>, verb: Verb, reason: &str) -> anyhow::Result<()> {
    let _guard = l.op.lock().await;
    let (id, from) = (l.sb.id.clone(), l.state());
    // There are no request headers behind a timer, a wake or a shutdown, but the
    // sandbox knows whose session it is — which is the half of `Corr` that a
    // lifecycle event is read by (§1).
    let corr = Corr { pi_session: l.pi_session.clone(), tool_call_id: String::new() };
    let (ty, to) = match verb {
        Verb::Stop => (EventType::SandboxStopped, SandboxState::Stopped),
        Verb::Start => (EventType::SandboxStarted, SandboxState::Ready),
        Verb::Pause => (EventType::SandboxPaused, SandboxState::Paused),
        Verb::Resume => (EventType::SandboxResumed, SandboxState::Ready),
        Verb::Archive => (EventType::SandboxArchived, SandboxState::Archived),
    };
    if from == to {
        return Ok(()); // idempotent: the verb's job is already done
    }
    let started = std::time::Instant::now();
    match verb {
        Verb::Stop => l.backend.stop(&l.sb).await?,
        // `start` on a paused sandbox is a resume: same intent, cheaper answer.
        Verb::Start if from == SandboxState::Paused => l.backend.resume(&l.sb).await?,
        Verb::Start => l.backend.start(&l.sb).await?,
        Verb::Pause => l.backend.pause(&l.sb).await?,
        Verb::Resume => l.backend.resume(&l.sb).await?,
        Verb::Archive => {
            // Archiving a running sandbox is a stop first: what gets moved out
            // of the jail is the snapshot `stop` writes.
            if from != SandboxState::Stopped {
                l.backend.stop(&l.sb).await?;
                l.set_state(SandboxState::Stopped);
                st.persist(l);
                st.emit(&id, &corr, EventType::SandboxStopped, json!({"reason": reason}));
            }
            l.backend.archive(&l.sb).await?
        }
    }
    if verb == Verb::Start {
        // The guest is a new process on the vm tier, so the two things qafas
        // told it at create have to be said again: which directory is the
        // workspace, and the session's `env` (§3a). A microVM comes back from a
        // memory snapshot and remembers both; the native shim reads them from
        // its environment.
        if l.isolation == Isolation::Vm {
            if let Err(e) = crate::backend::set_workspace(
                &l.sb.connector,
                l.sb.agent_token.as_deref(),
                &l.sb.workspace_path,
                &l.env,
            )
            .await
            {
                tracing::warn!(error = %e, sandbox_id = %id, "woken guest did not take the workspace path");
            }
        }
        // Its telemetry stream died with the old guest.
        spawn_guest_events(st.clone(), id.clone(), l.sb.connector.clone(), l.sb.agent_token.clone());
        l.long_running_fired.store(0, Ordering::Relaxed);
    }
    l.set_state(to);
    l.last_activity.store(now_ms(), Ordering::Relaxed);
    st.persist(l);
    let ms = started.elapsed().as_millis() as u64;
    st.emit(&id, &corr, ty, json!({"reason": reason, "duration_ms": ms}));
    tracing::info!(sandbox_id = %id, from = %state_name(from), to = %state_name(to), reason, ms, "lifecycle");
    Ok(())
}

async fn lifecycle(st: AppState, auth: Auth, id: String, verb: Verb) -> Response {
    if !auth.allows(&id) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(l) = st.live_get(&id).await else {
        return (StatusCode::NOT_FOUND, "no such sandbox").into_response();
    };
    if !l.backend.supports_lifecycle(verb) {
        // v4: stop/start exist everywhere, so the 409 names the verb that does not.
        let msg = format!("{} needs the remote tier", verb.as_str());
        return (StatusCode::CONFLICT, Json(json!({"error": msg}))).into_response();
    }
    // Each verb has the states it makes sense from; `transition` then treats
    // "already there" as success, so the verbs stay idempotent.
    let s = l.state();
    let sensible = match verb {
        Verb::Pause => l.running(),
        Verb::Resume => s == SandboxState::Paused,
        Verb::Stop => l.running() || matches!(s, SandboxState::Paused | SandboxState::Stopped),
        Verb::Archive => l.running() || !matches!(s, SandboxState::Destroyed),
        Verb::Start => !matches!(s, SandboxState::Destroyed),
    };
    if !sensible {
        return (StatusCode::CONFLICT, Json(json!({"error": format!("sandbox is {}", state_name(s))}))).into_response();
    }
    if let Err(e) = transition(&st, &l, verb, "api").await {
        st.emit(&id, &Corr::default(), EventType::Error, json!({"msg": e.to_string()}));
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response();
    }
    // `auto_delete_secs: 0` is "ephemeral": the sandbox exists only while it runs.
    if verb == Verb::Stop && l.auto_delete_secs == Some(0) {
        destroy_inner(&st, &id, "auto_delete").await;
        return StatusCode::NO_CONTENT.into_response();
    }
    match verb {
        Verb::Start => Json(st.info(&l)).into_response(),
        _ => StatusCode::NO_CONTENT.into_response(),
    }
}

async fn stop_h(State(st): State<AppState>, a: Auth, Path(id): Path<String>) -> Response {
    lifecycle(st, a, id, Verb::Stop).await
}
async fn start_h(State(st): State<AppState>, a: Auth, Path(id): Path<String>) -> Response {
    lifecycle(st, a, id, Verb::Start).await
}
async fn pause_h(State(st): State<AppState>, a: Auth, Path(id): Path<String>) -> Response {
    lifecycle(st, a, id, Verb::Pause).await
}
async fn resume_h(State(st): State<AppState>, a: Auth, Path(id): Path<String>) -> Response {
    lifecycle(st, a, id, Verb::Resume).await
}
async fn archive_h(State(st): State<AppState>, a: Auth, Path(id): Path<String>) -> Response {
    lifecycle(st, a, id, Verb::Archive).await
}

/// What the timers want done with one sandbox right now, or nothing.
/// Split out from the loop so the whole policy of §3a is one testable function
/// — which is also why it takes the five timers as plain values rather than a
/// `Live`: the test needs to state a situation, not build a sandbox.
#[allow(clippy::too_many_arguments)]
pub fn due(
    now: i64,
    state: SandboxState,
    remote: bool,
    idle_ms: i64,
    since_change_ms: i64,
    age_ms: i64,
    ttl_secs: u64,
    auto_stop: Option<u64>,
    auto_archive: Option<u64>,
    auto_delete: Option<u64>,
    max_age: Option<u64>,
) -> Option<(Option<Verb>, &'static str)> {
    let _ = now;
    let past = |ms: i64, secs: u64| ms > secs as i64 * 1000;
    // `0` disables a timer rather than firing it instantly, everywhere.
    if max_age.is_some_and(|s| s > 0 && past(age_ms, s)) {
        return Some((None, "max_age"));
    }
    let auto_stop = auto_stop.unwrap_or(0);
    match state {
        SandboxState::Ready | SandboxState::Busy | SandboxState::Creating | SandboxState::Paused => {
            // v4: sleeping is every tier's, so an idle sandbox stops instead of
            // being destroyed unless sleeping is switched off.
            if auto_stop > 0 && past(idle_ms, auto_stop) {
                return Some((Some(Verb::Stop), "auto_stop"));
            }
            // The idle TTL is only consulted where `auto_stop` does not own
            // idleness, so the two never race (§3a).
            if auto_stop == 0 && ttl_secs > 0 && past(idle_ms, ttl_secs) {
                return Some((None, "idle_ttl"));
            }
            None
        }
        SandboxState::Stopped => {
            if auto_delete.is_some_and(|s| past(since_change_ms, s) || s == 0) {
                return Some((None, "auto_delete"));
            }
            // Archiving is the remote tier's: elsewhere there is no snapshot to move.
            if remote && auto_archive.is_some_and(|s| past(since_change_ms, s)) {
                return Some((Some(Verb::Archive), "auto_archive"));
            }
            None
        }
        SandboxState::Archived => {
            auto_delete.is_some_and(|s| past(since_change_ms, s) || s == 0).then_some((None, "auto_delete"))
        }
        SandboxState::Destroyed => None,
    }
}

/// `sandbox.long_running` (§1.1): operational, not a transition. It rides the
/// alert pipeline every other rule uses, so it reaches the bus, the control
/// plane, the Alerts page and `sbx_alerts_total` with no second mechanism (D23).
/// Fires once per multiple of the threshold, and the multiple resets on a start.
fn long_running(st: &AppState, l: &Arc<Live>, now: i64) {
    let threshold = st.cfg.long_running_secs;
    if threshold == 0 || !l.running() {
        return;
    }
    let age_secs = l.running_secs(now);
    let k = age_secs / threshold;
    if k == 0 || l.long_running_fired.swap(k, Ordering::Relaxed) >= k {
        return;
    }
    let corr = Corr { pi_session: l.pi_session.clone(), tool_call_id: String::new() };
    st.emit(
        &l.sb.id,
        &corr,
        EventType::SecurityAlert,
        json!({
            "rule": proto::rules::SANDBOX_LONG_RUNNING,
            "severity": "medium",
            "msg": format!("sandbox {} has been running for {age_secs}s", l.name),
            // Flat, like every other rule (§1): `age_secs` sits beside `rule`.
            "age_secs": age_secs,
            "threshold_secs": threshold,
            "name": l.name,
            "tier": l.isolation.as_str(),
        }),
    );
}

/// Reconciles one sandbox with the process that is supposed to be running it.
/// Without this a VM that panicked, was OOM-killed or was killed by hand stays
/// `ready` in the daemon, the control plane and the dashboard until a client's
/// exec fails against it. Only running states are asked: a stopped, paused or
/// archived sandbox is *meant* to have no process. A warm pool entry is not in
/// `live` yet, so an acquire racing this cannot lose its sandbox to it — the
/// pool does its own probe on the way out.
///
/// Returns whether the sandbox was reaped, and is therefore out of `live`.
async fn died(st: &AppState, l: &Arc<Live>) -> bool {
    if !matches!(l.state(), SandboxState::Ready | SandboxState::Busy) {
        return false;
    }
    // A `stop` in flight has already killed the VM but has not set `stopped` yet;
    // without this the probe would read that as a death and destroy the sandbox
    // out from under the verb. `op` is exactly the lock that says "mid-verb".
    let Ok(_op) = l.op.try_lock() else { return false };
    if l.backend.alive(&l.sb).await {
        return false;
    }
    tracing::warn!(sandbox_id = %l.sb.id, tier = l.isolation.as_str(), "sandbox died; destroying");
    // The session that owns it is the one whose next exec would have failed.
    let corr = Corr { pi_session: l.pi_session.clone(), tool_call_id: String::new() };
    st.emit(&l.sb.id, &corr, EventType::Error, json!({"msg": "microVM exited unexpectedly"}));
    // Exactly the path `DELETE` takes: the backend cleans up, the sandbox leaves
    // `live`, and the next heartbeat tells the control plane it is destroyed.
    destroy_inner(st, &l.sb.id, "died").await
}

/// Timer loop (§3a): idle stop, idle TTL, archive, delete, max age. Every 5 s,
/// because the smallest useful timer a harness sets is measured in seconds and
/// a sandbox that outlives its `auto_stop` by four seconds costs nothing.
pub fn spawn_reaper(st: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tick.tick().await;
            let now = now_ms();
            let all: Vec<Arc<Live>> = st.live.lock().await.values().cloned().collect();
            for l in all {
                if died(&st, &l).await {
                    continue;
                }
                // v5 §3a: the usage sample rides the tick that is already
                // talking to every live sandbox, so it costs one extra call.
                // v5.1: a *busy* sandbox pushes its own every 2 s on the event
                // stream (`spawn_guest_events`); this pull is what covers an
                // idle one, which pushes nothing at all.
                if l.running() {
                    if let Some(u) = l.backend.usage(&l.sb).await {
                        *l.usage.lock().expect("usage") = Some(u);
                    }
                }
                long_running(&st, &l, now);
                let Some((verb, reason)) = due(
                    now,
                    l.state(),
                    l.isolation == Isolation::Remote,
                    now - l.last_activity.load(Ordering::Relaxed),
                    now - l.changed_ms(),
                    now - l.created_ms,
                    l.ttl_secs,
                    l.auto_stop_secs,
                    l.auto_archive_secs,
                    l.auto_delete_secs,
                    l.max_age_secs,
                ) else {
                    continue;
                };
                match verb {
                    None => {
                        tracing::info!(sandbox_id = %l.sb.id, reason, "timer expired; destroying");
                        destroy_inner(&st, &l.sb.id, reason).await;
                    }
                    Some(v) => {
                        if let Err(e) = transition(&st, &l, v, reason).await {
                            tracing::warn!(sandbox_id = %l.sb.id, error = %e, ?v, "timer transition failed");
                            // A stop that cannot snapshot must not be retried every
                            // 5 s forever; the idle TTL still ends the sandbox.
                            l.last_activity.store(now, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    });
}

// ------------------------------------------------------------------ v3 snapshots

async fn create_snapshot(State(st): State<AppState>, auth: Auth, body: axum::body::Bytes) -> Response {
    if !auth.admin {
        return (StatusCode::FORBIDDEN, "snapshots need the admin token").into_response();
    }
    let req: proto::CreateSnapshotReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    if !crate::snapshots::valid_name(&req.name) {
        return (StatusCode::BAD_REQUEST, "name must match [a-z0-9][a-z0-9._-]{0,63}").into_response();
    }
    if !(st.caps.vm || st.caps.remote) {
        return (StatusCode::NOT_IMPLEMENTED, "snapshots need the vm or remote tier").into_response();
    }
    // v4c §3a: a template is built for one runtime, and a host pools exactly one.
    // Aliases (`docker`, `firecracker`, `process`) were normalised by serde;
    // absent — or `auto` — means "whatever this host is".
    if let Some(rt) = req.runtime.filter(|r| *r != proto::Isolation::Auto) {
        if rt.as_str() != st.snapshots.runtime {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": format!(
                    "this host builds {} templates, not {}", st.snapshots.runtime, rt.as_str())})),
            )
                .into_response();
        }
    }
    let s = &req.source;
    if let Some(r) = &s.image {
        if let Err(e) = crate::snapshots::check_image_ref(r) {
            return (StatusCode::BAD_REQUEST, e).into_response();
        }
    }
    if s.image.is_none() && s.dockerfile.is_none() && s.sandbox_id.is_none() {
        return (StatusCode::BAD_REQUEST, "source needs image, dockerfile or sandbox_id").into_response();
    }
    if let Some(sid) = &s.sandbox_id {
        if st.live_get(sid).await.is_none() {
            return (StatusCode::NOT_FOUND, format!("no sandbox {sid}")).into_response();
        }
    }
    let info = crate::snapshots::new_info(&req.name, req.source.clone(), req.warm, req.memory_snapshot);
    if !st.snapshots.claim(&info).await {
        return (StatusCode::CONFLICT, format!("snapshot {} already exists", req.name)).into_response();
    }
    // The pool learns the target now; it only refills once the build is active.
    st.pool.set_warm(&req.name, req.warm).await;
    crate::snapshots::spawn_build(st.clone(), info.clone(), req.source);
    (StatusCode::ACCEPTED, Json(st.snapshots.stamp(info))).into_response()
}

async fn list_snapshots(State(st): State<AppState>, a: Auth) -> Response {
    if let Some(r) = admin_only(&a) {
        return r;
    }
    let mut v = st.snapshots.list().await;
    for i in &mut v {
        i.warm_ready = st.pool.warm_ready(&i.name).await;
    }
    Json(v).into_response()
}

async fn get_snapshot(State(st): State<AppState>, a: Auth, Path(name): Path<String>) -> Response {
    if let Some(r) = admin_only(&a) {
        return r;
    }
    match st.snapshots.get(&name).await {
        Some(mut i) => {
            i.warm_ready = st.pool.warm_ready(&name).await;
            Json(i).into_response()
        }
        None => (StatusCode::NOT_FOUND, "no such snapshot").into_response(),
    }
}

/// v5.2 `POST /snapshots/{name}/scan` — rescan a template. `202` with the row
/// as it is now; the scan runs in the background (one throwaway sandbox, seconds
/// to a minute on a busy microVM host) and `security.scanned_at` moves when it
/// is done, like a build moves `state`.
async fn scan_snapshot(State(st): State<AppState>, auth: Auth, Path(name): Path<String>) -> Response {
    if !auth.admin {
        return (StatusCode::FORBIDDEN, "snapshots need the admin token").into_response();
    }
    let info = match st.snapshots.get(&name).await {
        Some(i) if i.state == proto::SnapshotState::Active => i,
        Some(_) => {
            return (StatusCode::CONFLICT, Json(json!({"error": format!("template \"{name}\" is not active")})))
                .into_response()
        }
        None => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": format!("unknown template \"{name}\"")})))
                .into_response()
        }
    };
    let st2 = st.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::scan::run(&st2, &name).await {
            tracing::warn!(template = %name, error = %e, "template security scan failed");
        }
    });
    (StatusCode::ACCEPTED, Json(info)).into_response()
}

/// The refusal message when `trust: untrusted` asks for a template graded `F`.
fn insecure_for(trust: proto::Trust, template: &str, found: Option<&proto::SnapshotInfo>) -> Option<String> {
    let sec = found?.security.as_ref()?;
    if trust != proto::Trust::Untrusted || sec.grade != "F" {
        return None;
    }
    let failed: Vec<&str> =
        sec.findings.iter().filter(|c| !c.ok && c.class == "boundary").map(|c| c.id.as_str()).collect();
    Some(format!(
        "template {template} failed its security scan ({}); trust=untrusted cannot use it — fix the template, or run it trusted",
        failed.join(", ")
    ))
}

/// v4 §3a `PUT /snapshots/{name}` — how many restored sandboxes this host keeps
/// ready for this template. `base` is allowed; anything else must exist.
async fn update_snapshot(
    State(st): State<AppState>,
    auth: Auth,
    Path(name): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    if !auth.admin {
        return (StatusCode::FORBIDDEN, "snapshots need the admin token").into_response();
    }
    let req: proto::UpdateSnapshotReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let Some(mut info) = st.snapshots.set_warm(&name, req.warm).await else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": format!("unknown template \"{name}\"")}))).into_response();
    };
    st.pool.set_warm(&name, req.warm).await;
    // design: only a workspace-agnostic pool (microVMs) can fill a template
    // nobody has asked for yet — a container pool needs the workspace, which
    // only a create request carries, so there the number takes effect then.
    if !st.pool.backend().pool_by_workspace() {
        let dir = st.snapshots.dir_of(&name);
        // `base` boots the host's own rootfs until its memory has been captured;
        // every other template is the directory the build wrote.
        let snap = (name != crate::snapshots::BASE || crate::snapshots::has_memory(&dir))
            .then_some(crate::backend::SnapshotRef { dir });
        st.pool.spawn_refill(name.clone(), String::new(), String::new(), snap);
    }
    info.warm_ready = st.pool.warm_ready(&name).await;
    Json(info).into_response()
}

async fn delete_snapshot(State(st): State<AppState>, auth: Auth, Path(name): Path<String>) -> Response {
    if !auth.admin {
        return StatusCode::FORBIDDEN.into_response();
    }
    if name == crate::snapshots::BASE {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "base is the built-in image"}))).into_response();
    }
    // Deleting the rootfs a live microVM has open would not break it today (the
    // inode survives), but the next `start` would have nothing to restore.
    let users: Vec<String> =
        st.live.lock().await.values().filter(|l| l.sb.template == name).map(|l| l.sb.id.clone()).collect();
    if !users.is_empty() {
        return (StatusCode::CONFLICT, Json(json!({"error": format!("in use by {}", users.join(", "))})))
            .into_response();
    }
    match st.snapshots.remove(&name).await {
        true => {
            // Unconditional: a Firecracker host still builds the rootfs with its
            // own podman, so it holds a tag per snapshot too. The call tolerates
            // a missing image, so "no podman here" costs one failed exec.
            crate::snapshots::forget_podman_image(&name);
            // A build still running for this name was cancelled by `remove`; its
            // work tree is ours to take away (it can be over a gigabyte).
            let _ = std::fs::remove_dir_all(crate::snapshots::build_dir(&st.cfg, &name));
            st.pool.drain_template(&name).await;
            StatusCode::NO_CONTENT.into_response()
        }
        false => (StatusCode::NOT_FOUND, "no such snapshot").into_response(),
    }
}

// ------------------------------------------------------------------ v3 preview

async fn create_preview(
    State(st): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !auth.allows(&id) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let req: proto::CreatePreviewReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    if st.live_get(&id).await.is_none() {
        return (StatusCode::NOT_FOUND, "no such sandbox").into_response();
    }
    let exp = (now_ms() / 1000) as u64 + req.ttl_secs.unwrap_or(st.cfg.token_ttl_secs);
    let info = proto::PreviewInfo {
        url: format!("{}/preview/{id}/{}/", st.cfg.public_base(), req.port),
        token: crate::preview::mint(&st.cfg.token, &id, req.port, exp),
        port: req.port,
        expires_at: rfc3339_millis(exp as i64 * 1000),
    };
    st.emit(&id, &Corr::from_headers(&headers), EventType::PreviewCreated, json!({"port": req.port}));
    Json(info).into_response()
}

/// `/preview/<id>/<port>[/<rest>]` → `(id, port, rest)`.
fn split_preview(path: &str) -> Option<(String, u16, String)> {
    let rest = path.strip_prefix("/preview/")?;
    let (id, rest) = rest.split_once('/')?;
    let (port, rest) = match rest.split_once('/') {
        Some((p, r)) => (p, r),
        None => (rest, ""),
    };
    Some((id.to_string(), port.parse().ok()?, rest.to_string()))
}

/// No bearer token here: this is a URL a human pastes into a browser. The token
/// arrives once in the query, becomes a cookie scoped to this sandbox and port,
/// and everything after that is an ordinary reverse proxy hop to the guest's
/// `/proxy/<port>/...`.
async fn preview_proxy(State(st): State<AppState>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    let Some((id, port, rest)) = split_preview(&path) else {
        return (StatusCode::NOT_FOUND, "not a preview path").into_response();
    };
    let query = req.uri().query().unwrap_or("").to_string();
    // Owned up front: a borrow of the request cannot be held across an await
    // (its body is Send but not Sync).
    let (cookie, xhdr) = {
        let h = req.headers();
        let get = |n| h.get(n).and_then(|v: &axum::http::HeaderValue| v.to_str().ok()).map(str::to_string);
        (get("cookie"), get("x-sbx-preview"))
    };
    let presented = crate::preview::presented(
        (!query.is_empty()).then_some(query.as_str()),
        cookie.as_deref(),
        xhdr.as_deref(),
        &id,
        port,
    );
    let Some((token, from_query)) = presented else {
        return (StatusCode::UNAUTHORIZED, "preview token missing").into_response();
    };
    if !crate::preview::verify(&st.cfg.token, &token, &id, port, (now_ms() / 1000) as u64) {
        return (StatusCode::UNAUTHORIZED, "preview token invalid or expired").into_response();
    }
    // Move the token out of the URL: it would otherwise reach the dev server's
    // logs and every `Referer` the page sends.
    if from_query {
        let q = crate::preview::strip_token(&query);
        let to = if q.is_empty() { path.clone() } else { format!("{path}?{q}") };
        return (
            StatusCode::FOUND,
            [
                (axum::http::header::LOCATION, to),
                (
                    axum::http::header::SET_COOKIE,
                    format!(
                        "{}={token}; Path=/preview/{id}/{port}/; HttpOnly; SameSite=Lax",
                        crate::preview::cookie_name(&id, port)
                    ),
                ),
            ],
        )
            .into_response();
    }

    let (conn, token) = match agent_conn(&st, &id).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    st.touch(&id).await;
    // A native sandbox's server listens on the host's loopback and its shim is not
    // allowed to dial loopback (policy/seatbelt.sb.tmpl), so qafas, which is
    // outside the sandbox, connects to the port itself.
    // The direct hop is to the dev server, not to the guest, so it carries no
    // agent token — and `strip_client_auth` below would drop it anyway.
    let (conn, token, agent_path) = if matches!(conn, Connector::Unix(_)) {
        (Connector::Tcp(std::net::SocketAddr::from(([127, 0, 0, 1], port))), None, rest.to_string())
    } else {
        (conn, token, format!("proxy/{port}/{rest}"))
    };
    let (mut parts, body) = req.into_parts();
    // The preview cookie and any bearer token authenticate the caller to *us*;
    // what listens on the other side is code the agent wrote (finding 2).
    agent_core::proxy::strip_client_auth(&mut parts.headers);
    if parts.headers.get(axum::http::header::UPGRADE).is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket")) {
        return match WebSocketUpgrade::from_request_parts(&mut parts, &st).await {
            Ok(ws) => ws.on_upgrade(move |c| relay(st, id, conn, token, agent_path, Corr::default(), c)),
            Err(e) => e.into_response(),
        };
    }
    let pq = if query.is_empty() { format!("/{agent_path}") } else { format!("/{agent_path}?{query}") };
    match send(&st, &conn, token.as_deref(), &pq, Request::from_parts(parts, body)).await {
        Ok(r) => r,
        Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

async fn client_event(
    State(st): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !auth.allows(&id) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let ev: ClientEvent = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    st.emit(&id, &Corr::from_headers(&headers), ev.r#type, ev.data);
    StatusCode::NO_CONTENT.into_response()
}

/// `GET /sandboxes/{id}/processes` (protocol §3 v2). The agent answers it in
/// both tiers, so this is the same proxy hop as everything else.
async fn processes(State(st): State<AppState>, auth: Auth, Path(id): Path<String>, req: Request) -> Response {
    if !auth.allows(&id) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let (conn, token) = match agent_conn(&st, &id).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    match send(&st, &conn, token.as_deref(), "/processes", req).await {
        Ok(r) => r,
        Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

/// Events from the egress proxy container. It knows the peer address; only we
/// know which sandbox has it.
async fn internal_events(State(st): State<AppState>, auth: Auth, Json(evs): Json<Vec<Event>>) -> Response {
    if !auth.admin {
        return StatusCode::FORBIDDEN.into_response();
    }
    // peer IP → (sandbox id, the session that created it), so `egress.*` carries
    // the same attribution every other event does (§1).
    let by_ip: HashMap<String, (String, String)> = st
        .live
        .lock()
        .await
        .values()
        .filter_map(|l| l.sb.peer_ip.map(|ip| (ip.to_string(), (l.sb.id.clone(), l.pi_session.clone()))))
        .collect();
    for mut ev in evs {
        if ev.sandbox_id.is_empty() {
            if let Some((id, session)) = ev.data.get("peer").and_then(|p| p.as_str()).and_then(|p| by_ip.get(p)) {
                ev.sandbox_id = id.clone();
                if ev.pi_session.is_empty() {
                    ev.pi_session = session.clone();
                }
            }
        }
        let _ = st.bus.send(ev);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn events_ws(State(st): State<AppState>, a: Auth, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |mut sock| async move {
        let mut rx = st.bus.subscribe();
        while let Ok(ev) = rx.recv().await {
            // A scoped token streams its own sandbox only; host-level events
            // (empty `sandbox_id`) stay with the admin.
            if !a.allows(&ev.sandbox_id) {
                continue;
            }
            let Ok(txt) = serde_json::to_string(&ev) else { continue };
            if sock.send(AxMsg::Text(txt.into())).await.is_err() {
                break;
            }
        }
    })
}

/// Subscribes to a VM-tier sandbox's own `/events/ws` and republishes what it
/// reports onto this daemon's bus, with the host id filled in.
///
/// The guest cannot POST to us: it sits on an internal network whose only exit
/// is the egress proxy (D7). So the direction is inverted — we pull, over the
/// connector we already have.
pub fn spawn_guest_events(st: AppState, id: String, conn: Connector, token: Option<String>) {
    tokio::spawn(async move {
        let io = match conn.connect().await {
            Ok(io) => io,
            Err(e) => {
                tracing::debug!(sandbox_id = %id, error = %e, "no in-guest event stream");
                return;
            }
        };
        let mut req = match tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
            "ws://sandbox/events/ws",
        ) {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(sandbox_id = %id, error = %e, "bad guest event request");
                return;
            }
        };
        if let Some(Ok(t)) = token.as_deref().map(str::parse) {
            req.headers_mut().insert(proto::HDR_AGENT_TOKEN, t);
        }
        let Ok((mut stream, _)) = tokio_tungstenite::client_async(req, io).await else {
            tracing::debug!(sandbox_id = %id, "guest does not serve /events/ws");
            return;
        };
        while let Some(Ok(TgMsg::Text(t))) = stream.next().await {
            match serde_json::from_str::<Event>(&t) {
                Ok(mut ev) => {
                    ev.host_id = st.cfg.host_id.clone();
                    ev.sandbox_id = id.clone();
                    // v5.1 §1: the guest pushes its own usage while an exec is
                    // live. Taking it here is what makes `SandboxInfo.usage`
                    // follow a burst instead of waiting for the 5 s pull, which
                    // stays as the only sample an idle sandbox ever produces.
                    if ev.r#type == EventType::SandboxUsage {
                        if let Ok(u) = serde_json::from_value::<proto::SandboxUsage>(ev.data.clone()) {
                            if let Some(l) = st.live_get(&id).await {
                                *l.usage.lock().expect("usage") = Some(u);
                            }
                        }
                    }
                    let _ = st.bus.send(ev);
                }
                Err(e) => tracing::debug!(error = %e, "unparsable guest event"),
            }
        }
        tracing::debug!(sandbox_id = %id, "guest event stream ended");
    });
}

// ------------------------------------------------------------------ agent proxy

/// The connector to talk to a sandbox's guest, or the response to send instead.
///
/// v4 transparent start (D23): a `stopped` sandbox is woken here rather than in
/// every SDK and harness, so an idle-stopped sandbox looks like a slow first
/// call. `paused` and `archived` are explicit states and stay a 409.
/// `transition` holds the per-sandbox `op` lock and is idempotent, so concurrent
/// requests wake it exactly once.
/// v4: the podman tier's guest also wants `X-Sbx-Agent-Token`, so the secret
/// travels with the connector — every hop below adds it.
async fn agent_conn(st: &AppState, id: &str) -> Result<(Connector, Option<String>), Response> {
    let Some(l) = st.live_get(id).await else {
        return Err((StatusCode::NOT_FOUND, "no such sandbox").into_response());
    };
    if l.state() == SandboxState::Stopped {
        if let Err(e) = transition(st, &l, Verb::Start, "use").await {
            st.emit(id, &Corr::default(), EventType::Error, json!({"msg": e.to_string()}));
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("cannot wake the sandbox: {e}")})),
            )
                .into_response());
        }
    }
    if !l.running() {
        return Err((StatusCode::CONFLICT, Json(json!({"error": format!("sandbox is {}", state_name(l.state()))})))
            .into_response());
    }
    Ok((l.sb.connector.clone(), l.sb.agent_token.clone()))
}

fn content_length(h: &HeaderMap) -> u64 {
    h.get(axum::http::header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// The `path=` of an agent request, for the log line and the `fs.*` events.
/// Decoded by the same extractor the guest's own `/fs/*` handlers use, so the
/// two can never disagree about an escaped path. Empty for a request that has
/// none, which is most of them.
fn query_path(uri: &Uri) -> String {
    axum::extract::Query::<agent_core::fs::PathQ>::try_from_uri(uri).map(|q| q.0.path).unwrap_or_default()
}

/// Sends one request to the agent. TCP goes through a pooled client — which is
/// also the native tier's path, since its endpoint is a loopback port this
/// process serves; vsock does a fresh handshake per request.
/// `pq` is the agent path, i.e. everything after `/agent` plus the query.
async fn send(
    st: &AppState,
    conn: &Connector,
    token: Option<&str>,
    pq: &str,
    mut req: Request,
) -> anyhow::Result<Response> {
    if let Some(t) = token {
        req.headers_mut().insert(proto::HDR_AGENT_TOKEN, t.parse()?);
    }
    match conn.tcp_authority() {
        Some(authority) => {
            *req.uri_mut() = format!("http://{authority}{pq}").parse()?;
            let resp = st.agent.request(req).await?;
            Ok(resp.map(axum::body::Body::new).into_response())
        }
        None => {
            // The sandbox's kept-open connection when it is idle; otherwise a
            // fresh one, so a second call never queues behind a long exec.
            let pool = conn.keepalive();
            let mut sender = match pool {
                Some(k) => k.take().await,
                None => None,
            };
            if sender.is_none() {
                let io: Conn = conn.connect().await?;
                let (s, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
                tokio::spawn(async move {
                    let _ = connection.await;
                });
                sender = Some(s);
            }
            let mut sender = sender.expect("a sender either taken or just built");
            *req.uri_mut() = pq.parse()?;
            req.headers_mut().insert(axum::http::header::HOST, "sandbox".parse()?);
            let resp = sender.send_request(req).await?;
            // Back straight away: `is_ready` stays false until this response's
            // body is done, so the next taker only gets it once it is usable.
            if let Some(k) = pool {
                k.put(sender).await;
            }
            Ok(resp.map(axum::body::Body::new).into_response())
        }
    }
}

async fn agent_http(
    State(st): State<AppState>,
    auth: Auth,
    Path((id, rest)): Path<(String, String)>,
    req: Request,
) -> Response {
    if !auth.allows(&id) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let (conn, token) = match agent_conn(&st, &id).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    st.touch(&id).await;
    let corr = Corr::from_headers(req.headers());
    let started = std::time::Instant::now();
    let method = req.method().clone();
    let path = query_path(req.uri());
    let req_bytes = content_length(req.headers());
    // The guest buffers `/fs/tar` and `/fs/write` whole and, on the remote tier,
    // extracts onto a tmpfs — so the cap is enforced here as well as at the far
    // end: `content-length` up front, the stream itself after.
    let cap = st.cfg.max_upload_mb * 1024 * 1024;
    if req_bytes > cap {
        let msg = format!("body over SBX_MAX_UPLOAD_MB ({} MiB)", st.cfg.max_upload_mb);
        return (StatusCode::PAYLOAD_TOO_LARGE, msg).into_response();
    }
    let req = {
        let (parts, body) = req.into_parts();
        let limited = http_body_util::Limited::new(body, cap as usize);
        Request::from_parts(parts, axum::body::Body::new(limited))
    };
    // Strip the `/sandboxes/{id}/agent` prefix: the agent serves `/fs/list`,
    // not the routed path.
    let pq = match req.uri().query() {
        Some(q) => format!("/{rest}?{q}"),
        None => format!("/{rest}"),
    };

    // `POST /exec` is the only route whose body we look at: it is small, and it
    // is what makes exec.start meaningful.
    let req = if rest == "exec" && method == axum::http::Method::POST {
        let (parts, body) = req.into_parts();
        let Ok(bytes) = axum::body::to_bytes(body, 8 * 1024 * 1024).await else {
            return (StatusCode::BAD_REQUEST, "exec body too large").into_response();
        };
        if let Ok(er) = serde_json::from_slice::<ExecReq>(&bytes) {
            st.emit(&id, &corr, EventType::ExecStart, json!({"cmd": er.cmd, "cwd": er.cwd, "pty": false}));
        }
        Request::from_parts(parts, axum::body::Body::from(bytes))
    } else {
        req
    };

    let resp = match send(&st, &conn, token.as_deref(), &pq, req).await {
        Ok(r) => r,
        Err(e) => {
            st.emit(&id, &corr, EventType::Error, json!({"msg": e.to_string()}));
            return (StatusCode::BAD_GATEWAY, e.to_string()).into_response();
        }
    };

    match (rest.as_str(), &method) {
        ("exec", &axum::http::Method::POST) => {
            let (parts, body) = resp.into_parts();
            let bytes = axum::body::to_bytes(body, 64 * 1024 * 1024).await.unwrap_or_default();
            let exit = serde_json::from_slice::<ExecResp>(&bytes).map(|r| r.exit).unwrap_or(-1);
            st.emit(
                &id,
                &corr,
                EventType::ExecEnd,
                json!({
                    "exit": exit,
                    "duration_ms": started.elapsed().as_millis() as u64,
                    "bytes_out": bytes.len(),
                }),
            );
            Response::from_parts(parts, axum::body::Body::from(bytes))
        }
        ("fs/read", _) => {
            let bytes = content_length(resp.headers());
            st.emit(&id, &corr, EventType::FileRead, json!({"path": path, "bytes": bytes}));
            resp
        }
        ("fs/write", &axum::http::Method::PUT) | ("fs/tar", &axum::http::Method::PUT) => {
            st.emit(&id, &corr, EventType::FileWrite, json!({"path": path, "bytes": req_bytes}));
            resp
        }
        _ => resp,
    }
}

async fn agent_ws(
    State(st): State<AppState>,
    auth: Auth,
    uri: Uri,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    // The route patterns differ in how many segments they capture, so the id
    // comes off the path rather than out of an extractor.
    let id = uri.path().strip_prefix("/sandboxes/").and_then(|r| r.split('/').next()).unwrap_or_default().to_string();
    if !auth.allows(&id) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let (conn, token) = match agent_conn(&st, &id).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    st.touch(&id).await;
    // Everything after `/agent` is the agent path.
    let rest = uri.path().split_once("/agent/").map(|(_, r)| r.to_string()).unwrap_or_default();
    let corr = Corr::from_headers(&headers);
    ws.on_upgrade(move |client| relay(st, id, conn, token, rest, corr, client))
}

#[allow(clippy::too_many_arguments)]
async fn relay(
    st: AppState,
    id: String,
    conn: Connector,
    token: Option<String>,
    rest: String,
    corr: Corr,
    client: WebSocket,
) {
    let io = match conn.connect().await {
        Ok(io) => io,
        Err(e) => {
            st.emit(&id, &corr, EventType::Error, json!({"msg": e.to_string()}));
            return;
        }
    };
    // The correlation headers have to reach the agent too: in-guest telemetry
    // attributes a grandchild to the tool call by reading them off this upgrade.
    let mut request = match tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(format!(
        "ws://sandbox/{rest}"
    )) {
        Ok(r) => r,
        Err(e) => {
            st.emit(&id, &corr, EventType::Error, json!({"msg": format!("ws request: {e}")}));
            return;
        }
    };
    if let (Ok(s), Ok(t)) = (corr.pi_session.parse(), corr.tool_call_id.parse()) {
        request.headers_mut().insert(proto::HDR_PI_SESSION, s);
        request.headers_mut().insert(proto::HDR_TOOL_CALL_ID, t);
    }
    if let Some(Ok(t)) = token.as_deref().map(str::parse) {
        request.headers_mut().insert(proto::HDR_AGENT_TOKEN, t);
    }
    let upstream = match tokio_tungstenite::client_async(request, io).await {
        Ok((s, _)) => s,
        Err(e) => {
            st.emit(&id, &corr, EventType::Error, json!({"msg": format!("ws upgrade: {e}")}));
            return;
        }
    };

    let (mut cw, mut cr) = client.split();
    let (mut uw, mut ur) = upstream.split();
    let started = std::time::Instant::now();
    let is_exec = rest == "exec/ws";

    let c2u = async {
        while let Some(Ok(m)) = cr.next().await {
            if is_exec {
                if let AxMsg::Text(t) = &m {
                    // The `start` frame is the streaming equivalent of a POST body.
                    if let Ok(ExecFrame::Start { cmd, cwd, pty, .. }) = serde_json::from_str::<ExecFrame>(t) {
                        st.emit(
                            &id,
                            &corr,
                            EventType::ExecStart,
                            json!({"cmd": cmd, "cwd": cwd, "pty": pty.is_some()}),
                        );
                    }
                }
            }
            let out = match m {
                AxMsg::Text(t) => TgMsg::Text(t.as_str().into()),
                AxMsg::Binary(b) => TgMsg::Binary(b),
                AxMsg::Ping(b) => TgMsg::Ping(b),
                AxMsg::Pong(b) => TgMsg::Pong(b),
                AxMsg::Close(_) => break,
            };
            if uw.send(out).await.is_err() {
                break;
            }
        }
        let _ = uw.close().await;
    };

    let u2c = async {
        let mut bytes_out = 0usize;
        while let Some(Ok(m)) = ur.next().await {
            let out = match m {
                TgMsg::Text(t) => {
                    bytes_out += t.len();
                    if is_exec {
                        if let Ok(ExecFrame::Exit { code, duration_ms, .. }) = serde_json::from_str::<ExecFrame>(&t) {
                            st.emit(
                                &id,
                                &corr,
                                EventType::ExecEnd,
                                json!({
                                    "exit": code, "duration_ms": duration_ms, "bytes_out": bytes_out,
                                }),
                            );
                        }
                    }
                    AxMsg::Text(t.as_str().into())
                }
                TgMsg::Binary(b) => {
                    bytes_out += b.len();
                    AxMsg::Binary(b)
                }
                TgMsg::Ping(b) => AxMsg::Ping(b),
                TgMsg::Pong(b) => AxMsg::Pong(b),
                TgMsg::Close(_) | TgMsg::Frame(_) => break,
            };
            if cw.send(out).await.is_err() {
                break;
            }
        }
        if is_exec && bytes_out == 0 {
            tracing::debug!(id, elapsed_ms = started.elapsed().as_millis() as u64, "exec ws produced no output");
        }
        let _ = cw.close().await;
    };

    tokio::join!(c2u, u2c);
}

/// How long all the parks together may take. systemd gives us
/// `TimeoutStopSec=60`; past this budget a sandbox is destroyed rather than
/// risking a SIGKILL in the middle of a snapshot.
const PARK_BUDGET_SECS: u64 = 45;

/// v4d: stop this sandbox into its snapshot and mark the record so the next
/// start restores it. `transition` takes the per-sandbox `op` lock, so a verb
/// already in flight finishes first, and does the state, the event and the
/// persist exactly as a client `stop` would.
async fn park(st: &AppState, l: &Arc<Live>) -> anyhow::Result<()> {
    transition(st, l, Verb::Stop, "daemon_shutdown").await?;
    let mut rec = crate::livetable::LiveRecord::from(&**l);
    rec.resume_on_start = true;
    crate::livetable::write_rec(&st.cfg, &rec)?;
    Ok(())
}

/// Parks what can come back and destroys the rest. Called on shutdown.
pub async fn shutdown(st: &AppState) {
    let all: Vec<Arc<Live>> = st.live.lock().await.drain().map(|(_, v)| v).collect();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(PARK_BUDGET_SECS);
    let jobs = all.into_iter().map(|l| async move {
        let rec = crate::livetable::LiveRecord::from(&*l);
        // Only a tier that can take a sandbox back at the next start answers
        // `adopt` — today the microVM one. Everything else still has a container
        // to stop, so it goes as before.
        let adoptable = l.backend.adopt(&rec).is_some();
        // A stopped or archived sandbox has no process to leak and a record on
        // disk: destroying it here would make an orderly restart — or a host
        // reboot, where systemd stops us with SIGTERM — lose exactly what the
        // persisted table exists to keep.
        if adoptable && matches!(rec.state, SandboxState::Stopped | SandboxState::Archived) {
            return false;
        }
        // v4d: a running microVM is snapshotted rather than destroyed, and the
        // record says to restore it. `auto_delete_secs: 0` is "ephemeral": it
        // exists only while it runs, so a restart must not resurrect it.
        if adoptable
            && matches!(rec.state, SandboxState::Ready | SandboxState::Busy | SandboxState::Paused)
            && l.auto_delete_secs != Some(0)
        {
            match tokio::time::timeout_at(deadline, park(st, &l)).await {
                Ok(Ok(())) => return true,
                Ok(Err(e)) => tracing::warn!(
                    error = %e, sandbox_id = %l.sb.id, "park failed; destroying instead"),
                Err(_) => tracing::warn!(
                    sandbox_id = %l.sb.id, "park did not finish in the shutdown budget; destroying instead"),
            }
        }
        st.forget(&l.sb.id);
        if let Err(e) = l.backend.destroy(&l.sb).await {
            tracing::warn!(error = %e, sandbox_id = l.sb.id, "shutdown destroy failed");
        }
        false
    });
    let parked = futures_util::future::join_all(jobs).await.into_iter().filter(|p| *p).count();
    if parked > 0 {
        tracing::info!(parked, "parked {parked} running sandboxes for restart");
    }
    st.pool.drain().await;
}

/// v4d: restart what `shutdown` parked, by the same path `POST /start` takes —
/// so the restore, `ready`, the `sandbox.started` event, the guest telemetry
/// stream and the persist (which clears `resume_on_start`) all happen exactly as
/// they do for a client. Returns how many came back.
///
/// A resume that fails leaves the sandbox `stopped`: the next request wakes it
/// transparently, which is the same retry with a better error path.
pub async fn resume_parked(st: &AppState, ids: &[String]) -> usize {
    let jobs = ids.iter().map(|id| async move {
        let Some(l) = st.live_get(id).await else { return false };
        match transition(st, &l, Verb::Start, "daemon_restart").await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, sandbox_id = %id, "parked sandbox did not resume; it stays stopped");
                // Clears the flag (`From<&Live>` writes it false), so the next
                // shutdown does not keep trying to resurrect it.
                st.persist(&l);
                false
            }
        }
    });
    futures_util::future::join_all(jobs).await.into_iter().filter(|r| *r).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_is_refused_only_on_an_f_template() {
        let chk = |class: &str, ok: bool| proto::SecurityCheck {
            id: format!("{class}-{ok}"),
            class: class.into(),
            ok,
            detail: String::new(),
        };
        let row = |grade: &str, findings: Vec<proto::SecurityCheck>| {
            let mut i = crate::snapshots::new_info("t", proto::SnapshotSource::default(), 0, false);
            i.security = Some(proto::TemplateSecurity {
                grade: grade.into(),
                scanned_at: String::new(),
                image_digest: String::new(),
                findings,
            });
            i
        };
        let f = row("F", vec![chk("boundary", false), chk("hygiene", false)]);
        let msg = insecure_for(proto::Trust::Untrusted, "t", Some(&f)).expect("refused");
        assert!(msg.contains("boundary-false") && !msg.contains("hygiene"), "{msg}");
        assert!(insecure_for(proto::Trust::Trusted, "t", Some(&f)).is_none(), "trusted may use it");
        let c = row("C", vec![chk("hygiene", false); 3]);
        assert!(insecure_for(proto::Trust::Untrusted, "t", Some(&c)).is_none(), "hygiene alone never refuses");
        let unscanned = crate::snapshots::new_info("t", proto::SnapshotSource::default(), 0, false);
        assert!(insecure_for(proto::Trust::Untrusted, "t", Some(&unscanned)).is_none(), "no grade, no refusal");
    }
    use crate::config::FileConfig;

    fn state() -> AppState {
        state_of("api-test", Caps::default())
    }

    struct Null;
    impl crate::backend::Backend for Null {
        fn name(&self) -> &'static str {
            "null"
        }
        fn create(&self, _s: Spec) -> crate::backend::BoxFut<'_, anyhow::Result<Sandbox>> {
            Box::pin(async { anyhow::bail!("no") })
        }
        fn destroy(&self, _s: &Sandbox) -> crate::backend::BoxFut<'_, anyhow::Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// A backend that can hold a sandbox with no process of its own and take it
    /// back at the next start — what the microVM tier is, as far as `shutdown`
    /// and `resume_parked` can tell.
    struct Parkable;
    impl crate::backend::Backend for Parkable {
        fn name(&self) -> &'static str {
            "firecracker"
        }
        fn create(&self, _s: Spec) -> crate::backend::BoxFut<'_, anyhow::Result<Sandbox>> {
            Box::pin(async { anyhow::bail!("no") })
        }
        fn destroy(&self, _s: &Sandbox) -> crate::backend::BoxFut<'_, anyhow::Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn adopt(&self, rec: &crate::livetable::LiveRecord) -> Option<Sandbox> {
            Some(Sandbox {
                id: rec.id.clone(),
                template: rec.template.clone(),
                workspace_path: rec.workspace_path.clone(),
                connector: Connector::Tcp("127.0.0.1:1".parse().expect("addr")),
                agent_token: None,
                peer_ip: rec.peer_ip,
                created_at: rec.created_at.clone(),
                ready_at: None,
                boot_ms: 0,
            })
        }
        fn supports_lifecycle(&self, _v: Verb) -> bool {
            true
        }
        fn stop(&self, _s: &Sandbox) -> crate::backend::BoxFut<'_, anyhow::Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn start(&self, _s: &Sandbox) -> crate::backend::BoxFut<'_, anyhow::Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// `tag` keeps one test's snapshot records out of the next one's directory.
    fn state_of(tag: &str, caps: Caps) -> AppState {
        state_with(tag, caps, Arc::new(Null))
    }

    fn state_with(tag: &str, caps: Caps, backend: Arc<dyn crate::backend::Backend>) -> AppState {
        let mut c = Config::resolve(FileConfig::default());
        // The snapshot store writes records; keep the tests out of the real state dir.
        c.state_dir = std::env::temp_dir().join(format!("sbx-{tag}-{}", std::process::id())).display().to_string();
        let cfg = Arc::new(c);
        let bus = crate::events::bus();
        AppState::new(
            cfg.clone(),
            Pool::new(
                backend,
                crate::pool::Policy { base: 0, recent_secs: 3600, recent_max: 4 },
                bus.clone(),
                "h".into(),
                cfg.default_limits(),
            ),
            bus,
            caps,
        )
    }

    #[test]
    fn scoped_tokens_only_open_their_own_sandbox() {
        let secret = "dev";
        let now = 1_000u64;
        let tok = hmac_token::mint(secret, "sbx_a", now + 60);
        let a = Auth { admin: false, sandbox: hmac_token::verify(secret, &tok, now) };
        assert!(a.allows("sbx_a"));
        assert!(!a.allows("sbx_b"));
        assert!(Auth { admin: true, sandbox: None }.allows("anything"));
        assert_eq!(hmac_token::verify(secret, &tok, now + 61), None, "expiry is enforced");
    }

    #[test]
    fn bearer_header_or_query_token() {
        let mut h = HeaderMap::new();
        let uri: Uri = "/events/ws".parse().unwrap();
        assert_eq!(presented_token(&h, &uri), None);
        h.insert(axum::http::header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        assert_eq!(presented_token(&h, &uri).as_deref(), Some("abc"));

        // The query fallback exists for WebSocket clients that cannot set
        // headers, and for nothing else: on a plain GET there is no token at
        // all, so the extractor answers 401.
        let uri: Uri = "/events/ws?token=xyz".parse().unwrap();
        assert_eq!(presented_token(&HeaderMap::new(), &uri), None);
        let mut ws = HeaderMap::new();
        ws.insert(axum::http::header::UPGRADE, "WebSocket".parse().unwrap());
        assert_eq!(presented_token(&ws, &uri).as_deref(), Some("xyz"));
    }

    /// Finding 1: a scoped token is one sandbox's, not the host's.
    #[tokio::test]
    async fn a_scoped_token_sees_one_sandbox_and_no_host_wide_route() {
        let st = state();
        live_for(&st, "sbx_a").await;
        live_for(&st, "sbx_b").await;
        let scoped = || Auth { admin: false, sandbox: Some("sbx_a".into()) };
        let admin = || Auth { admin: true, sandbox: None };

        let mine = list(State(st.clone()), scoped()).await.0;
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].id, "sbx_a");
        assert_eq!(list(State(st.clone()), admin()).await.0.len(), 2);

        for r in [
            pool_stats(State(st.clone()), scoped()).await,
            policy(State(st.clone()), scoped()).await,
            list_snapshots(State(st.clone()), scoped()).await,
            get_snapshot(State(st.clone()), scoped(), Path("snap".into())).await,
        ] {
            assert_eq!(r.status(), StatusCode::FORBIDDEN);
        }
        assert_eq!(pool_stats(State(st.clone()), admin()).await.status(), StatusCode::OK);
        assert_eq!(policy(State(st), admin()).await.status(), StatusCode::OK);
    }

    /// Finding 5: an oversize upload is refused here, not in the guest's RAM.
    #[tokio::test]
    async fn an_oversize_upload_is_413_before_it_reaches_the_guest() {
        let st = state();
        live_for(&st, "sbx_up").await;
        let put = |len: u64| {
            let mut req = Request::new(axum::body::Body::empty());
            *req.method_mut() = axum::http::Method::PUT;
            *req.uri_mut() = "/sandboxes/sbx_up/agent/fs/tar?path=/w".parse().unwrap();
            req.headers_mut().insert(axum::http::header::CONTENT_LENGTH, len.into());
            req
        };
        let over = (st.cfg.max_upload_mb + 1) * 1024 * 1024;
        let r = agent_http(
            State(st.clone()),
            Auth { admin: true, sandbox: None },
            Path(("sbx_up".into(), "fs/tar".into())),
            put(over),
        )
        .await;
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // Under the cap it gets as far as the (dead) connector, i.e. past this check.
        let r = agent_http(
            State(st),
            Auth { admin: true, sandbox: None },
            Path(("sbx_up".into(), "fs/tar".into())),
            put(1024),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
    }

    /// v4 §2: the forward is a pipe. The body below never ends, so a handler
    /// that collected it before dialling the guest would hang here instead of
    /// failing at the (dead) connector.
    #[tokio::test]
    async fn the_agent_forward_streams_and_never_collects_the_body() {
        let st = state();
        live_for(&st, "sbx_stream").await;
        let endless =
            futures_util::stream::repeat_with(|| Ok::<_, std::io::Error>(axum::body::Bytes::from_static(&[0u8; 8192])));
        let mut req = Request::new(axum::body::Body::from_stream(endless));
        *req.method_mut() = axum::http::Method::PUT;
        *req.uri_mut() = "/sandboxes/sbx_stream/agent/fs/tar?path=/w".parse().unwrap();

        let call = agent_http(
            State(st),
            Auth { admin: true, sandbox: None },
            Path(("sbx_stream".into(), "fs/tar".into())),
            req,
        );
        let r = tokio::time::timeout(std::time::Duration::from_secs(5), call)
            .await
            .expect("the forward buffered the body instead of streaming it");
        assert_eq!(r.status(), StatusCode::BAD_GATEWAY);
    }

    /// v4 §2: every hop to a podman guest proves it is qafas. A sandbox with
    /// no token (native, firecracker) sends no header at all.
    #[tokio::test]
    async fn the_agent_forward_carries_the_per_sandbox_token() {
        // Stands in for the guest: echoes back what it was asked with.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/processes",
                axum::routing::get(|h: HeaderMap| async move {
                    h.get(proto::HDR_AGENT_TOKEN).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string()
                }),
            );
            axum::serve(l, app).await.unwrap()
        });

        let st = state();
        live_at(&st, "sbx_tok", Connector::Tcp(addr), Some("s3cret"), None, "").await;
        live_at(&st, "sbx_none", Connector::Tcp(addr), None, None, "").await;
        let seen = |id: &'static str| {
            let st = st.clone();
            async move {
                let r = processes(
                    State(st),
                    Auth { admin: true, sandbox: None },
                    Path(id.into()),
                    Request::new(axum::body::Body::empty()),
                )
                .await;
                assert_eq!(r.status(), StatusCode::OK);
                let b = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
                String::from_utf8_lossy(&b).into_owned()
            }
        };
        assert_eq!(seen("sbx_tok").await, "s3cret");
        assert_eq!(seen("sbx_none").await, "-");
    }

    #[test]
    fn path_query_is_decoded_for_file_events() {
        let uri: Uri = "/x?path=%2FUsers%2Fme%2Fa+b.txt".parse().unwrap();
        assert_eq!(query_path(&uri), "/Users/me/a b.txt");
        assert_eq!(query_path(&"/x".parse::<Uri>().unwrap()), "");
    }

    #[tokio::test]
    async fn unknown_sandbox_is_404_not_a_panic() {
        let st = state();
        assert!(agent_conn(&st, "sbx_missing").await.is_err());
        assert!(st.list().await.is_empty());
        st.touch("sbx_missing").await;
    }

    /// The timer table of §3a, in one place. `s` is seconds as milliseconds.
    #[test]
    fn the_timers_do_what_the_contract_says() {
        let s = |n: i64| n * 1000;
        let d = |state, remote, idle, since, age, ttl, stop, arch, del, max| {
            due(0, state, remote, s(idle), s(since), s(age), ttl, stop, arch, del, max)
        };
        let ready = SandboxState::Ready;

        // Nothing set but the default idle TTL: destroy when idle past it.
        assert_eq!(d(ready, true, 10, 10, 10, 3600, None, None, None, None), None);
        assert_eq!(d(ready, true, 4000, 10, 10, 3600, None, None, None, None), Some((None, "idle_ttl")));

        // auto_stop owns idleness; the TTL then does not destroy.
        assert_eq!(d(ready, true, 60, 10, 10, 30, Some(30), None, None, None), Some((Some(Verb::Stop), "auto_stop")));
        assert_eq!(d(ready, true, 20, 10, 10, 30, Some(30), None, None, None), None, "not idle long enough for either");
        // v4: on every tier, not just remote — an idle native sandbox sleeps too.
        assert_eq!(d(ready, false, 60, 10, 10, 30, Some(30), None, None, None), Some((Some(Verb::Stop), "auto_stop")));
        // v4 defaults, as `create` resolves them: sleep at 30 min, and the TTL
        // never gets a look in while sleeping is on.
        let (stop_d, del_d) = (Some(1800u64), Some(86400u64));
        assert_eq!(
            d(ready, false, 1801, 10, 10, 3600, stop_d, None, del_d, None),
            Some((Some(Verb::Stop), "auto_stop"))
        );
        assert_eq!(
            d(ready, false, 5000, 10, 10, 3600, stop_d, None, del_d, None),
            Some((Some(Verb::Stop), "auto_stop")),
            "past the TTL as well: it still sleeps"
        );
        // `auto_stop_secs: 0` switches sleeping off and hands idleness back to the TTL.
        assert_eq!(d(ready, false, 4000, 10, 10, 3600, Some(0), None, del_d, None), Some((None, "idle_ttl")));
        assert_eq!(d(ready, false, 10, 10, 10, 3600, Some(0), None, del_d, None), None);

        // max_age wins from any state, however busy the sandbox is.
        assert_eq!(d(ready, true, 0, 0, 100, 3600, Some(9999), None, None, Some(60)), Some((None, "max_age")));
        assert_eq!(d(SandboxState::Stopped, true, 0, 0, 100, 0, None, None, None, Some(60)), Some((None, "max_age")));

        // Stopped: archive after auto_archive, delete after auto_delete, and
        // `auto_delete_secs: 0` means the moment it stops.
        let stopped = SandboxState::Stopped;
        assert_eq!(d(stopped, true, 0, 10, 10, 3600, None, Some(60), None, None), None);
        assert_eq!(
            d(stopped, true, 0, 90, 90, 3600, None, Some(60), None, None),
            Some((Some(Verb::Archive), "auto_archive"))
        );
        assert_eq!(d(stopped, false, 0, 90, 90, 3600, None, Some(60), None, None), None, "archiving stays remote-only");
        // A slept sandbox is destroyed a day later, not immediately.
        assert_eq!(d(stopped, false, 0, 3600, 3600, 3600, stop_d, None, del_d, None), None);
        assert_eq!(d(stopped, false, 0, 90_000, 90_000, 3600, stop_d, None, del_d, None), Some((None, "auto_delete")));
        // `max_age_secs: 0` is "no limit", not "destroy at once".
        assert_eq!(d(ready, false, 0, 0, 99_999, 0, Some(0), None, None, Some(0)), None);
        assert_eq!(d(stopped, true, 0, 0, 0, 3600, None, Some(60), Some(0), None), Some((None, "auto_delete")));
        assert_eq!(
            d(stopped, true, 0, 90, 90, 3600, None, Some(60), Some(30), None),
            Some((None, "auto_delete")),
            "delete beats archive when both are due"
        );
        // A stopped sandbox is never destroyed by the idle TTL: it is not idle, it is off.
        assert_eq!(d(stopped, true, 99999, 10, 10, 3600, None, None, None, None), None);

        // Archived: only auto_delete and max_age reach it.
        let arch = SandboxState::Archived;
        assert_eq!(d(arch, true, 0, 99999, 99999, 3600, None, Some(1), None, None), None);
        assert_eq!(d(arch, true, 0, 90, 90, 3600, None, None, Some(30), None), Some((None, "auto_delete")));
    }

    /// `/metrics` must render on a daemon that has done nothing at all, and is
    /// only open to a loopback peer (§3 v4).
    #[tokio::test]
    async fn metrics_render_on_an_idle_daemon_and_need_a_token_off_loopback() {
        use axum::extract::ConnectInfo;
        let st = state();
        let scrape = |ip: [u8; 4], token: Option<&str>| {
            let mut req = Request::new(axum::body::Body::empty());
            req.extensions_mut().insert(ConnectInfo(std::net::SocketAddr::from((ip, 5000))));
            if let Some(t) = token {
                req.headers_mut().insert(axum::http::header::AUTHORIZATION, format!("Bearer {t}").parse().unwrap());
            }
            req
        };

        // The default config listens on loopback: open, whoever the peer is.
        let r = metrics(State(st.clone()), scrape([127, 0, 0, 1], None)).await;
        assert_eq!(r.status(), StatusCode::OK);

        // A worker bound to 0.0.0.0 wants the token even from a loopback peer: a
        // port forwarder in front rewrites the source address.
        let mut wide = (*st.cfg).clone();
        wide.listen = "0.0.0.0:7700".parse().unwrap();
        let mut worker = st.clone();
        worker.cfg = Arc::new(wide);
        let r = metrics(State(worker.clone()), scrape([127, 0, 0, 1], None)).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "non-loopback listener requires the token");

        let tok = worker.cfg.token.clone();
        let r = metrics(State(worker), scrape([10, 0, 0, 9], Some(&tok))).await;
        assert_eq!(r.status(), StatusCode::OK);

        // And the v4 series are all on the page, per tier, for one live sandbox.
        live_for(&st, "sbx_m").await;
        let body = axum::body::to_bytes(metrics(State(st), scrape([127, 0, 0, 1], None)).await.into_body(), 1 << 20)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        for want in [
            "sbx_sandboxes{tier=\"native\",state=\"ready\"} 1",
            "sbx_sandbox_age_seconds_max{tier=\"native\"}",
            "sbx_sandbox_idle_seconds_max{tier=\"native\"}",
            "sbx_create_duration_ms_count",
            "sbx_pool_hit_total{hit=\"true\"}",
            "sbx_build_info{version=",
            "sbx_uptime_seconds",
        ] {
            assert!(text.contains(want), "missing {want:?} in:\n{text}");
        }
    }

    /// The long-running rule fires once per multiple of the threshold, on the
    /// same alert path as every other rule (§1.1).
    #[tokio::test]
    async fn long_running_alerts_once_per_multiple() {
        let mut st = state();
        let mut cfg = Config::resolve(FileConfig::default());
        cfg.long_running_secs = 60;
        st.cfg = Arc::new(cfg);
        let mut rx = st.bus.subscribe();

        let l = live_for(&st, "sbx_lr").await;
        let now = now_ms();
        long_running(&st, &l, now); // 0 s in: nothing
        assert!(rx.try_recv().is_err());

        long_running(&st, &l, now + 61_000);
        let e = rx.try_recv().expect("an alert at the first multiple");
        assert_eq!(e.r#type, EventType::SecurityAlert);
        assert_eq!(e.data["rule"], proto::rules::SANDBOX_LONG_RUNNING);
        assert_eq!(e.data["severity"], "medium");
        assert_eq!(e.data["threshold_secs"], 60);
        assert_eq!(e.data["tier"], "native");

        long_running(&st, &l, now + 90_000);
        assert!(rx.try_recv().is_err(), "still the first multiple");
        long_running(&st, &l, now + 121_000);
        assert!(rx.try_recv().is_ok(), "and again at the second");

        // A stopped sandbox is not running, so it cannot be long-running.
        l.set_state(SandboxState::Stopped);
        long_running(&st, &l, now + 999_000);
        assert!(rx.try_recv().is_err());
    }

    /// A `Live` with no backend behind it: enough for the reaper's arithmetic.
    async fn live_for(st: &AppState, id: &str) -> Arc<Live> {
        live_at(st, id, Connector::Tcp("127.0.0.1:1".parse().unwrap()), None, None, "").await
    }

    /// The same, pointed at a connector that answers, with or without the
    /// per-sandbox agent token.
    async fn live_at(
        st: &AppState,
        id: &str,
        conn: Connector,
        token: Option<&str>,
        peer_ip: Option<&str>,
        pi_session: &str,
    ) -> Arc<Live> {
        let l = Arc::new(Live {
            sb: Sandbox {
                id: id.into(),
                template: "base".into(),
                workspace_path: "/w".into(),
                connector: conn,
                agent_token: token.map(str::to_string),
                peer_ip: peer_ip.map(|p| p.parse().expect("peer ip")),
                created_at: now_rfc3339(),
                ready_at: None,
                boot_ms: 1,
            },
            pi_session: pi_session.to_string(),
            isolation: Isolation::Native,
            backend: st.pool.backend().clone(),
            last_activity: AtomicI64::new(now_ms()),
            ttl_secs: 3600,
            name: id.into(),
            labels: Default::default(),
            created_ms: now_ms(),
            auto_stop_secs: Some(1800),
            auto_archive_secs: None,
            auto_delete_secs: Some(86400),
            max_age_secs: None,
            size: proto::sizes::DEFAULT.into(),
            limits: st.cfg.default_limits(),
            enforcement: "kernel".into(),
            usage: Default::default(),
            env: Default::default(),
            long_running_fired: Default::default(),
            state: std::sync::Mutex::new((SandboxState::Ready, now_ms())),
            op: Mutex::new(()),
        });
        st.live.lock().await.insert(id.to_string(), l.clone());
        l
    }

    /// N3: `egress.*` arrives from the proxy with a peer address and nothing
    /// else. It must leave with the sandbox *and* the session that owns it (§1).
    #[tokio::test]
    async fn an_egress_event_is_attributed_to_the_peer_s_session() {
        let st = state();
        live_at(&st, "sbx_eg", Connector::Tcp("127.0.0.1:1".parse().unwrap()), None, Some("172.16.11.2"), "e2e-alerts")
            .await;
        let mut rx = st.bus.subscribe();
        let ev = |peer: &str| Event {
            id: "01".into(),
            ts: now_rfc3339(),
            host_id: "h".into(),
            sandbox_id: String::new(),
            pi_session: String::new(),
            tool_call_id: String::new(),
            r#type: EventType::EgressDeny,
            data: json!({"host": "example.org", "port": 443, "peer": peer}),
        };
        let auth = Auth { admin: true, sandbox: None };
        internal_events(State(st.clone()), auth, Json(vec![ev("172.16.11.2"), ev("172.16.11.9")])).await;

        let known = rx.try_recv().expect("the known peer");
        assert_eq!(known.sandbox_id, "sbx_eg");
        assert_eq!(known.pi_session, "e2e-alerts");
        let unknown = rx.try_recv().expect("an unknown peer still reaches the bus");
        assert_eq!(unknown.sandbox_id, "");
        assert_eq!(unknown.pi_session, "");
    }

    /// v4d: the flag that resurrects a sandbox is never inferred from one.
    #[tokio::test]
    async fn the_park_flag_is_never_derived_from_a_live() {
        let st = state();
        let l = live_for(&st, "sbx_flag").await;
        assert!(!crate::livetable::LiveRecord::from(&*l).resume_on_start);
    }

    /// v4d: SIGTERM stops a running microVM into its snapshot and says so in the
    /// record, instead of destroying it. An ephemeral sandbox
    /// (`auto_delete_secs: 0`) exists only while it runs, so it still goes.
    #[tokio::test]
    async fn shutdown_parks_a_running_sandbox_its_backend_can_take_back() {
        let st = state_with("api-park", Caps::default(), Arc::new(Parkable));
        let _ = std::fs::remove_dir_all(crate::livetable::dir(&st.cfg));
        let keep = live_for(&st, "sbx_park").await;
        st.persist(&keep);
        // Same sandbox, made ephemeral: `adopt` is the one way to build a `Live`
        // with different timers without another constructor.
        let eph = live_for(&st, "sbx_eph").await;
        let rec =
            crate::livetable::LiveRecord { auto_delete_secs: Some(0), ..crate::livetable::LiveRecord::from(&*eph) };
        assert!(st.adopt(&rec, st.pool.backend().clone()).await);
        st.persist(&st.live_get("sbx_eph").await.expect("live"));

        shutdown(&st).await;

        let table: HashMap<String, crate::livetable::LiveRecord> =
            crate::livetable::load_all(&st.cfg).into_iter().map(|r| (r.id.clone(), r)).collect();
        let parked = table.get("sbx_park").expect("the running sandbox is parked, not destroyed");
        assert_eq!(parked.state, SandboxState::Stopped);
        assert!(parked.resume_on_start, "and the next start restores it");
        assert_eq!(keep.state(), SandboxState::Stopped);
        assert!(!table.contains_key("sbx_eph"), "an ephemeral sandbox is destroyed, not parked");
        let _ = std::fs::remove_dir_all(&st.cfg.state_dir);
    }

    /// v4d: and the start clears the flag, so a sandbox is resurrected once.
    #[tokio::test]
    async fn a_resumed_sandbox_stops_being_parked() {
        let st = state_with("api-resume", Caps::default(), Arc::new(Parkable));
        let _ = std::fs::remove_dir_all(crate::livetable::dir(&st.cfg));
        let l = live_for(&st, "sbx_res").await;
        l.set_state(SandboxState::Stopped);
        let rec = crate::livetable::LiveRecord { resume_on_start: true, ..crate::livetable::LiveRecord::from(&*l) };
        crate::livetable::write_rec(&st.cfg, &rec).expect("write");

        assert_eq!(resume_parked(&st, &["sbx_res".to_string()]).await, 1);
        assert_eq!(l.state(), SandboxState::Ready);
        let back = crate::livetable::load_all(&st.cfg);
        assert_eq!(back.len(), 1);
        assert!(!back[0].resume_on_start, "a started sandbox is no longer parked");
        // An id that did not come back at all is skipped, not a panic.
        assert_eq!(resume_parked(&st, &["sbx_gone".to_string()]).await, 0);
        let _ = std::fs::remove_dir_all(&st.cfg.state_dir);
    }

    /// v4: a stopped sandbox is woken by use, a paused one is not (§3a).
    #[tokio::test]
    async fn a_stopped_sandbox_wakes_on_use_and_a_paused_one_does_not() {
        let st = state();
        let l = live_for(&st, "sbx_wake").await;

        // The Null backend cannot start anything, so the wake fails — but it is
        // attempted, which is what distinguishes `stopped` from `paused`.
        l.set_state(SandboxState::Stopped);
        let err = agent_conn(&st, "sbx_wake").await.expect_err("wake fails on a null backend");
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);

        l.set_state(SandboxState::Paused);
        let err = agent_conn(&st, "sbx_wake").await.expect_err("paused stays 409");
        assert_eq!(err.status(), StatusCode::CONFLICT);

        l.set_state(SandboxState::Ready);
        assert!(agent_conn(&st, "sbx_wake").await.is_ok());
    }

    /// The 409 for a verb this tier does not have names the verb (§3a).
    #[tokio::test]
    async fn pause_names_itself_in_the_409() {
        let st = state();
        live_for(&st, "sbx_v").await;
        let auth = || Auth { admin: true, sandbox: None };
        for (verb, want) in [(Verb::Pause, StatusCode::CONFLICT), (Verb::Archive, StatusCode::CONFLICT)] {
            let r = lifecycle(st.clone(), auth(), "sbx_v".into(), verb).await;
            assert_eq!(r.status(), want);
            let b = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
            let text = String::from_utf8_lossy(&b).to_string();
            assert!(text.contains(&format!("{} needs the remote tier", verb.as_str())), "{text}");
        }
    }

    /// §3a template resolution, all four outcomes. Pure, so no daemon needed.
    #[test]
    fn template_resolution_never_falls_back_silently() {
        use crate::snapshots::new_info;
        let src = proto::SnapshotSource::default;
        assert_eq!(resolve_template("base", None), Ok(Resolved::BuiltIn));

        let mut active = new_info("node22", src(), 0, false);
        active.state = proto::SnapshotState::Active;
        assert_eq!(resolve_template("node22", Some(&active)), Ok(Resolved::Snapshot));

        let building = new_info("node22", src(), 0, false);
        assert_eq!(
            resolve_template("node22", Some(&building)),
            Err((StatusCode::CONFLICT, "snapshot node22 is building".into()))
        );

        let mut failed = new_info("node22", src(), 0, false);
        failed.state = proto::SnapshotState::Error;
        failed.error = Some("podman pull refused".into());
        assert_eq!(
            resolve_template("node22", Some(&failed)),
            Err((StatusCode::CONFLICT, "snapshot node22 failed: podman pull refused".into()))
        );

        assert_eq!(resolve_template("nope", None), Err((StatusCode::NOT_FOUND, "unknown template \"nope\"".into())));
    }

    /// §3a: `base` is a row like any other on the read paths, and not deletable.
    #[tokio::test]
    async fn base_is_listed_and_fetchable_but_never_deleted() {
        let st = state();
        let admin = || Auth { admin: true, sandbox: None };
        let rows = st.snapshots.list().await;
        let base = rows.first().expect("base leads the list");
        let listed = list_snapshots(State(st.clone()), admin()).await;
        assert_eq!(listed.status(), StatusCode::OK);
        assert_eq!((base.name.as_str(), base.kind.as_str()), ("base", "image"));
        assert_eq!(base.state, proto::SnapshotState::Active);
        assert_eq!(base.source.image.as_deref(), Some(st.cfg.template_image.as_str()));

        let got = get_snapshot(State(st.clone()), admin(), Path("base".into())).await;
        assert_eq!(got.status(), StatusCode::OK);

        let del = delete_snapshot(State(st.clone()), admin(), Path("base".into())).await;
        assert_eq!(del.status(), StatusCode::BAD_REQUEST);
        // Still there afterwards.
        assert!(st.snapshots.get("base").await.is_some());
    }

    /// v4c §3a: a template is built for one runtime and a host pools one, so a
    /// build aimed at the other runtime is a `409`, not a silent build here.
    #[tokio::test]
    async fn create_snapshot_refuses_another_hosts_runtime() {
        let st = state_of("api-rt", Caps { vm: true, ..Caps::default() });
        let _ = std::fs::remove_dir_all(&st.cfg.state_dir);
        let st = state_of("api-rt", Caps { vm: true, ..Caps::default() });
        let admin = || Auth { admin: true, sandbox: None };
        let post = |name: &str, rt: &str| {
            let body = axum::body::Bytes::from(format!(r#"{{"name":"{name}","source":{{"image":"node:22"}}{rt}}}"#));
            create_snapshot(State(st.clone()), admin(), body)
        };

        let r = post("a", r#","runtime":"remote""#).await;
        assert_eq!(r.status(), StatusCode::CONFLICT);
        let b = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&b), r#"{"error":"this host builds vm templates, not remote"}"#);

        // The alias means the same runtime, and an absent one accepts anything.
        assert_eq!(post("b", r#","runtime":"docker""#).await.status(), StatusCode::ACCEPTED);
        assert_eq!(post("c", "").await.status(), StatusCode::ACCEPTED);
        assert_eq!(st.snapshots.get("b").await.unwrap().runtime, "vm");
        let _ = std::fs::remove_dir_all(&st.cfg.state_dir);
    }

    /// v4 §3a `PUT /snapshots/{name}`: admin only, `base` allowed, unknown 404,
    /// and the number survives a restart of the store.
    #[tokio::test]
    async fn put_snapshot_sets_the_warm_target() {
        let st = state();
        let _ = std::fs::remove_dir_all(&st.cfg.state_dir);
        let st = state();
        let body = |n: u32| axum::body::Bytes::from(format!(r#"{{"warm":{n}}}"#));
        let put = |a: Auth, name: &str, n: u32| update_snapshot(State(st.clone()), a, Path(name.to_string()), body(n));

        let scoped = Auth { admin: false, sandbox: Some("sbx_a".into()) };
        assert_eq!(put(scoped, "base", 3).await.status(), StatusCode::FORBIDDEN);
        let admin = || Auth { admin: true, sandbox: None };
        assert_eq!(put(admin(), "nope", 3).await.status(), StatusCode::NOT_FOUND);

        assert_eq!(put(admin(), "base", 3).await.status(), StatusCode::OK);
        assert_eq!(st.snapshots.get("base").await.unwrap().warm, 3);

        // A named snapshot has to exist before its target can be set.
        let mut info = crate::snapshots::new_info("node22", proto::SnapshotSource::default(), 0, false);
        info.state = proto::SnapshotState::Active;
        assert!(st.snapshots.claim(&info).await);
        assert_eq!(put(admin(), "node22", 2).await.status(), StatusCode::OK);

        // Both numbers are on disk, not just in this process.
        let reloaded = crate::snapshots::Store::load(&st.cfg, "vm");
        assert_eq!(reloaded.get("node22").await.unwrap().warm, 2);
        assert_eq!(reloaded.get("base").await.unwrap().warm, 3, "base's number is kept too");
        let _ = std::fs::remove_dir_all(&st.cfg.state_dir);
    }
}
