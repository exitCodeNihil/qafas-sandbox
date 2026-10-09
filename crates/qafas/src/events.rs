//! One broadcast channel is the whole event bus: `/events/ws` subscribes to it,
//! and a flusher batches it to the control plane once a second.
//!
//! Every control-plane call is best-effort. qafas must work with no control
//! plane configured at all.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use proto::{Event, EventType, Heartbeat, HostRegister};
use tokio::sync::broadcast;

use crate::config::Config;

pub type Bus = broadcast::Sender<Event>;
pub type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

pub fn bus() -> Bus {
    broadcast::channel(1024).0
}

/// Speaks http and https; `tls` decides whom an https peer has to be — the
/// control plane's CA (`tls::client_config`) or, for the egress proxy's event
/// sink, exactly this daemon's own certificate (`tls::pinned_config`).
pub fn http_client_with(tls: rustls::ClientConfig) -> HttpClient {
    let https = hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(tls).https_or_http().enable_http1().build();
    Client::builder(TokioExecutor::new()).build(https)
}

/// http, plus https to anything the system bundle trusts.
pub fn http_client() -> HttpClient {
    http_client_with(crate::tls::client_config("").expect("no ca_file cannot fail"))
}

// Time and correlation live in `agent-core`, which both the daemon and the
// in-guest agent link, so there is exactly one implementation of each.
pub use agent_core::{now_ms, now_rfc3339, rfc3339_millis, Corr};

pub fn new_event(host_id: &str, sandbox_id: &str, corr: &Corr, ty: EventType, data: serde_json::Value) -> Event {
    Event {
        id: ulid::Ulid::new().to_string(),
        ts: now_rfc3339(),
        host_id: host_id.to_string(),
        sandbox_id: sandbox_id.to_string(),
        pi_session: corr.pi_session.clone(),
        tool_call_id: corr.tool_call_id.clone(),
        r#type: ty,
        data,
    }
}

async fn send_json(http: &HttpClient, method: &str, url: &str, token: &str, body: Vec<u8>) -> anyhow::Result<u16> {
    let req = hyper::Request::builder()
        .method(method)
        .uri(url)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Full::new(Bytes::from(body)))?;
    let resp = http.request(req).await?;
    let status = resp.status().as_u16();
    let _ = resp.into_body().collect().await;
    Ok(status)
}

// ------------------------------------------------------------------ spool

/// How much undelivered event JSON is kept on disk. A day of a busy host is a
/// few MiB; past this the oldest batches go, because the newest are the ones an
/// operator is looking at when the control plane comes back.
const SPOOL_CAP: u64 = 64 * 1024 * 1024;

/// One batch per line (serde writes compact JSON, so a batch never contains a
/// newline). Append-only, which makes "replay in order" a plain read.
fn spool_path(cfg: &Config) -> std::path::PathBuf {
    std::path::Path::new(&cfg.state_dir).join("events.spool")
}

/// Appends a batch and trims the file back under `SPOOL_CAP` from the front.
/// Returns how many older batches that cost.
fn spool_push(path: &std::path::Path, body: &[u8]) -> std::io::Result<usize> {
    use std::io::Write;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(body)?;
    f.write_all(b"\n")?;
    if f.metadata()?.len() <= SPOOL_CAP {
        return Ok(0);
    }
    drop(f);
    let all = std::fs::read(path)?;
    let mut lines: Vec<&[u8]> = all.split(|b| *b == b'\n').filter(|l| !l.is_empty()).collect();
    let mut dropped = 0;
    let mut total: u64 = lines.iter().map(|l| l.len() as u64 + 1).sum();
    while total > SPOOL_CAP && !lines.is_empty() {
        total -= lines.remove(0).len() as u64 + 1;
        dropped += 1;
    }
    let mut out = Vec::with_capacity(total as usize);
    for l in lines {
        out.extend_from_slice(l);
        out.push(b'\n');
    }
    std::fs::write(path, out)?;
    Ok(dropped)
}

/// Takes everything spooled and removes the file. The caller owns the batches
/// from here: whatever it cannot deliver it puts back.
fn spool_take(path: &std::path::Path) -> Vec<Vec<u8>> {
    let Ok(all) = std::fs::read(path) else { return Vec::new() };
    let _ = std::fs::remove_file(path);
    all.split(|b| *b == b'\n').filter(|l| !l.is_empty()).map(<[u8]>::to_vec).collect()
}

async fn post_batch(http: &HttpClient, url: &str, token: &str, body: Vec<u8>) -> bool {
    matches!(send_json(http, "POST", url, token, body).await, Ok(s) if (200..300).contains(&s))
}

/// Everything held back goes now, oldest first, stopping at the first refusal so
/// the order survives — whatever is left goes back on the spool.
async fn replay_spool(
    http: &HttpClient,
    url: &str,
    token: &str,
    spool: &std::path::Path,
    metrics: &crate::metrics::Metrics,
) {
    let held = spool_take(spool);
    for (i, old) in held.iter().enumerate() {
        if !post_batch(http, url, token, old.clone()).await {
            for rest in &held[i..] {
                let _ = spool_push(spool, rest);
            }
            return;
        }
        metrics.replayed(1);
    }
}

/// Flusher ticks between two attempts at a spool nobody else is going to touch.
/// An idle host that was partitioned has no new events to piggyback a replay on,
/// so the spool needs a clock of its own; 30 s because by then nobody is waiting
/// on those events, only on their eventually arriving.
const SPOOL_RETRY_TICKS: u32 = 30;

/// Whether an idle tick should go at the spool by itself. Split out so the
/// policy is checkable without a clock.
fn retry_due(since_replay: u32, spool_exists: bool) -> bool {
    spool_exists && since_replay >= SPOOL_RETRY_TICKS
}

/// Batches the bus to `SBX_CP_URL/api/events` every second — at once for a
/// lifecycle event, which the control plane's placement reads. A batch the control
/// plane will not take is spooled to `<state_dir>/events.spool` and replayed as
/// soon as delivery works again — on the next batch, or on the retry tick when
/// the host has gone quiet. So a control plane that restarts, or a host briefly
/// partitioned from it, costs no events rather than three seconds' worth. The
/// control plane is still an observer, never a dependency: the spool is capped
/// and the daemon never blocks on it.
pub fn spawn_flusher(cfg: Arc<Config>, bus: Bus, http: HttpClient, metrics: Arc<crate::metrics::Metrics>) {
    let Some(cp) = cfg.cp_url.clone() else { return };
    // Subscribed here, not inside the task: the bus drops what it has no
    // receiver for, and the caller emits (startup reconciliation) as soon as
    // this returns.
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        let url = format!("{cp}/api/events");
        let (spool, token) = (spool_path(&cfg), cfg.host_token.clone());
        let mut batch: Vec<Event> = Vec::new();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut since_replay = 0u32;
        loop {
            tokio::select! {
                r = rx.recv() => match r {
                    Ok(e) => {
                        // A lifecycle change does not wait for the tick: the control
                        // plane's capacity arithmetic reads it, and on a small host a
                        // create that follows a destroy within the second would be a 503.
                        let lifecycle = matches!(
                            e.r#type,
                            EventType::SandboxReady
                                | EventType::SandboxDestroyed
                                | EventType::SandboxStopped
                                | EventType::SandboxStarted
                        );
                        batch.push(e);
                        if !lifecycle {
                            continue;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(dropped = n, "event bus lagged");
                        continue;
                    }
                    Err(_) => return,
                },
                _ = tick.tick() => {
                    since_replay += 1;
                    if batch.is_empty() {
                        // Nothing new to prove delivery works; ask the spool itself.
                        if !retry_due(since_replay, spool.exists()) {
                            continue;
                        }
                        since_replay = 0;
                        replay_spool(&http, &url, &token, &spool, &metrics).await;
                        continue;
                    }
                }
            }
            let body = serde_json::to_vec(&batch).unwrap_or_default();
            batch.clear();
            if !post_batch(&http, &url, &token, body.clone()).await {
                match spool_push(&spool, &body) {
                    Ok(dropped) => metrics.spooled(1, dropped as u64),
                    Err(e) => tracing::warn!(error = %e, "event batch lost: spool unwritable"),
                }
                continue;
            }
            since_replay = 0;
            replay_spool(&http, &url, &token, &spool, &metrics).await;
        }
    });
}

/// Registers with the control plane on start, then heartbeats every 10 s.
pub fn spawn_registrar(cfg: Arc<Config>, http: HttpClient, state: crate::api::AppState) {
    let Some(cp) = cfg.cp_url.clone() else { return };
    tokio::spawn(async move {
        let reg = HostRegister {
            host_id: cfg.host_id.clone(),
            url: cfg.public_base(),
            backend: cfg.primary_backend().to_string(),
            capacity: cfg.pool_size * 8,
            // D25: what the host can actually do, the same list `/healthz` reports —
            // never the configured wish list.
            tiers: state.caps.tiers().iter().map(|t| t.to_string()).collect(),
            tls_fingerprint: state.tls_fingerprint.clone(),
            // v4c: the capabilities behind `tiers`, so the Hosts page can say why.
            caps: state.host_caps.clone(),
            policy: crate::api::policy_summary(&cfg),
        };
        let register = || async {
            let body = serde_json::to_vec(&reg).unwrap_or_default();
            let r = send_json(&http, "POST", &format!("{cp}/api/hosts/register"), &cfg.host_token, body).await;
            matches!(r, Ok(s) if (200..300).contains(&s))
        };
        while !register().await {
            tracing::warn!("host register failed; retrying");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        loop {
            tick.tick().await;
            let hb = Heartbeat { pool: state.pool.stats().await, sandboxes: state.list().await };
            let body = serde_json::to_vec(&hb).unwrap_or_default();
            let url = format!("{cp}/api/hosts/{}/heartbeat", cfg.host_id);
            match send_json(&http, "PUT", &url, &cfg.host_token, body).await {
                Ok(s) if (200..300).contains(&s) => {}
                // The control plane forgot us (fresh database, failover): re-register
                // rather than heartbeat into the void until someone restarts us.
                Ok(s) => {
                    tracing::warn!(status = s, "heartbeat rejected; re-registering");
                    let _ = register().await;
                }
                Err(e) => tracing::warn!(error = %e, "heartbeat failed"),
            }
        }
    });
}

/// Egress rules that only make sense with the whole stream in view (protocol
/// §1.1): a burst of denials for one sandbox, and any attempt at a cloud
/// metadata endpoint. Both run here rather than in the proxy because the proxy
/// is per-connection and stateless by design.
///
/// design: the burst window is a per-sandbox vector of timestamps, trimmed on
/// each event. Bounded by the 10 s window, so it cannot grow.
pub fn spawn_egress_rules(bus: Bus, host_id: String) {
    const WINDOW_MS: i64 = 10_000;
    const BURST: usize = 5;
    // The same list the in-sandbox rules scan command lines for, so the two
    // feeds never disagree about what counts as a metadata endpoint.
    use agent_core::rules::METADATA_HOSTS as METADATA;

    // Subscribed here, not inside the task: a broadcast receiver only sees what
    // is sent after it exists, and the caller sends as soon as this returns.
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        let mut denies: std::collections::HashMap<String, Vec<i64>> = Default::default();
        let mut burst_reported: std::collections::HashMap<String, i64> = Default::default();
        while let Ok(e) = rx.recv().await {
            if !matches!(e.r#type, EventType::EgressAllow | EventType::EgressDeny) {
                continue;
            }
            let corr = Corr { pi_session: e.pi_session.clone(), tool_call_id: e.tool_call_id.clone() };
            let host = e.data["host"].as_str().unwrap_or("").to_string();
            let alert = |rule: &str, sev: proto::Severity, msg: String, data: serde_json::Value| {
                let mut d = serde_json::json!({"severity": sev, "rule": rule, "msg": msg});
                d.as_object_mut().unwrap().insert("evidence".into(), data);
                let _ = bus.send(new_event(&host_id, &e.sandbox_id, &corr, EventType::SecurityAlert, d));
            };

            if METADATA.iter().any(|m| host.contains(m)) {
                alert(
                    proto::rules::METADATA_PROBE,
                    proto::Severity::High,
                    format!("attempt to reach the cloud metadata endpoint {host}"),
                    e.data.clone(),
                );
            }
            if e.r#type != EventType::EgressDeny {
                continue;
            }
            let now = now_ms();
            let v = denies.entry(e.sandbox_id.clone()).or_default();
            v.push(now);
            v.retain(|t| now - *t <= WINDOW_MS);
            let last = burst_reported.get(&e.sandbox_id).copied().unwrap_or(0);
            if v.len() >= BURST && now - last > WINDOW_MS {
                burst_reported.insert(e.sandbox_id.clone(), now);
                alert(
                    proto::rules::EGRESS_DENY_BURST,
                    proto::Severity::Medium,
                    format!("{} egress denials in {}s", v.len(), WINDOW_MS / 1000),
                    serde_json::json!({"count": v.len(), "last_host": host}),
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A batch the control plane refuses must come back, in order, and the cap
    /// must drop the *oldest* — the ones an operator has already stopped caring
    /// about — rather than refusing to take the newest.
    #[test]
    fn the_spool_replays_in_order_and_forgets_the_oldest_first() {
        let dir = std::env::temp_dir().join(format!("sbx-spool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("events.spool");

        for b in [&b"[1]"[..], b"[2]", b"[3]"] {
            assert_eq!(spool_push(&path, b).unwrap(), 0, "nothing near the cap yet");
        }
        assert_eq!(spool_take(&path), vec![b"[1]".to_vec(), b"[2]".to_vec(), b"[3]".to_vec()]);
        assert!(spool_take(&path).is_empty(), "taking it empties the file");

        // Over the cap: the front goes, the newest batch stays.
        let big = vec![b'x'; (SPOOL_CAP / 4) as usize];
        let mut dropped = 0;
        for _ in 0..6 {
            dropped += spool_push(&path, &big).unwrap();
        }
        assert!(dropped > 0, "the cap has to bite");
        let held = spool_take(&path);
        assert!(!held.is_empty() && held.iter().all(|b| b.len() == big.len()), "{} batches", held.len());
        assert!(
            held.iter().map(|b| b.len() as u64 + 1).sum::<u64>() <= SPOOL_CAP,
            "what is left must be under the cap",
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An idle host retries its spool on its own clock: with nothing new to
    /// piggyback a replay on, the tick is the only thing that can drain it, and
    /// a tick must not go at a spool that is not there.
    #[test]
    fn an_idle_tick_retries_the_spool_on_its_own() {
        assert!(!retry_due(0, true), "not on every tick");
        assert!(!retry_due(SPOOL_RETRY_TICKS - 1, true));
        assert!(retry_due(SPOOL_RETRY_TICKS, true), "an idle host must get there by itself");
        assert!(retry_due(SPOOL_RETRY_TICKS + 5, true));
        assert!(!retry_due(SPOOL_RETRY_TICKS, false), "nothing spooled, nothing to do");
    }

    /// The replay itself, against a control plane that is back: everything held
    /// back is delivered, in the order it was spooled, and the file goes.
    #[tokio::test]
    async fn a_reachable_control_plane_drains_the_whole_spool() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let got: Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        // How many more posts this control plane will take before it "goes away".
        let allow = Arc::new(AtomicUsize::new(0));
        let (g, r) = (got.clone(), allow.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/api/events",
                axum::routing::post(move |b: axum::body::Bytes| {
                    let (g, r) = (g.clone(), r.clone());
                    async move {
                        if r.load(Ordering::SeqCst) == 0 {
                            return axum::http::StatusCode::SERVICE_UNAVAILABLE;
                        }
                        r.fetch_sub(1, Ordering::SeqCst);
                        g.lock().unwrap().push(String::from_utf8_lossy(&b).into_owned());
                        axum::http::StatusCode::NO_CONTENT
                    }
                }),
            );
            axum::serve(l, app).await.unwrap()
        });

        let dir = std::env::temp_dir().join(format!("sbx-spool-drain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let spool = dir.join("events.spool");
        for b in [&b"[{\"a\":1}]"[..], b"[{\"a\":2}]", b"[{\"a\":3}]"] {
            spool_push(&spool, b).unwrap();
        }
        let (url, http, m) =
            (format!("http://127.0.0.1:{port}/api/events"), http_client(), crate::metrics::Metrics::new());

        // Away again after the first batch: the rest must go back, in order.
        allow.store(1, Ordering::SeqCst);
        replay_spool(&http, &url, "t", &spool, &m).await;
        assert_eq!(got.lock().unwrap().as_slice(), [r#"[{"a":1}]"#]);
        assert_eq!(spool_take(&spool), vec![b"[{\"a\":2}]".to_vec(), b"[{\"a\":3}]".to_vec()]);
        for b in [&b"[{\"a\":2}]"[..], b"[{\"a\":3}]"] {
            spool_push(&spool, b).unwrap();
        }

        // Back for good: the whole spool goes, oldest first, and the file with it.
        allow.store(100, Ordering::SeqCst);
        replay_spool(&http, &url, "t", &spool, &m).await;
        assert_eq!(
            got.lock().unwrap().as_slice(),
            [r#"[{"a":1}]"#, r#"[{"a":2}]"#, r#"[{"a":3}]"#],
            "delivered in the order they were spooled",
        );
        assert!(!spool.exists(), "and nothing is left holding it");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn timestamps_match_the_protocol_shape() {
        assert_eq!(rfc3339_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_millis(1_757_325_600_123), "2025-09-08T10:00:00.123Z");
    }

    /// Five denials inside the window raise exactly one burst alert, and a
    /// metadata host raises its own regardless of the decision.
    #[tokio::test]
    async fn egress_rules_fire_once_per_burst() {
        let bus = bus();
        spawn_egress_rules(bus.clone(), "h".into());
        let mut rx = bus.subscribe();
        let deny = |host: &str| {
            new_event(
                "h",
                "sbx_1",
                &Corr::default(),
                EventType::EgressDeny,
                serde_json::json!({"host": host, "port": 443, "bytes": 0}),
            )
        };
        for _ in 0..6 {
            let _ = bus.send(deny("evil.example"));
        }
        let _ = bus.send(deny("169.254.169.254"));

        let mut bursts = 0;
        let mut metadata = 0;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await {
                Ok(Ok(e)) if e.r#type == EventType::SecurityAlert => match e.data["rule"].as_str() {
                    Some("egress.deny_burst") => bursts += 1,
                    Some("metadata.probe") => metadata += 1,
                    _ => {}
                },
                Ok(Ok(_)) => {}
                _ => break,
            }
        }
        assert_eq!(bursts, 1, "one alert per burst, not one per denial");
        assert_eq!(metadata, 1);
    }
}
