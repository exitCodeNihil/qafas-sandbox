//! The listener: vsock :7777 when the guest has a vsock device (Firecracker),
//! TCP :7777 otherwise (podman, where the port is published on the host's
//! loopback). Exactly one of the two: on vsock reachability *is* the boundary
//! (protocol §2), and a TCP listener alongside it would make the microVM's root
//! agent reachable from inside the sandbox. The published TCP port cannot be
//! closed that way, so there `SBX_AGENT_TOKEN` is set and `agent_core::guard`
//! demands `X-Sbx-Agent-Token` on every route but `/healthz`.

use std::sync::Arc;

use agent_core::serve::{self, Bus};
use agent_core::{rules::Rules, spawn::Hardened, Ctx};
use axum::Router;

fn env(k: &str, d: &str) -> String {
    std::env::var(k).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| d.to_string())
}

/// `sbx.id=` off the kernel command line, for the Firecracker path where there
/// is no container environment to carry it.
fn cmdline_id() -> Option<String> {
    let c = std::fs::read_to_string("/proc/cmdline").ok()?;
    c.split_ascii_whitespace().find_map(|t| t.strip_prefix("sbx.id=")?.into()).map(str::to_string)
}

fn build() -> (Arc<Ctx>, Bus) {
    let bus = serve::bus();
    let sandbox_id = std::env::var("SBX_ID").ok().filter(|s| !s.is_empty()).or_else(cmdline_id);
    let ev = serve::emitter(&bus, &env("SBX_HOST_ID", ""), &sandbox_id.unwrap_or_default());
    let home = env("HOME", "/home/agent");
    Rules::plant_canaries(&home, &env("SBX_ID", "unknown"));
    let rules = Rules::guest(&env("SBX_WORKSPACE", &home), &home);
    (Ctx::new(Hardened::default(), ev, rules), bus)
}

/// `POST /restored` (protocol §3a). Not in `agent-core`: the native tier and the
/// podman tier have nothing to restore, and none of what it does is possible
/// without being PID 1 as root.
async fn restored(body: axum::body::Bytes) -> axum::response::Response {
    use axum::response::IntoResponse;
    if !crate::init::can_restore() {
        return (
            axum::http::StatusCode::CONFLICT,
            axum::Json(serde_json::json!({"error": "restore needs PID 1 as root"})),
        )
            .into_response();
    }
    match serde_json::from_slice::<crate::init::RestoredReq>(&body) {
        Ok(req) => {
            crate::init::restored(&req);
            axum::http::StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": e.to_string()})))
            .into_response(),
    }
}

pub async fn run() -> anyhow::Result<()> {
    let (ctx, bus) = build();
    // The guard wraps `/restored` too, so it goes on after every route is in.
    let app = agent_core::guard(
        serve::app(ctx, bus).route("/restored", axum::routing::post(restored)),
        agent_core::agent_token(),
    );
    let port = proto::GUEST_AGENT_PORT;

    // Firecracker: vsock is the only way in, so bind nothing else. The TCP
    // listener would sit on the guest's own loopback, unauthenticated, served by
    // a PID 1 that is root — while execs drop to uid 1000. Anything the sandbox
    // ran could then `PUT /fs/write` as root and undo the uid drop, the canaries
    // and procmon (docs/security.md M35).
    if std::path::Path::new("/dev/vsock").exists() {
        return serve_vsock(app, port.into()).await;
    }

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!(port, "guest-agent listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn serve_vsock(app: Router, port: u32) -> anyhow::Result<()> {
    let listener = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, port))?;
    tracing::info!(port, "vsock listening");
    loop {
        let (stream, _peer) = listener.accept().await?;
        tokio::spawn(serve::serve_stream(stream, app.clone()));
    }
}
