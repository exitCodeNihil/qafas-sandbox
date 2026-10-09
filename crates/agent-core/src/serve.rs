//! The serving half shared by the two places the handlers run: guest-agent
//! (TCP/vsock inside a VM or container) and qafas's native-tier shim (a unix
//! socket, wrapped once in the OS sandbox). Same router, same `/events/ws` feed
//! that qafas drains, same event bus.

use std::sync::Arc;

use axum::extract::ws::Message;
use axum::extract::{State, WebSocketUpgrade};
use axum::routing::get;
use axum::Router;
use proto::Event;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;

use crate::{Ctx, Emitter};

/// Events the sandbox observes about itself. qafas subscribes over the same
/// connector it uses for `/exec`, republishes them with the host id filled in,
/// and forwards to the control plane. The frames are plain `Event`s.
pub type Bus = broadcast::Sender<Event>;

pub fn bus() -> Bus {
    broadcast::channel(1024).0
}

pub fn emitter(bus: &Bus, host_id: &str, sandbox_id: &str) -> Emitter {
    let sink = bus.clone();
    Emitter::new(
        host_id,
        sandbox_id,
        Arc::new(move |e| {
            let _ = sink.send(e);
        }),
    )
}

async fn events_ws(State(bus): State<Bus>, ws: WebSocketUpgrade) -> axum::response::Response {
    ws.on_upgrade(move |mut sock| async move {
        let mut rx = bus.subscribe();
        while let Ok(ev) = rx.recv().await {
            let Ok(txt) = serde_json::to_string(&ev) else { continue };
            if sock.send(Message::Text(txt.into())).await.is_err() {
                break;
            }
        }
    })
}

/// The protocol §2 router plus `/events/ws`.
pub fn app(ctx: Arc<Ctx>, bus: Bus) -> Router {
    crate::router(ctx).merge(Router::new().route("/events/ws", get(events_ws)).with_state(bus))
}

/// Serves one accepted connection of any stream type (vsock, unix) with HTTP/1
/// upgrades, which is what keeps `/exec/ws`, `/events/ws` and `/browser/cdp`
/// working where `axum::serve` cannot be used.
pub async fn serve_stream<S>(stream: S, app: Router)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::service::TowerToHyperService;
    let svc = TowerToHyperService::new(app);
    if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(TokioIo::new(stream), svc)
        .await
    {
        tracing::debug!(error = %e, "connection ended");
    }
}
