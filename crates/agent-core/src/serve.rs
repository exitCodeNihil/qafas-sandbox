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
    // Subscribed before the 101 goes out, so an event emitted by a command the
    // client runs right after connecting is never missed.
    let mut rx = bus.subscribe();
    ws.on_upgrade(move |mut sock| async move {
        loop {
            let ev = match rx.recv().await {
                Ok(ev) => ev,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(dropped = n, "events stream lagged");
                    continue;
                }
                Err(_) => break,
            };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rules;
    use crate::spawn::Hardened;
    use futures_util::StreamExt;
    use proto::EventType;
    use std::future::IntoFuture;

    fn ev(n: usize) -> Event {
        Event {
            id: n.to_string(),
            ts: String::new(),
            host_id: "h".into(),
            sandbox_id: "s".into(),
            pi_session: String::new(),
            tool_call_id: String::new(),
            r#type: EventType::SandboxUsage,
            data: serde_json::Value::Null,
        }
    }

    async fn next_id<S>(ws: &mut S) -> String
    where
        S: futures_util::Stream<
                Item = Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>,
            > + Unpin,
    {
        loop {
            let m = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next()).await.unwrap().unwrap().unwrap();
            if let tokio_tungstenite::tungstenite::Message::Text(t) = m {
                return serde_json::from_str::<Event>(t.as_str()).unwrap().id;
            }
        }
    }

    #[tokio::test]
    async fn events_ws_subscribes_before_the_101_and_survives_lag() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let ctx = Ctx::new(Hardened::default(), Emitter::null(), Rules::guest("/tmp", "/tmp/nohome"));
        let bus = bus();
        // The upgrade task runs after the 101 is written, so a late subscribe
        // is a race a loopback client rarely loses; look at the bus the moment
        // the handler returns its response instead.
        let seen = Arc::new(AtomicUsize::new(usize::MAX));
        let (b, s) = (bus.clone(), seen.clone());
        let router =
            app(ctx, bus.clone()).layer(axum::middleware::from_fn(move |req, next: axum::middleware::Next| {
                let (b, s) = (b.clone(), s.clone());
                async move {
                    let r = next.run(req).await;
                    s.store(b.receiver_count(), SeqCst);
                    r
                }
            }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(axum::serve(l, router).into_future());
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/events/ws")).await.unwrap();
        assert_eq!(seen.load(SeqCst), 1, "subscribed before the upgrade response");
        let _ = bus.send(ev(0));
        assert_eq!(next_id(&mut ws).await, "0");
        // Overrun the 1024-slot bus before the socket task gets a turn: the
        // stream must skip the gap, not end.
        for i in 1..=1500 {
            let _ = bus.send(ev(i));
        }
        let _ = bus.send(ev(9999));
        loop {
            if next_id(&mut ws).await == "9999" {
                break;
            }
        }
    }
}
