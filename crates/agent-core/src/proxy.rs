//! `ANY /proxy/{port}/{*rest}` — what a preview URL ends up talking to
//! (protocol §3a "Preview"). Reverse-proxies to `127.0.0.1:{port}` inside the
//! sandbox, HTTP and WebSocket, streaming bodies both ways.
//!
//! Nothing is rewritten except `Host`: a dev server that emits absolute URLs is
//! the caller's problem, not ours. Same shape as qafas's `agent_http`/
//! `agent_ws`, one hop further in.

use std::sync::Arc;

use axum::extract::ws::{Message as AxMsg, WebSocket};
use axum::extract::{FromRequestParts, Request, WebSocketUpgrade};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::{SinkExt, StreamExt};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as TgMsg;

use crate::Ctx;

/// `/proxy/8080/a/b?q=1` → `(8080, "/a/b?q=1")`. The path is passed on verbatim,
/// so a server mounted at `/` sees `/a/b`.
fn split(uri: &axum::http::Uri) -> Option<(u16, String)> {
    let rest = uri.path().strip_prefix("/proxy/")?;
    let (port, path) = match rest.split_once('/') {
        Some((p, r)) => (p, format!("/{r}")),
        None => (rest, "/".to_string()),
    };
    let port: u16 = port.parse().ok()?;
    Some(match uri.query() {
        Some(q) => (port, format!("{path}?{q}")),
        None => (port, path),
    })
}

fn refused(port: u16) -> Response {
    (StatusCode::BAD_GATEWAY, Json(json!({"error": format!("nothing listening on 127.0.0.1:{port}")}))).into_response()
}

/// What authenticates the *caller* to qafas must never reach a server the
/// agent itself wrote: a dev server on `127.0.0.1:3000` would otherwise read the
/// scoped bearer token (or the preview cookie) off every proxied request and
/// exfiltrate it through any allowlisted host. The correlation and client
/// headers (`x-pi-session`, `x-tool-call-id`, `x-sbx-*`) are ours too: the guest
/// gets them on the agent routes, not through the preview hop — and `x-sbx-*`
/// is what carries the per-sandbox `X-Sbx-Agent-Token`, which a dev server must
/// never see.
/// Other cookies belong to the dev server and are left alone.
pub fn strip_client_auth(h: &mut axum::http::HeaderMap) {
    h.remove(header::AUTHORIZATION);
    h.remove(header::PROXY_AUTHORIZATION);
    h.remove(proto::HDR_PI_SESSION);
    h.remove(proto::HDR_TOOL_CALL_ID);
    let ours: Vec<_> = h.keys().filter(|n| n.as_str().starts_with("x-sbx-")).cloned().collect();
    for n in ours {
        h.remove(n);
    }
    let Some(cookie) = h.get(header::COOKIE).and_then(|v| v.to_str().ok()) else { return };
    let kept = cookie
        .split(';')
        .filter(|c| !c.trim_start().starts_with("sbx_preview_"))
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    match kept.parse() {
        Ok(v) if !kept.is_empty() => {
            h.insert(header::COOKIE, v);
        }
        _ => {
            h.remove(header::COOKIE);
        }
    }
}

fn is_websocket(req: &Request) -> bool {
    req.headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

pub async fn proxy(axum::extract::State(_ctx): axum::extract::State<Arc<Ctx>>, req: Request) -> Response {
    let Some((port, pq)) = split(req.uri()) else {
        return (StatusCode::BAD_REQUEST, "expected /proxy/{port}/...").into_response();
    };
    if is_websocket(&req) {
        return upgrade_ws(port, pq, req).await;
    }
    let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await else {
        return refused(port);
    };
    let handshake = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await;
    let (mut sender, conn) = match handshake {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let (mut parts, body) = req.into_parts();
    parts.uri = match pq.parse() {
        Ok(u) => u,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("{e}")).into_response(),
    };
    if let Ok(h) = format!("127.0.0.1:{port}").parse() {
        parts.headers.insert(header::HOST, h);
    }
    strip_client_auth(&mut parts.headers);
    match sender.send_request(Request::from_parts(parts, body)).await {
        Ok(r) => r.map(axum::body::Body::new).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

/// The upgrade path. axum answers the client's handshake for us; we open our own
/// to the guest server and shuttle frames.
async fn upgrade_ws(port: u16, pq: String, req: Request) -> Response {
    let (mut parts, _) = req.into_parts();
    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(w) => w,
        Err(e) => return e.into_response(),
    };
    // Refuse early, while we can still answer with a status instead of a
    // half-open socket.
    let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await else {
        return refused(port);
    };
    let mut request = match tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(format!(
        "ws://127.0.0.1:{port}{pq}"
    )) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    // Everything but the hop-by-hop handshake headers is the client's.
    for (k, v) in parts.headers.iter() {
        let n = k.as_str();
        if n.starts_with("sec-websocket-") || n == "host" || n == "connection" || n == "upgrade" {
            continue;
        }
        request.headers_mut().insert(k, v.clone());
    }
    strip_client_auth(request.headers_mut());
    let upstream = match tokio_tungstenite::client_async(request, stream).await {
        Ok((s, _)) => s,
        Err(e) => return (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    };
    ws.on_upgrade(move |client| relay(client, upstream))
}

pub(crate) async fn relay<S>(client: WebSocket, upstream: tokio_tungstenite::WebSocketStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut cw, mut cr) = client.split();
    let (mut uw, mut ur) = upstream.split();
    let c2u = async {
        while let Some(Ok(m)) = cr.next().await {
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
        while let Some(Ok(m)) = ur.next().await {
            let out = match m {
                TgMsg::Text(t) => AxMsg::Text(t.as_str().into()),
                TgMsg::Binary(b) => AxMsg::Binary(b),
                TgMsg::Ping(b) => AxMsg::Ping(b),
                TgMsg::Pong(b) => AxMsg::Pong(b),
                TgMsg::Close(_) | TgMsg::Frame(_) => break,
            };
            if cw.send(out).await.is_err() {
                break;
            }
        }
        let _ = cw.close().await;
    };
    tokio::join!(c2u, u2c);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_port_and_path() {
        let u = |s: &str| s.parse::<axum::http::Uri>().unwrap();
        assert_eq!(split(&u("/proxy/8080/a/b")), Some((8080, "/a/b".into())));
        assert_eq!(split(&u("/proxy/8080/")), Some((8080, "/".into())));
        assert_eq!(split(&u("/proxy/8080")), Some((8080, "/".into())));
        assert_eq!(split(&u("/proxy/8080/x?q=1&r=2")), Some((8080, "/x?q=1&r=2".into())));
        assert_eq!(split(&u("/proxy/notaport/x")), None);
        assert_eq!(split(&u("/exec")), None);
    }

    #[test]
    fn client_credentials_do_not_cross_into_the_sandbox() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer scoped".parse().unwrap());
        h.insert(proto::HDR_PI_SESSION, "sess".parse().unwrap());
        h.insert(proto::HDR_AGENT_TOKEN, "s3cret".parse().unwrap());
        h.insert(header::COOKIE, "sbx_preview_sbx_a_3000=tok; theirs=1".parse().unwrap());
        h.insert(header::ACCEPT, "text/html".parse().unwrap());
        strip_client_auth(&mut h);
        assert!(h.get(header::AUTHORIZATION).is_none());
        assert!(h.get(proto::HDR_PI_SESSION).is_none());
        assert!(h.get(proto::HDR_AGENT_TOKEN).is_none());
        assert_eq!(h.get(header::COOKIE).unwrap(), "theirs=1");
        assert_eq!(h.get(header::ACCEPT).unwrap(), "text/html");
        // A request whose only cookie was ours loses the header entirely.
        let mut h = axum::http::HeaderMap::new();
        h.insert(header::COOKIE, "sbx_preview_sbx_a_3000=tok".parse().unwrap());
        strip_client_auth(&mut h);
        assert!(h.get(header::COOKIE).is_none());
    }

    /// A real server on a real port, reached through the real router.
    #[tokio::test]
    async fn proxies_to_a_server_in_the_guest_and_reports_a_dead_port() {
        use crate::rules::Rules;
        use crate::spawn::Hardened;
        use crate::Emitter;

        let ctx = crate::Ctx::new(Hardened::default(), Emitter::null(), Rules::guest("/tmp", "/tmp/nohome"));
        let app = crate::router(ctx);
        let front = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_port = front.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(front, app).await.unwrap() });

        // The "app inside the sandbox".
        let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let back_port = back.local_addr().unwrap().port();
        tokio::spawn(async move {
            let inner = axum::Router::new()
                .route("/", axum::routing::get(|| async { "index" }))
                .route("/echo", axum::routing::post(|b: String| async move { b }))
                // What the "dev server the agent wrote" gets to see.
                .route(
                    "/hdr",
                    axum::routing::get(|h: axum::http::HeaderMap| async move {
                        let g = |n: &str| h.get(n).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
                        format!("{}|{}|{}", g("authorization"), g("cookie"), g("x-sbx-session"))
                    }),
                );
            axum::serve(back, inner).await.unwrap()
        });

        let get = |url: String| async move {
            let s = TcpStream::connect(("127.0.0.1", front_port)).await.unwrap();
            let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(s)).await.unwrap();
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let req = Request::builder()
                .uri(url)
                .header("host", "x")
                .header("authorization", "Bearer scoped")
                .header("cookie", "sbx_preview_a_1=tok; theirs=1")
                .header("x-sbx-session", "sess")
                .body(axum::body::Body::empty())
                .unwrap();
            let r = send.send_request(req).await.unwrap();
            let st = r.status();
            let b = axum::body::to_bytes(axum::body::Body::new(r.into_body()), 1 << 20).await.unwrap();
            (st, String::from_utf8_lossy(&b).into_owned())
        };

        assert_eq!(get(format!("/proxy/{back_port}/")).await, (StatusCode::OK, "index".to_string()));
        assert_eq!(get(format!("/proxy/{back_port}/hdr")).await.1, "-|theirs=1|-");
        let (st, body) = get("/proxy/1/".to_string()).await;
        assert_eq!(st, StatusCode::BAD_GATEWAY);
        assert!(body.contains("nothing listening on 127.0.0.1:1"), "{body}");
    }
}
