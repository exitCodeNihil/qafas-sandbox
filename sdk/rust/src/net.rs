//! HTTP(S) and WebSocket(S) plumbing: hyper's legacy client for requests, a hand-made
//! rustls connect for `ws://`/`wss://` (tokio-tungstenite is used without its TLS features, so
//! both transports share one `ClientConfig` and `SBX_CA_FILE` is honoured by both).

use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderName, http::HeaderValue};
use tokio_tungstenite::WebSocketStream;

use crate::{Error, Result};

pub(crate) type Headers = Vec<(String, String)>;

pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(crate) type Ws = WebSocketStream<Box<dyn Io>>;

pub(crate) struct Transport {
    http: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    tls: Arc<ClientConfig>,
}

/// System roots plus, when set, the PEM at `ca_file` (`SBX_CA_FILE`: the internal CA an https
/// control plane or worker chains to). A `ca_file` that cannot be read or holds no certificate
/// is an error, not an empty trust store.
fn tls_config(ca_file: Option<&str>) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    // ponytail: an unreadable OS store only costs the system roots; SBX_CA_FILE still works.
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if let Some(ca) = ca_file {
        let pem = std::fs::read(ca).map_err(|e| Error::Transport(format!("reading SBX_CA_FILE {ca}: {e}")))?;
        let (added, _) = roots.add_parsable_certificates(CertificateDer::pem_slice_iter(&pem).filter_map(|c| c.ok()));
        if added == 0 {
            return Err(Error::Transport(format!("SBX_CA_FILE {ca} holds no usable certificate")));
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Transport(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

impl Transport {
    pub(crate) fn new(ca_file: Option<&str>) -> Result<Transport> {
        let tls = tls_config(ca_file.filter(|c| !c.is_empty()))?;
        let https = HttpsConnectorBuilder::new().with_tls_config(tls.clone()).https_or_http().enable_http1().build();
        Ok(Transport { http: Client::builder(TokioExecutor::new()).build(https), tls: Arc::new(tls) })
    }

    /// One request; returns the status and the whole body whatever the status is.
    pub(crate) async fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>)> {
        let mut b = hyper::Request::builder().method(method).uri(url);
        for (k, v) in headers {
            b = b.header(k, v);
        }
        let req = b
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .map_err(|e| Error::Transport(format!("{method} {url}: {e}")))?;
        let resp = self.http.request(req).await.map_err(|e| Error::Transport(format!("{method} {url}: {e}")))?;
        let status = resp.status().as_u16();
        let data = resp.into_body().collect().await.map_err(|e| Error::Transport(format!("{method} {url}: {e}")))?;
        Ok((status, data.to_bytes().to_vec()))
    }

    pub(crate) async fn ws_connect(&self, url: &str, headers: &[(String, String)]) -> Result<Ws> {
        let t = |e: &dyn std::fmt::Display| Error::Transport(format!("websocket {url}: {e}"));
        let uri: hyper::Uri = url.parse().map_err(|e| t(&e))?;
        let tls = match uri.scheme_str() {
            Some("wss") => true,
            Some("ws") => false,
            _ => return Err(t(&"expected a ws:// or wss:// URL")),
        };
        let host = uri.host().ok_or_else(|| t(&"no host"))?.trim_matches(['[', ']']).to_owned();
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
        let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await.map_err(|e| t(&e))?;
        let stream: Box<dyn Io> = if tls {
            let name = ServerName::try_from(host.clone()).map_err(|e| t(&e))?;
            Box::new(tokio_rustls::TlsConnector::from(self.tls.clone()).connect(name, tcp).await.map_err(|e| t(&e))?)
        } else {
            Box::new(tcp)
        };
        let mut req = url.into_client_request().map_err(|e| t(&e))?;
        for (k, v) in headers {
            let name = HeaderName::from_bytes(k.as_bytes()).map_err(|e| t(&e))?;
            req.headers_mut().insert(name, HeaderValue::from_str(v).map_err(|e| t(&e))?);
        }
        match tokio_tungstenite::client_async(req, stream).await {
            Ok((ws, _)) => Ok(ws),
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
                let body = resp.body().clone().unwrap_or_default();
                Err(Error::http(resp.status().as_u16(), &body))
            }
            Err(e) => Err(t(&e)),
        }
    }
}

/// The process-wide transport, built from `SBX_CA_FILE` on first use.
// ponytail: the env is read once per process (the Python SDK re-reads it per call); build a
// Transport per Sandbox if a process ever needs two CAs.
pub(crate) fn transport() -> Result<Arc<Transport>> {
    static T: OnceLock<Arc<Transport>> = OnceLock::new();
    if let Some(t) = T.get() {
        return Ok(t.clone());
    }
    let t = Arc::new(Transport::new(std::env::var("SBX_CA_FILE").ok().as_deref())?);
    Ok(T.get_or_init(|| t).clone())
}

/// `http://h` -> `ws://h`, `https://h` -> `wss://h` (the first `http` only, like the Python SDK).
pub(crate) fn to_ws(url: &str) -> String {
    url.replacen("http", "ws", 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    #[test]
    fn http_becomes_ws_and_https_wss() {
        assert_eq!(to_ws("http://h:1/x"), "ws://h:1/x");
        assert_eq!(to_ws("https://h/x/http"), "wss://h/x/http");
    }

    #[test]
    fn a_ca_file_with_no_certificate_is_an_error() {
        assert!(tls_config(Some("/nonexistent/ca.pem")).is_err());
        let p = std::env::temp_dir().join(format!("qafas-sdk-badca-{}.pem", std::process::id()));
        std::fs::write(&p, "not a certificate").unwrap();
        assert!(tls_config(p.to_str()).is_err());
        let _ = std::fs::remove_file(&p);
    }

    /// SBX_CA_FILE is trusted for https and for wss: a self-signed server answers a GET and
    /// echoes one WebSocket frame, and a client without that CA is refused.
    #[tokio::test]
    async fn sbx_ca_file_is_trusted_for_https_and_wss() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ca = std::env::temp_dir().join(format!("qafas-sdk-ca-{}.pem", std::process::id()));
        std::fs::write(&ca, ck.cert.pem()).unwrap();

        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(ck.signing_key.serialize_pem().as_bytes()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![ck.cert.der().clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            // First connection: plain HTTP/1.1 over TLS. Second: a WebSocket echo. Third: the
            // untrusting client, which never completes the handshake.
            for i in 0..3 {
                let (tcp, _) = listener.accept().await.unwrap();
                let Ok(mut tls) = acceptor.accept(tcp).await else { continue };
                if i == 0 {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 1024];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok").await;
                    let _ = tls.shutdown().await;
                } else {
                    let mut ws = tokio_tungstenite::accept_async(tls).await.unwrap();
                    let m = ws.next().await.unwrap().unwrap();
                    ws.send(m).await.unwrap();
                }
            }
        });

        let tp = Transport::new(ca.to_str()).unwrap();
        let (status, body) = tp.send("GET", &format!("https://localhost:{port}/healthz"), &[], None).await.unwrap();
        assert_eq!((status, body.as_slice()), (200, &b"ok"[..]));

        let mut ws = tp
            .ws_connect(&format!("wss://localhost:{port}/events/ws"), &[("authorization".into(), "Bearer t".into())])
            .await
            .unwrap();
        ws.send(Message::Text("ping".into())).await.unwrap();
        assert_eq!(ws.next().await.unwrap().unwrap().into_text().unwrap().as_str(), "ping");

        // Without the CA the self-signed certificate is rejected.
        assert!(Transport::new(None).unwrap().ws_connect(&format!("wss://localhost:{port}/x"), &[]).await.is_err());
        let _ = std::fs::remove_file(&ca);
    }
}
