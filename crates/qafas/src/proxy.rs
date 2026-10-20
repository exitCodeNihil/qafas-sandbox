//! `qafas proxy` — the only way out of a sandbox (D7).
//!
//! Deny by default: the host must match a glob in `policy/egress.json` *and*
//! every address it resolves to must be public — or, v5.3, inside one of the
//! host file's `allow_private_cidrs` (an internal mirror). The sandbox has no resolver of
//! its own, so name resolution happens here, on the allowed side of the
//! boundary, and DNS tunnelling has nothing to tunnel through.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use futures_util::future::BoxFuture;
use http_body_util::{BodyExt, Full};
use proto::{EgressPolicy, EventType};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wildmatch::WildMatch;

use crate::events::{http_client, new_event, now_rfc3339, Corr, HttpClient};

const MAX_HEADERS: usize = 64 * 1024;

pub struct Policy {
    allow: Vec<WildMatch>,
    /// One sandbox's own `egress_allow` (D22), kept apart from the host file's
    /// so `egress.allow` can say which list let a name through.
    extra: Vec<WildMatch>,
    deny_extra: Vec<(IpAddr, u8)>,
    /// Host-file only (`allow_private_cidrs`): internal mirrors an allowed name
    /// may resolve into. Never filled from a create request.
    allow_private: Vec<(IpAddr, u8)>,
}

pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    match s.split_once('/') {
        Some((ip, len)) => Some((ip.parse().ok()?, len.parse().ok()?)),
        None => {
            let ip: IpAddr = s.parse().ok()?;
            Some((ip, if ip.is_ipv4() { 32 } else { 128 }))
        }
    }
}

fn in_cidr(ip: IpAddr, (net, len): (IpAddr, u8)) -> bool {
    let (a, b) = match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (a.octets().to_vec(), b.octets().to_vec()),
        (IpAddr::V6(a), IpAddr::V6(b)) => (a.octets().to_vec(), b.octets().to_vec()),
        _ => return false,
    };
    let (whole, bits) = (len as usize / 8, len as usize % 8);
    if a[..whole] != b[..whole] {
        return false;
    }
    bits == 0 || (a[whole] ^ b[whole]) >> (8 - bits) == 0
}

/// Denied whatever the allowlist says: anything that is not a public address
/// (protocol §6). `169.254.169.254` is covered by link-local.
pub fn is_private_v4(a: Ipv4Addr) -> bool {
    a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_unspecified()
        || a.is_broadcast()
        || a.is_multicast()
        || a.octets()[0] == 0
        // 100.64.0.0/10, carrier-grade NAT — a cloud metadata neighbourhood.
        || (a.octets()[0] == 100 && (64..128).contains(&a.octets()[1]))
}

/// The private ranges `allow_private_cidrs` can open: RFC1918 and IPv6
/// unique-local, where an internal package mirror lives. Never loopback,
/// link-local (the metadata endpoint), CGNAT (100.100.100.200 is a metadata
/// endpoint too), unspecified, broadcast or multicast, whatever the list says.
fn openable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private(),
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => v4.is_private(),
            None => (a.segments()[0] & 0xfe00) == 0xfc00,
        },
    }
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => is_private_v4(a),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_private_v4(v4);
            }
            // Forms that carry an IPv4 address are judged by the one inside: an
            // allowed name whose AAAA record is `64:ff9b::a9fe:a9fe` reaches the
            // metadata endpoint on a host with NAT64. Covered: NAT64 `64:ff9b::/96`,
            // the deprecated IPv4-compatible `::/96` and 6to4 `2002::/16`. Teredo
            // (`2001::/32`) and the local-use NAT64 prefix (`64:ff9b:1::/48`) are refused
            // outright, since nothing here has a use for them.
            let s = a.segments();
            let embedded = |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] || s[..6] == [0; 6] {
                return is_private_v4(embedded(s[6], s[7]));
            }
            if s[0] == 0x2002 {
                return is_private_v4(embedded(s[1], s[2]));
            }
            if (s[0] == 0x2001 && s[1] == 0) || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1) {
                return true;
            }
            a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                // fc00::/7 covers the fd00::/8 unique-local range.
                || (a.segments()[0] & 0xfe00) == 0xfc00
                || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

impl Policy {
    /// Extra allow globs for one sandbox, from `egress_allow` on the create
    /// request. They come from harness configuration, never from the model
    /// (D22), and they never widen the private-address deny list.
    pub fn with_extra(mut self, globs: &[String]) -> Self {
        self.extra.extend(globs.iter().map(|g| WildMatch::new(g)));
        self
    }

    /// `SBX_POLICY_JSON` (the content, which is how the proxy container gets
    /// it) wins over the file at `path`.
    pub fn load(path: &str) -> Self {
        let text = std::env::var("SBX_POLICY_JSON").ok().or_else(|| std::fs::read_to_string(path).ok());
        let p: EgressPolicy = text.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| {
            tracing::warn!(path, "no egress policy readable; denying everything");
            EgressPolicy::default()
        });
        Self::from_policy(&p)
    }

    pub fn from_policy(p: &EgressPolicy) -> Self {
        Self {
            allow: p.allow.iter().map(|g| WildMatch::new(g)).collect(),
            extra: Vec::new(),
            deny_extra: p.deny_cidrs_extra.iter().filter_map(|s| parse_cidr(s)).collect(),
            allow_private: p.allow_private_cidrs.iter().filter_map(|s| parse_cidr(s)).collect(),
        }
    }

    /// `Ok(via)` or `Err(reason)`. Reason lands in the `egress.deny` event,
    /// `via` in the `egress.allow` one: `baseline` when the host file's list
    /// matched, `sandbox` when only the sandbox's own `egress_allow` did.
    pub fn decide(&self, host: &str, ips: &[IpAddr]) -> Result<&'static str, String> {
        self.decide_with(host, ips, &[])
    }

    /// The same, plus the `egress_allow` the shared proxy looked up for its
    /// peer (`PeerInfo`). Names only: the address rules below are the same.
    pub fn decide_with(&self, host: &str, ips: &[IpAddr], peer: &[String]) -> Result<&'static str, String> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let via = if self.allow.iter().any(|g| g.matches(&host)) {
            "baseline"
        } else if self.extra.iter().any(|g| g.matches(&host)) || peer.iter().any(|g| WildMatch::new(g).matches(&host)) {
            "sandbox"
        } else {
            return Err(NOT_LISTED.into());
        };
        if ips.is_empty() {
            return Err("dns resolution failed".into());
        }
        self.check_addresses(ips)?;
        Ok(via)
    }

    /// The address half alone: what a route host (D34), allowed by being one,
    /// is still held to.
    pub fn check_addresses(&self, ips: &[IpAddr]) -> Result<(), String> {
        for ip in ips {
            let opened = openable(*ip) && self.allow_private.iter().any(|c| in_cidr(*ip, *c));
            if is_private(*ip) && !opened {
                return Err(format!("resolves to non-public address {ip}"));
            }
            if self.deny_extra.iter().any(|c| in_cidr(*ip, *c)) {
                return Err(format!("address {ip} in deny_cidrs_extra"));
            }
        }
        Ok(())
    }
}

/// The deny reason for a name no list has: the only one a sandbox's own
/// `egress_allow` can still turn around.
pub const NOT_LISTED: &str = "host not in allowlist";

// ------------------------------------------------------------------ server

/// Where an egress event goes when the proxy runs inside qafas rather than in
/// its own container: straight onto the bus, already attributed.
pub type Emit = Arc<dyn Fn(EventType, serde_json::Value) + Send + Sync>;

/// What the daemon's live table holds for the sandbox behind one peer address.
/// The vm and remote proxies serve every sandbox on the host, so this is how
/// they learn one sandbox's own allowlist (D22) — and its trust.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerInfo {
    /// `egress_allow` from the create request: names on top of the host file's.
    pub egress_allow: Vec<String>,
    pub trust: proto::Trust,
}

/// `peer address -> PeerInfo`, `None` for an address no running sandbox has.
/// The daemon answers from its live table (`AppState::peer_lookup`); the proxy
/// container asks it over the event sink's channel (`http_peer`).
pub type PeerLookup = Arc<dyn Fn(IpAddr) -> BoxFuture<'static, Option<PeerInfo>> + Send + Sync>;

/// How long a connection waits on the daemon's answer before it is decided
/// on the host file alone. Loopback or the container bridge: milliseconds.
const PEER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

pub struct ProxyCtx {
    pub policy: Policy,
    /// The shared proxies' (vm, remote) per-peer lookup. `None` on the native
    /// tier, whose proxy belongs to one sandbox and has its globs in `policy`.
    pub peer: Option<PeerLookup>,
    /// URL to POST events to (the container case), or `None`.
    pub sink: Option<String>,
    /// In-process callback (the native and firecracker cases).
    pub emit: Option<Emit>,
    pub token: String,
    pub host_id: String,
    pub http: HttpClient,
    /// D34: the routes, when the host file has any. `None` is exactly the
    /// proxy without routes.
    pub intercept: Option<Arc<crate::intercept::Intercept>>,
    /// The trust of the one sandbox a native proxy serves; the shared proxies
    /// learn it per peer (`PeerInfo`).
    pub trust: Option<proto::Trust>,
}

impl ProxyCtx {
    pub fn new(policy: Policy, host_id: String, token: String) -> Self {
        Self {
            policy,
            peer: None,
            sink: None,
            emit: None,
            token,
            host_id,
            http: http_client(),
            intercept: None,
            trust: None,
        }
    }

    /// The sandbox behind `ip`, asked of the daemon. Only the shared proxies
    /// have someone to ask.
    pub async fn peer_info(&self, ip: IpAddr) -> Option<PeerInfo> {
        let look = self.peer.as_ref()?;
        tokio::time::timeout(PEER_TIMEOUT, look(ip.to_canonical())).await.ok()?
    }
}

/// The proxy container's lookup: `GET /internal/egress/peer?ip=` on the daemon
/// that receives its events, with the same token and TLS pin as the sink.
pub fn http_peer(sink: &str, http: HttpClient, token: String) -> Option<PeerLookup> {
    let base = sink.strip_suffix("/internal/events")?.to_string();
    Some(Arc::new(move |ip| {
        let (http, token, url) = (http.clone(), token.clone(), format!("{base}/internal/egress/peer?ip={ip}"));
        Box::pin(async move {
            let req = hyper::Request::get(url)
                .header("authorization", format!("Bearer {token}"))
                .body(Full::new(Bytes::new()))
                .ok()?;
            let resp = http.request(req).await.ok()?;
            if !resp.status().is_success() {
                return None;
            }
            serde_json::from_slice(&resp.into_body().collect().await.ok()?.to_bytes()).ok()
        })
    }))
}

/// `peer`: the daemon's own lookup when the proxy runs in its process (the
/// remote tier); `None` derives the HTTP one from `sink` (the container).
/// `intercept` likewise: the daemon's, or `None` for `SBX_ROUTES_JSON`.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    listen: SocketAddr,
    policy: &str,
    sink: Option<String>,
    sink_ca: Option<Vec<u8>>,
    token: String,
    host_id: String,
    peer: Option<PeerLookup>,
    intercept: Option<Arc<crate::intercept::Intercept>>,
) -> anyhow::Result<()> {
    let mut ctx = ProxyCtx::new(Policy::load(policy), host_id, token);
    if let Some(pem) = sink_ca {
        ctx.http = crate::events::http_client_with(crate::tls::pinned_config(&pem)?);
    }
    ctx.peer = peer.or_else(|| http_peer(sink.as_deref()?, ctx.http.clone(), ctx.token.clone()));
    ctx.intercept = match intercept {
        Some(ic) => Some(ic),
        None => crate::intercept::from_env()?,
    };
    ctx.sink = sink;
    let l = TcpListener::bind(listen).await?;
    tracing::info!(%listen, policy, "egress proxy listening");
    serve(l, Arc::new(ctx)).await
}

/// Serves an already-bound listener. The native tier gives every sandbox its own
/// loopback port, which is what makes `egress.*` attributable: the proxy sees
/// 127.0.0.1 from every native sandbox, so the *port* is the identity, not the
/// peer address.
pub async fn serve(l: TcpListener, ctx: Arc<ProxyCtx>) -> anyhow::Result<()> {
    loop {
        let (sock, peer) = l.accept().await?;
        // A relay forwards whatever arrives as it arrives; Nagle would hold a
        // short tail back for the peer's delayed ACK. Both sides, as on the relay.
        let _ = sock.set_nodelay(true);
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, peer, &ctx).await {
                tracing::debug!(error = %e, %peer, "proxy connection ended");
            }
        });
    }
}

/// The relay: a CONNECT tunnel with no policy, for qafas itself to reach guest
/// agents where the host has no route onto the sandbox network (rootful podman
/// on Linux: `internal: true` means no host address on the bridge). Only a peer
/// *outside* `net` may use it and only for a target *inside* `net`, so a sandbox
/// gains nothing it did not have — it can already reach its neighbours.
pub async fn serve_relay(l: TcpListener, net: (IpAddr, u8)) -> anyhow::Result<()> {
    loop {
        let (mut sock, peer) = l.accept().await?;
        let _ = sock.set_nodelay(true);
        tokio::spawn(async move {
            if in_cidr(peer.ip(), net) {
                return;
            }
            let Ok((head, _)) = read_headers(&mut sock).await else { return };
            let mut parts = head.split("\r\n").next().unwrap_or_default().split_whitespace();
            let target = match (parts.next(), parts.next().and_then(|u| u.parse::<SocketAddr>().ok())) {
                (Some("CONNECT"), Some(t)) if in_cidr(t.ip(), net) => t,
                _ => {
                    let _ = sock
                        .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .await;
                    return;
                }
            };
            let Ok(mut up) = TcpStream::connect(target).await else {
                let _ =
                    sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                return;
            };
            let _ = up.set_nodelay(true);
            if sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_ok() {
                let _ = tokio::io::copy_bidirectional(&mut sock, &mut up).await;
            }
        });
    }
}

/// Reads up to the end of the header block, returning `(headers, leftover_body)`.
async fn read_headers(sock: &mut TcpStream) -> anyhow::Result<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            anyhow::bail!("client closed before sending a request");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let body = buf.split_off(i + 4);
            return Ok((String::from_utf8_lossy(&buf).into_owned(), body));
        }
        if buf.len() > MAX_HEADERS {
            anyhow::bail!("request headers over {MAX_HEADERS} bytes");
        }
    }
}

/// `host:port` from a CONNECT target or an absolute URI, plus the origin-form
/// path for the forward case.
fn target(method: &str, uri: &str) -> Option<(String, u16, String)> {
    if method == "CONNECT" {
        let (h, p) = uri.rsplit_once(':')?;
        return Some((h.trim_matches(['[', ']']).to_string(), p.parse().ok()?, String::new()));
    }
    let rest = uri.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h, p.parse().ok()?),
        _ => (authority, 80u16),
    };
    Some((host.to_string(), port, path.to_string()))
}

/// Absolute-URI → origin-form, minus the proxy's own hop-by-hop headers, and
/// with `Connection: close` for the upstream.
///
/// design: one plain-HTTP request per upstream connection, and one upstream host
/// per client connection. Keeping the socket alive instead was measured and
/// reverted: `handle` relays bytes, so it cannot see where one response ends and
/// the next request begins, and curl (like every proxy client) reuses a *proxy*
/// connection for a different destination host — which would be answered by the
/// first host's socket. Wrong answers, not a policy bypass: the upstream is
/// still only the addresses `policy.decide` approved. Real traffic is CONNECT
/// anyway, and a tunnel is already one upstream for the whole connection; making
/// this path reuse needs a response-framing parser, which is a proxy rewrite.
fn origin_head<'a>(method: &str, path: &str, headers: impl Iterator<Item = &'a str>) -> String {
    let mut out = format!("{method} {path} HTTP/1.1\r\n");
    for l in headers {
        let lower = l.to_ascii_lowercase();
        if l.is_empty()
            || lower.starts_with("proxy-connection:")
            || lower.starts_with("proxy-authorization:")
            || lower.starts_with("connection:")
        {
            continue;
        }
        out.push_str(l);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    out
}

async fn handle(mut sock: TcpStream, peer: SocketAddr, ctx: &Arc<ProxyCtx>) -> anyhow::Result<()> {
    let opened = std::time::Instant::now();
    let (head, leftover) = read_headers(&mut sock).await?;
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or_default();
    let mut parts = first.split_whitespace();
    let (method, uri) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());

    let Some((host, port, path)) = target(method, uri) else {
        sock.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
        anyhow::bail!("unsupported proxy request: {first:?}");
    };

    let ips: Vec<IpAddr> = match tokio::net::lookup_host((host.as_str(), port)).await {
        Ok(it) => it.map(|a| a.ip()).collect(),
        Err(e) => {
            tracing::warn!(host, error = %e, "dns lookup failed");
            Vec::new()
        }
    };

    // D34: a route host, for a sandbox the route applies to, is the
    // interceptor's whatever the lists say; for anyone else it is not there.
    if let Some(ic) = ctx.intercept.clone() {
        if let Some(claim) = ic.claim(ctx, peer.ip(), method == "CONNECT", &host, port, &ips).await {
            return crate::intercept::serve(sock, peer, ctx.clone(), ic, claim, host, port, ips).await;
        }
    }

    let via = match verdict(ctx, peer.ip(), &host, &ips).await {
        Ok(via) => via,
        Err(reason) => {
            sock.write_all(
                b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 24\r\nConnection: close\r\n\r\nblocked by egress policy",
            )
            .await?;
            emit(ctx, peer, EventType::EgressDeny, json!({"host": host, "port": port, "bytes": 0, "reason": reason}))
                .await;
            return Ok(());
        }
    };

    let Some(mut up) = upstream(&mut sock, peer, ctx, &host, port, &ips).await else { return Ok(()) };
    let _ = up.set_nodelay(true);

    if method == "CONNECT" {
        sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
    } else {
        up.write_all(origin_head(method, &path, lines).as_bytes()).await?;
        up.write_all(&leftover).await?;
    }

    let (a, b) = tokio::io::copy_bidirectional(&mut sock, &mut up).await.unwrap_or((0, 0));
    // `duration_ms`: the event goes out at close, so qafas needs it to find the
    // tool call that was current when the tunnel opened (`events::egress_call`).
    let ms = opened.elapsed().as_millis() as u64;
    let data = json!({"host": host, "port": port, "bytes": a + b, "via": via, "duration_ms": ms});
    emit(ctx, peer, EventType::EgressAllow, data).await;
    Ok(())
}

/// The host file first; the peer's own `egress_allow` only when that said no
/// to the name — one call to the daemon, and never for an address rule.
///
/// ponytail: no cache, so a sandbox that keeps trying names nobody listed
/// costs one local round trip per attempt. Upgrade path: a short per-IP cache
/// that `destroy` invalidates, if the daemon ever shows up in a profile.
async fn verdict(ctx: &ProxyCtx, peer: IpAddr, host: &str, ips: &[IpAddr]) -> Result<&'static str, String> {
    match ctx.policy.decide(host, ips) {
        Err(r) if r == NOT_LISTED => match ctx.peer_info(peer).await {
            Some(p) => ctx.policy.decide_with(host, ips, &p.egress_allow),
            None => Err(r),
        },
        v => v,
    }
}

/// The upstream socket, or `None` once the client has its 502 and the stream
/// its `egress.deny`: an approved name whose addresses do not answer is still
/// a connection that did not happen, and the operator should see it.
async fn upstream(
    sock: &mut TcpStream,
    peer: SocketAddr,
    ctx: &ProxyCtx,
    host: &str,
    port: u16,
    ips: &[IpAddr],
) -> Option<TcpStream> {
    let started = std::time::Instant::now();
    let e = match TcpStream::connect(&ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect::<Vec<_>>()[..]).await {
        Ok(up) => return Some(up),
        Err(e) => e,
    };
    tracing::info!(host, port, error = %e, "upstream connect failed");
    let _ = sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
    // A refused or timed-out connect can take a minute: like an allow, it says
    // how long, so it is matched to the call that made it.
    let ms = started.elapsed().as_millis() as u64;
    let data = json!({"host": host, "port": port, "bytes": 0, "reason": "upstream connect failed", "duration_ms": ms});
    emit(ctx, peer, EventType::EgressDeny, data).await;
    None
}

/// Events carry the peer address; qafas turns it into a `sandbox_id`, since
/// only it knows which container has which IP.
pub(crate) async fn emit(ctx: &ProxyCtx, peer: SocketAddr, ty: EventType, mut data: serde_json::Value) {
    data["peer"] = json!(peer.ip().to_canonical().to_string());
    if let Some(f) = &ctx.emit {
        f(ty, data);
        return;
    }
    let mut ev = new_event(&ctx.host_id, "", &Corr::default(), ty, data);
    ev.ts = now_rfc3339();
    tracing::info!(event = %ev.r#type.as_str(), data = %ev.data, "egress");
    let Some(sink) = &ctx.sink else { return };
    let body = serde_json::to_vec(&[ev]).unwrap_or_default();
    let req = hyper::Request::builder()
        .method("POST")
        .uri(sink)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", ctx.token))
        .body(Full::new(Bytes::from(body)));
    if let Ok(req) = req {
        if let Err(e) = ctx.http.request(req).await {
            tracing::warn!(error = %e, "egress event sink failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::from_policy(&EgressPolicy {
            allow: vec!["github.com".into(), "*.github.com".into(), "pypi.org".into()],
            deny_cidrs_extra: vec!["203.0.113.0/24".into()],
            allow_private_cidrs: vec![],
            ..Default::default()
        })
    }

    async fn relay_on(net: &str) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(serve_relay(l, parse_cidr(net).unwrap()));
        addr
    }

    async fn relay_connect(relay: SocketAddr, target: &str) -> String {
        let mut s = TcpStream::connect(relay).await.unwrap();
        s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 256];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), s.read(&mut buf)).await.unwrap().unwrap_or(0);
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    #[tokio::test]
    async fn relay_serves_only_outsiders_and_only_into_the_sandbox_net() {
        // The peer (127.0.0.1) is inside the sandbox net: silence, no tunnel.
        let inside = relay_on("127.0.0.0/8").await;
        assert_eq!(relay_connect(inside, "127.0.0.1:1").await, "");
        // The peer is outside, but so is the target: refused.
        let outside = relay_on("10.89.0.0/24").await;
        assert!(relay_connect(outside, "127.0.0.1:1").await.starts_with("HTTP/1.1 403"));
        assert!(relay_connect(outside, "github.com:443").await.starts_with("HTTP/1.1 403"), "names are not addresses");
    }

    // Only Linux lets a test bind another loopback address to stand in for a sandbox.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn relay_tunnels_to_a_sandbox_address() {
        let guest = TcpListener::bind("127.0.1.5:0").await.unwrap();
        let target = guest.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = guest.accept().await.unwrap();
            let mut b = [0u8; 5];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap();
        });
        let relay = relay_on("127.0.1.0/24").await;
        let mut s = TcpStream::connect(relay).await.unwrap();
        s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await.unwrap();
        let mut head = vec![0u8; 39];
        s.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..12], b"HTTP/1.1 200");
        s.write_all(b"hello").await.unwrap();
        let mut echo = [0u8; 5];
        s.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"hello");
    }

    /// v5.3: an internal mirror opens only for an allowed name inside a listed
    /// range, and the list cannot open loopback, link-local or CGNAT.
    #[test]
    fn allow_private_cidrs_opens_internal_mirrors_and_nothing_else() {
        let p = Policy::from_policy(&EgressPolicy {
            allow: vec!["mirror.corp".into(), "*.internal".into()],
            deny_cidrs_extra: vec!["10.1.9.0/24".into()],
            allow_private_cidrs: vec![
                "10.1.0.0/16".into(),
                "169.254.0.0/16".into(),
                "127.0.0.0/8".into(),
                "100.64.0.0/10".into(),
                "fd00::/8".into(),
            ],
            ..Default::default()
        });
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        assert!(p.decide("mirror.corp", &[ip("10.1.2.3")]).is_ok());
        assert!(p.decide("mirror.corp", &[ip("fd00::5")]).is_ok());
        assert!(p.decide("other.corp", &[ip("10.1.2.3")]).is_err(), "the name must still be allowed");
        assert!(p.decide("mirror.corp", &[ip("10.2.0.1")]).is_err(), "outside the listed range");
        assert!(p.decide("mirror.corp", &[ip("10.1.9.9")]).is_err(), "deny_cidrs_extra still wins");
        for never in ["169.254.169.254", "127.0.0.1", "100.100.100.200"] {
            assert!(p.decide("mirror.corp", &[ip(never)]).is_err(), "{never} can never be opened");
        }
        // A harness widening names cannot widen ranges: with no list, 10/8 stays shut.
        assert!(policy().with_extra(&["mirror.corp".into()]).decide("mirror.corp", &[ip("10.1.2.3")]).is_err());
    }

    #[test]
    fn per_sandbox_allow_widens_names_but_not_addresses() {
        let p = policy().with_extra(&["internal.example.com".into()]);
        let public: IpAddr = "140.82.121.4".parse().unwrap();
        assert_eq!(p.decide("internal.example.com", &[public]), Ok("sandbox"), "the allow says which list");
        assert_eq!(p.decide("github.com", &[public]), Ok("baseline"));
        assert!(p.decide("other.example.com", &[public]).is_err());
        // The private-range rule is not something a harness can opt out of.
        assert!(p.decide("internal.example.com", &["10.0.0.1".parse().unwrap()]).is_err());
    }

    /// E1: the shared proxy (vm, remote) asks the daemon about its peer only
    /// when the host file said no to the name, and a sandbox's own names open
    /// for that sandbox's address alone — never for a neighbour, never for an
    /// address nobody has, never past the address rules.
    #[tokio::test]
    async fn a_sandboxs_own_names_open_for_its_address_only() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        let (a, neighbour, nobody, public) = (ip("10.89.0.2"), ip("10.89.0.3"), ip("10.89.0.9"), ip("140.82.121.4"));
        let asked = Arc::new(AtomicUsize::new(0));
        let mut ctx = ProxyCtx::new(policy(), "h".into(), "t".into());
        let n = asked.clone();
        ctx.peer = Some(Arc::new(move |peer| {
            n.fetch_add(1, Ordering::SeqCst);
            let info = |allow: &[&str]| PeerInfo {
                egress_allow: allow.iter().map(|g| g.to_string()).collect(),
                trust: proto::Trust::Untrusted,
            };
            let found = match peer.to_string().as_str() {
                "10.89.0.2" => Some(info(&["only-a.example", "*.a.example"])),
                "10.89.0.3" => Some(info(&[])),
                _ => None,
            };
            Box::pin(async move { found })
        }));

        assert_eq!(verdict(&ctx, a, "only-a.example", &[public]).await, Ok("sandbox"));
        assert_eq!(verdict(&ctx, a, "x.a.example", &[public]).await, Ok("sandbox"), "globs, as in the host file");
        assert_eq!(verdict(&ctx, neighbour, "only-a.example", &[public]).await, Err(NOT_LISTED.into()));
        // An address no sandbox has changes nothing: the host file's answer stands.
        for host in ["only-a.example", "github.com", "example.com"] {
            assert_eq!(verdict(&ctx, nobody, host, &[public]).await, ctx.policy.decide(host, &[public]), "{host}");
        }
        // A per-sandbox name cannot open a private address, nor an extra-denied one.
        let private = verdict(&ctx, a, "only-a.example", &[ip("10.0.0.1")]).await.unwrap_err();
        assert!(private.contains("non-public"), "{private}");
        assert!(verdict(&ctx, a, "only-a.example", &[ip("203.0.113.7")]).await.is_err());
        // An IPv4 peer seen through a dual-stack socket is the same sandbox.
        assert_eq!(verdict(&ctx, ip("::ffff:10.89.0.2"), "only-a.example", &[public]).await, Ok("sandbox"));

        // The daemon is asked only after the host file said no to the name.
        let before = asked.load(Ordering::SeqCst);
        assert_eq!(verdict(&ctx, a, "github.com", &[public]).await, Ok("baseline"));
        assert!(verdict(&ctx, a, "github.com", &[ip("10.0.0.1")]).await.is_err());
        assert_eq!(asked.load(Ordering::SeqCst), before, "a listed name or an address deny asks nobody");
    }

    /// The same through the listener: two sandboxes on one proxy, told apart by
    /// the address they connect from. A's own name gets past the name check (to
    /// an address rule, so the test needs no network); B's does not.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn one_proxy_tells_two_sandboxes_apart_by_address() {
        let got: Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Default::default();
        let mut ctx = ProxyCtx::new(policy(), "h".into(), "t".into());
        let g = got.clone();
        ctx.emit = Some(Arc::new(move |_, data| g.lock().unwrap().push(data)));
        ctx.peer = Some(Arc::new(|peer| {
            let allow = if peer.to_string() == "127.0.0.2" { vec!["203.0.113.7".to_string()] } else { vec![] };
            Box::pin(async move { Some(PeerInfo { egress_allow: allow, trust: proto::Trust::Trusted }) })
        }));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(serve(l, Arc::new(ctx)));
        for from in ["127.0.0.2", "127.0.0.3"] {
            let s = tokio::net::TcpSocket::new_v4().unwrap();
            s.bind(format!("{from}:0").parse().unwrap()).unwrap();
            let mut c = s.connect(addr).await.unwrap();
            c.write_all(b"CONNECT 203.0.113.7:443 HTTP/1.1\r\nHost: 203.0.113.7:443\r\n\r\n").await.unwrap();
            let mut reply = String::new();
            c.read_to_string(&mut reply).await.unwrap();
            assert!(reply.starts_with("HTTP/1.1 403"), "{reply:?}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let got = got.lock().unwrap().clone();
        let reason = |peer: &str| got.iter().find(|d| d["peer"] == peer).map(|d| d["reason"].clone());
        assert_eq!(reason("127.0.0.2"), Some(json!("address 203.0.113.7 in deny_cidrs_extra")), "{got:?}");
        assert_eq!(reason("127.0.0.3"), Some(json!(NOT_LISTED)), "{got:?}");
    }

    /// An approved name whose address does not answer is a connection that did
    /// not happen: the client gets a 502 and the stream an `egress.deny`.
    #[tokio::test]
    async fn a_failed_upstream_connect_is_a_deny_with_its_reason() {
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
        let got: Arc<std::sync::Mutex<Vec<(EventType, serde_json::Value)>>> = Default::default();
        let mut ctx = ProxyCtx::new(policy(), "h".into(), "t".into());
        let g = got.clone();
        ctx.emit = Some(Arc::new(move |ty, data| g.lock().unwrap().push((ty, data))));

        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (mut sock, peer) = l.accept().await.unwrap();
        let ips = ["127.0.0.1".parse().unwrap()];
        assert!(upstream(&mut sock, peer, &ctx, "mirror.example", closed, &ips).await.is_none());

        let got = got.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, EventType::EgressDeny);
        assert_eq!(got[0].1["reason"], "upstream connect failed");
        assert!(got[0].1["duration_ms"].is_u64(), "it says how long, for the tool call lookup");
        assert_eq!(
            (got[0].1["host"].as_str(), got[0].1["port"].as_u64()),
            (Some("mirror.example"), Some(closed.into()))
        );
        drop(sock);
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 502"), "{reply:?}");
    }

    #[test]
    fn allowlist_and_private_addresses() {
        let p = policy();
        let public = "140.82.121.4".parse().unwrap();
        assert!(p.decide("github.com", &[public]).is_ok());
        assert!(p.decide("api.github.com", &[public]).is_ok());
        assert!(p.decide("GitHub.com.", &[public]).is_ok(), "case and trailing dot");

        assert!(p.decide("example.com", &[public]).is_err(), "not in the allowlist");
        assert!(p.decide("evil.github.com.attacker.net", &[public]).is_err());
        assert!(p.decide("github.com", &[]).is_err(), "unresolvable");

        // Rebinding: an allowed name pointing at something internal.
        for bad in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.5",
            "172.16.9.9",
            "169.254.169.254",
            "0.0.0.0",
            "100.100.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            // IPv4 inside an IPv6 address (NAT64, IPv4-compatible, 6to4, Teredo).
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::7f00:1",
            "64:ff9b::a00:1",
            "::a9fe:a9fe",
            "2002:a9fe:a9fe::1",
            "2002:7f00:1::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "64:ff9b:1::1",
        ] {
            let ip: IpAddr = bad.parse().unwrap();
            assert!(p.decide("github.com", &[ip]).is_err(), "{bad} must be denied");
        }
        // A public IPv4 behind a NAT64 or 6to4 prefix is as public as the IPv4.
        for ok in ["64:ff9b::808:808", "2002:808:808::1", "2606:4700::1111"] {
            assert!(p.decide("github.com", &[ok.parse().unwrap()]).is_ok(), "{ok} must be allowed");
        }
        // One bad address in the set poisons the whole answer.
        assert!(p.decide("github.com", &[public, "10.0.0.1".parse().unwrap()]).is_err());
        // deny_cidrs_extra.
        assert!(p.decide("github.com", &["203.0.113.7".parse().unwrap()]).is_err());
        assert!(p.decide("github.com", &["203.0.114.7".parse().unwrap()]).is_ok());
    }

    /// The forwarded head is origin-form, carries the client's own headers, and
    /// drops every one that is this hop's: the client's `Connection` (replaced
    /// with our `close`, which is what bounds one upstream to one request) and
    /// the `Proxy-*` pair, whose credentials must never reach an origin server.
    #[test]
    fn the_forwarded_head_is_origin_form_without_the_proxys_own_headers() {
        let head = "Host: pypi.org\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic x\r\nAccept: */*";
        let out = origin_head("GET", "/simple/", head.split("\r\n"));
        assert!(out.starts_with("GET /simple/ HTTP/1.1\r\n"), "{out:?}");
        assert!(out.contains("Host: pypi.org\r\n"));
        assert!(out.contains("Accept: */*\r\n"));
        assert_eq!(out.to_ascii_lowercase().matches("connection:").count(), 1, "exactly ours: {out:?}");
        assert!(out.contains("Connection: close\r\n"), "{out:?}");
        assert!(!out.contains("Basic x"), "the proxy's own credentials must not travel: {out:?}");
        assert!(out.ends_with("\r\n\r\n"));
    }

    #[test]
    fn request_targets() {
        assert_eq!(target("CONNECT", "github.com:443"), Some(("github.com".into(), 443, "".into())));
        assert_eq!(target("GET", "http://pypi.org/simple/"), Some(("pypi.org".into(), 80, "/simple/".into())));
        assert_eq!(target("GET", "http://pypi.org:8080/x?y=1"), Some(("pypi.org".into(), 8080, "/x?y=1".into())));
        assert_eq!(target("GET", "http://pypi.org"), Some(("pypi.org".into(), 80, "/".into())));
        assert_eq!(target("GET", "/relative"), None, "an origin-form request has no proxy target");
        assert_eq!(target("GET", "https://pypi.org/"), None, "TLS must arrive as CONNECT");
    }

    #[test]
    fn cidr_matching() {
        let c = parse_cidr("10.0.0.0/8").unwrap();
        assert!(in_cidr("10.255.1.1".parse().unwrap(), c));
        assert!(!in_cidr("11.0.0.1".parse().unwrap(), c));
        let exact = parse_cidr("1.2.3.4").unwrap();
        assert!(in_cidr("1.2.3.4".parse().unwrap(), exact));
        assert!(!in_cidr("1.2.3.5".parse().unwrap(), exact));
    }
}
