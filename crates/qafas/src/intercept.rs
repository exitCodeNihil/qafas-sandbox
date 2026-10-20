//! D34: credential injection and per-request rules at the egress proxy.
//!
//! A route (`EgressPolicy.routes`, protocol §6) binds host globs to a secret
//! and/or an allow-list of requests. For a sandbox the route applies to, every
//! CONNECT to one of its hosts on one of its ports ends here instead of in a
//! blind tunnel: the proxy answers TLS with a leaf from a per-install CA, reads
//! each HTTP/1.1 request, checks it against the route's rules, swaps the
//! sandbox's placeholder for the real secret, and forwards it over TLS to the
//! addresses the policy approved. Every copy of the secret is removed from what
//! comes back. The sandbox only ever holds the placeholder.
//!
//! Where the secret can go, by construction: only into a request on a
//! connection that was claimed for its own route (so only to that route's
//! hosts, after a TLS handshake that verified the host), and only in header
//! values and query values. Nothing here follows a redirect.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Frame, Incoming, SizeHint};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use proto::{EgressInject, EgressPolicy, EgressRoute, EventType, Trust};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    PublicKeyData, SerialNumber,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use wildmatch::WildMatch;

use crate::config::Config;
use crate::proxy::ProxyCtx;

/// The variables that point a sandbox's TLS clients at the bundle `/ca` writes.
/// `NODE_EXTRA_CA_CERTS` adds to Node's own store, so it gets the CA alone.
const BUNDLE_VARS: [&str; 6] =
    ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "CARGO_HTTP_CAINFO", "PIP_CERT"];
const CA_VARS: [&str; 2] = ["NODE_EXTRA_CA_CERTS", "SBX_CA_SPKI"];

/// Headers a route may not `inject`: framing, routing and the proxy's own.
const NOT_INJECTABLE: [&str; 9] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "proxy-authorization",
    "proxy-connection",
];

/// Request headers that belong to one hop, never forwarded as they came.
const HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Headers some servers and frameworks take as the method or the path. The
/// rules see only the request line, so a route with rules does not send them.
const OVERRIDES: [&str; 5] =
    ["x-http-method-override", "x-http-method", "x-method-override", "x-original-url", "x-rewrite-url"];

const SECRET_MIN: usize = 8;
const LEAF_TTL: Duration = Duration::from_secs(12 * 3600);
const LEAF_CACHE: usize = 256;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// The secret is a credential the sandbox must never see. Nothing prints it:
/// not `{:?}`, not `{}`. The one way out is `expose`, used where a request is
/// built and nowhere else.
pub struct Secret(String);

impl Secret {
    fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

// ------------------------------------------------------------------ config

/// One route as the operator wrote it, checked, with its secret read.
pub struct RouteDef {
    spec: EgressRoute,
    secret: Option<Secret>,
}

fn host_norm(h: &str) -> String {
    h.trim_end_matches('.').to_ascii_lowercase()
}

fn is_env_name(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|f| f == '_' || f.is_ascii_alphabetic()) && c.all(|x| x == '_' || x.is_ascii_alphanumeric())
}

/// A host a route may bind: a name, an address, or `*.` followed by at least
/// two literal labels (`*.example.com`). Refused: `*.com`, `*github.com`,
/// `git*.com`, `*.*`, any `?`: each covers names nobody listed.
fn host_glob_ok(h: &str) -> bool {
    let h = host_norm(h);
    if h.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
        return true;
    }
    let rest = h.strip_prefix("*.").unwrap_or(&h);
    let labels: Vec<&str> = rest.split('.').collect();
    !rest.contains(['*', '?']) && labels.iter().all(|l| !l.is_empty()) && (rest.len() == h.len() || labels.len() >= 2)
}

/// Everything about a route that does not need its secret. The message never
/// carries a value, only names and references.
fn validate(r: &EgressRoute, names: &mut HashSet<String>, envs: &mut HashMap<String, String>) -> Result<(), String> {
    if r.name.is_empty()
        || !r.name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err("name must be [a-z0-9_-]+".into());
    }
    if !names.insert(r.name.clone()) {
        return Err("duplicate route name".into());
    }
    if r.hosts.is_empty() {
        return Err("hosts is empty".into());
    }
    if let Some(h) = r.hosts.iter().find(|h| !host_glob_ok(h)) {
        return Err(format!(
            "host {h:?} is too broad: name the host, or make the wildcard the whole leftmost label \
             with at least two labels after it (*.example.com)"
        ));
    }
    if r.ports.is_empty() || r.ports.contains(&0) {
        return Err("ports must list at least one port, none of them 0".into());
    }
    if r.trust.is_empty() {
        return Err("trust is empty: the route would apply to no sandbox".into());
    }
    match (&r.secret, &r.env) {
        (Some(_), None) => return Err("secret needs env (the variable that carries the placeholder)".into()),
        (None, Some(_)) => return Err("env without secret".into()),
        _ => {}
    }
    if let Some(env) = &r.env {
        if !is_env_name(env)
            || !agent_core::spawn::env_allowed(env)
            || BUNDLE_VARS.contains(&env.as_str())
            || CA_VARS.contains(&env.as_str())
        {
            return Err(format!("env {env:?} is not a name a sandbox variable can have"));
        }
        if let Some(other) = envs.insert(env.clone(), r.name.clone()) {
            return Err(format!("env {env:?} is already route {other:?}'s"));
        }
    }
    if let Some(inj) = &r.inject {
        if r.secret.is_none() {
            return Err("inject needs secret".into());
        }
        let ok = HeaderName::from_bytes(inj.header.as_bytes()).is_ok_and(|h| !NOT_INJECTABLE.contains(&h.as_str()));
        if !ok {
            return Err(format!("inject.header {:?} cannot be injected", inj.header));
        }
        if !inj.format.contains("{secret}") {
            return Err("inject.format must contain {secret}".into());
        }
    }
    for rule in &r.rules {
        if rule.paths.is_empty() {
            return Err("a rule with no paths matches nothing; list at least one".into());
        }
        if let Some(p) = rule.paths.iter().find(|p| !p.starts_with('/') && !p.starts_with('*')) {
            return Err(format!("rule path {p:?} must start with /"));
        }
        if let Some(m) = rule.methods.iter().find(|m| m.is_empty() || !m.bytes().all(|b| b.is_ascii_alphabetic())) {
            return Err(format!("rule method {m:?} is not a method"));
        }
    }
    Ok(())
}

/// `env://NAME` or `file:///abs/path`, read now and never again.
fn read_secret(reference: &str) -> Result<Secret, String> {
    let raw = if let Some(name) = reference.strip_prefix("env://") {
        std::env::var(name).map_err(|_| format!("secret {reference} is not set"))?
    } else if let Some(path) = reference.strip_prefix("file://") {
        if !path.starts_with('/') {
            return Err(format!("secret {reference}: file:// needs an absolute path"));
        }
        let meta = std::fs::metadata(path).map_err(|e| format!("secret {reference}: {e}"))?;
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o044 != 0 {
            return Err(format!("secret {reference} is readable by group or others; chmod 600 it"));
        }
        std::fs::read_to_string(path).map_err(|e| format!("secret {reference}: {e}"))?
    } else {
        return Err("secret must be env://NAME or file:///abs/path".into());
    };
    let v = raw.trim();
    if v.is_empty() {
        return Err(format!("secret {reference} is empty"));
    }
    if v.len() < SECRET_MIN {
        return Err(format!("secret {reference} is shorter than {SECRET_MIN} characters"));
    }
    // It is written into header values: visible ASCII and spaces only.
    if !v.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(format!("secret {reference} has characters a header value cannot carry"));
    }
    Ok(Secret(v.to_string()))
}

/// Two hosts, one from each route, that one connection could match, when the
/// routes also share a port and a trust. The first route binding a host wins,
/// so the later one's rules and secret would silently never apply. Each glob
/// is tested as a string against the other, both ways.
fn overlap(a: &EgressRoute, b: &EgressRoute) -> Option<(String, String)> {
    if !a.ports.iter().any(|p| b.ports.contains(p)) || !a.trust.iter().any(|t| b.trust.contains(t)) {
        return None;
    }
    a.hosts.iter().map(|h| host_norm(h)).find_map(|x| {
        b.hosts
            .iter()
            .map(|h| host_norm(h))
            .find(|y| WildMatch::new(&x).matches(y) || WildMatch::new(y).matches(&x))
            .map(|y| (x.clone(), y))
    })
}

/// Checks every route and reads every secret. The first problem is an error
/// that names the route and, for a secret, its reference: never its value.
pub fn resolve_routes(p: &EgressPolicy) -> anyhow::Result<Vec<RouteDef>> {
    let (mut names, mut envs) = (HashSet::new(), HashMap::new());
    let mut out = Vec::new();
    for (n, r) in p.routes.iter().enumerate() {
        let fail = |why: String| anyhow::anyhow!("egress route {:?}: {why}", r.name);
        validate(r, &mut names, &mut envs).map_err(fail)?;
        if let Some((e, (x, y))) = p.routes[..n].iter().find_map(|e| overlap(e, r).map(|o| (e, o))) {
            return Err(fail(format!(
                "host {y:?} overlaps route {:?}'s host {x:?} on a port and a trust both list; make the hosts disjoint",
                e.name
            )));
        }
        let secret = r.secret.as_deref().map(read_secret).transpose().map_err(fail)?;
        out.push(RouteDef { spec: EgressRoute { secret: None, ..r.clone() }, secret });
    }
    Ok(out)
}

/// The host file the way the proxy reads it (`SBX_POLICY_JSON` first). An
/// unreadable or malformed file has no routes: the proxy denies everything then.
fn read_policy(cfg: &Config) -> EgressPolicy {
    std::env::var("SBX_POLICY_JSON")
        .ok()
        .or_else(|| std::fs::read_to_string(&cfg.policy).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

// ------------------------------------------------------------------ the CA

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// `(year, month, day)` in UTC, `days` from today.
fn ymd(days: i64) -> (i32, u8, u8) {
    let s = agent_core::rfc3339_millis(agent_core::now_ms() + days * 86_400_000);
    (s[0..4].parse().unwrap_or(2026), s[5..7].parse().unwrap_or(1), s[8..10].parse().unwrap_or(1))
}

fn random<const N: usize>() -> [u8; N] {
    use std::io::Read;
    let mut b = [0u8; N];
    let _ = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b));
    b
}

/// Derived from the key alone, so a restart signs with the identical issuer
/// name without parsing `ca.pem`: `qafas egress CA <12 hex of the key's SPKI hash>`.
fn ca_params(key: &KeyPair) -> CertificateParams {
    let id = crate::backend::hex(&Sha256::digest(key.subject_public_key_info()));
    let mut p = CertificateParams::default();
    p.distinguished_name = rcgen::DistinguishedName::new();
    p.distinguished_name.push(DnType::CommonName, format!("qafas egress CA {}", &id[..12]));
    p.distinguished_name.push(DnType::OrganizationName, "qafas");
    // Path length 0: it signs leaves and nothing that could sign more.
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    let (y, _, _) = ymd(0);
    p.not_before = rcgen::date_time_ymd(y - 1, 1, 1);
    p.not_after = rcgen::date_time_ymd(y + 10, 1, 1);
    p
}

/// The per-install CA. Its key signs the leaves and keys the placeholders.
pub struct Ca {
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    key: KeyPair,
    params: CertificateParams,
    /// base64(SHA-256(SubjectPublicKeyInfo)): Chromium's `--ignore-certificate-errors-spki-list`.
    spki: String,
}

impl Ca {
    fn from_pem(cert_pem: &str, key_pem: &str) -> anyhow::Result<Self> {
        let key = KeyPair::from_pem(key_pem).context("the egress CA key does not parse")?;
        let cert_der =
            CertificateDer::from_pem_slice(cert_pem.as_bytes()).context("the egress CA certificate does not parse")?;
        let spki_der = key.subject_public_key_info();
        anyhow::ensure!(
            cert_der.windows(spki_der.len()).any(|w| w == spki_der.as_slice()),
            "ca.pem does not belong to ca.key"
        );
        let spki = STANDARD.encode(Sha256::digest(&spki_der));
        Ok(Self { cert_pem: cert_pem.to_string(), cert_der, params: ca_params(&key), key, spki })
    }

    /// `<dir>/ca.pem` and `ca.key` (0600, in a 0700 directory): made on the
    /// first start with routes, then kept, so placeholders and every warm
    /// sandbox's trust survive a restart. Rotation is deleting the directory.
    pub fn load_or_create(dir: &Path) -> anyhow::Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
        let (cert, key) = (dir.join("ca.pem"), dir.join("ca.key"));
        if !cert.is_file() || !key.is_file() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            let k = KeyPair::generate()?;
            let c = ca_params(&k).self_signed(&k)?;
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&key)?;
            std::io::Write::write_all(&mut f, k.serialize_pem().as_bytes())?;
            std::fs::write(&cert, c.pem())?;
            tracing::info!(dir = %dir.display(), "created the egress CA");
        }
        let mode = std::fs::metadata(&key)?.permissions().mode();
        anyhow::ensure!(
            mode & 0o077 == 0,
            "{} is readable by others (mode {:o}); chmod 600 it",
            key.display(),
            mode & 0o777
        );
        Self::from_pem(&std::fs::read_to_string(&cert)?, &std::fs::read_to_string(&key)?)
            .with_context(|| format!("{}: delete it to make a new CA", dir.display()))
    }

    pub fn fingerprint(&self) -> String {
        crate::backend::hex(&Sha256::digest(self.cert_der.as_ref()))
    }

    /// `qafas_ph_<name>_<24 hex>`: HMAC-SHA256 under the CA key, so it is the
    /// same across restarts and different on every install.
    fn placeholder(&self, name: &str) -> String {
        let mut m = Hmac::<Sha256>::new_from_slice(self.key.serialized_der()).expect("hmac takes any key");
        m.update(format!("placeholder:{name}").as_bytes());
        format!("qafas_ph_{name}_{}", &crate::backend::hex(&m.finalize().into_bytes())[..24])
    }
}

// ------------------------------------------------------------------ routes

struct Route {
    name: String,
    hosts: Vec<WildMatch>,
    ports: Vec<u16>,
    trust: Vec<Trust>,
    env: Option<String>,
    inject: Option<EgressInject>,
    /// `(methods upper-cased, path globs)`. Empty: every request.
    rules: Vec<(Vec<String>, Vec<WildMatch>)>,
    secret: Option<Secret>,
    placeholder: Option<String>,
    /// Every form of the secret a response could carry back.
    needles: Arc<Vec<Vec<u8>>>,
    spec: EgressRoute,
}

impl Route {
    fn new(d: RouteDef, ca: &Ca) -> Self {
        let s = &d.spec;
        let placeholder = d.secret.as_ref().map(|_| ca.placeholder(&s.name));
        let needles = Arc::new(d.secret.as_ref().map(|s| needles(s.expose().as_bytes())).unwrap_or_default());
        Self {
            name: s.name.clone(),
            hosts: s.hosts.iter().map(|h| WildMatch::new(&host_norm(h))).collect(),
            ports: s.ports.clone(),
            trust: s.trust.clone(),
            env: s.env.clone(),
            inject: s.inject.clone(),
            rules: s
                .rules
                .iter()
                .map(|r| {
                    (
                        r.methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
                        r.paths.iter().map(|p| WildMatch::new(p)).collect(),
                    )
                })
                .collect(),
            secret: d.secret,
            placeholder,
            needles,
            spec: d.spec,
        }
    }

    fn binds(&self, host: &str) -> bool {
        self.hosts.iter().any(|g| g.matches(host))
    }

    /// The route's allow-list: a rule matches when the method is listed (or
    /// none is) and the path, without its query, matches one of its globs. The
    /// path must be canonical first, or `/org/*` could be walked out of.
    fn allows(&self, method: &str, path: &str) -> bool {
        self.rules.is_empty()
            || (canonical(path)
                && self.rules.iter().any(|(ms, ps)| {
                    (ms.is_empty() || ms.iter().any(|m| m.eq_ignore_ascii_case(method)))
                        && ps.iter().any(|g| g.matches(path))
                }))
    }
}

fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn hexval(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// A path the rules can be trusted on: it says exactly one place, whichever
/// way the server decodes it. Refused: a backslash; an escape of a character
/// that needs none (`%2e` is a disguised `.`); a NUL; and — after decoding
/// every escape, so `%2F..%2F` counts — a `.` or `..` segment (also as `..;`,
/// Tomcat's path parameter) or an empty one (`//`). Also refused: `%25` and two
/// hex digits (`%252e` is `%2e` to a server that decodes twice), and escapes
/// that do not decode to valid UTF-8 (`%c0%ae`, an overlong `.`). What is
/// matched is the path as sent, so an encoded slash stays one segment to the globs.
fn canonical(path: &str) -> bool {
    let b = path.as_bytes();
    if !path.starts_with('/') || path.contains('\\') {
        return false;
    }
    let mut decoded = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let (Some(h), Some(l)) = (b.get(i + 1).and_then(|c| hexval(*c)), b.get(i + 2).and_then(|c| hexval(*c)))
            else {
                return false;
            };
            let c = h * 16 + l;
            let hex_at = |j: usize| b.get(j).and_then(|c| hexval(*c)).is_some();
            let twice = c == b'%' && hex_at(i + 3) && hex_at(i + 4);
            if unreserved(c) || c == b'\\' || c == 0 || twice {
                return false;
            }
            decoded.push(c);
            i += 3;
        } else {
            decoded.push(b[i]);
            i += 1;
        }
    }
    if std::str::from_utf8(&decoded).is_err() {
        return false;
    }
    let segs: Vec<&[u8]> = decoded[1..].split(|c| *c == b'/').collect();
    segs.iter().enumerate().all(|(n, s)| {
        let bare = s.split(|c| *c == b';').next().unwrap_or_default();
        bare != b"." && bare != b".." && (!s.is_empty() || n + 1 == segs.len())
    })
}

/// RFC 3986 unreserved characters stay, everything else is `%XX`: valid in any
/// query value, whatever the secret holds.
fn pct(s: &str) -> String {
    s.bytes().map(|b| if unreserved(b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// The secret, its query (percent) and JSON-escaped forms, and the parts of
/// its base64 (standard and URL alphabets) that do not depend on what comes
/// before or after it in the encoded string: at each of the three byte
/// alignments, the characters that only the secret's own bytes determine.
/// That is what a `Basic` echo (`base64("user:" + secret)`) carries.
fn needles(secret: &[u8]) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(secret);
    let mut out: Vec<Vec<u8>> = vec![secret.to_vec(), pct(&text).into_bytes()];
    out.push(serde_json::to_string(&text).unwrap_or_default().trim_matches('"').as_bytes().to_vec());
    out.push(text.replace('/', "\\/").into_bytes());
    for eng in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        for k in 0..3usize {
            let mut buf = vec![0u8; k];
            buf.extend_from_slice(secret);
            let enc = eng.encode(&buf);
            let (from, to) = ((4 * k).div_ceil(3), 4 * (k + secret.len()) / 3);
            out.push(enc.as_bytes()[from..to].to_vec());
        }
    }
    out.retain(|n| n.len() >= 6);
    out.sort();
    out.dedup();
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    (needle.len() <= hay.len()).then(|| hay.windows(needle.len()).position(|w| w == needle)).flatten()
}

/// Overwrites every occurrence with `*`, keeping the length: `Content-Length`
/// stays true and nothing has to be re-framed.
fn redact(buf: &mut [u8], needles: &[Vec<u8>]) -> bool {
    let mut hit = false;
    for n in needles {
        let mut from = 0;
        while let Some(i) = find(&buf[from..], n) {
            buf[from + i..from + i + n.len()].fill(b'*');
            from += i + n.len();
            hit = true;
        }
    }
    hit
}

fn replace(hay: &[u8], from: &[u8], to: &[u8]) -> Option<Vec<u8>> {
    find(hay, from)?;
    let (mut out, mut rest) = (Vec::with_capacity(hay.len()), hay);
    while let Some(i) = find(rest, from) {
        out.extend_from_slice(&rest[..i]);
        out.extend_from_slice(to);
        rest = &rest[i + from.len()..];
    }
    out.extend_from_slice(rest);
    Some(out)
}

/// The placeholder in one header value, swapped. An `Authorization: Basic`
/// value is decoded first, since that is where git and pip put a password.
fn swap_value(name: &HeaderName, v: &HeaderValue, ph: &str, secret: &str) -> Option<HeaderValue> {
    if name == header::AUTHORIZATION {
        let s = v.as_bytes();
        if s.len() > 6 && s[..6].eq_ignore_ascii_case(b"basic ") {
            let enc = std::str::from_utf8(&s[6..]).ok()?.trim();
            if let Ok(dec) = STANDARD.decode(enc).or_else(|_| STANDARD_NO_PAD.decode(enc)) {
                if let Some(new) = replace(&dec, ph.as_bytes(), secret.as_bytes()) {
                    return HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(new))).ok();
                }
            }
        }
    }
    HeaderValue::from_bytes(&replace(v.as_bytes(), ph.as_bytes(), secret.as_bytes())?).ok()
}

fn carries(name: &HeaderName, v: &HeaderValue, ph: &str) -> bool {
    swap_value(name, v, ph, "x").is_some()
}

// ------------------------------------------------------------------ the interceptor

/// Picks the certificate for the one host a tunnel was opened to: an SNI that
/// names another host (or none, for a name) aborts the handshake.
struct ForHost {
    host: String,
    key: Arc<CertifiedKey>,
}

impl std::fmt::Debug for ForHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ForHost({})", self.host)
    }
}

impl ResolvesServerCert for ForHost {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match hello.server_name() {
            Some(sni) if host_norm(sni) == self.host => Some(self.key.clone()),
            // Clients send no SNI for an address.
            None if self.host.parse::<IpAddr>().is_ok() => Some(self.key.clone()),
            _ => None,
        }
    }
}

/// What the proxy does with a connection to a host some route binds.
pub enum Claim {
    /// Refused before any byte reaches the upstream: `(reason, route)`.
    Deny(String, String),
    /// Intercepted for the route at this index.
    Tunnel(usize),
}

pub struct Intercept {
    routes: Vec<Route>,
    ca: Ca,
    leaf_key: KeyPair,
    leaf_signer: Arc<dyn rustls::sign::SigningKey>,
    leaves: Mutex<HashMap<String, (Arc<rustls::ServerConfig>, Instant)>>,
    upstream: Arc<rustls::ClientConfig>,
    upstream_ca: String,
}

/// What the proxy container receives in `SBX_ROUTES_JSON`. No `Debug`: it
/// holds every secret and the CA key.
#[derive(Serialize, Deserialize)]
struct Wire {
    routes: Vec<EgressRoute>,
    secrets: BTreeMap<String, String>,
    ca_cert: String,
    ca_key: String,
    #[serde(default)]
    upstream_ca: String,
}

static INSTALLED: OnceLock<Arc<Intercept>> = OnceLock::new();

/// The daemon's interceptor, when its host file has routes.
pub fn installed() -> Option<Arc<Intercept>> {
    INSTALLED.get().cloned()
}

/// `serve`'s start: read the routes, their secrets and the extra upstream CA,
/// load or make the egress CA. `None` without routes. An error names the route
/// and stops the daemon: running without a credential it was told to attach
/// is worse than not running.
pub fn init(cfg: &Config) -> anyhow::Result<Option<Arc<Intercept>>> {
    let policy = read_policy(cfg);
    if policy.routes.is_empty() {
        return Ok(None);
    }
    let defs = resolve_routes(&policy)?;
    let extra = upstream_ca_pem(cfg)?;
    let ca = Ca::load_or_create(&Path::new(&cfg.state_dir).join("egress-ca"))?;
    let ic = Arc::new(Intercept::new(defs, ca, extra)?);
    tracing::info!(
        routes = ic.routes.len(),
        names = ?ic.routes.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
        ca = %ic.ca.fingerprint(),
        "egress routes: TLS terminated for their hosts, secrets resolved",
    );
    let _ = INSTALLED.set(ic.clone());
    Ok(Some(ic))
}

/// `SBX_EGRESS_CA_FILE`: internal CAs the route hosts' certificates may chain
/// to, on top of the system roots.
fn upstream_ca_pem(cfg: &Config) -> anyhow::Result<String> {
    if cfg.egress_ca_file.is_empty() {
        return Ok(String::new());
    }
    std::fs::read_to_string(&cfg.egress_ca_file)
        .with_context(|| format!("reading SBX_EGRESS_CA_FILE {}", cfg.egress_ca_file))
}

/// `qafas proxy` in its container: everything arrives in `SBX_ROUTES_JSON`.
pub fn from_env() -> anyhow::Result<Option<Arc<Intercept>>> {
    let Some(text) = std::env::var("SBX_ROUTES_JSON").ok().filter(|s| !s.is_empty()) else { return Ok(None) };
    std::env::remove_var("SBX_ROUTES_JSON");
    let ic = Intercept::from_wire(&text)?;
    tracing::info!(routes = ic.routes.len(), ca = %ic.ca.fingerprint(), "egress routes received");
    Ok(Some(Arc::new(ic)))
}

/// `doctor`'s line: `None` on a host without routes.
pub fn doctor(cfg: &Config) -> Option<(bool, String)> {
    let policy = read_policy(cfg);
    if policy.routes.is_empty() {
        return None;
    }
    let names: Vec<&str> = policy.routes.iter().map(|r| r.name.as_str()).collect();
    if let Err(e) =
        resolve_routes(&policy).and_then(|_| upstream_ca_pem(cfg).and_then(|p| upstream_config(&p).map(|_| ())))
    {
        return Some((false, format!("{e:#}")));
    }
    let dir = Path::new(&cfg.state_dir).join("egress-ca");
    let ca = match std::fs::read(dir.join("ca.pem")) {
        Ok(pem) => format!("CA {}", crate::tls::fingerprint(&pem).unwrap_or_else(|_| "unreadable".into())),
        Err(_) => format!("CA made at first serve in {}", dir.display()),
    };
    Some((true, format!("{} ({}), {ca}, secrets resolved", names.len(), names.join(", "))))
}

/// The system roots plus the operator's internal CAs.
fn upstream_config(extra: &str) -> anyhow::Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    if let Some(pem) = agent_core::ca::SYSTEM_BUNDLES.iter().find_map(|p| std::fs::read(p).ok()) {
        roots.add_parsable_certificates(CertificateDer::pem_slice_iter(&pem).filter_map(Result::ok));
    }
    if !extra.is_empty() {
        let (added, _) =
            roots.add_parsable_certificates(CertificateDer::pem_slice_iter(extra.as_bytes()).filter_map(Result::ok));
        anyhow::ensure!(added > 0, "SBX_EGRESS_CA_FILE holds no usable certificate");
    }
    let mut c = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(c)
}

impl Intercept {
    pub fn new(defs: Vec<RouteDef>, ca: Ca, upstream_ca: String) -> anyhow::Result<Self> {
        let leaf_key = KeyPair::generate()?;
        let leaf_signer = provider()
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()))
            .map_err(|e| anyhow::anyhow!("leaf key: {e}"))?;
        let upstream = Arc::new(upstream_config(&upstream_ca)?);
        let routes = defs.into_iter().map(|d| Route::new(d, &ca)).collect();
        Ok(Self { routes, ca, leaf_key, leaf_signer, leaves: Default::default(), upstream, upstream_ca })
    }

    fn from_wire(text: &str) -> anyhow::Result<Self> {
        // The parse error says where, never what: the text holds the secrets.
        let w: Wire = serde_json::from_str(text).map_err(|e| {
            anyhow::anyhow!("SBX_ROUTES_JSON does not parse (line {}, column {})", e.line(), e.column())
        })?;
        let ca = Ca::from_pem(&w.ca_cert, &w.ca_key)?;
        let mut secrets = w.secrets;
        let defs = w
            .routes
            .into_iter()
            .map(|spec| {
                let secret = secrets.remove(&spec.name).map(Secret);
                RouteDef { spec, secret }
            })
            .collect();
        Self::new(defs, ca, w.upstream_ca)
    }

    /// The proxy container's `SBX_ROUTES_JSON`.
    pub fn container_json(&self) -> String {
        let w = Wire {
            routes: self.routes.iter().map(|r| r.spec.clone()).collect(),
            secrets: self
                .routes
                .iter()
                .filter_map(|r| Some((r.name.clone(), r.secret.as_ref()?.expose().to_string())))
                .collect(),
            ca_cert: self.ca.cert_pem.clone(),
            ca_key: self.ca.key.serialize_pem(),
            upstream_ca: self.upstream_ca.clone(),
        };
        serde_json::to_string(&w).expect("plain strings serialise")
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca.cert_pem
    }

    /// Does any route apply to a sandbox of this trust?
    pub fn applies(&self, trust: Trust) -> bool {
        self.routes.iter().any(|r| r.trust.contains(&trust))
    }

    /// The variables a sandbox of `trust` gets: each applicable route's
    /// placeholder, and the CA paths under `ca_dir` (where `POST /ca` writes).
    /// Empty when no route applies.
    pub fn sandbox_env(&self, trust: Trust, ca_dir: &str) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        if !self.applies(trust) {
            return env;
        }
        for r in self.routes.iter().filter(|r| r.trust.contains(&trust)) {
            if let (Some(k), Some(v)) = (&r.env, &r.placeholder) {
                env.insert(k.clone(), v.clone());
            }
        }
        for k in BUNDLE_VARS {
            env.insert(k.into(), format!("{ca_dir}/bundle.pem"));
        }
        env.insert("NODE_EXTRA_CA_CERTS".into(), format!("{ca_dir}/ca.pem"));
        env.insert("SBX_CA_SPKI".into(), self.ca.spki.clone());
        env
    }

    /// `None` when no route binds `host` for this peer: the ordinary policy
    /// decides, exactly as without routes. A peer the route does not apply to
    /// (by trust, or one the daemon does not know) is not given the host either.
    /// A peer the daemon could not be asked about is refused: handing it to
    /// the ordinary policy would make a route host that `allow` also lists a
    /// blind tunnel, past the rules, for a sandbox the route applies to.
    pub async fn claim(
        &self,
        ctx: &ProxyCtx,
        peer: IpAddr,
        connect: bool,
        host: &str,
        port: u16,
        ips: &[IpAddr],
    ) -> Option<Claim> {
        let host = host_norm(host);
        if !self.routes.iter().any(|r| r.binds(&host)) {
            return None;
        }
        let trust = match ctx.trust {
            Some(t) => t,
            None => match ctx.peer_info(peer).await {
                Ok(p) => p?.trust,
                Err(why) => {
                    tracing::warn!(%peer, error = %why, "peer lookup failed; a route host is refused");
                    let first = self.routes.iter().find(|r| r.binds(&host)).map(|r| r.name.clone());
                    return Some(Claim::Deny("peer lookup failed".into(), first.unwrap_or_default()));
                }
            },
        };
        let mine: Vec<usize> = (0..self.routes.len())
            .filter(|i| self.routes[*i].binds(&host) && self.routes[*i].trust.contains(&trust))
            .collect();
        let first = self.routes[*mine.first()?].name.clone();
        // Every way to the host but TLS on a route port is closed for this
        // sandbox: that is what keeps the rules and the secret on this path.
        if !connect {
            return Some(Claim::Deny("plain http to a route host".into(), first));
        }
        let Some(i) = mine.iter().copied().find(|i| self.routes[*i].ports.contains(&port)) else {
            return Some(Claim::Deny(format!("port {port} is not a route port"), first));
        };
        if ips.is_empty() {
            return Some(Claim::Deny("dns resolution failed".into(), first));
        }
        // Allowed by being a route host; the address rules still hold.
        if let Err(why) = ctx.policy.check_addresses(ips) {
            return Some(Claim::Deny(why, first));
        }
        Some(Claim::Tunnel(i))
    }

    /// A TLS server config that presents a leaf for `host` (signed by the CA,
    /// a few days valid, cached) and speaks HTTP/1.1 only.
    fn server_config(&self, host: &str) -> anyhow::Result<Arc<rustls::ServerConfig>> {
        let host = host_norm(host);
        let mut cache = self.leaves.lock().expect("leaf cache");
        if let Some((cfg, made)) = cache.get(&host) {
            if made.elapsed() < LEAF_TTL {
                return Ok(cfg.clone());
            }
        }
        let mut p = CertificateParams::new(vec![host.clone()])?;
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, host.clone());
        let mut serial = random::<16>();
        serial[0] &= 0x7f;
        p.serial_number = Some(SerialNumber::from_slice(&serial));
        let ((y0, m0, d0), (y1, m1, d1)) = (ymd(-1), ymd(2));
        p.not_before = rcgen::date_time_ymd(y0, m0, d0);
        p.not_after = rcgen::date_time_ymd(y1, m1, d1);
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.use_authority_key_identifier_extension = true;
        let leaf = p.signed_by(&self.leaf_key, &Issuer::from_params(&self.ca.params, &self.ca.key))?;
        // The CA rides in the chain: Chromium's SPKI allow-list matches a
        // certificate the server presents.
        let key =
            Arc::new(CertifiedKey::new(vec![leaf.der().clone(), self.ca.cert_der.clone()], self.leaf_signer.clone()));
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(ForHost { host: host.clone(), key }));
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        // ponytail: a full cache is emptied, not evicted by age; 256 distinct
        // route hosts within 12 h is past any route file we expect. Upgrade: LRU.
        if cache.len() >= LEAF_CACHE {
            cache.clear();
        }
        cache.insert(host, (cfg.clone(), Instant::now()));
        Ok(cfg)
    }
}

// ------------------------------------------------------------------ serving

const FORBIDDEN: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 24\r\nConnection: close\r\n\r\nblocked by egress policy";

/// The proxy's hook: a refusal, or the tunnel.
#[allow(clippy::too_many_arguments)]
pub async fn serve(
    mut sock: TcpStream,
    peer: SocketAddr,
    ctx: Arc<ProxyCtx>,
    ic: Arc<Intercept>,
    claim: Claim,
    host: String,
    port: u16,
    ips: Vec<IpAddr>,
) -> anyhow::Result<()> {
    let route = match claim {
        Claim::Tunnel(i) => i,
        Claim::Deny(reason, route) => {
            sock.write_all(FORBIDDEN).await?;
            let data = json!({"host": host, "port": port, "bytes": 0, "route": route, "reason": reason});
            crate::proxy::emit(&ctx, peer, EventType::EgressDeny, data).await;
            return Ok(());
        }
    };
    let addrs = ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
    tunnel(sock, peer, ctx, ic, route, host, port, addrs).await
}

/// 200, TLS as `host`, then one HTTP/1.1 conversation. `addrs` are the
/// addresses the policy approved: every upstream connection goes to them, and
/// the name is never resolved again.
#[allow(clippy::too_many_arguments)]
pub async fn tunnel(
    mut sock: TcpStream,
    peer: SocketAddr,
    ctx: Arc<ProxyCtx>,
    ic: Arc<Intercept>,
    route: usize,
    host: String,
    port: u16,
    addrs: Vec<SocketAddr>,
) -> anyhow::Result<()> {
    let host = host_norm(&host);
    sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
    let tls = match tokio_rustls::TlsAcceptor::from(ic.server_config(&host)?).accept(sock).await {
        Ok(t) => t,
        Err(e) => {
            let name = ic.routes[route].name.clone();
            let data = json!({"host": host, "port": port, "bytes": 0, "route": name, "reason": format!("tls handshake failed: {e}")});
            crate::proxy::emit(&ctx, peer, EventType::EgressDeny, data).await;
            return Ok(());
        }
    };
    let conn = Arc::new(Conn { ctx, ic, route, host, port, addrs, peer });
    let svc = hyper::service::service_fn(move |req| {
        let c = conn.clone();
        async move { Ok::<_, Infallible>(c.request(req).await) }
    });
    if let Err(e) =
        hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), svc).with_upgrades().await
    {
        tracing::debug!(error = %e, %peer, "intercepted connection ended");
    }
    Ok(())
}

type Body = UnsyncBoxBody<Bytes, hyper::Error>;

fn text(status: StatusCode, msg: &'static str) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::from_static(msg.as_bytes())).map_err(|n| match n {}).boxed_unsync());
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    r
}

struct Conn {
    ctx: Arc<ProxyCtx>,
    ic: Arc<Intercept>,
    route: usize,
    host: String,
    port: u16,
    addrs: Vec<SocketAddr>,
    peer: SocketAddr,
}

impl Conn {
    fn route(&self) -> &Route {
        &self.ic.routes[self.route]
    }

    /// The tunnel's host, as an authority: the port only when it is not 443.
    fn authority(&self) -> String {
        let h = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        match self.port {
            443 => h,
            p => format!("{h}:{p}"),
        }
    }

    /// Every name the request gives for its target must be the tunnel's: the
    /// secret is for this host, and a CDN in front of it would route a `Host`
    /// of somebody else's to somebody else.
    fn same_host(&self, req: &Request<Incoming>) -> bool {
        let ok = |a: &str| {
            let (h, p) = match a.strip_prefix('[') {
                Some(v6) => match v6.split_once(']') {
                    Some((h, tail)) => (h, tail.strip_prefix(':')),
                    None => (v6, None),
                },
                None => match a.split_once(':') {
                    Some((h, p)) if !p.contains(':') => (h, Some(p)),
                    _ => (a, None),
                },
            };
            host_norm(h) == self.host && p.is_none_or(|p| p.parse() == Ok(self.port))
        };
        if req.uri().authority().is_some_and(|a| !ok(a.as_str())) {
            return false;
        }
        let hosts: Vec<_> = req.headers().get_all(header::HOST).iter().collect();
        match hosts.as_slice() {
            [] => true,
            [h] => h.to_str().is_ok_and(ok),
            _ => false,
        }
    }

    async fn deny(&self, mut data: serde_json::Value, started: Instant, reason: &str) {
        data["reason"] = json!(reason);
        data["bytes"] = json!(0);
        data["duration_ms"] = json!(started.elapsed().as_millis() as u64);
        crate::proxy::emit(&self.ctx, self.peer, EventType::EgressDeny, data).await;
    }

    async fn request(self: Arc<Self>, mut req: Request<Incoming>) -> Response<Body> {
        let started = Instant::now();
        let r = self.route();
        let method = req.method().as_str().to_string();
        let path = req.uri().path().to_string();
        let mut data = json!({
            "host": self.host, "port": self.port, "method": method, "path": path,
            "route": r.name, "injected": [],
        });
        if req.method() == hyper::Method::CONNECT {
            self.deny(data, started, "connect inside a route tunnel").await;
            return text(StatusCode::FORBIDDEN, "blocked by egress policy");
        }
        if !self.same_host(&req) {
            self.deny(data, started, "host header is not the tunnel's host").await;
            return text(StatusCode::FORBIDDEN, "blocked by egress policy");
        }
        if !r.allows(&method, &path) {
            self.deny(data, started, "l7 rule").await;
            return text(StatusCode::FORBIDDEN, "blocked by egress policy");
        }

        // An upgrade leaves HTTP, and the rules with it: only a WebSocket, whose
        // handshake the rules just checked, is relayed. `h2c` would carry
        // requests the rules never see.
        let upgrade = req.headers().contains_key(header::UPGRADE);
        if upgrade && !only_websocket(req.headers()) {
            self.deny(data, started, "upgrade other than websocket").await;
            return text(StatusCode::BAD_REQUEST, "only a websocket upgrade is relayed");
        }
        let from_client = upgrade.then(|| hyper::upgrade::on(&mut req));
        let (mut head, body) = req.into_parts();
        let injected = self.rewrite(&mut head, upgrade);
        if injected {
            data["injected"] = json!([r.name]);
        }
        let sent = Arc::new(AtomicU64::new(0));
        let up_req = Request::from_parts(head, Tap::new(body, None, sent.clone()));
        let mut resp = match self.send(up_req).await {
            Ok(resp) => resp,
            Err(why) => {
                tracing::info!(host = %self.host, port = self.port, error = %why, "route upstream failed");
                self.deny(data, started, &why).await;
                return text(StatusCode::BAD_GATEWAY, "upstream unavailable");
            }
        };

        if resp.status() == StatusCode::SWITCHING_PROTOCOLS && !only_websocket(resp.headers()) {
            self.deny(data, started, "upstream switched to a protocol other than websocket").await;
            return text(StatusCode::BAD_GATEWAY, "upstream unavailable");
        }
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS && from_client.is_some() {
            // ponytail: an upgraded connection (WebSocket) is relayed as bytes,
            // after the rules check and the swap on its handshake, with no
            // scrubbing of what flows back. Upgrade: a frame-aware scrubber.
            let to_upstream = hyper::upgrade::on(&mut resp);
            let (ctx, peer) = (self.ctx.clone(), self.peer);
            tokio::spawn(async move {
                let (Ok(a), Ok(b)) = tokio::join!(from_client.expect("checked"), to_upstream) else { return };
                let (x, y) =
                    tokio::io::copy_bidirectional(&mut TokioIo::new(a), &mut TokioIo::new(b)).await.unwrap_or((0, 0));
                data["bytes"] = json!(x + y);
                data["duration_ms"] = json!(started.elapsed().as_millis() as u64);
                crate::proxy::emit(&ctx, peer, EventType::EgressAllow, data).await;
            });
            let (mut parts, _) = resp.into_parts();
            redact_headers(&mut parts.headers, &r.needles);
            return Response::from_parts(parts, Empty::new().map_err(|n| match n {}).boxed_unsync());
        }

        let (mut parts, body) = resp.into_parts();
        // The scrubber reads bytes; a compressed body hides the secret from it.
        // The request asked for identity (whatever the client asked for), so
        // this is an upstream that ignored it: the fallback, not the rule.
        // ponytail: identity costs the bandwidth the client meant to save, and
        // an upstream that compresses anyway is refused. Upgrade: decode,
        // scrub, re-encode.
        let encoded = parts
            .headers
            .get(header::CONTENT_ENCODING)
            .is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"));
        if r.secret.is_some() && encoded {
            self.deny(data, started, "encoded response cannot be scrubbed").await;
            return text(StatusCode::BAD_GATEWAY, "upstream unavailable");
        }
        for h in ["connection", "keep-alive", "transfer-encoding", "proxy-connection", "upgrade"] {
            parts.headers.remove(h);
        }
        redact_headers(&mut parts.headers, &r.needles);
        let (ctx, peer) = (self.ctx.clone(), self.peer);
        let done = Box::new(move |got: u64| {
            data["bytes"] = json!(sent.load(Ordering::Relaxed) + got);
            data["duration_ms"] = json!(started.elapsed().as_millis() as u64);
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move { crate::proxy::emit(&ctx, peer, EventType::EgressAllow, data).await });
            }
        });
        let scrub = (r.secret.is_some()).then(|| Scrub::new(r.needles.clone()));
        let mut tap = Tap::new(body, scrub, Arc::new(AtomicU64::new(0)));
        tap.done = Some(done);
        Response::from_parts(parts, tap.boxed_unsync())
    }

    /// The upstream head: this hop's headers gone, the target in origin form,
    /// the placeholder swapped, `inject` applied. True when the secret is in it.
    fn rewrite(&self, head: &mut hyper::http::request::Parts, upgrade: bool) -> bool {
        let r = self.route();
        let listed: Vec<String> = head
            .headers
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(',').map(|t| t.trim().to_ascii_lowercase()))
            .collect();
        let framed = head.headers.contains_key(header::TRANSFER_ENCODING);
        let mut h = HeaderMap::new();
        for (name, value) in head.headers.iter() {
            let n = name.as_str();
            if HOP.contains(&n) || listed.iter().any(|l| l == n) || n == "host" || (framed && n == "content-length") {
                continue;
            }
            // The scrubber needs plain bytes back, and whole ones: a range of a
            // reflected secret is a piece no needle matches.
            if r.secret.is_some() && matches!(n, "accept-encoding" | "range" | "if-range") {
                continue;
            }
            if !r.rules.is_empty() && OVERRIDES.contains(&n) {
                continue;
            }
            h.append(name.clone(), value.clone());
        }
        let mut injected = false;
        let mut query = head.uri.query().map(str::to_string);
        if let (Some(ph), Some(secret)) = (&r.placeholder, &r.secret) {
            let inj_name = r.inject.as_ref().and_then(|i| HeaderName::from_bytes(i.header.as_bytes()).ok());
            // `inject`'s header is the proxy's to set: a copy the sandbox sent
            // without the placeholder in it does not go out.
            if let Some(n) = &inj_name {
                if !h.get_all(n).iter().any(|v| carries(n, v, ph)) {
                    h.remove(n);
                }
            }
            let names: Vec<HeaderName> = h.keys().cloned().collect();
            for name in names {
                if let header::Entry::Occupied(mut e) = h.entry(name.clone()) {
                    for v in e.iter_mut() {
                        if let Some(new) = swap_value(&name, v, ph, secret.expose()) {
                            *v = new;
                            injected = true;
                        }
                    }
                }
            }
            if let Some(q) = &query {
                if let Some(new) = replace(q.as_bytes(), ph.as_bytes(), pct(secret.expose()).as_bytes()) {
                    query = Some(String::from_utf8(new).expect("ascii in, ascii out"));
                    injected = true;
                }
            }
            if let (false, Some(n), Some(i)) = (injected, inj_name, &r.inject) {
                if let Ok(v) = HeaderValue::from_str(&i.format.replace("{secret}", secret.expose())) {
                    h.insert(n, v);
                    injected = true;
                }
            }
            h.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        }
        h.insert(header::HOST, HeaderValue::from_str(&self.authority()).expect("a host is a header value"));
        if upgrade {
            // `request` let nothing but a WebSocket through.
            h.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        } else {
            // ponytail: one upstream connection per request. Upgrade: a pool
            // per (route, address), if a route's latency ever shows in a trace.
            h.insert(header::CONNECTION, HeaderValue::from_static("close"));
        }
        let target = match &query {
            Some(q) => format!("{}?{q}", head.uri.path()),
            None => head.uri.path().to_string(),
        };
        head.uri = target.parse().unwrap_or_else(|_| hyper::Uri::from_static("/"));
        head.version = hyper::Version::HTTP_11;
        head.headers = h;
        injected
    }

    /// One TLS connection to the approved addresses, verified as the host.
    /// The timeout bounds reaching it, not the request: an upload or a slow
    /// answer takes as long as it takes, as in a blind tunnel.
    async fn send(&self, req: Request<Tap>) -> Result<Response<Incoming>, String> {
        let reach = async {
            let tcp = TcpStream::connect(&self.addrs[..]).await.map_err(|_| "upstream connect failed".to_string())?;
            let _ = tcp.set_nodelay(true);
            let name = ServerName::try_from(self.host.clone())
                .map_err(|_| "upstream name is not a server name".to_string())?;
            let tls = tokio_rustls::TlsConnector::from(self.ic.upstream.clone())
                .connect(name, tcp)
                .await
                .map_err(|e| format!("upstream tls failed: {e}"))?;
            hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .map_err(|e| format!("upstream http failed: {e}"))
        };
        let (mut sender, conn) =
            tokio::time::timeout(UPSTREAM_TIMEOUT, reach).await.unwrap_or_else(|_| Err("upstream timed out".into()))?;
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        sender.send_request(req).await.map_err(|e| format!("upstream request failed: {e}"))
    }
}

/// The comma-separated tokens of every value of `name`, trimmed, lower-cased,
/// empty ones dropped. A value that is not UTF-8 is a token nothing matches.
fn tokens(h: &HeaderMap, name: HeaderName) -> Vec<String> {
    h.get_all(name)
        .iter()
        .flat_map(|v| {
            String::from_utf8_lossy(v.as_bytes()).split(',').map(|t| t.trim().to_ascii_lowercase()).collect::<Vec<_>>()
        })
        .filter(|t| !t.is_empty())
        .collect()
}

/// `Upgrade` names exactly the WebSocket protocol, in any case, and nothing else.
fn only_websocket(h: &HeaderMap) -> bool {
    let t = tokens(h, header::UPGRADE);
    !t.is_empty() && t.iter().all(|t| t == "websocket")
}

fn redact_headers(h: &mut HeaderMap, needles: &[Vec<u8>]) {
    if needles.is_empty() {
        return;
    }
    for v in h.values_mut() {
        let mut b = v.as_bytes().to_vec();
        if redact(&mut b, needles) {
            *v = HeaderValue::from_bytes(&b).unwrap_or_else(|_| HeaderValue::from_static("*"));
        }
    }
}

/// Streaming redaction. The last `longest - 1` bytes of each chunk are held
/// back until the next one arrives, so a secret split across two chunks is
/// whole in the buffer when it is searched.
struct Scrub {
    needles: Arc<Vec<Vec<u8>>>,
    carry: Vec<u8>,
    keep: usize,
}

impl Scrub {
    fn new(needles: Arc<Vec<Vec<u8>>>) -> Self {
        let keep = needles.iter().map(Vec::len).max().unwrap_or(1).saturating_sub(1);
        Self { needles, carry: Vec::new(), keep }
    }

    fn push(&mut self, data: &[u8]) -> Bytes {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(data);
        redact(&mut buf, &self.needles);
        let cut = buf.len().saturating_sub(self.keep);
        self.carry = buf.split_off(cut);
        Bytes::from(buf)
    }

    fn finish(&mut self) -> Bytes {
        let mut buf = std::mem::take(&mut self.carry);
        redact(&mut buf, &self.needles);
        Bytes::from(buf)
    }
}

/// A body passed through: counted, and scrubbed when `scrub` is set. `done`
/// runs once, when the body is finished or dropped, with the bytes it carried.
struct Tap {
    inner: Incoming,
    scrub: Option<Scrub>,
    bytes: Arc<AtomicU64>,
    trailers: Option<HeaderMap>,
    ended: bool,
    done: Option<Box<dyn FnOnce(u64) + Send>>,
}

impl Tap {
    fn new(inner: Incoming, scrub: Option<Scrub>, bytes: Arc<AtomicU64>) -> Self {
        Self { inner, scrub, bytes, trailers: None, ended: false, done: None }
    }
}

impl hyper::body::Body for Tap {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        loop {
            if let Some(t) = this.trailers.take() {
                return Poll::Ready(Some(Ok(Frame::trailers(t))));
            }
            if this.ended {
                return Poll::Ready(None);
            }
            let frame = match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(Some(Ok(f))) => f,
                Poll::Ready(None) => {
                    this.ended = true;
                    match this.scrub.as_mut().map(Scrub::finish).filter(|t| !t.is_empty()) {
                        Some(tail) => return Poll::Ready(Some(Ok(Frame::data(tail)))),
                        None => continue,
                    }
                }
            };
            let frame = match frame.into_data() {
                Ok(d) => {
                    this.bytes.fetch_add(d.len() as u64, Ordering::Relaxed);
                    let out = match this.scrub.as_mut() {
                        Some(s) => s.push(&d),
                        None => d,
                    };
                    if out.is_empty() {
                        continue;
                    }
                    return Poll::Ready(Some(Ok(Frame::data(out))));
                }
                Err(f) => f,
            };
            if let Ok(mut t) = frame.into_trailers() {
                let tail = match this.scrub.as_mut() {
                    Some(s) => {
                        redact_headers(&mut t, &s.needles);
                        s.finish()
                    }
                    None => Bytes::new(),
                };
                this.trailers = Some(t);
                if !tail.is_empty() {
                    return Poll::Ready(Some(Ok(Frame::data(tail))));
                }
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        // Redaction keeps the length, so the upstream's hint stays true.
        self.inner.size_hint()
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            done(self.bytes.load(Ordering::Relaxed));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::Policy;
    use std::sync::Mutex as StdMutex;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    const SECRET: &str = "FAKE-TOKEN-1234";
    const OTHER_SECRET: &str = "OTHER-SECRET-5678";
    const HOST: &str = "api.example.test";

    type Seen = Arc<StdMutex<Vec<(EventType, serde_json::Value)>>>;
    type Got = Arc<StdMutex<Vec<(String, HeaderMap)>>>;
    type Client = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sbx-ic-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// Every form of a secret this file knows a response could carry.
    fn leaks(text: &str, secret: &str) -> Vec<String> {
        let mut forms: Vec<String> =
            needles(secret.as_bytes()).into_iter().map(|n| String::from_utf8(n).unwrap()).collect();
        forms.push(STANDARD.encode(format!("x-access-token:{secret}")));
        forms.into_iter().filter(|f| text.contains(f.as_str())).collect()
    }

    // ---------------------------------------------------------------- upstream

    /// A CA of the upstream's own (what `SBX_EGRESS_CA_FILE` names) and a
    /// server config for `HOST` signed by it.
    fn upstream_tls() -> (String, Arc<rustls::ServerConfig>) {
        let ca_key = KeyPair::generate().unwrap();
        let mut cap = CertificateParams::default();
        cap.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        cap.distinguished_name.push(DnType::CommonName, "upstream test CA");
        cap.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
        let ca = cap.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec![HOST.to_string()])
            .unwrap()
            .signed_by(&leaf_key, &Issuer::from_params(&cap, &ca_key))
            .unwrap();
        let mut sc = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()))
            .unwrap();
        sc.alpn_protocols = vec![b"http/1.1".to_vec()];
        (ca.pem(), Arc::new(sc))
    }

    type UpBody = UnsyncBoxBody<Bytes, Infallible>;

    /// The upstream: records what reached it, echoes it back (the request line
    /// and every header in the body, `Authorization` in a header too), and has
    /// a few paths that misbehave on purpose.
    async fn answer(mut req: Request<Incoming>, got: Got) -> Response<UpBody> {
        let full = |s: String| Full::new(Bytes::from(s)).boxed_unsync();
        let mut dump = format!("{} {}\n", req.method(), req.uri());
        for (k, v) in req.headers() {
            dump.push_str(&format!("{k}: {}\n", String::from_utf8_lossy(v.as_bytes())));
        }
        got.lock().unwrap().push((req.uri().to_string(), req.headers().clone()));
        match req.uri().path() {
            "/split" => {
                // The secret across two writes, far enough apart to be two reads.
                let parts = vec![Bytes::from("before FAKE-TO"), Bytes::from("KEN-1234 after")];
                let s = futures_util::stream::unfold(parts.into_iter(), |mut it| async move {
                    let c = it.next()?;
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Some((Ok::<_, Infallible>(Frame::data(c)), it))
                });
                Response::new(http_body_util::StreamBody::new(s).boxed_unsync())
            }
            "/redirect" => {
                let q = req.uri().query().unwrap_or("").to_string();
                let mut r = Response::new(full(String::new()));
                *r.status_mut() = StatusCode::FOUND;
                let loc = format!("https://other.example.test/landing?{q}");
                r.headers_mut().insert(header::LOCATION, HeaderValue::from_str(&loc).unwrap());
                r
            }
            "/gzip" => {
                let mut r = Response::new(full(dump));
                r.headers_mut().insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                r
            }
            "/ws" => {
                let up = hyper::upgrade::on(&mut req);
                tokio::spawn(async move {
                    if let Ok(u) = up.await {
                        let mut io = TokioIo::new(u);
                        let mut b = [0u8; 4];
                        if io.read_exact(&mut b).await.is_ok() {
                            let _ = io.write_all(&b).await;
                        }
                    }
                });
                let mut r = Response::new(Empty::new().boxed_unsync());
                *r.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                r.headers_mut().insert(header::UPGRADE, HeaderValue::from_static("websocket"));
                r.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
                r
            }
            _ => {
                let auth = req.headers().get(header::AUTHORIZATION).cloned();
                let mut r = Response::new(full(dump));
                if let Some(a) = auth {
                    r.headers_mut().insert("x-echo-auth", a);
                }
                r
            }
        }
    }

    async fn upstream() -> (String, SocketAddr, Got) {
        let (ca, cfg) = upstream_tls();
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let got: Got = Default::default();
        let g = got.clone();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                let (cfg, g) = (cfg.clone(), g.clone());
                tokio::spawn(async move {
                    let Ok(tls) = tokio_rustls::TlsAcceptor::from(cfg).accept(s).await else { return };
                    let svc = hyper::service::service_fn(move |req| {
                        let g = g.clone();
                        async move { Ok::<_, Infallible>(answer(req, g).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .with_upgrades()
                        .await;
                });
            }
        });
        (ca, addr, got)
    }

    // ---------------------------------------------------------------- proxy side

    fn def(v: serde_json::Value, secret: &str) -> RouteDef {
        let spec: EgressRoute = serde_json::from_value(v).unwrap();
        let s = spec.secret.as_ref().map(|_| Secret(secret.into()));
        RouteDef { spec: EgressRoute { secret: None, ..spec }, secret: s }
    }

    fn github() -> serde_json::Value {
        json!({"name": "gh", "hosts": [HOST], "secret": "env://X", "env": "GH_TOKEN"})
    }

    struct H {
        proxy: SocketAddr,
        events: Seen,
        got: Got,
        ic: Arc<Intercept>,
    }

    /// The tunnel for route 0 as the hook would open it: `HOST:443`, the
    /// upstream's address as the approved one, events captured.
    async fn harness(tag: &str, routes: Vec<RouteDef>) -> H {
        let (up_ca, up, got) = upstream().await;
        let ca = Ca::load_or_create(&tmp(tag)).unwrap();
        let ic = Arc::new(Intercept::new(routes, ca, up_ca).unwrap());
        let events: Seen = Default::default();
        let mut ctx = ProxyCtx::new(Policy::from_policy(&EgressPolicy::default()), "h".into(), "t".into());
        let e = events.clone();
        ctx.emit = Some(Arc::new(move |ty, data| e.lock().unwrap().push((ty, data))));
        ctx.trust = Some(Trust::Trusted);
        let ctx = Arc::new(ctx);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = l.local_addr().unwrap();
        let ic2 = ic.clone();
        tokio::spawn(async move {
            loop {
                let (s, peer) = l.accept().await.unwrap();
                let (ctx, ic) = (ctx.clone(), ic2.clone());
                tokio::spawn(async move {
                    let _ = tunnel(s, peer, ctx, ic, 0, HOST.into(), 443, vec![up]).await;
                });
            }
        });
        H { proxy, events, got, ic }
    }

    /// A sandbox's client: past the 200, TLS trusting only the egress CA (and
    /// offering h2 first, which it must not get), HTTP/1.1.
    async fn open(h: &H, sni: &str) -> anyhow::Result<Client> {
        let mut s = TcpStream::connect(h.proxy).await?;
        let mut head = [0u8; 39];
        s.read_exact(&mut head).await?;
        assert!(head.starts_with(b"HTTP/1.1 200"));
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add_parsable_certificates(CertificateDer::pem_slice_iter(h.ic.ca_pem().as_bytes()).filter_map(Result::ok));
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let tls =
            tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(ServerName::try_from(sni.to_string())?, s).await?;
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]), "HTTP/1.1 only");
        let (send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        Ok(send)
    }

    fn req(method: &str, path: &str) -> hyper::http::request::Builder {
        Request::builder().method(method).uri(path).header(header::HOST, HOST)
    }

    async fn call(c: &mut Client, r: hyper::http::request::Builder) -> (StatusCode, HeaderMap, String) {
        let resp = c.send_request(r.body(Full::new(Bytes::new())).unwrap()).await.unwrap();
        let (p, b) = resp.into_parts();
        (p.status, p.headers, String::from_utf8_lossy(&b.collect().await.unwrap().to_bytes()).into_owned())
    }

    /// Events go out when a response body is done, from a spawned task.
    async fn events(h: &H, n: usize) -> Vec<(EventType, serde_json::Value)> {
        for _ in 0..200 {
            if h.events.lock().unwrap().len() >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        h.events.lock().unwrap().clone()
    }

    fn upstream_saw(h: &H, i: usize, name: &str) -> Vec<String> {
        let got = h.got.lock().unwrap();
        got[i].1.get_all(name).iter().map(|v| v.to_str().unwrap().to_string()).collect()
    }

    // ---------------------------------------------------------------- swap and scrub

    /// The placeholder becomes the secret in a header, in a Basic password and
    /// in a query value; the upstream's echo of it comes back with every form
    /// of the secret overwritten, in headers and body; nothing the proxy emits
    /// or logs carries any of it.
    #[tokio::test]
    async fn the_placeholder_is_swapped_out_and_the_secret_never_comes_back() {
        let logs = Arc::new(StdMutex::new(Vec::<u8>::new()));
        #[derive(Clone)]
        struct Buf(Arc<StdMutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf(logs.clone());
        let sub = tracing_subscriber::fmt().with_max_level(tracing::Level::TRACE).with_writer(move || buf.clone());
        let _g = tracing::subscriber::set_default(sub.finish());

        let h = harness("swap", vec![def(github(), SECRET)]).await;
        let ph = h.ic.routes[0].placeholder.clone().unwrap();
        let mut c = open(&h, HOST).await.unwrap();

        let (s, hd, body) = call(&mut c, req("GET", "/echo").header("authorization", format!("Bearer {ph}"))).await;
        assert_eq!(s, 200);
        assert_eq!(upstream_saw(&h, 0, "authorization"), [format!("Bearer {SECRET}")], "the real secret went upstream");
        assert!(body.contains("authorization: Bearer ***************"), "{body}");
        assert_eq!(hd["x-echo-auth"], "Bearer ***************");

        let basic = STANDARD.encode(format!("x-access-token:{ph}"));
        let (_, hd, body) = call(&mut c, req("GET", "/echo").header("authorization", format!("Basic {basic}"))).await;
        let sent = STANDARD.encode(format!("x-access-token:{SECRET}"));
        assert_eq!(upstream_saw(&h, 1, "authorization"), [format!("Basic {sent}")], "decoded, swapped, re-encoded");
        assert!(leaks(&body, SECRET).is_empty() && leaks(hd["x-echo-auth"].to_str().unwrap(), SECRET).is_empty());

        let (_, _, body) = call(&mut c, req("GET", &format!("/echo?a=1&token={ph}&b=2"))).await;
        assert_eq!(h.got.lock().unwrap()[2].0, format!("/echo?a=1&token={SECRET}&b=2"));
        assert!(body.starts_with("GET /echo?a=1&token=***************&b=2"), "{body}");

        let evs = events(&h, 3).await;
        assert_eq!(evs.len(), 3, "one event per request: {evs:?}");
        for (ty, d) in &evs {
            assert_eq!(*ty, EventType::EgressAllow);
            assert_eq!(
                (d["host"].as_str(), d["port"].as_u64(), d["route"].as_str()),
                (Some(HOST), Some(443), Some("gh"))
            );
            assert_eq!(d["injected"], json!(["gh"]));
            assert_eq!(d["path"], "/echo", "the path, never the query");
            assert!(d["bytes"].as_u64().unwrap() > 0 && d["duration_ms"].is_u64() && d["peer"].is_string(), "{d}");
        }
        let all = format!("{evs:?}{}", String::from_utf8_lossy(&logs.lock().unwrap()));
        assert!(leaks(&all, SECRET).is_empty(), "the secret in an event or a log line: {:?}", leaks(&all, SECRET));
        assert!(!all.contains(&ph), "nor the placeholder-swapped values");
    }

    /// A secret split across two upstream writes is still removed.
    #[tokio::test]
    async fn a_secret_split_across_two_chunks_is_still_scrubbed() {
        let h = harness("split", vec![def(github(), SECRET)]).await;
        let mut c = open(&h, HOST).await.unwrap();
        let (_, _, body) = call(&mut c, req("GET", "/split")).await;
        assert_eq!(body, "before *************** after");
    }

    #[test]
    fn scrubbing_holds_at_every_split_point() {
        let body = format!("x {SECRET} y {} z", STANDARD.encode(format!("u:{SECRET}")));
        for cut in 0..body.len() {
            let mut s = Scrub::new(Arc::new(needles(SECRET.as_bytes())));
            let mut out = s.push(&body.as_bytes()[..cut]).to_vec();
            out.extend_from_slice(&s.push(&body.as_bytes()[cut..]));
            out.extend_from_slice(&s.finish());
            let out = String::from_utf8(out).unwrap();
            assert_eq!(out.len(), body.len(), "same length, so Content-Length stays true");
            assert!(leaks(&out, SECRET).is_empty(), "cut at {cut}: {out}");
        }
    }

    /// `inject` adds the header when nothing carried the placeholder, and a
    /// copy the sandbox set itself never goes out.
    #[tokio::test]
    async fn inject_adds_the_header_and_a_sandbox_copy_is_dropped() {
        let mut r = github();
        r["inject"] = json!({"header": "X-Api-Key", "format": "key {secret}"});
        let h = harness("inject", vec![def(r, SECRET)]).await;
        let ph = h.ic.routes[0].placeholder.clone().unwrap();
        let mut c = open(&h, HOST).await.unwrap();

        call(&mut c, req("GET", "/echo").header("x-api-key", "chosen-by-the-sandbox")).await;
        assert_eq!(upstream_saw(&h, 0, "x-api-key"), [format!("key {SECRET}")]);
        call(&mut c, req("GET", &format!("/echo?t={ph}")).header("x-api-key", "chosen-by-the-sandbox")).await;
        assert!(upstream_saw(&h, 1, "x-api-key").is_empty(), "the query carried it; the sandbox's copy is gone");
        call(&mut c, req("GET", "/echo").header("x-api-key", format!("key {ph}"))).await;
        assert_eq!(upstream_saw(&h, 2, "x-api-key"), [format!("key {SECRET}")], "a placeholder in it is swapped");
        call(&mut c, req("GET", "/echo")).await;
        assert_eq!(upstream_saw(&h, 3, "x-api-key"), [format!("key {SECRET}")], "absent: added");
        assert_eq!(upstream_saw(&h, 3, "accept-encoding"), ["identity"], "the scrubber gets plain bytes");
    }

    /// The secret is bound to its route: another route's placeholder on this
    /// tunnel goes out as it came.
    #[tokio::test]
    async fn a_placeholder_only_becomes_its_own_routes_secret() {
        let other =
            json!({"name": "other", "hosts": ["other.example.test"], "secret": "env://Y", "env": "OTHER_TOKEN"});
        let h = harness("bind", vec![def(github(), SECRET), def(other, OTHER_SECRET)]).await;
        let theirs = h.ic.routes[1].placeholder.clone().unwrap();
        assert_ne!(theirs, h.ic.routes[0].placeholder.clone().unwrap());
        let mut c = open(&h, HOST).await.unwrap();
        call(&mut c, req("GET", "/echo").header("authorization", format!("Bearer {theirs}"))).await;
        assert_eq!(upstream_saw(&h, 0, "authorization"), [format!("Bearer {theirs}")]);
        let evs = events(&h, 1).await;
        assert_eq!(evs[0].1["injected"], json!([]), "{evs:?}");
    }

    /// A redirect is handed to the sandbox, never followed: the next hop is the
    /// sandbox's own CONNECT, to a host that is not this route's.
    #[tokio::test]
    async fn a_redirect_is_passed_back_not_followed() {
        let h = harness("redirect", vec![def(github(), SECRET)]).await;
        let ph = h.ic.routes[0].placeholder.clone().unwrap();
        let mut c = open(&h, HOST).await.unwrap();
        let (s, hd, _) = call(&mut c, req("GET", &format!("/redirect?tok={ph}"))).await;
        assert_eq!(s, StatusCode::FOUND);
        assert_eq!(hd[header::LOCATION], "https://other.example.test/landing?tok=***************");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(h.got.lock().unwrap().len(), 1, "one request reached the upstream");
    }

    /// Every name the request gives for its target must be the tunnel's.
    #[tokio::test]
    async fn another_host_inside_the_tunnel_is_refused() {
        let h = harness("fronting", vec![def(github(), SECRET)]).await;
        let mut c = open(&h, HOST).await.unwrap();
        let r = Request::builder().uri("/echo").header(header::HOST, "attacker.example");
        assert_eq!(call(&mut c, r).await.0, StatusCode::FORBIDDEN);
        let r = Request::builder().uri("https://attacker.example/echo");
        assert_eq!(call(&mut c, r).await.0, StatusCode::FORBIDDEN);
        let two = req("GET", "/echo").header(header::HOST, "attacker.example");
        assert_eq!(call(&mut c, two).await.0, StatusCode::FORBIDDEN, "two Host headers");
        let r = Request::builder().uri("/echo").header(header::HOST, "API.example.test:443");
        assert_eq!(call(&mut c, r).await.0, 200, "its own name, any case, with its own port");
        assert_eq!(h.got.lock().unwrap().len(), 1);
    }

    /// A client that asks for gzip (git, npm, pip, `curl --compressed`) is
    /// served: the upstream is asked for identity, so the body can be scrubbed.
    /// Only an upstream that compresses anyway is refused, since the scrubber
    /// cannot see into what it sent.
    #[tokio::test]
    async fn a_gzip_client_is_served_plain_and_only_a_gzipping_upstream_is_refused() {
        let h = harness("gzip", vec![def(github(), SECRET)]).await;
        let ph = h.ic.routes[0].placeholder.clone().unwrap();
        let mut c = open(&h, HOST).await.unwrap();
        let asks =
            req("GET", "/echo").header("accept-encoding", "gzip, br").header("authorization", format!("Bearer {ph}"));
        let (s, hd, body) = call(&mut c, asks).await;
        assert_eq!(s, 200);
        assert!(hd.get(header::CONTENT_ENCODING).is_none(), "{hd:?}");
        assert_eq!(upstream_saw(&h, 0, "accept-encoding"), ["identity"], "the client's own wish is replaced");
        assert!(body.contains("Bearer ***************") && leaks(&body, SECRET).is_empty(), "{body}");

        assert_eq!(call(&mut c, req("GET", "/gzip")).await.0, StatusCode::BAD_GATEWAY);
        let evs = events(&h, 2).await;
        let evs = &evs[1..];
        assert_eq!(
            (evs[0].0, evs[0].1["reason"].as_str()),
            (EventType::EgressDeny, Some("encoded response cannot be scrubbed"))
        );
    }

    #[tokio::test]
    async fn a_websocket_upgrade_is_relayed_after_the_rules() {
        let mut r = github();
        r["rules"] = json!([{"paths": ["/ws"]}]);
        let h = harness("ws", vec![def(r, SECRET)]).await;
        let mut c = open(&h, HOST).await.unwrap();
        let up = req("GET", "/ws").header(header::UPGRADE, "websocket").header(header::CONNECTION, "upgrade");
        let resp = c.send_request(up.body(Full::new(Bytes::new())).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
        let mut io = TokioIo::new(hyper::upgrade::on(resp).await.unwrap());
        io.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        io.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping");
        let mut c = open(&h, HOST).await.unwrap();
        let denied = req("GET", "/other").header(header::UPGRADE, "websocket").header(header::CONNECTION, "upgrade");
        assert_eq!(call(&mut c, denied).await.0, StatusCode::FORBIDDEN, "the rules hold for an upgrade too");
    }

    /// An upgrade to anything but a WebSocket (`h2c` would carry requests the
    /// rules never see) is refused before it reaches the upstream.
    #[tokio::test]
    async fn only_a_websocket_upgrade_is_relayed() {
        let mut r = github();
        r["rules"] = json!([{"paths": ["/ws", "/echo"]}]);
        let h = harness("h2c", vec![def(r, SECRET)]).await;
        let refused = ["h2c", "websocket, h2c", "WebSocket/13", "TLS/1.2", ","];
        for up in refused {
            let mut c = open(&h, HOST).await.unwrap();
            let q = req("GET", "/echo")
                .header(header::UPGRADE, up)
                .header(header::CONNECTION, "Upgrade, HTTP2-Settings")
                .header("http2-settings", "AAMAAABkAAQAAP__");
            assert_eq!(call(&mut c, q).await.0, StatusCode::BAD_REQUEST, "{up}");
        }
        let mut c = open(&h, HOST).await.unwrap();
        let two = req("GET", "/echo").header(header::UPGRADE, "websocket").header(header::UPGRADE, "h2c");
        assert_eq!(call(&mut c, two.header(header::CONNECTION, "upgrade")).await.0, StatusCode::BAD_REQUEST);
        assert!(h.got.lock().unwrap().is_empty(), "nothing refused reached the upstream");
        let evs = events(&h, refused.len() + 1).await;
        assert!(evs.iter().all(|(t, d)| *t == EventType::EgressDeny && d["reason"] == "upgrade other than websocket"));

        let mut c = open(&h, HOST).await.unwrap();
        let ws = req("GET", "/ws").header(header::UPGRADE, "WebSocket").header(header::CONNECTION, "Upgrade");
        let resp = c.send_request(ws.body(Full::new(Bytes::new())).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS, "a WebSocket in any case");
        assert_eq!(upstream_saw(&h, 0, "upgrade"), ["websocket"]);
    }

    // ---------------------------------------------------------------- rules

    #[tokio::test]
    async fn rules_allow_by_method_and_path_and_cannot_be_walked_around() {
        let mut r = github();
        r["rules"] = json!([{"methods": ["get"], "paths": ["/org/*"]}]);
        let h = harness("rules", vec![def(r, SECRET)]).await;
        let mut c = open(&h, HOST).await.unwrap();
        assert_eq!(call(&mut c, req("GET", "/org/repo")).await.0, 200, "method compared without case");
        assert_eq!(call(&mut c, req("GET", "/org/repo?next=/../../other")).await.0, 200, "the query is not the path");
        let refused = [
            ("POST", "/org/repo"),
            ("GET", "/other"),
            ("GET", "/org"),
            ("GET", "/org/../other"),
            ("GET", "/org/./../other"),
            ("GET", "/org/%2e%2e/other"),
            ("GET", "/org/%2E%2E/other"),
            ("GET", "/org/.%2e/other"),
            ("GET", "/org/x%2F..%2F..%2Fother"),
            ("GET", "/org/x%2f..%2f..%2fother"),
            ("GET", "/org//../other"),
            ("GET", "/org//x"),
            ("GET", "/org/..;/other"),
            ("GET", "/org/%5c..%5cother"),
            ("GET", "/%6Frg/repo"),
            ("GET", "/org/%zz"),
            ("GET", "/org/%252e%252e/other"),
            ("GET", "/org/%c0%ae%c0%ae/other"),
        ];
        for (m, p) in refused {
            assert_eq!(call(&mut c, req(m, p)).await.0, StatusCode::FORBIDDEN, "{m} {p}");
        }
        assert_eq!(h.got.lock().unwrap().len(), 2, "nothing refused reached the upstream");
        let evs = events(&h, 2 + refused.len()).await;
        let denies: Vec<_> = evs.iter().filter(|(t, _)| *t == EventType::EgressDeny).collect();
        assert_eq!(denies.len(), refused.len());
        assert!(denies.iter().all(|(_, d)| d["reason"] == "l7 rule" && d["method"].is_string() && d["route"] == "gh"));
        assert_eq!((denies[0].1["method"].as_str(), denies[0].1["path"].as_str()), (Some("POST"), Some("/org/repo")));
    }

    /// The rules see the request line, so on a route with rules nothing that
    /// restates the method or the path goes out; on a route with a secret a
    /// response is never partial, so the scrubber always sees whole copies.
    #[tokio::test]
    async fn headers_that_restate_the_request_or_ask_for_a_part_do_not_go_out() {
        let mut r = github();
        r["rules"] = json!([{"methods": ["GET"], "paths": ["/echo"]}]);
        let h = harness("override", vec![def(r, SECRET)]).await;
        let mut c = open(&h, HOST).await.unwrap();
        let mut q =
            req("GET", "/echo").header("range", "bytes=0-3").header("if-range", "\"x\"").header("accept", "*/*");
        for n in OVERRIDES {
            q = q.header(n, "/admin");
        }
        assert_eq!(call(&mut c, q).await.0, 200);
        for n in OVERRIDES.iter().chain(&["range", "if-range"]) {
            assert!(upstream_saw(&h, 0, n).is_empty(), "{n} went out");
        }
        assert_eq!(upstream_saw(&h, 0, "accept"), ["*/*"], "everything else does");

        // No rules: nothing for an override to get around. A secret: no ranges.
        let h = harness("override2", vec![def(github(), SECRET)]).await;
        let mut c = open(&h, HOST).await.unwrap();
        call(&mut c, req("GET", "/echo").header("range", "bytes=0-3").header("x-http-method-override", "PUT")).await;
        assert_eq!(upstream_saw(&h, 0, "x-http-method-override"), ["PUT"]);
        assert!(upstream_saw(&h, 0, "range").is_empty());
    }

    #[test]
    fn canonical_paths() {
        let ok = [
            "/",
            "/org/",
            "/org/repo",
            "/a/b.c/d",
            "/projects/group%2Fproject",
            "/x%20y",
            "/.well-known/x",
            "/a/..b",
            "/price/%E2%82%AC",
            "/100%25",
            "/100%25x",
        ];
        for p in ok {
            assert!(canonical(p), "{p}");
        }
        for p in ["", "org", "/a/../b", "/a/./b", "/a/..", "/a//b", "/%2e", "/a\\b", "/a%5Cb", "/a%00", "/a%2", "/..;x"]
        {
            assert!(!canonical(p), "{p}");
        }
        // Decoded twice, `%252e%252e` is `..`; `%c0%ae` is an overlong `.`; a
        // lone continuation byte or a cut sequence decodes to nothing valid.
        for p in ["/org/%252e%252e/x", "/org/%252F", "/a%25%32%65", "/org/%c0%ae%c0%ae/x", "/a%80", "/a%E2%82"] {
            assert!(!canonical(p), "{p}");
        }
    }

    // ---------------------------------------------------------------- TLS

    #[derive(Debug)]
    struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

    impl rustls::client::danger::ServerCertVerifier for AnyCert {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    #[tokio::test]
    async fn an_sni_for_another_host_is_refused() {
        let h = harness("sni", vec![def(github(), SECRET)]).await;
        // A client that would take any certificate at all: what refuses the
        // handshake can only be the proxy.
        let mut s = TcpStream::connect(h.proxy).await.unwrap();
        let mut head = [0u8; 39];
        s.read_exact(&mut head).await.unwrap();
        let p = provider();
        let cfg = rustls::ClientConfig::builder_with_provider(p.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert(p)))
            .with_no_client_auth();
        let name = ServerName::try_from("evil.example.test".to_string()).unwrap();
        assert!(tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, s).await.is_err());
        let evs = events(&h, 1).await;
        assert!(evs[0].1["reason"].as_str().unwrap().starts_with("tls handshake failed"), "{evs:?}");
        assert!(open(&h, "API.EXAMPLE.TEST").await.is_ok(), "names compare without case");
    }

    // ---------------------------------------------------------------- the hook

    /// A route host as an address literal, so the hook needs no resolver, and
    /// a public one (TEST-NET-3), so the address rules let it through.
    const IP_HOST: &str = "203.0.113.10";

    fn hook_ctx(tag: &str, trust: Option<Trust>, allow: &[&str]) -> (Arc<ProxyCtx>, Seen) {
        let r = json!({"name": "ip", "hosts": [IP_HOST], "secret": "env://X", "env": "IP_TOKEN"});
        let ca = Ca::load_or_create(&tmp(tag)).unwrap();
        let ic = Arc::new(Intercept::new(vec![def(r, SECRET)], ca, String::new()).unwrap());
        let policy = EgressPolicy { allow: allow.iter().map(|s| s.to_string()).collect(), ..Default::default() };
        let mut ctx = ProxyCtx::new(Policy::from_policy(&policy), "h".into(), "t".into());
        let seen: Seen = Default::default();
        let s = seen.clone();
        ctx.emit = Some(Arc::new(move |ty, data| s.lock().unwrap().push((ty, data))));
        (ctx.intercept, ctx.trust) = (Some(ic), trust);
        (Arc::new(ctx), seen)
    }

    async fn through(ctx: Arc<ProxyCtx>, head: &str) -> String {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(crate::proxy::serve(l, ctx));
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(head.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await.unwrap().unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    async fn reason(seen: &Seen) -> String {
        tokio::time::sleep(Duration::from_millis(20)).await;
        seen.lock().unwrap().last().map(|(_, d)| d["reason"].as_str().unwrap_or("").to_string()).unwrap_or_default()
    }

    /// For a sandbox the route applies to, the route port is intercepted — the
    /// answer is a TLS handshake with the egress CA — and every other way to
    /// the host is closed, whatever the allow list says.
    #[tokio::test]
    async fn the_route_port_is_intercepted_and_every_other_way_is_closed() {
        let (ctx, seen) = hook_ctx("hook", Some(Trust::Trusted), &[IP_HOST]);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let ca = ctx.intercept.as_ref().unwrap().ca_pem().to_string();
        tokio::spawn(crate::proxy::serve(l, ctx.clone()));
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("CONNECT {IP_HOST}:443 HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
        let mut head = [0u8; 39];
        s.read_exact(&mut head).await.unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(CertificateDer::pem_slice_iter(ca.as_bytes()).filter_map(Result::ok));
        let cfg = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(IP_HOST.to_string()).unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, s).await;
        assert!(tls.is_ok(), "a leaf for the address, from the egress CA: {:?}", tls.err());

        let r = through(ctx.clone(), &format!("CONNECT {IP_HOST}:8443 HTTP/1.1\r\n\r\n")).await;
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        assert_eq!(reason(&seen).await, "port 8443 is not a route port");
        let r = through(ctx.clone(), &format!("GET http://{IP_HOST}/x HTTP/1.1\r\nHost: {IP_HOST}\r\n\r\n")).await;
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        assert_eq!(reason(&seen).await, "plain http to a route host");
    }

    /// For a sandbox the route does not apply to, the route host is just a
    /// name: not given (no implicit allow), and when the operator listed it,
    /// the ordinary blind tunnel decides — never the interceptor.
    #[tokio::test]
    async fn a_sandbox_the_route_does_not_apply_to_gets_no_route() {
        let (ctx, seen) = hook_ctx("untrusted", Some(Trust::Untrusted), &[]);
        assert!(through(ctx, &format!("CONNECT {IP_HOST}:443 HTTP/1.1\r\n\r\n")).await.starts_with("HTTP/1.1 403"));
        assert_eq!(reason(&seen).await, crate::proxy::NOT_LISTED, "no implicit allow");
        // A shared proxy that cannot place the peer treats it the same way.
        let (ctx, seen) = hook_ctx("unknown", None, &[]);
        assert!(through(ctx, &format!("CONNECT {IP_HOST}:443 HTTP/1.1\r\n\r\n")).await.starts_with("HTTP/1.1 403"));
        assert_eq!(reason(&seen).await, crate::proxy::NOT_LISTED);

        let (ctx, _) = hook_ctx("claims", Some(Trust::Untrusted), &[IP_HOST]);
        let ic = ctx.intercept.clone().unwrap();
        let ip = [IP_HOST.parse().unwrap()];
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(ic.claim(&ctx, peer, true, IP_HOST, 443, &ip).await.is_none(), "listed: the blind tunnel decides");
        assert!(ic.sandbox_env(Trust::Untrusted, "/tmp/qafas-ca").is_empty(), "no placeholder, no CA");
        let (ctx, _) = hook_ctx("claims2", Some(Trust::Trusted), &[]);
        assert!(matches!(ic.claim(&ctx, peer, true, IP_HOST, 443, &ip).await, Some(Claim::Tunnel(0))));
        assert!(ic.claim(&ctx, peer, true, "other.example", 443, &ip).await.is_none(), "not a route host");
    }

    /// A shared proxy that cannot ask the daemon about its peer (an error, or
    /// no answer in time) refuses a route host, even one `allow` lists; only an
    /// address the daemon says nobody has is left to the ordinary policy.
    #[tokio::test]
    async fn a_failed_peer_lookup_refuses_a_route_host() {
        let with = |tag: &str, look: crate::proxy::PeerLookup| {
            let (ctx, seen) = hook_ctx(tag, None, &[IP_HOST]);
            let mut ctx = Arc::into_inner(ctx).unwrap();
            ctx.peer = Some(look);
            (Arc::new(ctx), seen)
        };
        let (ctx, seen) = with("lookup-err", Arc::new(|_| Box::pin(async { Err("daemon answered 500".to_string()) })));
        let r = through(ctx, &format!("CONNECT {IP_HOST}:443 HTTP/1.1\r\n\r\n")).await;
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        assert_eq!(reason(&seen).await, "peer lookup failed");
        let (ty, d) = seen.lock().unwrap().last().cloned().unwrap();
        assert_eq!((ty, d["route"].as_str()), (EventType::EgressDeny, Some("ip")));

        let (ip, peer): ([IpAddr; 1], IpAddr) = ([IP_HOST.parse().unwrap()], "127.0.0.1".parse().unwrap());
        let (ctx, _) = with("lookup-hang", Arc::new(|_| Box::pin(futures_util::future::pending())));
        let c = ctx.intercept.clone().unwrap().claim(&ctx, peer, true, IP_HOST, 443, &ip).await;
        assert!(matches!(c, Some(Claim::Deny(r, _)) if r == "peer lookup failed"), "a timeout is a failure");
        let (ctx, _) = with("lookup-none", Arc::new(|_| Box::pin(async { Ok(None) })));
        let c = ctx.intercept.clone().unwrap().claim(&ctx, peer, true, IP_HOST, 443, &ip).await;
        assert!(c.is_none(), "an address nobody has: the ordinary policy decides");
    }

    /// Hosts no route binds go through `handle` exactly as before.
    #[tokio::test]
    async fn other_hosts_are_decided_as_before() {
        let (ctx, seen) = hook_ctx("others", Some(Trust::Trusted), &["127.0.0.1"]);
        assert!(through(ctx.clone(), "CONNECT 192.0.2.1:443 HTTP/1.1\r\n\r\n").await.starts_with("HTTP/1.1 403"));
        assert_eq!(reason(&seen).await, crate::proxy::NOT_LISTED);
        assert!(through(ctx, "CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n").await.starts_with("HTTP/1.1 403"));
        assert_eq!(reason(&seen).await, "resolves to non-public address 127.0.0.1");
    }

    // ---------------------------------------------------------------- config, CA, delivery

    fn policy(routes: serde_json::Value) -> EgressPolicy {
        serde_json::from_value(json!({ "routes": routes })).unwrap()
    }

    #[test]
    fn a_bad_route_is_an_error_that_names_it_and_never_a_value() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("secret");
        std::fs::create_dir_all(&dir).unwrap();
        let (open_file, ok_file) = (dir.join("open"), dir.join("ok"));
        for (f, mode) in [(&open_file, 0o644), (&ok_file, 0o600)] {
            std::fs::write(f, format!("{SECRET}\n")).unwrap();
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let open_ref = format!("file://{}", open_file.display());
        let ok_ref = format!("file://{}", ok_file.display());
        let r = |extra: serde_json::Value| {
            let mut v = json!({"name": "gh", "hosts": ["github.com"], "secret": ok_ref, "env": "GH_TOKEN"});
            for (k, x) in extra.as_object().unwrap() {
                v[k] = x.clone();
            }
            v
        };
        for (routes, why) in [
            (json!([r(json!({})), r(json!({}))]), "duplicate route name"),
            (json!([r(json!({"hosts": ["*"]}))]), "too broad"),
            (json!([r(json!({"hosts": ["*.com"]}))]), "too broad"),
            (json!([r(json!({"hosts": ["github.com", "*github.com"]}))]), "too broad"),
            (json!([r(json!({"hosts": ["git*.com"]}))]), "too broad"),
            (json!([r(json!({"hosts": ["*.*"]}))]), "too broad"),
            (json!([r(json!({"hosts": ["*.*.example.com"]}))]), "too broad"),
            (json!([r(json!({"hosts": ["api?.example.com"]}))]), "too broad"),
            (json!([r(json!({"hosts": ["api..example.com"]}))]), "too broad"),
            (json!([r(json!({"env": null}))]), "secret needs env"),
            (json!([r(json!({"env": "PATH"}))]), "is not a name"),
            (json!([r(json!({"env": "LD_PRELOAD"}))]), "is not a name"),
            (json!([r(json!({"env": "SSL_CERT_FILE"}))]), "is not a name"),
            (json!([r(json!({"env": "1BAD"}))]), "is not a name"),
            (json!([r(json!({"rules": [{"methods": ["GET"], "paths": []}]}))]), "no paths"),
            (json!([r(json!({"name": "Bad Name"}))]), "name must be"),
            (json!([r(json!({"secret": "env://QAFAS_TEST_SURELY_UNSET"}))]), "is not set"),
            (json!([r(json!({"secret": open_ref}))]), "readable by group or others"),
            (json!([r(json!({"secret": "file://relative"}))]), "absolute path"),
            (json!([r(json!({"secret": "vault://x"}))]), "env://NAME or file://"),
            (json!([r(json!({"inject": {"header": "Host", "format": "{secret}"}}))]), "cannot be injected"),
            (json!([r(json!({"trust": []}))]), "trust is empty"),
        ] {
            let e = match resolve_routes(&policy(routes.clone())) {
                Err(e) => format!("{e:#}"),
                Ok(_) => panic!("accepted {routes}"),
            };
            assert!(e.contains(why) && e.contains("egress route"), "{why}: {e}");
            assert!(!e.contains(SECRET), "{e}");
        }
        let defs = resolve_routes(&policy(json!([r(json!({}))]))).unwrap();
        assert_eq!(defs[0].secret.as_ref().unwrap().expose(), SECRET, "read once, trimmed");
        assert!(defs[0].spec.secret.is_none(), "the reference is not kept");
        assert!(resolve_routes(&policy(json!([r(json!({"secret": "env://PATH"}))]))).is_ok());
        for hosts in [json!(["*.github.com", "github.com"]), json!(["203.0.113.10"]), json!(["2001:db8::1"])] {
            assert!(resolve_routes(&policy(json!([r(json!({"hosts": hosts}))]))).is_ok(), "{hosts}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two routes one connection could match, on a port and a trust both list,
    /// are refused, naming both: the first would win and the other's rules
    /// would never apply. Disjoint hosts, ports or trust still load.
    #[test]
    fn overlapping_routes_are_refused_and_named() {
        let r = |name: &str, hosts: serde_json::Value, extra: serde_json::Value| {
            let mut v = json!({"name": name, "hosts": hosts, "rules": [{"paths": ["/acme/*"]}]});
            for (k, x) in extra.as_object().unwrap() {
                v[k] = x.clone();
            }
            v
        };
        let none = json!({});
        for (a, b) in [
            (json!(["*.example.com"]), json!(["api.example.com"])),
            (json!(["api.example.com"]), json!(["*.example.com"])),
            (json!(["api.example.com"]), json!(["API.example.com."])),
            (json!(["x.test", "*.b.example.com"]), json!(["*.a.b.example.com"])),
        ] {
            let p = policy(json!([r("broad", a.clone(), none.clone()), r("strict", b.clone(), none.clone())]));
            let e = format!("{:#}", resolve_routes(&p).err().unwrap_or_else(|| panic!("accepted {a} then {b}")));
            assert!(e.contains("\"strict\"") && e.contains("\"broad\"") && e.contains("overlaps"), "{e}");
        }
        for (a, b, extra) in [
            (json!(["*.example.com"]), json!(["example.com"]), none.clone()),
            (json!(["api.example.com"]), json!(["www.example.com"]), none.clone()),
            (json!(["*.example.com"]), json!(["api.example.com"]), json!({"ports": [8443]})),
            (json!(["api.example.com"]), json!(["api.example.com"]), json!({"trust": ["untrusted"]})),
        ] {
            let p = policy(json!([r("one", a.clone(), none.clone()), r("two", b.clone(), extra.clone())]));
            assert!(resolve_routes(&p).is_ok(), "{a} {b} {extra}: {:#}", resolve_routes(&p).err().unwrap());
        }
    }

    #[test]
    fn the_secret_holder_never_prints_the_secret() {
        let s = Secret(SECRET.into());
        assert_eq!(format!("{s:?} {s}"), "Secret(<redacted>) <redacted>");
        let d = def(github(), SECRET);
        assert!(!format!("{:?}", d.secret).contains(SECRET));
    }

    /// Made once with the right modes, the same on a second start, and the
    /// placeholders with it; another install's are different.
    #[test]
    fn the_ca_is_made_once_and_the_placeholders_follow_it() {
        use std::os::unix::fs::PermissionsExt;
        let (a, b) = (tmp("ca-a"), tmp("ca-b"));
        let one = Ca::load_or_create(&a).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode(&a), mode(&a.join("ca.key"))), (0o700, 0o600));
        let pem = std::fs::read(a.join("ca.pem")).unwrap();
        let two = Ca::load_or_create(&a).unwrap();
        assert_eq!(std::fs::read(a.join("ca.pem")).unwrap(), pem, "reused, not remade");
        assert_eq!(one.placeholder("gh"), two.placeholder("gh"), "stable across restarts");
        let ph = one.placeholder("gh");
        assert!(ph.starts_with("qafas_ph_gh_") && ph.len() == "qafas_ph_gh_".len() + 24, "{ph}");
        assert_ne!(one.placeholder("gh"), one.placeholder("pypi"));
        assert_ne!(Ca::load_or_create(&b).unwrap().placeholder("gh"), ph, "different on every install");
        assert_eq!(one.spki, two.spki);
        assert!(String::from_utf8_lossy(&pem).contains("BEGIN CERTIFICATE"));

        std::fs::set_permissions(a.join("ca.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Ca::load_or_create(&a).is_err(), "a key others can read is refused");
        std::fs::set_permissions(a.join("ca.key"), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::copy(b.join("ca.pem"), a.join("ca.pem")).unwrap();
        assert!(Ca::load_or_create(&a).is_err(), "a certificate that is not the key's is refused");
        let _ = (std::fs::remove_dir_all(&a), std::fs::remove_dir_all(&b));
    }

    /// The proxy container's copy is the same interceptor: same CA, same
    /// placeholders, same secrets. A broken value says where, not what.
    #[test]
    fn the_container_gets_the_same_interceptor() {
        let ca = Ca::load_or_create(&tmp("wire")).unwrap();
        let ic = Intercept::new(vec![def(github(), SECRET)], ca, String::new()).unwrap();
        let back = Intercept::from_wire(&ic.container_json()).unwrap();
        assert_eq!(back.ca_pem(), ic.ca_pem());
        assert_eq!(back.routes[0].placeholder, ic.routes[0].placeholder);
        assert_eq!(back.routes[0].secret.as_ref().unwrap().expose(), SECRET);
        assert_eq!(back.sandbox_env(Trust::Trusted, "/d"), ic.sandbox_env(Trust::Trusted, "/d"));
        let broken = ic.container_json().replace("\"secrets\":{", "\"secrets\":[");
        let e = Intercept::from_wire(&broken).err().unwrap().to_string();
        assert!(!e.contains(SECRET) && e.contains("column"), "{e}");
    }

    #[test]
    fn a_sandbox_gets_its_placeholders_and_the_ca_paths() {
        let mut both = json!({"name": "both", "hosts": ["x.example"], "secret": "env://Z", "env": "BOTH_TOKEN"});
        both["trust"] = json!(["trusted", "untrusted"]);
        let ca = Ca::load_or_create(&tmp("env")).unwrap();
        let ic = Intercept::new(vec![def(github(), SECRET), def(both, OTHER_SECRET)], ca, String::new()).unwrap();
        let env = ic.sandbox_env(Trust::Trusted, "/tmp/qafas-ca");
        assert_eq!(env["GH_TOKEN"], ic.routes[0].placeholder.clone().unwrap());
        assert_eq!(env["BOTH_TOKEN"], ic.routes[1].placeholder.clone().unwrap());
        for k in BUNDLE_VARS {
            assert_eq!(env[k], "/tmp/qafas-ca/bundle.pem", "{k}");
        }
        assert_eq!(env["NODE_EXTRA_CA_CERTS"], "/tmp/qafas-ca/ca.pem");
        assert_eq!(env["SBX_CA_SPKI"], ic.ca.spki);
        let theirs = ic.sandbox_env(Trust::Untrusted, "/tmp/qafas-ca");
        assert!(!theirs.contains_key("GH_TOKEN") && theirs.contains_key("BOTH_TOKEN"), "only the routes that apply");
        assert!(!format!("{env:?}{theirs:?}").contains(SECRET) && !format!("{env:?}").contains(OTHER_SECRET));
    }

    /// What a host reports (registration, `GET /policy`) has every route but
    /// none of its secrets, not even where they live.
    #[test]
    fn the_reported_policy_has_no_secret_references() {
        let dir = tmp("report");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("egress.json");
        let p = json!({"allow": ["pypi.org"], "routes": [
            {"name": "gh", "hosts": ["github.com"], "secret": "env://QAFAS_GH", "env": "GH_TOKEN"},
            {"name": "f", "hosts": ["f.example"], "secret": "file:///etc/qafas/f.token", "env": "F_TOKEN"}]});
        std::fs::write(&file, p.to_string()).unwrap();
        let mut cfg = Config::resolve(crate::config::FileConfig::default());
        cfg.policy = file.display().to_string();
        let out = crate::api::policy_summary(&cfg).to_string();
        assert!(out.contains("\"gh\"") && out.contains("github.com"), "{out}");
        for no in ["env://", "file://", "QAFAS_GH", "f.token", "\"secret\""] {
            assert!(!out.contains(no), "{no} in {out}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn base64_forms_of_the_secret_are_caught_at_every_alignment() {
        for prefix in ["", "u:", "us:", "use:", "x-access-token:"] {
            let enc = STANDARD.encode(format!("{prefix}{SECRET}"));
            let url = URL_SAFE_NO_PAD.encode(format!("{prefix}{SECRET}?>"));
            let n = needles(SECRET.as_bytes());
            assert!(n.iter().any(|x| enc.contains(std::str::from_utf8(x).unwrap())), "{prefix}");
            assert!(n.iter().any(|x| url.contains(std::str::from_utf8(x).unwrap())), "{prefix}");
        }
        assert!(needles(b"a/b c&d=e").iter().any(|n| n == b"a%2Fb%20c%26d%3De"), "the query form");
    }
}
