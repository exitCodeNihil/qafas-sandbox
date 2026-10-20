//! v3 preview URLs (protocol §3a): signed access to one port inside one
//! sandbox, for a dev server the agent started.
//!
//! No bearer token — a browser cannot set one. The first request carries
//! `?sbx_preview=<token>`, which we turn into an HttpOnly cookie scoped to
//! `/preview/<id>/<port>/` and redirect away, so the token stops appearing in
//! the address bar, in `Referer` and in the dev server's own logs.

use proto::hmac_token;

/// What the HMAC is over. The prefix is what stops a scoped *sandbox* token
/// from being replayed as a preview token and vice versa.
pub fn payload(id: &str, port: u16) -> String {
    format!("preview:{id}:{port}")
}

pub fn mint(secret: &str, id: &str, port: u16, exp_unix: u64) -> String {
    hmac_token::mint(secret, &payload(id, port), exp_unix)
}

pub fn cookie_name(id: &str, port: u16) -> String {
    format!("sbx_preview_{id}_{port}")
}

pub fn verify(secret: &str, token: &str, id: &str, port: u16, now_unix: u64) -> bool {
    hmac_token::verify(secret, token, now_unix).is_some_and(|p| p == payload(id, port))
}

/// The token this request presents, and whether it came from the query string
/// (which is what the cookie-and-redirect dance keys on).
pub fn presented(
    query: Option<&str>,
    cookie: Option<&str>,
    header: Option<&str>,
    id: &str,
    port: u16,
) -> Option<(String, bool)> {
    if let Some(t) = query.and_then(|q| param(q, "sbx_preview")) {
        // A token always has a `:` in it, which a browser or an HTTP client is
        // free to send as `%3A`; the header and the cookie carry it as it is.
        return Some((agent_core::cmdline_decode(&t), true));
    }
    if let Some(t) = header {
        return Some((t.trim().to_string(), false));
    }
    let want = cookie_name(id, port);
    cookie?
        .split(';')
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == want)
        .map(|(_, v)| (v.to_string(), false))
}

fn param(query: &str, key: &str) -> Option<String> {
    query.split('&').filter_map(|kv| kv.split_once('=')).find(|(k, _)| *k == key).map(|(_, v)| v.to_string())
}

/// The query minus `sbx_preview`, so the redirect target is the page the user
/// actually asked for.
pub fn strip_token(query: &str) -> String {
    query.split('&').filter(|kv| !kv.starts_with("sbx_preview=")).collect::<Vec<_>>().join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_preview_token_opens_one_port_of_one_sandbox_and_nothing_else() {
        let (secret, now) = ("dev", 1_000u64);
        let t = mint(secret, "sbx_a", 8000, now + 60);
        assert!(verify(secret, &t, "sbx_a", 8000, now));
        assert!(!verify(secret, &t, "sbx_a", 8001, now), "port is signed");
        assert!(!verify(secret, &t, "sbx_b", 8000, now), "sandbox is signed");
        assert!(!verify(secret, &t, "sbx_a", 8000, now + 61), "expiry is enforced");
        assert!(!verify("other", &t, "sbx_a", 8000, now));
        // A plain sandbox token must not open a preview: no prefix, no match.
        let plain = hmac_token::mint(secret, "sbx_a", now + 60);
        assert!(!verify(secret, &plain, "sbx_a", 8000, now));
    }

    #[test]
    fn the_token_is_found_wherever_a_browser_can_put_it() {
        let (id, port) = ("sbx_a", 8000);
        assert_eq!(presented(Some("sbx_preview=tok&x=1"), None, None, id, port), Some(("tok".into(), true)));
        assert_eq!(presented(None, None, Some("hdr"), id, port), Some(("hdr".into(), false)));
        assert_eq!(presented(None, Some("a=b; sbx_preview_sbx_a_8000=ck"), None, id, port), Some(("ck".into(), false)));
        assert_eq!(
            presented(None, Some("sbx_preview_sbx_a_8001=ck"), None, id, port),
            None,
            "another port's cookie is not this port's"
        );
        assert_eq!(presented(None, None, None, id, port), None);
        assert_eq!(strip_token("a=1&sbx_preview=t&b=2"), "a=1&b=2");
        assert_eq!(strip_token("sbx_preview=t"), "");
    }

    /// Every token has a `:` in it (`payload:signature`), and a client that
    /// percent-encodes the query sends `%3A`. Verified as received, that was a 401.
    #[test]
    fn a_token_whose_colon_was_percent_encoded_still_verifies() {
        let (secret, now) = ("dev", 1_000u64);
        let t = mint(secret, "sbx_a", 8000, now + 60);
        assert!(t.contains(':'), "the premise: a token carries a colon");
        let encoded = t.replace(':', "%3A");
        assert_ne!(encoded, t);

        let (got, from_query) =
            presented(Some(&format!("x=1&sbx_preview={encoded}")), None, None, "sbx_a", 8000).unwrap();
        assert!(from_query);
        assert_eq!(got, t);
        assert!(verify(secret, &got, "sbx_a", 8000, now));
        // The lower-case spelling, and the unencoded one, are the same token.
        let lower = t.replace(':', "%3a");
        assert_eq!(presented(Some(&format!("sbx_preview={lower}")), None, None, "sbx_a", 8000).unwrap().0, t);
        assert_eq!(presented(Some(&format!("sbx_preview={t}")), None, None, "sbx_a", 8000).unwrap().0, t);
        // Decoding must not turn a different token into this one.
        let other = mint(secret, "sbx_b", 8000, now + 60).replace(':', "%3A");
        let (got, _) = presented(Some(&format!("sbx_preview={other}")), None, None, "sbx_a", 8000).unwrap();
        assert!(!verify(secret, &got, "sbx_a", 8000, now));
    }
}
