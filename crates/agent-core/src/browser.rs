//! `GET /browser/cdp` — lazily launch `chrome-headless-shell` and relay the
//! browser-level DevTools socket. One process per sandbox, one context per
//! session on the client side (D12). Never `--single-process`.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::WebSocket;
use futures_util::SinkExt;

use crate::Ctx;

/// The profile this sandbox's Chromium runs out of, under its own scratch — so
/// two sandboxes in one process (the native tier serves a router per sandbox)
/// neither share a profile nor race for a fixed debugging port.
fn profile_dir() -> std::path::PathBuf {
    std::path::Path::new(&crate::limits::scratch_dir()).join("chrome")
}

/// Chromium's command line. Never `--single-process`, never a blanket
/// `--ignore-certificate-errors`.
fn chromium_args(ctx: &Ctx, profile: &std::path::Path) -> Vec<String> {
    let mut a: Vec<String> = [
        "--headless",
        // 0: the kernel picks, Chromium writes it to DevToolsActivePort. No
        // port to collide over and no bind/launch race to lose.
        "--remote-debugging-port=0",
        "--remote-debugging-address=127.0.0.1",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--no-first-run",
    ]
    .map(String::from)
    .into();
    a.push(format!("--user-data-dir={}", profile.display()));
    if let Ok(p) = std::env::var("HTTP_PROXY") {
        a.push(format!("--proxy-server={p}"));
    }
    // D34: the egress proxy's CA, by its key's hash, for route hosts. Chromium
    // reads no CA file; this trusts exactly certificates chained to that key.
    // The sandbox's env (`PUT /workspace`) on the vm and remote tiers, the
    // shim's own on the native one.
    let spki = ctx.env.read().unwrap().get("SBX_CA_SPKI").cloned().or_else(|| std::env::var("SBX_CA_SPKI").ok());
    if let Some(s) = spki.filter(|s| !s.is_empty()) {
        a.push(format!("--ignore-certificate-errors-spki-list={s}"));
    }
    // The container/VM is already the boundary, and the container denies user
    // namespaces, so Chromium's own userns sandbox cannot start (D12).
    if std::env::var("SBX_CHROME_NO_SANDBOX").as_deref() == Ok("1") {
        a.push("--no-sandbox".into());
    }
    a
}

fn spawn_chromium(ctx: &Ctx) -> std::io::Result<()> {
    let profile = profile_dir();
    // A leftover DevToolsActivePort would otherwise be read as this launch's.
    let _ = std::fs::remove_dir_all(&profile);
    // The Spawner decides the confinement: `pre_exec` hardening without seccomp
    // in a VM (D8), the OS sandbox wrapper on the native tier.
    let mut c = ctx.spawner.helper("chrome-headless-shell");
    c.args(chromium_args(ctx, &profile));
    c.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    let child = c.spawn()?;
    tracing::info!(pid = child.id(), "chromium launched");
    // Deliberately leaked: it must outlive this request and die with the sandbox.
    std::mem::forget(child);
    Ok(())
}

/// `<port>\n<browser ws path>` — what Chromium writes once its DevTools server
/// is listening. It is the endpoint *and* the readiness signal, which is why
/// there is no HTTP client in this binary.
fn read_active_port(profile: &std::path::Path) -> Option<String> {
    let raw = std::fs::read_to_string(profile.join("DevToolsActivePort")).ok()?;
    let (port, path) = raw.trim().split_once('\n')?;
    port.parse::<u16>().ok()?;
    Some(format!("ws://127.0.0.1:{port}{path}"))
}

/// One Chromium per sandbox: the `OnceCell` lives on the sandbox's own `Ctx`,
/// not on the process, so the native tier's second sandbox gets its own browser
/// instead of reaching into the first one's.
async fn endpoint(ctx: &Ctx) -> anyhow::Result<String> {
    ctx.browser
        .get_or_try_init(|| async {
            spawn_chromium(ctx)?;
            let profile = profile_dir();
            for _ in 0..100 {
                if let Some(url) = read_active_port(&profile) {
                    return Ok(url);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(anyhow::anyhow!("chromium did not open a devtools port within 5s"))
        })
        .await
        .cloned()
}

pub async fn cdp(ctx: Arc<Ctx>, socket: WebSocket) {
    let url = match endpoint(&ctx).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "browser launch failed");
            let mut s = socket;
            let _ = s.close().await;
            return;
        }
    };
    let upstream = match tokio_tungstenite::connect_async(&url).await {
        Ok((s, _)) => s,
        Err(e) => {
            tracing::error!(error = %e, url, "cdp connect failed");
            let mut s = socket;
            let _ = s.close().await;
            return;
        }
    };
    // Same shuttling as a preview upgrade, one hop further in.
    crate::proxy::relay(socket, upstream).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D34: with the sandbox's `SBX_CA_SPKI` set, Chromium trusts that key and
    /// nothing wider; without it, the command line is what it was.
    #[test]
    fn the_egress_ca_is_trusted_by_its_key_and_nothing_wider() {
        let ctx = Ctx::new(
            crate::spawn::Hardened::default(),
            crate::Emitter::null(),
            crate::rules::Rules::guest("/tmp", "/tmp/nohome"),
        );
        let p = std::path::Path::new("/tmp/chrome");
        let before = chromium_args(&ctx, p);
        assert!(!before.iter().any(|a| a.contains("ignore-certificate-errors")), "{before:?}");
        ctx.env.write().unwrap().insert("SBX_CA_SPKI".into(), "q1w2e3r4t5y6u7i8o9p0==".into());
        let after = chromium_args(&ctx, p);
        assert!(after.contains(&"--ignore-certificate-errors-spki-list=q1w2e3r4t5y6u7i8o9p0==".to_string()));
        assert!(!after.iter().any(|a| a == "--ignore-certificate-errors" || a == "--single-process"), "{after:?}");
    }
}
