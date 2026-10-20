//! `qafas shim --socket <path>`: the native tier's in-sandbox agent.
//!
//! The daemon spawns this once per native sandbox, already wrapped in the OS
//! sandbox (`sandbox-exec` on macOS, `bwrap` on Linux, where every command it
//! spawns also gets Landlock and seccomp). It
//! serves the same handlers as guest-agent on a unix socket in the sandbox's
//! scratch directory, so every command is a plain fork from a confined parent
//! instead of a fresh `sandbox-exec` (which recompiles the profile: ~5 ms on
//! its own, ~8 ms with a login shell). Measured: 8.7 ms → ~2 ms per exec.
//!
//! Its environment is the curated one `backend/native.rs` builds; it never sees
//! the daemon's.

use std::path::PathBuf;
use std::sync::Arc;

use agent_core::rules::Rules;
use agent_core::serve;
use agent_core::spawn::Hardened;
use agent_core::Ctx;

use crate::backend::native::survive_accept;

fn env(k: &str, d: &str) -> String {
    std::env::var(k).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| d.to_string())
}

pub async fn run(socket: PathBuf) -> anyhow::Result<()> {
    // The seccomp programs `Hardened` installs on every command, built once here
    // as guest-agent builds them at its start; without this the shim's commands
    // ran with no filter at all on Linux.
    #[cfg(target_os = "linux")]
    agent_core::harden::init_filter();
    let bus = serve::bus();
    let id = env("SBX_ID", "");
    let home = env("HOME", "/tmp");
    let workspace = env("SBX_WORKSPACE", &home);
    let rules = Rules::guest(&workspace, &home);
    let scratch = socket.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    // Linux: this sandbox's egress proxy port and the daemon's network
    // namespace, both set by the daemon (unset on macOS).
    let proxy_port = std::env::var("SBX_PROXY_PORT").ok().and_then(|p| p.parse::<u16>().ok());
    let private_netns = private_netns(std::env::var("SBX_HOST_NETNS").ok().and_then(|n| n.parse().ok()));
    let confine = crate::backend::native::linux::confine(&workspace, &scratch, proxy_port, private_netns);
    let spawner = Hardened { confine, ..Default::default() };
    let ctx = Ctx::new(spawner, serve::emitter(&bus, &env("SBX_HOST_ID", ""), &id), rules);

    // Every exec's process group goes on disk before it runs, so a daemon that
    // dies without calling `destroy` can still clean up on its next start.
    if let Some(scratch) = socket.parent().map(|p| p.to_path_buf()) {
        ctx.mon.on_watch(Arc::new(move |pgid| crate::backend::native::record_group(&scratch, pgid)));
    }

    // M46: in a network namespace of its own (bwrap `--unshare-net`) the
    // sandbox cannot reach the proxy on the host's loopback. Put it back at the
    // same address, relayed to the daemon's `proxy.sock`. Bound before
    // `agent.sock`, which is what the daemon waits for to call it ready.
    if let (true, Some(port)) = (private_netns, proxy_port) {
        let l = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
        let sock = scratch.join("proxy.sock");
        tokio::spawn(async move {
            if let Err(e) = relay(l, sock).await {
                tracing::warn!(error = %e, "egress proxy relay stopped");
            }
        });
    }

    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket)?;
    tracing::info!(sandbox_id = %id, socket = %socket.display(), "shim listening");

    // No PR_SET_PDEATHSIG on macOS: notice the daemon going away by re-parenting.
    // Re-parenting, not "parent is 1": under bwrap's pid namespace the parent is
    // its init, pid 1 from the start, and that test killed every Linux shim a
    // second after it came up. There `--die-with-parent` covers the daemon.
    let parent = unsafe { libc::getppid() };
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if unsafe { libc::getppid() } != parent {
                tracing::info!("daemon gone; shim exiting");
                std::process::exit(0);
            }
        }
    });

    let app = serve::app(ctx, bus);
    loop {
        // The same bare `?` here would end the shim, and the sandbox with it, on
        // the first EMFILE.
        let Some((stream, _)) = survive_accept(listener.accept().await, "agent.sock").await? else { continue };
        tokio::spawn(serve::serve_stream(stream, app.clone()));
    }
}

/// Whether this shim provably runs in a network namespace other than the
/// daemon's (`host`, from `SBX_HOST_NETNS`). Anything unknown counts as
/// shared, the stricter case for Landlock.
fn private_netns(host: Option<u64>) -> bool {
    matches!((host, crate::backend::native::linux::netns_id()), (Some(h), Some(me)) if h != 0 && h != me)
}

/// M46: relays every connection on `l` to the daemon's `proxy.sock`, which
/// bridges it to this sandbox's egress proxy.
async fn relay(l: tokio::net::TcpListener, sock: PathBuf) -> std::io::Result<()> {
    relay_accepting(|| l.accept(), sock).await
}

/// `relay` over any source of accepted streams (see `bridge_accepting`).
async fn relay_accepting<F, Fut, A>(mut accept: F, sock: PathBuf) -> std::io::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<(tokio::net::TcpStream, A)>>,
{
    loop {
        let Some((mut from, _)) = survive_accept(accept().await, "egress proxy relay").await? else { continue };
        let _ = from.set_nodelay(true);
        let sock = sock.clone();
        tokio::spawn(async move {
            let Ok(mut to) = tokio::net::UnixStream::connect(&sock).await else { return };
            let _ = tokio::io::copy_bidirectional(&mut from, &mut to).await;
        });
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A connection to the relay's TCP port comes out of `proxy.sock`, and
    /// the answer goes back the same way.
    #[tokio::test]
    async fn the_relay_carries_the_proxy_port_to_the_unix_socket() {
        let dir = std::path::PathBuf::from(format!("/tmp/sbx-relay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("proxy.sock");
        let daemon = tokio::net::UnixListener::bind(&sock).unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(super::relay(l, sock));

        let exchange = async {
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            client.write_all(b"CONNECT").await.unwrap();
            let (mut far, _) = daemon.accept().await.unwrap();
            let mut got = [0u8; 7];
            far.read_exact(&mut got).await.unwrap();
            far.write_all(b"200").await.unwrap();
            let mut back = [0u8; 3];
            client.read_exact(&mut back).await.unwrap();
            (got, back)
        };
        let (got, back) = tokio::time::timeout(std::time::Duration::from_secs(5), exchange)
            .await
            .expect("nothing came through the relay within 5 s");
        assert_eq!((&got, &back), (b"CONNECT", b"200"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A failed `accept` (descriptors exhausted, say) must not end the relay: the
    /// sandbox would have no egress for the rest of its life, and `relay` only
    /// logs that it stopped. Two failures, then a real connection.
    #[tokio::test]
    async fn the_relay_keeps_serving_after_accept_fails() {
        let dir = std::path::PathBuf::from(format!("/tmp/sbx-relay2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("proxy.sock");
        let daemon = tokio::net::UnixListener::bind(&sock).unwrap();
        let l = std::sync::Arc::new(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
        let port = l.local_addr().unwrap().port();
        let mut script = std::collections::VecDeque::from([
            Err(std::io::Error::from_raw_os_error(libc::EMFILE)),
            Err(std::io::Error::from_raw_os_error(libc::ENFILE)),
            Ok(()),
        ]);
        let accept = move || {
            let next = script.pop_front();
            let l = l.clone();
            async move {
                match next {
                    Some(Ok(())) => l.accept().await,
                    Some(Err(e)) => Err(e),
                    None => std::future::pending().await,
                }
            }
        };
        let relay = tokio::spawn(super::relay_accepting(accept, sock));

        let exchange = async {
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            client.write_all(b"CONNECT").await.unwrap();
            let (mut far, _) = daemon.accept().await.unwrap();
            let mut got = [0u8; 7];
            far.read_exact(&mut got).await.unwrap();
            got
        };
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), exchange)
            .await
            .expect("the relay stopped serving after a failed accept");
        assert_eq!(&got, b"CONNECT");
        assert!(!relay.is_finished());
        relay.abort();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Only a namespace that is known and differs from the daemon's is
    /// private: an unknown or matching one keeps bind handled by Landlock.
    #[test]
    fn only_a_different_known_namespace_is_private() {
        let me = crate::backend::native::linux::netns_id().expect("/proc/self/ns/net");
        assert!(!super::private_netns(Some(me)), "the daemon's own namespace is shared");
        assert!(!super::private_netns(None), "no SBX_HOST_NETNS is shared");
        assert!(!super::private_netns(Some(0)), "a daemon that could not read its own is shared");
        assert!(super::private_netns(Some(me + 1)));
    }
}
