//! `qafas shim --socket <path>`: the native tier's in-sandbox agent.
//!
//! The daemon spawns this once per native sandbox, already wrapped in the OS
//! sandbox (`sandbox-exec` on macOS, `bwrap` + Landlock + seccomp on Linux). It
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

fn env(k: &str, d: &str) -> String {
    std::env::var(k).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| d.to_string())
}

pub async fn run(socket: PathBuf) -> anyhow::Result<()> {
    let bus = serve::bus();
    let id = env("SBX_ID", "");
    let home = env("HOME", "/tmp");
    let workspace = env("SBX_WORKSPACE", &home);
    let rules = Rules::guest(&workspace, &home);
    let ctx = Ctx::new(Hardened::default(), serve::emitter(&bus, &env("SBX_HOST_ID", ""), &id), rules);

    // Every exec's process group goes on disk before it runs, so a daemon that
    // dies without calling `destroy` can still clean up on its next start.
    if let Some(scratch) = socket.parent().map(|p| p.to_path_buf()) {
        ctx.mon.on_watch(Arc::new(move |pgid| crate::backend::native::record_group(&scratch, pgid)));
    }

    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket)?;
    tracing::info!(sandbox_id = %id, socket = %socket.display(), "shim listening");

    // No PR_SET_PDEATHSIG on macOS: notice the daemon going away by re-parenting.
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if unsafe { libc::getppid() } == 1 {
                tracing::info!("daemon gone; shim exiting");
                std::process::exit(0);
            }
        }
    });

    let app = serve::app(ctx, bus);
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(serve::serve_stream(stream, app.clone()));
    }
}
