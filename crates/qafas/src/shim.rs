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
    let spawner =
        Hardened { confine: crate::backend::native::linux::confine(&workspace, &scratch), ..Default::default() };
    let ctx = Ctx::new(spawner, serve::emitter(&bus, &env("SBX_HOST_ID", ""), &id), rules);

    // Every exec's process group goes on disk before it runs, so a daemon that
    // dies without calling `destroy` can still clean up on its next start.
    if let Some(scratch) = socket.parent().map(|p| p.to_path_buf()) {
        ctx.mon.on_watch(Arc::new(move |pgid| crate::backend::native::record_group(&scratch, pgid)));
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
        let (stream, _) = listener.accept().await?;
        tokio::spawn(serve::serve_stream(stream, app.clone()));
    }
}
