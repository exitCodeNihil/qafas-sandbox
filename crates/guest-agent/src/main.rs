//! guest-agent: the only thing that runs inside a VM-tier sandbox.
//!
//! Two shapes, one binary:
//!   * Firecracker microVM — PID 1 with euid 0, so it does `init::boot()` first.
//!   * podman container    — PID 1 but uid 1000, no CAP_SYS_ADMIN: boot is skipped.
//!
//! Everything it serves comes from `agent-core` (D17); this crate is init plus
//! the two listeners.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("guest-agent is Linux-only; build with --target <arch>-unknown-linux-musl");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod init;
#[cfg(target_os = "linux")]
mod serve;

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    // Mounting, hostname and the NIC are the microVM path only. As a
    // container entrypoint we are uid 1000 without CAP_SYS_ADMIN and the
    // runtime has already done all of it.
    if std::process::id() == 1 && nix::unistd::geteuid().is_root() {
        init::boot();
    }

    // Build the seccomp programs once, in the parent, so `pre_exec` only has to
    // call prctl(2) on already-allocated BPF.
    agent_core::harden::init_filter();

    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(async {
        // Whoever is PID 1 inherits orphans and has to reap them. Started inside
        // the runtime because the reaper waits on SIGCHLD.
        if std::process::id() == 1 {
            init::start_reaper();
        }
        serve::run().await
    })
}
