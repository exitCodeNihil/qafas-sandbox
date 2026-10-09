//! The native tier: the OS's own process sandbox, no container, no VM (D16).
//!
//! One sandbox is a directory and a policy:
//!
//! ```text
//! /tmp/sbx-<id>/
//!   profile.sb     the rendered Seatbelt profile (macOS)
//!   home/          the sandbox's HOME, with canaries and read-only toolchain links
//!   tmp/           scratch
//!   pgid           process groups this sandbox has spawned, for restart safety
//!   agent.sock     the shim's listener
//! ```
//!
//! The agent process is `qafas shim`, spawned once per sandbox *inside* the
//! OS sandbox (`sandbox-exec -f profile.sb` on macOS; `bwrap` + Landlock +
//! seccomp on Linux). It serves the guest-agent handlers on `agent.sock`, so
//! `/sandboxes/{id}/agent/*` goes through exactly the proxy path the VM tier
//! uses, and every command is a plain fork from an already-confined parent.
//! Wrapping each command instead costs a profile compile per exec (~5 ms).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_core::rules::Rules;
use agent_core::spawn::Limits;
use agent_core::{Corr, Emitter};
use proto::Event;
use tokio::sync::Mutex;

use super::{Backend, BoxFut, Connector, Sandbox, Spec};
use crate::config::Config;
use crate::events::Bus;
use crate::seatbelt;

/// A live native sandbox. Keyed by sandbox id in the registry; `sblog` looks
/// sandboxes up here to attribute kernel denial reports, `destroy` to tear down.
pub struct Live {
    pub connector: Connector,
    pub ev: Emitter,
    /// The shim's process group: the shim and everything it ever spawned.
    /// v4: `0` while the sandbox is stopped, so nothing signals process group 0
    /// (which is the daemon's own).
    pgid: std::sync::atomic::AtomicU32,
    /// This sandbox's own egress proxy. One listener per sandbox is what makes
    /// `egress.*` attributable on a tier where every sandbox is 127.0.0.1. It
    /// outlives a `stop`: its port is baked into the profile and the shim's env,
    /// so keeping the listener is what lets `start` reuse both.
    proxy: tokio::task::JoinHandle<()>,
    /// v4. Everything `start` needs to put an identical shim back on the same
    /// socket: the workspace and scratch dir are the sandbox's identity here.
    scratch: PathBuf,
    workspace: String,
    profile: PathBuf,
    env: BTreeMap<String, String>,
    /// v5 §3a. Kept so `start` puts the shim back under the same ceilings.
    limits: std::sync::Mutex<proto::SandboxLimits>,
}

impl Live {
    /// The tool call that owns a pid, asked of the shim (the only process that
    /// knows). Short-lived processes may already be gone: then it is nobody's.
    pub async fn corr_for_pid(&self, pid: u32) -> Corr {
        let procs =
            match super::guest_json::<Vec<agent_core::procmon::ProcInfo>>(&self.connector, "GET", "/processes").await {
                Ok(p) => p,
                Err(_) => return Corr::default(),
            };
        procs
            .into_iter()
            .find(|p| p.pid == pid)
            .map(|p| Corr { pi_session: p.pi_session, tool_call_id: p.tool_call_id })
            .unwrap_or_default()
    }

    /// SIGKILLs the shim's process group and forgets it. A pgid of 0 means the
    /// sandbox is already stopped — and `killpg(0)` would signal *our* group.
    fn kill_shim(&self) {
        let pgid = self.pgid.swap(0, std::sync::atomic::Ordering::Relaxed);
        if pgid == 0 {
            return;
        }
        let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pgid as i32), nix::sys::signal::Signal::SIGKILL);
    }
}

/// Every native sandbox this daemon owns. `sblog` looks sandboxes up here to
/// attribute kernel denial reports.
pub type Registry = Arc<Mutex<BTreeMap<String, Arc<Live>>>>;

pub struct Native {
    cfg: Arc<Config>,
    bus: Bus,
    pub reg: Registry,
    template: String,
    /// v5 §3a. Whether this host can give a native sandbox a cgroup of its own.
    /// Decided once: it is a property of the kernel and of our privileges, not
    /// of the sandbox. `false` → the shim's watchdog, `enforcement: "daemon"`.
    kernel_enforced: bool,
}

impl Native {
    pub fn new(cfg: Arc<Config>, bus: Bus) -> anyhow::Result<Self> {
        let template = std::fs::read_to_string(&cfg.seatbelt_profile)
            .map_err(|e| anyhow::anyhow!("{}: {e} (set SBX_SEATBELT_PROFILE)", cfg.seatbelt_profile))?;
        let kernel_enforced = linux::cgroup_writable();
        if !kernel_enforced {
            tracing::info!("native tier limits are daemon-enforced (no writable cgroup v2 root)");
        }
        Ok(Self { cfg, bus, reg: Default::default(), template, kernel_enforced })
    }

    fn scratch_of(&self, id: &str) -> PathBuf {
        PathBuf::from(&self.cfg.scratch_dir).join(format!("sbx-{id}"))
    }

    /// v4c §3a: the working directory of a sandbox created without a workspace.
    /// Its own scratch directory (`create` makes it, `0700`), never the shared
    /// scratch root — the profile makes the workspace writable, and the root is
    /// where every other native sandbox keeps its `agent.sock`.
    pub fn workspace_of(&self, id: &str) -> String {
        self.scratch_of(id).display().to_string()
    }
}

/// `/tmp/sbx-<id>`, owner-only. It holds `agent.sock` — an unauthenticated
/// `/exec` and `/fs/*` into this sandbox — and the fake HOME, under a
/// world-traversable `/tmp`; the default umask would leave both readable to
/// every local process.
fn make_scratch(scratch: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(scratch)?;
    std::fs::set_permissions(scratch, std::fs::Permissions::from_mode(0o700))?;
    std::fs::create_dir_all(scratch.join("tmp"))
}

impl Native {
    /// The fake HOME: canaries, plus read-only links to the host toolchain
    /// directories the profile allows reading. Links rather than copies, because
    /// a copy of `~/.cargo` is gigabytes and would go stale.
    fn build_home(&self, home: &Path, real_home: &str, id: &str) -> std::io::Result<Vec<String>> {
        std::fs::create_dir_all(home.join(".ssh"))?;
        std::fs::create_dir_all(home.join(".aws"))?;
        std::fs::create_dir_all(home.join(".config"))?;
        std::fs::create_dir_all(home.join(".cache"))?;

        Rules::plant_canaries(&home.display().to_string(), id);
        let canaries = Rules::canary_files(&home.display().to_string());

        // Read-only by policy, not by mode: the Seatbelt profile allows reading
        // these paths and allows writing only under the workspace and scratch.
        for src in seatbelt::default_toolchains(real_home) {
            let Some(name) = Path::new(&src).file_name() else { continue };
            let dst = home.join(name);
            if dst.exists() {
                continue;
            }
            let _ = std::os::unix::fs::symlink(&src, &dst);
        }
        Ok(canaries)
    }

    /// One egress proxy per sandbox, on its own loopback port, with this
    /// sandbox's extra allow globs. Returns the port and the task serving it.
    async fn start_proxy(
        &self,
        id: &str,
        extra: &[String],
        pi_session: String,
        ev: Emitter,
    ) -> anyhow::Result<(u16, tokio::task::JoinHandle<()>)> {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        let policy = crate::proxy::Policy::load(&self.cfg.policy).with_extra(extra);
        let mut ctx = crate::proxy::ProxyCtx::new(policy, self.cfg.host_id.clone(), self.cfg.token.clone());
        // Events go straight onto the bus already carrying the sandbox id, and
        // the tool call is recovered from whichever process group is live.
        let corr = agent_core::Corr { pi_session, tool_call_id: String::new() };
        ctx.emit = Some(Arc::new(move |ty, data| {
            ev.emit(&corr, ty, data);
        }));
        let id = id.to_string();
        let task = tokio::spawn(async move {
            if let Err(e) = crate::proxy::serve(listener, Arc::new(ctx)).await {
                tracing::warn!(error = %e, %id, "per-sandbox egress proxy stopped");
            }
        });
        Ok((port, task))
    }

    /// Renders the profile and builds the shim's curated environment.
    fn prepare(
        &self,
        id: &str,
        scratch: &Path,
        workspace: &str,
        proxy_port: u16,
        extra: &BTreeMap<String, String>,
    ) -> anyhow::Result<(PathBuf, BTreeMap<String, String>)> {
        let home = scratch.join("home");
        let real_home = std::env::var("HOME").unwrap_or_default();
        let canaries = self.build_home(&home, &real_home, id)?;

        let profile = seatbelt::Profile {
            id: id.to_string(),
            workspace: workspace.to_string(),
            scratch: scratch.display().to_string(),
            home: home.display().to_string(),
            toolchains: seatbelt::default_toolchains(&real_home),
            sensitive: seatbelt::default_sensitive(&real_home),
            real_home: real_home.clone(),
            canaries,
            proxy_port,
            loopback_outbound: std::env::var("SBX_NATIVE_LOOPBACK").is_ok_and(|v| v == "all"),
            blocked_loopback_ports: vec![self.cfg.listen.port(), proto::CONTROLPLANE_PORT],
        };
        let profile_path = profile.write(&self.template)?;

        let proxy = format!("http://127.0.0.1:{proxy_port}");
        let mut env = BTreeMap::from([
            // A curated environment, not the daemon's: this is what keeps an LLM
            // API key out of a native sandbox even though we share a machine.
            ("PATH".into(), std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin:/usr/sbin:/sbin".into())),
            ("HOME".into(), home.display().to_string()),
            ("TMPDIR".into(), scratch.join("tmp").display().to_string()),
            // v5 §3a: `disk_mib` is charged against the whole sandbox scratch
            // (the fake HOME as much as TMPDIR), which is what the watchdog
            // measures and `GET /usage` reports.
            ("SBX_SCRATCH".into(), scratch.display().to_string()),
            ("TERM".into(), "xterm-256color".into()),
            ("LANG".into(), std::env::var("LANG").unwrap_or_else(|_| "en_US.UTF-8".into())),
            ("SBX_ID".into(), id.to_string()),
            ("SBX_HOST_ID".into(), self.cfg.host_id.clone()),
            ("SBX_WORKSPACE".into(), workspace.to_string()),
            ("SBX_MAX_UPLOAD_MB".into(), self.cfg.max_upload_mb.to_string()),
            ("SBX_HOST_HOME".into(), real_home),
            ("RUST_LOG".into(), std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into())),
            ("HTTP_PROXY".into(), proxy.clone()),
            ("HTTPS_PROXY".into(), proxy.clone()),
            ("http_proxy".into(), proxy.clone()),
            ("https_proxy".into(), proxy),
            ("NO_PROXY".into(), "127.0.0.1,localhost".into()),
            ("no_proxy".into(), "127.0.0.1,localhost".into()),
        ]);
        // v3 `POST /sandboxes {env}`. The native tier has no guest to hand it
        // to: the shim's environment *is* every exec's environment. The
        // protected names stay ours, or a caller could point the sandbox's
        // loader or proxy somewhere else.
        for (k, v) in extra.iter().filter(|(k, _)| agent_core::spawn::env_allowed(k)) {
            env.insert(k.clone(), v.clone());
        }
        Ok((profile_path, env))
    }

    /// Spawns `qafas shim` under the OS sandbox and waits for its socket.
    /// Returns the shim's pgid.
    async fn spawn_shim(
        &self,
        scratch: &Path,
        workspace: &str,
        profile: &Path,
        env: &BTreeMap<String, String>,
        l: &proto::SandboxLimits,
    ) -> anyhow::Result<u32> {
        use std::os::unix::process::CommandExt;
        let socket = scratch.join("agent.sock");
        let me = std::env::current_exe()?;
        let mut argv = wrapper_prefix(&self.cfg, profile, workspace, scratch, l);
        argv.extend([me.display().to_string(), "shim".into(), "--socket".into(), socket.display().to_string()]);

        let mut c = std::process::Command::new(&argv[0]);
        c.args(&argv[1..]).env_clear().envs(env).current_dir(workspace);
        c.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::inherit());
        // v5 §3a. The shim's rlimits become every exec's: a child may lower them
        // but cannot raise a hard limit back, so `Hardened`'s own defaults do not
        // undo these. macOS keeps the default `nproc` (RLIMIT_NPROC is per-uid
        // there, so a per-sandbox value would throttle the whole login session).
        let limits = Limits::from(l).headroom();
        let confine = linux::confine(workspace, scratch);
        unsafe {
            c.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                limits.apply()?;
                match &confine {
                    Some(f) => f(),
                    None => Ok(()),
                }
            });
        }
        let child = c.spawn()?;
        let pgid = child.id();
        record_group(scratch, pgid);
        // The child is reaped by the tokio runtime's SIGCHLD handling? No: it is
        // a std child we deliberately leak; `destroy` kills the group and the
        // daemon's periodic reaper collects it.
        std::mem::forget(child);

        // Wait for the listener: typically ~10 ms including the profile compile.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if tokio::net::UnixStream::connect(&socket).await.is_ok() {
                return Ok(pgid);
            }
            if std::time::Instant::now() > deadline {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pgid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
                anyhow::bail!("native shim did not come up within 5 s (see daemon stderr)");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }
}

/// The argv that wraps every command. macOS: `sandbox-exec -f <profile>`.
/// Linux: `bwrap` with the mount plan of PLAN §2.2; the Landlock and seccomp
/// halves are applied in `pre_exec` instead (see `linux::confine`).
fn wrapper_prefix(
    cfg: &Config,
    profile: &Path,
    workspace: &str,
    scratch: &Path,
    l: &proto::SandboxLimits,
) -> Vec<String> {
    if cfg.native_permissive {
        tracing::warn!("SBX_NATIVE_PERMISSIVE: the native tier is running unwrapped");
        return Vec::new();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (workspace, scratch, l);
        vec!["/usr/bin/sandbox-exec".into(), "-f".into(), profile.display().to_string()]
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = profile;
        linux::bwrap_prefix(workspace, scratch, l.disk_mib)
    }
}

impl Native {
    /// v5 §3a. Puts one native sandbox under `l`. On Linux that is a cgroup v2
    /// leaf the shim's process group is moved into, which the sandbox cannot
    /// reach (it sees a read-only `/` under bwrap). Where there is no cgroup to
    /// write — macOS, or an unprivileged Linux daemon with no delegation — the
    /// shim's own watchdog holds the line instead and `enforcement` says so.
    // design: on macOS that watchdog samples RSS every 100 ms and the scratch every 1 s and never caps CPU at all, so a burst under the sampling window gets through; there is no upgrade short of a macOS resource-limit API (Linux already takes the cgroup leaf above).
    async fn enforce(&self, id: &str, pgid: u32, l: &proto::SandboxLimits) -> anyhow::Result<()> {
        if self.kernel_enforced && linux::cgroup_apply(id, pgid, l).is_ok() {
            return Ok(());
        }
        let Some(live) = self.reg.lock().await.get(id).cloned() else { anyhow::bail!("no live native sandbox {id}") };
        super::set_limits(&live.connector, None, l).await
    }
}

impl Backend for Native {
    fn name(&self) -> &'static str {
        "native"
    }

    fn enforcement(&self) -> &'static str {
        if self.kernel_enforced {
            "kernel"
        } else {
            "daemon"
        }
    }

    fn apply_limits(&self, sb: &Sandbox, l: &proto::SandboxLimits) -> BoxFut<'_, anyhow::Result<()>> {
        let (id, l) = (sb.id.clone(), *l);
        Box::pin(async move {
            let Some(live) = self.reg.lock().await.get(&id).cloned() else {
                anyhow::bail!("no live native sandbox {id}")
            };
            *live.limits.lock().expect("native limits") = l;
            self.enforce(&id, live.pgid.load(std::sync::atomic::Ordering::Relaxed), &l).await
        })
    }

    /// The shim answers `GET /usage` exactly as a guest agent does, so the
    /// native tier needs no sampling path of its own.
    fn usage(&self, sb: &Sandbox) -> BoxFut<'_, Option<proto::SandboxUsage>> {
        let conn = sb.connector.clone();
        Box::pin(async move { super::guest_usage(&conn, None).await })
    }

    fn create(&self, spec: Spec) -> BoxFut<'_, anyhow::Result<Sandbox>> {
        Box::pin(async move {
            let started = std::time::Instant::now();
            let created_at = agent_core::now_rfc3339();
            let scratch = self.scratch_of(&spec.id);
            make_scratch(&scratch)?;

            let bus = self.bus.clone();
            let ev = Emitter::new(
                self.cfg.host_id.clone(),
                spec.id.clone(),
                Arc::new(move |e: Event| {
                    let _ = bus.send(e);
                }),
            );
            let (proxy_port, proxy) =
                self.start_proxy(&spec.id, &spec.egress_allow, spec.pi_session.clone(), ev.clone()).await?;
            let (profile, env) = self.prepare(&spec.id, &scratch, &spec.workspace_path, proxy_port, &spec.env)?;
            let pgid = match self.spawn_shim(&scratch, &spec.workspace_path, &profile, &env, &spec.limits).await {
                Ok(p) => p,
                Err(e) => {
                    proxy.abort();
                    return Err(e);
                }
            };
            let connector = Connector::Unix(scratch.join("agent.sock"));

            self.reg.lock().await.insert(
                spec.id.clone(),
                Arc::new(Live {
                    connector: connector.clone(),
                    ev,
                    pgid: pgid.into(),
                    proxy,
                    scratch,
                    workspace: spec.workspace_path.clone(),
                    profile,
                    env,
                    limits: std::sync::Mutex::new(spec.limits),
                }),
            );
            self.enforce(&spec.id, pgid, &spec.limits).await?;

            Ok(Sandbox {
                id: spec.id,
                template: spec.template,
                workspace_path: spec.workspace_path,
                connector,
                // The shim's socket is in a `0700` scratch dir, so reachability
                // is the boundary (docs/security.md M39): no token needed.
                agent_token: None,
                // Native sandboxes reach the proxy over loopback, so the proxy
                // sees 127.0.0.1 for all of them and cannot attribute by peer.
                // `sblog` and the exec layer attribute instead.
                peer_ip: None,
                created_at,
                ready_at: Some(agent_core::now_rfc3339()),
                boot_ms: started.elapsed().as_millis() as u64,
            })
        })
    }

    fn destroy(&self, sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        let id = sb.id.clone();
        Box::pin(async move {
            if let Some(live) = self.reg.lock().await.remove(&id) {
                live.proxy.abort();
                live.kill_shim();
            }
            // Whatever is still running in this sandbox's process groups dies
            // with it; the scratch dir goes with the canaries in it.
            let scratch = self.scratch_of(&id);
            kill_recorded_groups(&scratch);
            let _ = std::fs::remove_dir_all(&scratch);
            linux::cgroup_remove(&id);
            Ok(())
        })
    }

    // ---------------------------------------------------------------- v4 lifecycle
    //
    // A native sandbox has no memory to snapshot: its state is the workspace,
    // which is a host directory nobody has to save. So `stop` is "kill every
    // process" and `start` is "put an identical shim back", on the same id,
    // token, workspace and unix socket — the endpoint never changes (§3a).

    fn supports_lifecycle(&self, verb: super::Verb) -> bool {
        matches!(verb, super::Verb::Stop | super::Verb::Start)
    }

    fn stop(&self, sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        let id = sb.id.clone();
        Box::pin(async move {
            let Some(live) = self.reg.lock().await.get(&id).cloned() else {
                anyhow::bail!("no live native sandbox {id}");
            };
            live.kill_shim();
            // Execs that outlived their request (a background server) are in
            // their own groups; a stopped sandbox has no processes at all.
            kill_recorded_groups(&live.scratch);
            let _ = std::fs::remove_file(live.scratch.join("agent.sock"));
            Ok(())
        })
    }

    fn start(&self, sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        let id = sb.id.clone();
        Box::pin(async move {
            let Some(live) = self.reg.lock().await.get(&id).cloned() else {
                anyhow::bail!("no live native sandbox {id}");
            };
            if live.pgid.load(std::sync::atomic::Ordering::Relaxed) != 0 {
                return Ok(()); // already running
            }
            let l = *live.limits.lock().expect("native limits");
            let pgid = self.spawn_shim(&live.scratch, &live.workspace, &live.profile, &live.env, &l).await?;
            live.pgid.store(pgid, std::sync::atomic::Ordering::Relaxed);
            self.enforce(&id, pgid, &l).await
        })
    }
}

// ------------------------------------------------------------------ restart safety

/// `<pgid> <start_secs>` per line. Written by the exec layer through
/// `record_group`, read back on the next start.
fn pgid_file(scratch: &Path) -> PathBuf {
    scratch.join("pgid")
}

/// Records a process group so a crashed daemon's leftovers can be cleaned up.
pub fn record_group(scratch: &Path, pgid: u32) {
    use std::io::Write;
    let Some(start) = agent_core::procmon::start_secs(pgid) else { return };
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(pgid_file(scratch)) {
        let _ = writeln!(f, "{pgid} {start}");
    }
}

/// Kills the groups a scratch dir recorded, but only those whose leader is still
/// the process we wrote down. Without the start-time check this would be a pid
/// reuse bug that kills an unrelated process group on every restart.
fn kill_recorded_groups(scratch: &Path) -> usize {
    let Ok(text) = std::fs::read_to_string(pgid_file(scratch)) else { return 0 };
    let mut killed = 0;
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(pgid), Some(start)) = (it.next(), it.next()) else { continue };
        let (Ok(pgid), Ok(start)) = (pgid.parse::<u32>(), start.parse::<u64>()) else { continue };
        if agent_core::procmon::start_secs(pgid) != Some(start) {
            continue; // gone, or the pid has been recycled since
        }
        let r = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pgid as i32), nix::sys::signal::Signal::SIGKILL);
        tracing::warn!(pgid, ?r, "killed a process group left by a previous run");
        killed += 1;
    }
    killed
}

/// Startup sweep: every `sbx-*` directory under the scratch root belongs to a
/// sandbox that no longer exists, because a live one is only in memory.
pub fn sweep_leftovers(scratch_root: &str) -> usize {
    let Ok(rd) = std::fs::read_dir(scratch_root) else { return 0 };
    let mut n = 0;
    for e in rd.flatten() {
        let p = e.path();
        if !p.file_name().and_then(|s| s.to_str()).is_some_and(|s| s.starts_with("sbx-")) {
            continue;
        }
        n += kill_recorded_groups(&p);
        let _ = std::fs::remove_dir_all(&p);
        tracing::info!(dir = %p.display(), "removed a native sandbox left by a previous run");
    }
    n
}

// ------------------------------------------------------------------ Linux

/// The Linux half. It compiles for both musl targets and is exercised on the
/// Linux box; on macOS every function here is inert.
#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;

    pub fn bwrap() -> Option<PathBuf> {
        agent_core::procmon::which("bwrap")
    }

    /// v5 §3a. Where a native sandbox's cgroup leaf goes. One directory per
    /// sandbox under `sbx/`, so a kill or a limit change never reaches another.
    fn cgroup_dir(id: &str) -> PathBuf {
        PathBuf::from("/sys/fs/cgroup/sbx").join(id)
    }

    /// Can this daemon make a leaf at all? Creating and removing the parent is
    /// the only honest test: root, a delegated cgroup and a read-only cgroupfs
    /// are not distinguishable from the mount alone.
    pub fn cgroup_writable() -> bool {
        let p = PathBuf::from("/sys/fs/cgroup/sbx");
        std::fs::create_dir_all(&p).is_ok()
            && std::fs::write(p.join("cgroup.subtree_control"), "+cpu +memory +pids").is_ok()
    }

    /// Writes the three ceilings and moves the shim's process group in. Leaf
    /// first, then `cgroup.procs`: a cgroup v2 leaf may only hold processes
    /// once it has no children of its own, which it never gets here.
    pub fn cgroup_apply(id: &str, pgid: u32, l: &proto::SandboxLimits) -> std::io::Result<()> {
        let d = cgroup_dir(id);
        std::fs::create_dir_all(&d)?;
        agent_core::limits::write_ceilings(&d, l)?;
        if pgid != 0 {
            // Every process of the group, one write each: `cgroup.procs` takes
            // one pid at a time and the shim has already forked children.
            for pid in agent_core::procmon::group_pids(pgid) {
                let _ = std::fs::write(d.join("cgroup.procs"), pid.to_string());
            }
            std::fs::write(d.join("cgroup.procs"), pgid.to_string())?;
        }
        Ok(())
    }

    /// Removing the directory is what frees the cgroup; it only succeeds once
    /// every process in it is gone, which `destroy` has already seen to.
    pub fn cgroup_remove(id: &str) {
        let _ = std::fs::remove_dir(cgroup_dir(id));
    }

    /// The kernel's Landlock ABI level, straight from the documented probe:
    /// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`
    /// returns the highest version supported, or -1 when the LSM is absent.
    /// v4 (kernel 6.7) is the first with `LANDLOCK_ACCESS_NET_CONNECT_TCP`.
    pub fn abi() -> i32 {
        // Syscall 444 on every architecture with the generic table, x86_64 and
        // aarch64 included.
        const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
        const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
        unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            ) as i32
        }
    }

    pub fn landlock_net_available() -> bool {
        abi() >= 4
    }

    /// PLAN §2.2. The whole filesystem read-only, the workspace and the scratch
    /// dir writable, private pid/uts/ipc namespaces, and the process dies with
    /// the daemon. The network namespace stays shared so the egress proxy on
    /// loopback stays reachable; Landlock closes the rest of the network.
    pub fn bwrap_prefix(workspace: &str, scratch: &Path, disk_mib: u64) -> Vec<String> {
        let Some(bw) = bwrap() else { return Vec::new() };
        let s = scratch.display().to_string();
        let mut v: Vec<String> = vec![bw.display().to_string()];
        for a in ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"] {
            v.push(a.into());
        }
        // v5 §3a: `--size` applies to the next `--tmpfs`, so the scratch cap is
        // a mount option rather than anything the workload can remount.
        v.extend(["--size".into(), (disk_mib * 1024 * 1024).to_string(), "--tmpfs".into(), "/tmp".into()]);
        v.extend(["--bind".into(), workspace.into(), workspace.into()]);
        v.extend(["--bind".into(), s.clone(), s]);
        for a in ["--unshare-pid", "--unshare-uts", "--unshare-ipc", "--die-with-parent", "--new-session"] {
            v.push(a.into());
        }
        // If Landlock cannot restrict the network on this kernel, take the whole
        // namespace away instead and log the downgrade (PLAN §5 risks). The
        // sandbox then reaches the proxy over a unix-socket bridge, which is why
        // `doctor` prints which of the two a host is using.
        if !landlock_net_available() {
            tracing::warn!(abi = abi(), "Landlock network rules unavailable; using --unshare-net");
            v.push("--unshare-net".into());
        }
        v.push("--".into());
        v
    }

    /// Filesystem and network rules mirroring the Seatbelt profile, applied
    /// between fork and exec so everything the shell spawns inherits them, plus
    /// the same seccomp deny-list the VM tier installs (D8/D18).
    pub fn confine(workspace: &str, scratch: &Path) -> Option<agent_core::spawn::Confine> {
        use landlock::{
            Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
            RulesetStatus, ABI,
        };
        let (ws, sc) = (workspace.to_string(), scratch.display().to_string());
        let net = landlock_net_available();
        Some(Arc::new(move || {
            let err = |e: String| std::io::Error::other(e);
            // V2 is the floor we require; the crate's best-effort compatibility
            // downgrades the rest on an older kernel rather than failing.
            let abi = if net { ABI::V4 } else { ABI::V2 };
            let mut rs = Ruleset::default().handle_access(AccessFs::from_all(abi)).map_err(|e| err(e.to_string()))?;
            if net {
                rs = rs.handle_access(AccessNet::from_all(abi)).map_err(|e| err(e.to_string()))?;
            }
            let mut created = rs.create().map_err(|e| err(e.to_string()))?;
            // Read the world, write only the sandbox's own two directories.
            for (path, access) in [
                ("/", AccessFs::from_read(abi)),
                (ws.as_str(), AccessFs::from_all(abi)),
                (sc.as_str(), AccessFs::from_all(abi)),
            ] {
                if let Ok(fd) = PathFd::new(path) {
                    created = created.add_rule(PathBeneath::new(fd, access)).map_err(|e| err(e.to_string()))?;
                }
            }
            if net {
                // One reachable port. Binding is not granted at all, so nothing
                // inside can listen.
                created = created
                    .add_rule(NetPort::new(proto::EGRESS_PROXY_PORT, AccessNet::ConnectTcp))
                    .map_err(|e| err(e.to_string()))?;
            }
            let status = created.restrict_self().map_err(|e| err(e.to_string()))?;
            if status.ruleset == RulesetStatus::NotEnforced {
                return Err(err("Landlock is not enforced on this kernel".into()));
            }
            agent_core::harden::apply(true)
        }))
    }
}

/// Inert on macOS. Kept so `doctor` and the backend can call the same names on
/// both platforms without `cfg` at every call site.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub mod linux {
    use super::*;

    pub fn bwrap() -> Option<PathBuf> {
        None
    }
    pub fn bwrap_prefix(_workspace: &str, _scratch: &Path, _disk_mib: u64) -> Vec<String> {
        Vec::new()
    }
    /// No cgroups on macOS: the native tier is `enforcement: "daemon"` there
    /// (protocol §3a), and the shim's watchdog is what enforces.
    pub fn cgroup_writable() -> bool {
        false
    }
    pub fn cgroup_apply(_id: &str, _pgid: u32, _l: &proto::SandboxLimits) -> std::io::Result<()> {
        Err(std::io::Error::other("no cgroups on this platform"))
    }
    pub fn cgroup_remove(_id: &str) {}
    pub fn landlock_net_available() -> bool {
        false
    }
    /// No Landlock off Linux; `doctor` prints this as "unsupported".
    pub fn abi() -> i32 {
        -1
    }
    pub fn confine(_workspace: &str, _scratch: &Path) -> Option<agent_core::spawn::Confine> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scratch directory holds `agent.sock`; `/tmp` is world-traversable.
    #[test]
    fn the_scratch_directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sbx-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        make_scratch(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "scratch must not be readable by other local users");
        assert!(dir.join("tmp").is_dir());
        // Idempotent: create() runs it on a path that may already exist.
        make_scratch(&dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// v4c §3a: a create with no workspace still gets a directory of its own.
    /// If it were the scratch root, the profile would make every other native
    /// sandbox's `agent.sock` — an unauthenticated `/exec` — readable and
    /// writable from inside this one.
    #[test]
    fn a_missing_workspace_is_this_sandboxs_scratch_not_the_root() {
        let tmpl = std::env::temp_dir().join(format!("sbx-tmpl-{}.sb", std::process::id()));
        std::fs::write(&tmpl, "(version 1)").unwrap();
        let mut cfg = crate::config::Config::resolve(crate::config::FileConfig::default());
        cfg.scratch_dir = "/tmp".into();
        cfg.seatbelt_profile = tmpl.display().to_string();
        let n = Native::new(Arc::new(cfg), crate::events::bus()).unwrap();
        assert_eq!(n.workspace_of("abc"), "/tmp/sbx-abc");
        assert_ne!(n.workspace_of("abc"), "/tmp");
        std::fs::remove_file(&tmpl).unwrap();
    }

    #[test]
    fn recorded_groups_survive_only_while_their_leader_does() {
        let dir = std::env::temp_dir().join(format!("sbx-pgid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // A pid that is certainly not alive with that start time.
        std::fs::write(pgid_file(&dir), "999999 12345\n").unwrap();
        assert_eq!(kill_recorded_groups(&dir), 0, "a dead pgid is not killed");

        // Our own pid recorded with the wrong start time must also be spared —
        // that is the pid-reuse case.
        let me = std::process::id();
        std::fs::write(pgid_file(&dir), format!("{me} 1\n")).unwrap();
        assert_eq!(kill_recorded_groups(&dir), 0, "a recycled pid must not be killed");

        // And a real record round-trips.
        record_group(&dir, me);
        let text = std::fs::read_to_string(pgid_file(&dir)).unwrap();
        let last = text.lines().last().unwrap();
        assert_eq!(last.split(' ').next(), Some(me.to_string().as_str()));
        assert_eq!(last.split(' ').nth(1).and_then(|s| s.parse::<u64>().ok()), agent_core::procmon::start_secs(me),);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn leftover_sweep_only_touches_our_directories() {
        let root = std::env::temp_dir().join(format!("sbx-sweep-{}", std::process::id()));
        std::fs::create_dir_all(root.join("sbx-abc")).unwrap();
        std::fs::create_dir_all(root.join("someone-elses")).unwrap();
        sweep_leftovers(&root.display().to_string());
        assert!(!root.join("sbx-abc").exists());
        assert!(root.join("someone-elses").exists(), "we only clean up our own");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
