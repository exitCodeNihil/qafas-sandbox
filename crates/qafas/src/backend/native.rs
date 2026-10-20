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
//!   proxy.sock     Linux: the daemon's end of the shim's egress proxy relay
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

/// Whether an `accept` error means the listener itself is finished: its
/// descriptor is closed or is not a listening socket. Anything else (EMFILE and
/// ENFILE when descriptors run out, ECONNABORTED when a client left before it
/// was accepted, EINTR, EAGAIN, ENOBUFS, ENOMEM) says something about this
/// moment, not about the listener, and the next `accept` can succeed.
pub(crate) fn listener_is_gone(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EBADF | libc::EINVAL | libc::ENOTSOCK | libc::EFAULT))
}

/// One `accept` result in a loop that must keep serving: the connection, or
/// `None` after a warning and a short pause (so a descriptor shortage is not a
/// busy loop that fills the log), and `Err` only when `listener_is_gone`. With a
/// bare `?` the first EMFILE ended the loop, and for the per-sandbox bridge that
/// stopped the sandbox's whole egress proxy until it was recreated.
///
/// ponytail: a flat 100 ms pause and no rate limit on the warning, so a long
/// shortage logs ten lines a second. Upgrade: back off exponentially, as hyper's
/// own accept loop does.
pub(crate) async fn survive_accept<T>(r: std::io::Result<T>, what: &str) -> std::io::Result<Option<T>> {
    match r {
        Ok(c) => Ok(Some(c)),
        Err(e) if listener_is_gone(&e) => Err(e),
        Err(e) => {
            tracing::warn!(error = %e, what, "accept failed; still serving");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            Ok(None)
        }
    }
}

/// M46, the daemon's end of the shim's relay: every connection on
/// `proxy.sock` is bridged to this sandbox's egress proxy on `127.0.0.1:port`.
async fn bridge_to(l: tokio::net::UnixListener, port: u16) -> std::io::Result<()> {
    bridge_accepting(|| l.accept(), port).await
}

/// `bridge_to` over any source of accepted streams, so the loop's reaction to a
/// failing `accept` can be tested without making the kernel fail one.
async fn bridge_accepting<F, Fut, A>(mut accept: F, port: u16) -> std::io::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<(tokio::net::UnixStream, A)>>,
{
    loop {
        let Some((mut from, _)) = survive_accept(accept().await, "proxy.sock bridge").await? else { continue };
        tokio::spawn(async move {
            let Ok(mut to) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else { return };
            let _ = to.set_nodelay(true);
            let _ = tokio::io::copy_bidirectional(&mut from, &mut to).await;
        });
    }
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
        scratch: &Path,
        extra: &[String],
        pi_session: String,
        ev: Emitter,
    ) -> anyhow::Result<(u16, tokio::task::JoinHandle<()>)> {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        // M46, Linux: the sandbox has a network namespace of its own, so this
        // loopback is out of its reach. Its shim relays the proxy port to
        // `proxy.sock` (in the `0700` scratch dir, like `agent.sock`) and the
        // bridge brings it back here. Same task as the proxy: it outlives
        // `stop` and dies on `destroy`.
        let bridge = match cfg!(target_os = "linux") {
            true => {
                let sock = scratch.join("proxy.sock");
                let _ = std::fs::remove_file(&sock);
                Some(tokio::net::UnixListener::bind(&sock)?)
            }
            false => None,
        };
        let policy = crate::proxy::Policy::load(&self.cfg.policy).with_extra(extra);
        let mut ctx = crate::proxy::ProxyCtx::new(policy, self.cfg.host_id.clone(), self.cfg.token.clone());
        // Events go straight onto the bus already carrying the sandbox id, and
        // the tool call is the one forwarded to it when the connection opened.
        ctx.emit = Some(Arc::new(move |ty, data| {
            let tool_call_id = crate::events::egress_call(ev.sandbox_id(), &data);
            ev.emit(&agent_core::Corr { pi_session: pi_session.clone(), tool_call_id }, ty, data);
        }));
        let id = id.to_string();
        let task = tokio::spawn(async move {
            let serve = crate::proxy::serve(listener, Arc::new(ctx));
            let r = match bridge {
                Some(b) => tokio::select! { r = serve => r, r = bridge_to(b, port) => r.map_err(Into::into) },
                None => serve.await,
            };
            if let Err(e) = r {
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
        // Linux: the proxy port the shim relays (and, if it shares the host's
        // network namespace, the one port Landlock lets a command connect to),
        // and the daemon's network namespace, which the shim compares with its
        // own (M46). After the caller's env, so a caller cannot set either.
        if cfg!(target_os = "linux") {
            env.insert("SBX_PROXY_PORT".into(), proxy_port.to_string());
            env.insert("SBX_HOST_NETNS".into(), linux::netns_id().unwrap_or(0).to_string());
        }
        Ok((profile_path, env))
    }

    /// Everything a native sandbox owns, undone: its proxy task and shim (if
    /// registered), whatever still runs in its process groups, the scratch dir
    /// with the canaries in it, and its cgroup. Idempotent, so `create` can run
    /// it for a sandbox that got only part of the way.
    async fn teardown(&self, id: &str) {
        if let Some(live) = self.reg.lock().await.remove(id) {
            live.proxy.abort();
            live.kill_shim();
        }
        let scratch = self.scratch_of(id);
        kill_recorded_groups(&scratch);
        let _ = std::fs::remove_dir_all(&scratch);
        linux::cgroup_remove(id);
    }

    /// `create` without the cleanup on failure. `proxy_abort` receives the
    /// proxy task's abort handle the moment the task exists, so the caller can
    /// stop it when a later step fails.
    async fn create_in(
        &self,
        spec: Spec,
        proxy_abort: &mut Option<tokio::task::AbortHandle>,
    ) -> anyhow::Result<Sandbox> {
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
            self.start_proxy(&spec.id, &scratch, &spec.egress_allow, spec.pi_session.clone(), ev.clone()).await?;
        *proxy_abort = Some(proxy.abort_handle());
        let (profile, env) = self.prepare(&spec.id, &scratch, &spec.workspace_path, proxy_port, &spec.env)?;
        let pgid = self.spawn_shim(&scratch, &spec.workspace_path, &profile, &env, &spec.limits).await?;
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
        unsafe {
            c.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                limits.apply()
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

/// The argv that wraps the shim. macOS: `sandbox-exec -f <profile>`. Linux:
/// `bwrap` with the mount plan of PLAN §2.2; Landlock and seccomp go on every
/// command the shim spawns (`linux::confine`, `Hardened::confine`), because on
/// `bwrap` itself they forbid the mounts and namespaces it is there to make.
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
            let id = spec.id.clone();
            let mut proxy = None;
            match self.create_in(spec, &mut proxy).await {
                Ok(sb) => Ok(sb),
                Err(e) => {
                    // Nobody holds a `Sandbox` to destroy, so whatever got as far as
                    // existing goes here: the proxy task (not registered yet if the
                    // failure came before the shim), the shim and its groups, and the
                    // scratch dir with its dead `proxy.sock`, canary home and profile
                    // (bwrap refusing `--unshare-net` left all of it until the next
                    // start's sweep).
                    if let Some(p) = proxy {
                        p.abort();
                    }
                    self.teardown(&id).await;
                    Err(e)
                }
            }
        })
    }

    fn destroy(&self, sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        let id = sb.id.clone();
        Box::pin(async move {
            self.teardown(&id).await;
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

    /// One real `bwrap` start with the namespaces the shim gets. A non-root
    /// daemon needs an unprivileged user namespace for it, which Ubuntu 24.04
    /// and later refuse unless an AppArmor profile allows `bwrap`.
    pub fn bwrap_probe(bwrap: &str) -> (bool, String) {
        let args = ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--unshare-pid", "--unshare-uts"];
        let more = ["--unshare-ipc", "--unshare-net", "--", "/bin/true"];
        match std::process::Command::new(bwrap).args(args).args(more).output() {
            Ok(o) if o.status.success() => (true, "starts as this user".into()),
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
                let restricted = std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
                    .is_ok_and(|s| s.trim() == "1");
                (false, bwrap_hint(&err, restricted))
            }
            Err(e) => (false, e.to_string()),
        }
    }

    /// What `bwrap_probe` (and so `qafas doctor`) says about a failed start.
    /// ENOSPC is the kernel's per-user cap on namespaces: `--unshare-net` fails
    /// when `user.max_net_namespaces` is 0 (some hardened hosts set it), which has
    /// nothing to do with AppArmor or with disk space. bubblewrap 0.9 words it
    /// "nesting depth or /proc/sys/user/max_*_namespaces exceeded (ENOSPC)"
    /// (measured, Ubuntu 24.04), older ones print strerror, "No space left on
    /// device". Any other error on a host that restricts unprivileged user
    /// namespaces is the Ubuntu 24.04 AppArmor case (EACCES, EPERM).
    pub(super) fn bwrap_hint(err: &str, apparmor_restricts_userns: bool) -> String {
        if err.contains("ENOSPC") || err.contains("No space left on device") {
            return format!(
                "{err}: the kernel's namespace limit is exhausted or 0; check `sysctl user.max_net_namespaces` \
                 (and user.max_user_namespaces), and raise it to enable the native tier"
            );
        }
        match apparmor_restricts_userns {
            true => format!("{err}: AppArmor restricts unprivileged user namespaces; allow bwrap (docs/deployment.md)"),
            false => err.to_string(),
        }
    }

    /// PLAN §2.2, mirroring the Seatbelt profile: the system read-only; every
    /// home, `/root` and `/run` (the user's credentials, the podman, Docker and
    /// D-Bus sockets) replaced by empty tmpfs; the daemon user's toolchains and
    /// this binary read-only again; the workspace and the scratch dir writable;
    /// the credential paths covered even inside the workspace; private
    /// pid/uts/ipc/net namespaces; and the process dies with the daemon. M46:
    /// the network namespace has only `lo`, so no address outside the sandbox
    /// is reachable at all (Landlock restricts TCP by port, never by address);
    /// the shim relays the egress proxy port back in over `proxy.sock`.
    pub fn bwrap_prefix(workspace: &str, scratch: &Path, disk_mib: u64) -> Vec<String> {
        let Some(bw) = bwrap() else { return Vec::new() };
        let real_home = std::env::var("HOME").unwrap_or_default();
        let s = scratch.display().to_string();
        let mut v: Vec<String> = vec![bw.display().to_string()];
        for a in ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"] {
            v.push(a.into());
        }
        // v5 §3a: `--size` applies to the next `--tmpfs`, so the scratch cap is
        // a mount option rather than anything the workload can remount.
        v.extend(["--size".into(), (disk_mib * 1024 * 1024).to_string(), "--tmpfs".into(), "/tmp".into()]);
        for hidden in ["/home", "/root", "/run"].into_iter().filter(|d| Path::new(d).is_dir()) {
            v.extend(["--tmpfs".into(), hidden.into()]);
        }
        let mut readable = crate::seatbelt::default_toolchains(&real_home);
        readable.extend(std::env::current_exe().ok().map(|p| p.display().to_string()));
        for p in readable {
            v.extend(["--ro-bind".into(), p.clone(), p]);
        }
        v.extend(["--bind".into(), workspace.into(), workspace.into()]);
        v.extend(["--bind".into(), s.clone(), s]);
        for p in crate::seatbelt::default_sensitive(&real_home) {
            match std::fs::metadata(&p) {
                Ok(m) if m.is_dir() => v.extend(["--tmpfs".into(), p]),
                Ok(_) => v.extend(["--ro-bind".into(), "/dev/null".into(), p]),
                Err(_) => {}
            }
        }
        for a in
            ["--unshare-pid", "--unshare-uts", "--unshare-ipc", "--unshare-net", "--die-with-parent", "--new-session"]
        {
            v.push(a.into());
        }
        v.push("--".into());
        v
    }

    /// The network namespace this process is in: the inode of
    /// `/proc/self/ns/net`, unique per namespace on the running kernel.
    pub fn netns_id() -> Option<u64> {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self/ns/net").ok().map(|m| m.ino())
    }

    #[cfg(target_arch = "aarch64")]
    const ARCH: seccompiler::TargetArch = seccompiler::TargetArch::aarch64;
    #[cfg(target_arch = "x86_64")]
    const ARCH: seccompiler::TargetArch = seccompiler::TargetArch::x86_64;

    /// `socket()` returns EPERM for AF_INET/AF_INET6 unless it is plain TCP.
    /// Landlock ABI 4 governs TCP bind/connect only, and the sandbox shares the
    /// host's network namespace, so without this any command could send UDP
    /// (DNS to 8.8.8.8, QUIC) or open a raw, SCTP or MPTCP socket straight past
    /// the egress proxy. Also refuses TCP Fast Open's `MSG_FASTOPEN` sends: they
    /// connect inside `sendto`/`sendmsg`/`sendmmsg` without passing the connect
    /// hook Landlock's port rule hangs on.
    // ponytail: x32 syscall numbers (nr | 0x40000000 under the x86_64 audit
    // arch) are not matched; that only matters on a kernel with x32 enabled at
    // runtime. Upgrade: deny `nr & 0x40000000` up front.
    pub fn socket_filter() -> anyhow::Result<seccompiler::BpfProgram> {
        use seccompiler::{SeccompAction, SeccompCmpArgLen::Dword, SeccompCmpOp::*, SeccompCondition as C};
        use seccompiler::{SeccompFilter, SeccompRule};
        let (sock_stream, type_mask) = (libc::SOCK_STREAM as u64, 0xf); // SOCK_TYPE_MASK
        let mut rules = Vec::new();
        for domain in [libc::AF_INET, libc::AF_INET6] {
            let dom = || C::new(0, Dword, Eq, domain as u64);
            // Every type but SOCK_STREAM, masked so NONBLOCK/CLOEXEC don't slip by.
            for ty in [
                libc::SOCK_DGRAM,
                libc::SOCK_RAW,
                libc::SOCK_RDM,
                libc::SOCK_SEQPACKET,
                6,  /* DCCP */
                10, /* PACKET */
            ] {
                rules.push(SeccompRule::new(vec![dom()?, C::new(1, Dword, MaskedEq(type_mask), ty as u64)?])?);
            }
            // Stream, but not TCP (SCTP is 132, MPTCP 262): Landlock ignores both.
            rules.push(SeccompRule::new(vec![
                dom()?,
                C::new(1, Dword, MaskedEq(type_mask), sock_stream)?,
                C::new(2, Dword, Ne, 0)?,
                C::new(2, Dword, Ne, libc::IPPROTO_TCP as u64)?,
            ])?);
        }
        // `flags` is arg3 of sendto and sendmmsg, arg2 of sendmsg.
        let fastopen = |arg| -> anyhow::Result<Vec<SeccompRule>> {
            let flag = libc::MSG_FASTOPEN as u64;
            Ok(vec![SeccompRule::new(vec![C::new(arg, Dword, MaskedEq(flag), flag)?])?])
        };
        let filter = SeccompFilter::new(
            [
                (libc::SYS_socket, rules),
                (libc::SYS_sendto, fastopen(3)?),
                (libc::SYS_sendmsg, fastopen(2)?),
                (libc::SYS_sendmmsg, fastopen(3)?),
            ]
            .into(),
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            ARCH,
        )?;
        Ok(filter.try_into()?)
    }

    /// Filesystem and network rules mirroring the Seatbelt profile, applied to
    /// each command between fork and exec, so everything it spawns inherits
    /// them; `Hardened` adds the seccomp deny-list the VM tier installs right
    /// after (D8/D18). `private_netns` says the shim runs in its own network
    /// namespace (`--unshare-net`, M46); otherwise `proxy_port`, the sandbox's
    /// own egress proxy, is the one TCP port a command may connect to (`None`:
    /// none at all).
    pub fn confine(
        workspace: &str,
        scratch: &Path,
        proxy_port: Option<u16>,
        private_netns: bool,
    ) -> Option<agent_core::spawn::Confine> {
        use landlock::{
            Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
            RulesetStatus, ABI,
        };
        let (ws, sc) = (workspace.to_string(), scratch.display().to_string());
        let net = landlock_net_available();
        // In a namespace of our own only `lo` exists: a command reaches its own
        // listeners (a server and its client, tests, a browser on a dev server)
        // and the shim's relay, nothing else, and the abstract unix namespace is
        // per-netns too. A port rule there buys nothing, so there is none.
        // Sharing the host's (SBX_NATIVE_PERMISSIVE, no bwrap): connect to the
        // proxy port only, and no bind, so nothing inside can listen.
        let net_rules = net && !private_netns;
        // Built once here, not per command; a build failure fails every command
        // rather than silently leaving UDP open.
        let socks = socket_filter().map_err(|e| e.to_string());
        Some(Arc::new(move || {
            let err = |e: String| std::io::Error::other(e);
            // V2 is the floor we require; the crate's best-effort compatibility
            // downgrades the rest on an older kernel rather than failing.
            let abi = if net { ABI::V4 } else { ABI::V2 };
            let mut rs = Ruleset::default().handle_access(AccessFs::from_all(abi)).map_err(|e| err(e.to_string()))?;
            if net_rules {
                rs = rs.handle_access(AccessNet::from_all(abi)).map_err(|e| err(e.to_string()))?;
            }
            let mut created = rs.create().map_err(|e| err(e.to_string()))?;
            // Read the world, write only the sandbox's own two directories and
            // the devices every shell writes to (Seatbelt allows the same three).
            for (path, access) in [
                ("/", AccessFs::from_read(abi)),
                (ws.as_str(), AccessFs::from_all(abi)),
                (sc.as_str(), AccessFs::from_all(abi)),
                ("/dev/null", AccessFs::from_file(abi)),
                ("/dev/zero", AccessFs::from_file(abi)),
                ("/dev/tty", AccessFs::from_file(abi)),
            ] {
                if let Ok(fd) = PathFd::new(path) {
                    created = created.add_rule(PathBeneath::new(fd, access)).map_err(|e| err(e.to_string()))?;
                }
            }
            if let (true, Some(port)) = (net_rules, proxy_port) {
                created =
                    created.add_rule(NetPort::new(port, AccessNet::ConnectTcp)).map_err(|e| err(e.to_string()))?;
            }
            let status = created.restrict_self().map_err(|e| err(e.to_string()))?;
            if status.ruleset == RulesetStatus::NotEnforced {
                return Err(err("Landlock is not enforced on this kernel".into()));
            }
            // restrict_self() set no_new_privs, so the filter needs no privilege.
            seccompiler::apply_filter(socks.as_ref().map_err(|e| err(e.clone()))?).map_err(|e| err(e.to_string()))
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
    pub fn confine(
        _workspace: &str,
        _scratch: &Path,
        _proxy_port: Option<u16>,
        _private_netns: bool,
    ) -> Option<agent_core::spawn::Confine> {
        None
    }
    pub fn netns_id() -> Option<u64> {
        None
    }
    pub fn bwrap_probe(_bwrap: &str) -> (bool, String) {
        (false, "Linux only".into())
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

    /// Hard rule: every event carries `tool_call_id`. The per-sandbox proxy's
    /// `egress.*` takes the newest call forwarded to its sandbox.
    #[tokio::test]
    async fn the_native_proxys_events_carry_the_newest_tool_call() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let tmpl = std::env::temp_dir().join(format!("sbx-tmpl-tc-{}.sb", std::process::id()));
        std::fs::write(&tmpl, "(version 1)").unwrap();
        let mut cfg = crate::config::Config::resolve(crate::config::FileConfig::default());
        cfg.seatbelt_profile = tmpl.display().to_string();
        let bus = crate::events::bus();
        let n = Native::new(Arc::new(cfg), bus.clone()).unwrap();
        let mut rx = bus.subscribe();
        let ev = Emitter::new("h", "sbx_ntc", Arc::new(move |e: Event| drop(bus.send(e))));
        let (port, task) = n.start_proxy("sbx_ntc", &[], "sess".into(), ev).await.unwrap();
        crate::events::note_call("sbx_ntc", &Corr { pi_session: "sess".into(), tool_call_id: "tc-n".into() });

        // A literal nobody listed: denied without a DNS lookup or a network.
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        c.write_all(b"CONNECT 192.0.2.1:443 HTTP/1.1\r\nHost: 192.0.2.1:443\r\n\r\n").await.unwrap();
        let mut reply = String::new();
        c.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 403"), "{reply:?}");
        let e = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv()).await.unwrap().unwrap();
        assert_eq!(e.r#type, proto::EventType::EgressDeny);
        assert_eq!(
            (e.sandbox_id.as_str(), e.pi_session.as_str(), e.tool_call_id.as_str()),
            ("sbx_ntc", "sess", "tc-n")
        );
        task.abort();
        crate::events::forget_call("sbx_ntc");
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

    /// bwrap refusing to start (here: the `home` the sandbox would build is a
    /// file, which stops `prepare` the way a missing `--unshare-net` stops the
    /// shim) answers the create with an error, and the sandbox it never became
    /// must not leave its scratch dir behind: `proxy.sock`, the canary home and
    /// the profile sat there until the next daemon start.
    #[tokio::test]
    async fn a_failed_create_leaves_no_scratch_directory_and_no_registration() {
        let root = std::env::temp_dir().join(format!("sbx-failed-create-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let tmpl = root.join("profile.sb");
        std::fs::write(&tmpl, "(version 1)").unwrap();
        let mut cfg = crate::config::Config::resolve(crate::config::FileConfig::default());
        cfg.scratch_dir = root.display().to_string();
        cfg.seatbelt_profile = tmpl.display().to_string();
        let limits = cfg.default_limits();
        let n = Native::new(Arc::new(cfg), crate::events::bus()).unwrap();
        // `prepare` makes `<scratch>/home/.ssh`: a file in the way fails it.
        let scratch = root.join("sbx-failing");
        std::fs::create_dir_all(&scratch).unwrap();
        std::fs::write(scratch.join("home"), "in the way").unwrap();

        let spec = Spec {
            id: "failing".into(),
            template: String::new(),
            workspace_path: root.display().to_string(),
            egress_allow: vec![],
            image: String::new(),
            snapshot: None,
            env: Default::default(),
            pi_session: String::new(),
            limits,
        };
        let e = n.create(spec).await.unwrap_err();
        assert!(!e.to_string().is_empty());
        assert!(!scratch.exists(), "the scratch dir of a sandbox that never came up is removed");
        assert!(n.reg.lock().await.is_empty(), "and nothing is registered for it");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Out of descriptors, a client that left before it was accepted, a signal:
    /// all of them are about this moment. Only a listener that is closed or not
    /// a listener is finished.
    #[test]
    fn only_a_dead_listener_ends_an_accept_loop() {
        for errno in [libc::EMFILE, libc::ENFILE, libc::ECONNABORTED, libc::EINTR, libc::EAGAIN, libc::ENOBUFS] {
            let e = std::io::Error::from_raw_os_error(errno);
            assert!(!listener_is_gone(&e), "{e} is transient");
        }
        for errno in [libc::EBADF, libc::EINVAL, libc::ENOTSOCK] {
            let e = std::io::Error::from_raw_os_error(errno);
            assert!(listener_is_gone(&e), "{e} means there is no listener");
        }
        assert!(!listener_is_gone(&std::io::Error::other("no errno")));
    }

    #[tokio::test]
    async fn a_transient_accept_error_costs_a_pause_not_the_loop() {
        let t = std::time::Instant::now();
        assert_eq!(survive_accept(Ok(7), "t").await.unwrap(), Some(7));
        assert!(t.elapsed() < std::time::Duration::from_millis(50), "a connection costs nothing");

        let t = std::time::Instant::now();
        let emfile = std::io::Error::from_raw_os_error(libc::EMFILE);
        assert_eq!(survive_accept::<u8>(Err(emfile), "t").await.unwrap(), None);
        assert!(t.elapsed() >= std::time::Duration::from_millis(90), "a pause, so a shortage is not a busy loop");

        let gone = std::io::Error::from_raw_os_error(libc::EBADF);
        assert!(survive_accept::<u8>(Err(gone), "t").await.is_err());
    }

    /// The per-sandbox bridge shares a `select!` with the egress proxy: when it
    /// returned on the first EMFILE, that sandbox lost its proxy for good. Here
    /// the accept fails twice and then delivers a connection, which must still
    /// reach the proxy port.
    #[tokio::test]
    async fn the_bridge_keeps_serving_after_accept_fails() {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = proxy.local_addr().unwrap().port();
        let (mut shim, daemon_end) = tokio::net::UnixStream::pair().unwrap();
        let mut script: std::collections::VecDeque<std::io::Result<tokio::net::UnixStream>> = [
            Err(std::io::Error::from_raw_os_error(libc::EMFILE)),
            Err(std::io::Error::from_raw_os_error(libc::ECONNABORTED)),
            Ok(daemon_end),
        ]
        .into();
        let accept = move || {
            let next = script.pop_front();
            async move {
                match next {
                    Some(r) => r.map(|s| (s, ())),
                    None => std::future::pending().await,
                }
            }
        };
        let bridge = tokio::spawn(super::bridge_accepting(accept, port));

        let exchange = async {
            shim.write_all(b"CONNECT").await.unwrap();
            let (mut far, _) = proxy.accept().await.unwrap();
            let mut got = [0u8; 7];
            far.read_exact(&mut got).await.unwrap();
            got
        };
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), exchange)
            .await
            .expect("the bridge stopped serving after a failed accept");
        assert_eq!(&got, b"CONNECT");
        assert!(!bridge.is_finished(), "and it is still looping");
        bridge.abort();
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

/// Linux only: the forked children below are where the socket filter and the
/// Landlock network rules are proven, so they can't run on macOS.
#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::linux::socket_filter;

    fn errno_of(domain: i32, ty: i32, proto: i32) -> i32 {
        let fd = unsafe { libc::socket(domain, ty, proto) };
        if fd >= 0 {
            unsafe { libc::close(fd) };
            return 0;
        }
        std::io::Error::last_os_error().raw_os_error().unwrap()
    }

    #[test]
    fn only_tcp_sockets_survive_the_filter() {
        let prog = socket_filter().unwrap();
        // A fork, because the filter cannot be removed from the test process.
        // The child only makes syscalls; its exit code is 0 or the failed check.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let code = (|| {
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
                seccompiler::apply_filter(&prog).map_err(|_| 100)?;
                let (inet, inet6, cloexec) = (libc::AF_INET, libc::AF_INET6, libc::SOCK_CLOEXEC);
                let denied = [
                    errno_of(inet, libc::SOCK_DGRAM, 0),
                    errno_of(inet6, libc::SOCK_DGRAM | cloexec, 0),
                    errno_of(inet, libc::SOCK_RAW, 1),
                    errno_of(inet, libc::SOCK_STREAM, 132),
                    errno_of(inet6, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 262),
                ];
                for (i, e) in denied.iter().enumerate() {
                    if *e != libc::EPERM {
                        return Err(1 + i as i32);
                    }
                }
                let allowed = [
                    errno_of(inet, libc::SOCK_STREAM, 0),
                    errno_of(inet6, libc::SOCK_STREAM | cloexec, libc::IPPROTO_TCP),
                    errno_of(libc::AF_UNIX, libc::SOCK_DGRAM, 0),
                ];
                for (i, e) in allowed.iter().enumerate() {
                    if *e != 0 {
                        return Err(10 + i as i32);
                    }
                }
                // TCP Fast Open: unfiltered, this fails with ECONNREFUSED or
                // EINPROGRESS (port 1 has no listener), never EPERM.
                let tcp = unsafe { libc::socket(inet, libc::SOCK_STREAM, 0) };
                let mut to: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                to.sin_family = inet as u16;
                to.sin_port = 1u16.to_be();
                to.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
                let sent = unsafe {
                    libc::sendto(
                        tcp,
                        b"x".as_ptr().cast(),
                        1,
                        libc::MSG_FASTOPEN,
                        (&raw const to).cast(),
                        std::mem::size_of_val(&to) as u32,
                    )
                };
                if sent >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                    return Err(20);
                }
                // A plain send (sendto with flags 0) still works.
                let mut pair = [0; 2];
                if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) } != 0
                    || unsafe { libc::send(pair[0], b"x".as_ptr().cast(), 1, 0) } != 1
                {
                    return Err(21);
                }
                Ok(())
            })();
            unsafe { libc::_exit(code.err().unwrap_or(0)) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child did not exit: {status:#x}");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "failed check (1-5 denied, 10-12 allowed, 20 fastopen, 21 send, 100 apply)"
        );
    }

    /// The per-command Landlock rules, in a forked child (they cannot be
    /// lifted from the test process). With a network namespace of its own
    /// (M46) a command binds and connects on its own loopback freely: a server
    /// and its client in one sandbox. Sharing the host's, the sandbox's proxy
    /// port is the one TCP port it reaches, and it cannot listen.
    #[test]
    fn a_private_netns_sandbox_uses_its_own_loopback_and_a_shared_one_only_the_proxy() {
        if !super::linux::landlock_net_available() {
            eprintln!("skipped: Landlock ABI {} has no network rules", super::linux::abi());
            return;
        }
        let port = |l: &std::net::TcpListener| l.local_addr().unwrap().port();
        let (proxy, other) =
            (std::net::TcpListener::bind("127.0.0.1:0").unwrap(), std::net::TcpListener::bind("127.0.0.1:0").unwrap());
        let (pp, op) = (port(&proxy), port(&other));
        let refused = |r: std::io::Result<()>| matches!(r, Err(e) if e.raw_os_error() == Some(libc::EACCES));
        for private in [false, true] {
            let nowhere = std::path::Path::new("/nonexistent");
            let confine = super::linux::confine("/nonexistent", nowhere, Some(pp), private).unwrap();
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                let code = (|| {
                    confine().map_err(|_| 100)?;
                    std::net::TcpStream::connect(("127.0.0.1", pp)).map_err(|_| 1)?;
                    let other = std::net::TcpStream::connect(("127.0.0.1", op)).map(drop);
                    let own = std::net::TcpListener::bind("127.0.0.1:0");
                    if !private {
                        return match (refused(other), refused(own.map(drop))) {
                            (false, _) => Err(2),
                            (_, false) => Err(3),
                            _ => Ok(()),
                        };
                    }
                    let own = own.map_err(|_| 4)?;
                    std::net::TcpStream::connect(own.local_addr().map_err(|_| 4)?).map_err(|_| 5)?;
                    other.map_err(|_| 6)
                })();
                unsafe { libc::_exit(code.err().unwrap_or(0)) };
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status), "child did not exit: {status:#x}");
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "private netns {private}: failed check (1 proxy port refused; shared: 2 other port reached, \
                 3 bind allowed; private: 4 bind refused, 5 own listener refused, 6 other port refused; 100 confine)"
            );
        }
    }

    /// `qafas doctor` prints this for a bwrap that will not start. A host with
    /// `user.max_net_namespaces=0` fails `--unshare-net` with ENOSPC, which used
    /// to read as a full disk (or, on Ubuntu 24.04, as the AppArmor case).
    #[test]
    fn the_bwrap_hint_names_the_namespace_limit_for_enospc_and_apparmor_for_eperm() {
        use super::linux::bwrap_hint;
        // bubblewrap 0.9.0 on Ubuntu 24.04, as printed with user.max_net_namespaces=0, and the
        // strerror wording of older versions.
        for enospc in [
            "bwrap: Creating new namespace failed: nesting depth or /proc/sys/user/max_*_namespaces exceeded (ENOSPC)",
            "bwrap: Creating new namespace failed: No space left on device",
        ] {
            for restricted in [false, true] {
                let h = bwrap_hint(enospc, restricted);
                assert!(h.starts_with(enospc), "the error stays in front: {h}");
                assert!(h.contains("user.max_net_namespaces"), "{h}");
                assert!(!h.contains("AppArmor"), "ENOSPC is not the AppArmor case: {h}");
            }
        }
        let eperm = "bwrap: setting up uid map: Permission denied";
        let h = bwrap_hint(eperm, true);
        assert!(h.contains("AppArmor") && h.contains("docs/deployment.md"), "{h}");
        assert!(!h.contains("max_net_namespaces"), "{h}");
        assert_eq!(bwrap_hint(eperm, false), eperm, "no AppArmor restriction: nothing to add");
    }

    /// M46: a connection on `proxy.sock` reaches the proxy's TCP port, and the
    /// answer comes back the same way.
    #[tokio::test]
    async fn the_bridge_carries_proxy_sock_to_the_proxy_port() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = std::path::PathBuf::from(format!("/tmp/sbx-bridge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("proxy.sock");
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = proxy.local_addr().unwrap().port();
        tokio::spawn(super::bridge_to(tokio::net::UnixListener::bind(&sock).unwrap(), port));

        let exchange = async {
            let mut shim = tokio::net::UnixStream::connect(&sock).await.unwrap();
            shim.write_all(b"CONNECT").await.unwrap();
            let (mut far, _) = proxy.accept().await.unwrap();
            let mut got = [0u8; 7];
            far.read_exact(&mut got).await.unwrap();
            far.write_all(b"200").await.unwrap();
            let mut back = [0u8; 3];
            shim.read_exact(&mut back).await.unwrap();
            (got, back)
        };
        let (got, back) = tokio::time::timeout(std::time::Duration::from_secs(5), exchange)
            .await
            .expect("nothing came through the bridge within 5 s");
        assert_eq!((&got, &back), (b"CONNECT", b"200"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
