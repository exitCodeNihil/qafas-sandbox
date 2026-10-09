//! How a command is confined (D17).
//!
//!   * `Hardened` — we are already inside the boundary (container or microVM):
//!     drop to uid 1000, `no_new_privs`, seccomp deny-list, own process group.
//!   * The native tier uses the same `Hardened` inside `qafas shim`, which is
//!     itself wrapped once in the OS sandbox (`sandbox-exec` / `bwrap`); the
//!     process-level confinement the OS cannot express is a `Confine` applied
//!     when the shim is spawned.

use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::sync::Arc;

use tokio::process::Command;

/// Per-process resource ceilings. `resource.limit` alerts come from hitting them.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub nproc: u64,
    pub cpu_secs: u64,
    /// Address space in bytes. Linux only; macOS ignores RLIMIT_AS for practical
    /// purposes (the JIT allocations every runtime makes trip it immediately).
    pub as_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self { nproc: 512, cpu_secs: 3600, as_bytes: 8 << 30 }
    }
}

/// v5 §3a. The rlimit half of a sandbox size, for the one tier with no cgroup
/// to put it in (native). `nproc` is left alone on macOS: `RLIMIT_NPROC` is
/// counted per *uid* there, so a per-sandbox value would throttle every other
/// process the same user is running, the daemon included.
impl From<&proto::SandboxLimits> for Limits {
    fn from(l: &proto::SandboxLimits) -> Self {
        let d = Self::default();
        Self {
            nproc: if cfg!(target_os = "macos") { d.nproc } else { u64::from(l.pids) },
            cpu_secs: d.cpu_secs,
            as_bytes: l.mem_mib * 1024 * 1024,
        }
    }
}

impl Limits {
    /// Call before fork. macOS counts `RLIMIT_NPROC` per *uid*, so a flat 512 stops
    /// every fork as soon as the user's own session has more processes than that
    /// (a busy desktop does). Make it headroom over what is already running.
    ///
    /// It is measured once per spawn, which makes it belt and braces rather than
    /// the limit: the number that actually holds the sandbox to its size is the
    /// per-group pid count in the procmon watchdog (`Monitor::watchdog`), and
    /// that one is re-read every sweep.
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    pub fn headroom(mut self) -> Self {
        #[cfg(target_os = "macos")]
        {
            // PROC_UID_ONLY = 4. A null buffer sizes for *every* process on the machine,
            // so fill a real one: the return is then the bytes used by this uid's pids.
            const PID: usize = std::mem::size_of::<libc::pid_t>();
            let all = unsafe { libc::proc_listpids(4, libc::getuid(), std::ptr::null_mut(), 0) };
            let mut buf = vec![0 as libc::pid_t; all.max(0) as usize / PID + 64];
            let used = unsafe {
                libc::proc_listpids(4, libc::getuid(), buf.as_mut_ptr().cast(), (buf.len() * PID) as libc::c_int)
            };
            self.nproc += used.max(0) as u64 / PID as u64;
        }
        self
    }

    /// Runs between fork and exec: allocation-free, async-signal-safe.
    pub fn apply(&self) -> std::io::Result<()> {
        // The resource id is `c_int` on musl and macOS but `__rlimit_resource_t`
        // (u32) on glibc: let the parameter take `setrlimit`'s own type.
        let set = |res, v: u64| {
            let rl = libc::rlimit { rlim_cur: v as libc::rlim_t, rlim_max: v as libc::rlim_t };
            unsafe { libc::setrlimit(res, &rl) };
        };
        set(libc::RLIMIT_NPROC, self.nproc);
        set(libc::RLIMIT_CPU, self.cpu_secs);
        #[cfg(target_os = "linux")]
        set(libc::RLIMIT_AS, self.as_bytes);
        Ok(())
    }
}

/// Variables the sandbox owns. A request may set anything else; these come from
/// the sandbox's own environment so a harness cannot point HOME or TMPDIR at the
/// host, swap the proxy, or change the sandbox identity (D6, D22).
pub const PROTECTED_ENV: &[&str] = &[
    "HOME",
    "TMPDIR",
    "PATH",
    "SBX_ID",
    "SBX_HOST_ID",
    "SBX_WORKSPACE",
    "SBX_HOST_HOME",
    "SBX_MAX_UPLOAD_MB",
    "SBX_AGENT_TOKEN",
    "SBX_SCRATCH",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSH_AUTH_SOCK",
    "DYLD_INSERT_LIBRARIES",
    "LD_PRELOAD",
];

pub fn env_allowed(key: &str) -> bool {
    !PROTECTED_ENV.contains(&key) && !key.starts_with("DYLD_") && !key.starts_with("LD_")
}

/// Its own process group — and its own session where the kernel allows one,
/// because `setsid` gives both and a PTY child *has* to be a session leader
/// before it can claim its slave as a controlling terminal (`exec::spawn_session`).
/// Doing it the other way round does not work: `setsid` refuses a process that is
/// already a group leader, which is what `setpgid(0,0)` would have made it.
fn own_process_group() -> std::io::Result<()> {
    if unsafe { libc::setsid() } >= 0 {
        return Ok(());
    }
    if unsafe { libc::setpgid(0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Moves the calling process into the workload cgroup leaf (`limits::WORK`),
/// where `PUT /limits` wrote the ceilings. Runs between fork and exec, so: raw
/// syscalls, no allocation — `"0"` is cgroup v2's name for "the writer", which
/// is also why there is no pid to format here. Best effort: the leaf only exists
/// where this agent is root and made one, and the uid drop below has not
/// happened yet, so the write is still permitted.
#[cfg(target_os = "linux")]
fn join_work_cgroup() {
    let fd = unsafe { libc::open(c"/sys/fs/cgroup/sbx/work/cgroup.procs".as_ptr(), libc::O_WRONLY) };
    if fd >= 0 {
        unsafe {
            libc::write(fd, b"0".as_ptr().cast(), 1);
            libc::close(fd);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn join_work_cgroup() {}

// ------------------------------------------------------------------ hardened

/// Inside the VM/container: `harden::apply` does uid drop + seccomp.
pub struct Hardened {
    pub limits: Limits,
}

impl Default for Hardened {
    fn default() -> Self {
        Self { limits: Limits::default() }
    }
}

#[cfg(target_os = "linux")]
fn harden(seccomp: bool) -> std::io::Result<()> {
    crate::harden::apply(seccomp)
}

#[cfg(not(target_os = "linux"))]
fn harden(_seccomp: bool) -> std::io::Result<()> {
    Ok(())
}

impl Hardened {
    /// The confined shell command. The child is always in its own process group,
    /// so a timeout can `killpg` the whole tree.
    pub fn command(&self, cmd: &str, cwd: &str, env: &BTreeMap<String, String>) -> Command {
        let mut c = Command::new("/bin/bash");
        // A login shell reads /etc/profile: cheap in the image, ~8 ms on macOS
        // (path_helper). The native shim already carries a curated PATH.
        let flag = if cfg!(target_os = "macos") { "-c" } else { "-lc" };
        c.arg(flag).arg(cmd).current_dir(cwd);
        // The child inherits the agent's own environment on purpose (HOME, PATH,
        // the proxy, the sandbox identity all come from there); only the secret
        // must not travel with it.
        c.env_remove("SBX_AGENT_TOKEN");
        for (k, v) in env.iter().filter(|(k, _)| env_allowed(k)) {
            c.env(k, v);
        }
        c.kill_on_drop(true);
        let limits = self.limits.headroom();
        unsafe {
            c.pre_exec(move || {
                own_process_group()?;
                join_work_cgroup();
                limits.apply()?;
                harden(true)
            });
        }
        c
    }

    /// A long-lived helper (Chromium). Own process group, no seccomp — it needs
    /// the syscalls the deny-list removes (D8) — but the same OS sandbox.
    pub fn helper(&self, program: &str) -> std::process::Command {
        let mut c = std::process::Command::new(program);
        unsafe {
            c.pre_exec(|| {
                own_process_group()?;
                join_work_cgroup();
                harden(false)
            });
        }
        c
    }

    /// Home directory a caller should assume when the request gives no `cwd`.
    pub fn home(&self) -> String {
        std::env::var("HOME").unwrap_or_else(|_| "/tmp".into())
    }
}

// ------------------------------------------------------------------ confine

/// Extra confinement the OS wrapper cannot express, applied between fork and
/// exec of the native tier's shim so everything it spawns inherits it. macOS
/// has none (Seatbelt is the wrapper); Linux installs Landlock and seccomp here.
pub type Confine = Arc<dyn Fn() -> std::io::Result<()> + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_variables_cannot_be_overridden() {
        for k in ["HOME", "TMPDIR", "PATH", "HTTP_PROXY", "SBX_ID", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD"] {
            assert!(!env_allowed(k), "{k} must be sandbox-owned");
        }
        assert!(env_allowed("TERM") && env_allowed("MY_APP_FLAG"));
    }

    /// v5 §3a: the size table maps onto rlimits the same way on every row, and
    /// macOS keeps the default `nproc` because that limit is per-uid there.
    #[test]
    fn rlimits_follow_the_size() {
        let t = proto::sizes::default_table();
        for (name, want_mib) in [("micro", 512u64), ("mini", 1024), ("medium", 2048), ("high", 4096)] {
            let l = Limits::from(&t[name]);
            assert_eq!(l.as_bytes, want_mib * 1024 * 1024, "{name}");
            let want_nproc = if cfg!(target_os = "macos") { Limits::default().nproc } else { u64::from(t[name].pids) };
            assert_eq!(l.nproc, want_nproc, "{name}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_nproc_is_headroom_over_this_uids_processes() {
        let base = Limits::default().nproc;
        let mine = Limits::default().headroom().nproc - base;
        let out = std::process::Command::new("ps")
            .args(["-U", &unsafe { libc::getuid() }.to_string(), "-o", "pid="])
            .output()
            .unwrap();
        let ps = String::from_utf8_lossy(&out.stdout).lines().count() as u64;
        assert!(mine > 0 && mine.abs_diff(ps) < 50, "uid process count {mine} should be close to ps's {ps}");
    }

    #[tokio::test]
    async fn hardened_command_runs_in_its_own_group_with_env() {
        let env = BTreeMap::from([("SBX_T".to_string(), "1".to_string()), ("HOME".to_string(), "/nope".to_string())]);
        let mut c =
            Hardened::default().command("[ \"$HOME\" != /nope ] && echo -n $SBX_T; ps -o pgid= -p $$", "/", &env);
        let out = c.output().await.expect("bash runs");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.starts_with('1'), "env reaches the shell: {text:?}");
        let pgid: i32 = text[1..].trim().parse().expect("pgid printed");
        assert_ne!(pgid, unsafe { libc::getpgrp() }, "child must be its own process group");
    }
}
