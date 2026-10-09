//! PID-1 duties. The reaper runs wherever we are PID 1; `boot()` (mounts,
//! hostname, NIC, proxy env) is the Firecracker path only — as a container
//! entrypoint we are uid 1000 without CAP_SYS_ADMIN and the runtime has already
//! done all of it.
//!
//! Everything here is best-effort: a failed mount is logged, never fatal.

use nix::mount::{mount, MsFlags};
use nix::sys::wait::{waitid, waitpid, Id, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

/// Mounts, hostname, NIC, proxy env. Only meaningful as root in a microVM.
pub fn boot() {
    // The kernel starts init with only HOME and TERM; everything we spawn
    // inherits our environment, so set the basics here.
    if std::env::var_os("PATH").is_none() {
        std::env::set_var("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    }
    // The kernel's `HOME=/` would put the canaries and every tool cache in `/`.
    if std::env::var("HOME").map(|h| h == "/" || h.is_empty()).unwrap_or(true) {
        std::env::set_var("HOME", "/home/agent");
    }
    // v5 §3a: the scratch cap is a tmpfs `size=` option, and the upper layer of
    // the root is mounted before anything else runs — so `/proc` goes up first,
    // purely to read `sbx.disk_mb` off the command line in time. The pivot
    // leaves that mount behind with the old root; `mount_all` puts it back.
    mnt("proc", "/proc", "proc", MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC, None);
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    overlay_root(cmdline_arg(&cmdline, "sbx.disk_mb").and_then(|v| v.parse::<u64>().ok()));
    mount_all();
    let _ = nix::unistd::sethostname("sandbox");
    configure_net(&cmdline);
    export_proxy(&cmdline);
    // Percent-encoded by the daemon, because the kernel splits the command line
    // on whitespace and a workspace path may contain some.
    if let Some(w) = cmdline_arg(&cmdline, "sbx.workspace") {
        std::env::set_var("SBX_WORKSPACE", agent_core::cmdline_decode(w));
    }
    if let Some(mb) = cmdline_arg(&cmdline, "sbx.max_upload_mb") {
        std::env::set_var("SBX_MAX_UPLOAD_MB", mb);
    }
    // The root's upper layer already carries `size=` from `overlay_root`; this
    // catches `/tmp`, which `mount_all` mounts at a fixed size, through the same
    // helper `PUT /limits` uses on a restore, so cold and restored agree.
    if let Some(mb) = cmdline_arg(&cmdline, "sbx.disk_mb").and_then(|v| v.parse::<u64>().ok()) {
        if let Err(e) = agent_core::limits::remount_scratch(mb) {
            tracing::warn!(error = %e, "scratch tmpfs not sized");
        }
    }
    warm_page_cache();
    tracing::info!(cmdline = %cmdline.trim(), "init done");
}

/// A fresh microVM has an empty page cache, and the rootfs is a virtio-blk
/// device: the first `node -v` streams 120 MB off it (1.9 s nested, ~300 ms on
/// bare KVM) before it prints anything. The VM sits in the pool for far longer
/// than that, so touch the interpreters now, while nobody is waiting.
/// design: fixed list; a Firecracker snapshot of the warmed VM is the upgrade path.
fn warm_page_cache() {
    let _ = std::process::Command::new("/bin/sh")
        .args(["-c", proto::WARM_CMD])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .env("HOME", "/tmp")
        .spawn();
}

/// Runs whenever we are PID 1 — in a container as much as in a microVM, since
/// either way orphaned grandchildren are reparented onto us. Must be called from
/// inside the runtime: the reaper waits on SIGCHLD through tokio's signal driver.
pub fn start_reaper() {
    tokio::spawn(reap_loop());
}

/// The rootfs is one read-only image shared by every microVM on the host (no
/// per-VM copy: creation is jailer + kernel boot, nothing else). Writes land in
/// a tmpfs upper layer through overlayfs, and we pivot into the merged view so
/// the rest of init and every child see an ordinary writable root.
/// Skipped when the root is already writable (a copied image, or a container).
fn overlay_root(disk_mb: Option<u64>) {
    use nix::unistd::pivot_root;
    let ro = std::fs::OpenOptions::new().write(true).open("/.sbx-rw-probe").is_err();
    if !ro {
        let _ = std::fs::remove_file("/.sbx-rw-probe");
        return;
    }
    let ov = "/overlay";
    // v5 §3a: sized here, at first mount, because this tmpfs *is* the writable
    // root's capacity — with no `size=` it defaults to half the guest's RAM.
    let opts = match disk_mb {
        Some(mb) => format!("mode=0755,size={mb}m"),
        None => "mode=0755".to_string(),
    };
    if let Err(e) = mount(Some("tmpfs"), ov, Some("tmpfs"), MsFlags::MS_NOSUID | MsFlags::MS_NODEV, Some(opts.as_str()))
    {
        // A read-only image without an /overlay directory has nowhere to mount;
        // the image build creates it.
        tracing::warn!(error = %e, "overlay tmpfs failed; running on the read-only root");
        return;
    }
    for d in ["upper", "work", "merged"] {
        let _ = std::fs::create_dir_all(format!("{ov}/{d}"));
    }
    let opts = format!("lowerdir=/,upperdir={ov}/upper,workdir={ov}/work");
    if let Err(e) =
        mount(Some("overlay"), format!("{ov}/merged").as_str(), Some("overlay"), MsFlags::empty(), Some(opts.as_str()))
    {
        tracing::warn!(error = %e, "overlayfs mount failed; running on the read-only root");
        return;
    }
    let merged = format!("{ov}/merged");
    // v5 §3a. After the pivot the upper tmpfs is named only by the overlay's
    // `upperdir=` option — it has no mount point of its own, so `PUT /limits`
    // has nothing to remount and the writable root stays at half of RAM. A bind
    // of it inside the new root keeps the superblock reachable: an `MS_REMOUNT`
    // with `size=` through the bind resizes the tmpfs itself, which is what
    // bounds `/`. Root-only (0700) and not the workspace's business — it is a
    // second path to the upper layer, so uid 1000 must not be able to traverse
    // it. Best effort: without it `disk_mib` degrades to the watchdog.
    let bind = format!("{merged}/.sbx/overlay");
    if let Err(e) = bind_upper(ov, &bind) {
        tracing::warn!(error = %e, "upper tmpfs not bound; the writable root cannot be resized later");
    }
    let old = format!("{merged}/.oldroot");
    let _ = std::fs::create_dir_all(&old);
    if let Err(e) = pivot_root(merged.as_str(), old.as_str()) {
        tracing::warn!(error = %e, "pivot_root failed; running on the read-only root");
        return;
    }
    let _ = nix::unistd::chdir("/");
    let _ = nix::mount::umount2("/.oldroot", nix::mount::MntFlags::MNT_DETACH);
    let _ = std::fs::remove_dir("/.oldroot");
    tracing::info!("root is a tmpfs overlay over the shared read-only image");
}

/// Binds the overlay's upper tmpfs somewhere inside the merged root, `0700` so
/// only root can walk into it. Both directories are created on the upper layer,
/// which is the tmpfs itself.
fn bind_upper(upper: &str, target: &str) -> nix::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let parent = std::path::Path::new(target).parent().unwrap_or(std::path::Path::new("/"));
    std::fs::create_dir_all(target).map_err(|_| nix::errno::Errno::EIO)?;
    for d in [parent, std::path::Path::new(target)] {
        let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700));
    }
    mount(Some(upper), target, None::<&str>, MsFlags::MS_BIND, None::<&str>)
}

fn mnt(src: &str, target: &str, fstype: &str, flags: MsFlags, data: Option<&str>) {
    let _ = std::fs::create_dir_all(target);
    if let Err(e) = mount(Some(src), target, Some(fstype), flags, data) {
        tracing::warn!(target, error = %e, "mount failed");
    }
}

fn mount_all() {
    let nosuid = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    mnt("proc", "/proc", "proc", nosuid, None);
    mnt("sysfs", "/sys", "sysfs", nosuid, None);
    mnt("devtmpfs", "/dev", "devtmpfs", MsFlags::MS_NOSUID, Some("mode=0755"));
    mnt("devpts", "/dev/pts", "devpts", MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC, Some("mode=0620,gid=5,ptmxmode=666"));
    mnt("tmpfs", "/dev/shm", "tmpfs", nosuid & !MsFlags::MS_NOEXEC, Some("mode=1777,size=512m"));
    mnt("tmpfs", "/tmp", "tmpfs", MsFlags::MS_NOSUID | MsFlags::MS_NODEV, Some("mode=1777,size=1g"));
    mnt("tmpfs", "/run", "tmpfs", nosuid, Some("mode=0755,size=64m"));
    // v5 §3a: the in-guest cgroup v2 leaf `PUT /limits` writes lives here. A
    // kernel without cgroup v2 logs the failed mount and the sandbox degrades to
    // the rlimit-and-watchdog path (`enforcement: "daemon"`).
    mnt("cgroup2", "/sys/fs/cgroup", "cgroup2", nosuid, Some("nsdelegate"));
    // bpftrace finds tracepoints through tracefs (D19). Harmless where absent.
    mnt("tracefs", "/sys/kernel/tracing", "tracefs", nosuid, None);
    mnt("debugfs", "/sys/kernel/debug", "debugfs", nosuid, None);
}

/// `sbx.key=value` out of the kernel command line.
fn cmdline_arg<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    cmdline.split_ascii_whitespace().find_map(|t| t.strip_prefix(key)?.strip_prefix('='))
}

/// `sbx.ip=172.16.N.2/30 sbx.gw=172.16.N.1` on eth0.
///
/// design: shells out to iproute2 (which the image already ships) instead of
/// pulling in a netlink crate. Upgrade to `rtnetlink` if the image ever drops
/// `ip`, or if the ~5 ms of process spawns shows up in boot time.
fn configure_net(cmdline: &str) {
    let Some(ip) = cmdline_arg(cmdline, "sbx.ip") else { return };
    set_net(ip, cmdline_arg(cmdline, "sbx.gw"), false);
}

/// `flush` is the restore path: the snapshot still carries the previous VM's
/// address and default route on eth0, and `ip addr add` would just add a second.
fn set_net(ip: &str, gw: Option<&str>, flush: bool) {
    let run = |args: &[&str]| match std::process::Command::new("ip").args(args).status() {
        Ok(s) if s.success() => {}
        r => tracing::warn!(?args, ?r, "ip command failed"),
    };
    run(&["link", "set", "lo", "up"]);
    if flush {
        run(&["addr", "flush", "dev", "eth0"]);
    }
    run(&["addr", "add", ip, "dev", "eth0"]);
    run(&["link", "set", "eth0", "up"]);
    if let Some(gw) = gw {
        run(&["route", "add", "default", "via", gw]);
    }
}

/// `sbx.proxy=http://172.16.N.1:3128` becomes the proxy env every child inherits.
/// There is no resolver in the guest (D7), so NO_PROXY stays loopback-only.
fn export_proxy(cmdline: &str) {
    let Some(p) = cmdline_arg(cmdline, "sbx.proxy") else { return };
    set_proxy(p);
}

fn set_proxy(p: &str) {
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        std::env::set_var(k, p);
    }
    std::env::set_var("NO_PROXY", "127.0.0.1,localhost");
    std::env::set_var("no_proxy", "127.0.0.1,localhost");
}

// ------------------------------------------------------------------ restore

/// `POST /restored` (protocol §3a, Snapshots): one Firecracker snapshot is
/// restored many times, so everything that identifies *this* sandbox — id,
/// network, canary tokens — is per-restore state and is replaced here. The
/// clock comes with it because a restored guest wakes up at the instant the
/// snapshot was taken.
#[derive(serde::Deserialize)]
pub struct RestoredReq {
    pub id: String,
    /// `172.16.N.2/30`. Empty leaves eth0 alone.
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub gw: String,
    #[serde(default)]
    pub proxy: String,
    /// Unix milliseconds. Absent leaves the (stale) clock alone.
    #[serde(default)]
    pub now: Option<i64>,
}

/// True only where the restore actually applies: PID 1 with euid 0, i.e. a
/// microVM. A container entrypoint is uid 1000 and cannot do any of it.
pub fn can_restore() -> bool {
    std::process::id() == 1 && nix::unistd::geteuid().is_root()
}

pub fn restored(req: &RestoredReq) {
    let _ = nix::unistd::sethostname("sandbox");
    std::env::set_var("SBX_ID", &req.id);
    if !req.ip.is_empty() {
        set_net(&req.ip, Some(req.gw.as_str()).filter(|g| !g.is_empty()), true);
    }
    if !req.proxy.is_empty() {
        set_proxy(&req.proxy);
    }
    if let Some(ms) = req.now {
        set_clock(ms);
    }
    // The canary *paths* are fixed, so `ctx.rules` needs no update; only the
    // tokens inside the files name a sandbox, and those are rewritten here.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/agent".into());
    agent_core::rules::Rules::replant_canaries(&home, &req.id);
    tracing::info!(id = req.id, ip = req.ip, "restored");
}

/// The kernel's clock froze when the snapshot was taken; `hwclock` would need a
/// device Firecracker does not give us, so the host tells us the time instead.
fn set_clock(unix_ms: i64) {
    let ts =
        libc::timespec { tv_sec: unix_ms.div_euclid(1000) as _, tv_nsec: (unix_ms.rem_euclid(1000) * 1_000_000) as _ };
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) } != 0 {
        tracing::warn!(error = %std::io::Error::last_os_error(), "clock_settime failed");
    }
}

// ------------------------------------------------------------------ reaper

/// `agent_core::exec` registers every child it spawns so the reaper does not
/// steal the exit status tokio is waiting for.
fn is_ours(pid: Pid) -> bool {
    agent_core::exec::is_tracked(pid.as_raw())
}

/// SIGCHLD does not queue: two deaths while we are already reaping can leave a
/// zombie that no further signal announces. This tick is what eventually
/// collects it, and the only thing that runs at all on an idle sandbox.
const REAP_SAFETY: std::time::Duration = std::time::Duration::from_secs(30);

/// Reaps processes orphaned onto PID 1 — most often a backgrounded job whose
/// shell we killed on timeout. Driven by SIGCHLD, so a zombie is collected when
/// it appears rather than up to a poll interval later.
async fn reap_loop() {
    use tokio::signal::unix::{signal, SignalKind};
    // tokio's own process driver listens for the same signal; the driver
    // broadcasts, so both hear every one.
    let mut chld = match signal(SignalKind::child()) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(error = %e, "no SIGCHLD stream; reaping on the safety tick alone");
            None
        }
    };
    loop {
        match chld.as_mut() {
            Some(s) => {
                tokio::select! {
                    _ = s.recv() => {}
                    _ = tokio::time::sleep(REAP_SAFETY) => {}
                }
            }
            None => tokio::time::sleep(REAP_SAFETY).await,
        }
        reap_ready();
    }
}

/// Every zombie that is not one of ours. Peeks with WNOWAIT first: anything
/// tokio spawned is left alone, because reaping it here would turn its `wait()`
/// into ECHILD. `WNOHANG` throughout, so this never blocks the runtime.
fn reap_ready() {
    let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
    loop {
        match waitid(Id::All, flags) {
            Ok(WaitStatus::StillAlive) | Err(_) => break,
            Ok(st) => match st.pid() {
                Some(pid) if !is_ours(pid) => {
                    let _ = waitpid(pid, Some(WaitPidFlag::WNOHANG));
                }
                // One of ours, not yet reaped by tokio: stop peeking, it is
                // always the same zombie until tokio gets to it.
                _ => break,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_cmdline() {
        let c = "console=ttyS0 sbx.ip=172.16.3.2/30 sbx.gw=172.16.3.1 sbx.proxy=http://172.16.3.1:3128 pci=off";
        assert_eq!(super::cmdline_arg(c, "sbx.ip"), Some("172.16.3.2/30"));
        assert_eq!(super::cmdline_arg(c, "sbx.gw"), Some("172.16.3.1"));
        assert_eq!(super::cmdline_arg(c, "sbx.proxy"), Some("http://172.16.3.1:3128"));
        assert_eq!(super::cmdline_arg(c, "sbx.nope"), None);
        // A bare `sbx.ip` with no `=` must not match.
        assert_eq!(super::cmdline_arg("sbx.ip", "sbx.ip"), None);
    }

    /// The body qafas sends on restore. `{id}` alone has to be enough, and
    /// `now` is unix milliseconds.
    #[test]
    fn restored_body_defaults() {
        let r: super::RestoredReq = serde_json::from_str(r#"{"id":"sbx_1"}"#).unwrap();
        assert!(r.ip.is_empty() && r.gw.is_empty() && r.proxy.is_empty() && r.now.is_none());
        let r: super::RestoredReq = serde_json::from_str(
            r#"{"id":"sbx_2","ip":"172.16.3.2/30","gw":"172.16.3.1","proxy":"http://172.16.3.1:3128","now":1757325600123}"#,
        )
        .unwrap();
        assert_eq!((r.id.as_str(), r.now), ("sbx_2", Some(1_757_325_600_123)));
        // Not PID 1 as root in a test process, so the route must refuse.
        assert!(!super::can_restore());
    }

    #[test]
    fn untracked_pids_are_reapable() {
        // Nothing has been exec'd, so no pid belongs to the exec layer and the
        // reaper is free to take every zombie it finds.
        assert!(!super::is_ours(nix::unistd::Pid::from_raw(4242)));
    }

    /// Guest-only by construction (this crate is Linux-only), but it needs no
    /// PID 1: a child of the test process is a zombie the same way an orphan is.
    /// One `reap_ready` pass must collect it, which is what makes SIGCHLD a
    /// usable trigger — a pass that left the zombie behind would rely on the
    /// 30 s safety tick for everything.
    #[test]
    fn one_pass_collects_a_zombie() {
        let child = std::process::Command::new("/bin/sh").args(["-c", "exit 0"]).spawn().unwrap();
        let pid = nix::unistd::Pid::from_raw(child.id() as i32);
        std::mem::forget(child); // do not let `Child`'s own wait race us
                                 // Wait for it to actually die; until then there is nothing to reap.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            super::reap_ready();
            if nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)).is_err() {
                return; // ECHILD: already reaped by the pass above
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("the zombie was never collected");
    }
}
