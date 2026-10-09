//! v5 sizes and limits (protocol §3a), the in-sandbox half: `PUT /limits` and
//! `GET /usage`.
//!
//! Who enforces what depends on where this agent runs, and the agent is the only
//! one that knows:
//!
//!   * **vm** — uid 1000 in a container whose cgroup podman owns. `PUT /limits`
//!     is never called; `GET /usage` reads the container's own cgroup files,
//!     which the cgroup namespace puts at `/sys/fs/cgroup` directly.
//!   * **remote** — PID 1 as root in a microVM. `PUT /limits` makes a cgroup v2
//!     leaf, moves us into it (so every exec inherits it) and remounts the
//!     scratch tmpfs to `disk_mib`.
//!   * **native** — `qafas shim`, no cgroups on macOS. `PUT /limits` records
//!     a budget the procmon sweep enforces by killing the process group
//!     (`SandboxInfo.enforcement: "daemon"`).
//!
//! Nothing here is ever asked of the workload: every number is read from the
//! kernel, and the files that hold them are out of the sandbox's reach.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use proto::{SandboxLimits, SandboxUsage};

/// The cgroup v2 subtree the guest agent makes when it is root. It holds no
/// processes itself: cgroup v2 forbids that in a cgroup that delegates
/// controllers to its children, and both children below need them.
#[cfg(target_os = "linux")]
const LEAF: &str = "/sys/fs/cgroup/sbx";
/// The workload's leaf: the ceilings live here and every exec joins it
/// (`spawn::join_work_cgroup`), so a memory limit hit picks a workload process
/// as the OOM victim and never this agent.
#[cfg(target_os = "linux")]
pub const WORK: &str = "/sys/fs/cgroup/sbx/work";
/// The agent's own sibling leaf, out of the workload's reach.
#[cfg(target_os = "linux")]
const AGENT: &str = "/sys/fs/cgroup/sbx/agent";

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Our own cgroup directory on the host filesystem: `/proc/self/cgroup` is
/// `0::<path>` relative to the v2 mount. In a container the namespace makes that
/// `/`, so this is the container's cgroup; after `apply` it is the `sbx` leaf.
/// `None` where there is no cgroup v2 at all (macOS, a v1-only kernel).
pub fn cgroup_dir() -> Option<String> {
    let rel = read("/proc/self/cgroup")?.lines().find_map(|l| l.strip_prefix("0::").map(str::to_string))?;
    let dir = format!("/sys/fs/cgroup{}", rel.trim_end_matches('/'));
    std::path::Path::new(&dir).join("cgroup.controllers").exists().then_some(dir)
}

/// The cgroup whose numbers describe the *workload*: the `work` leaf wherever
/// this agent built one, and otherwise our own cgroup — which on the vm tier is
/// the container's, the one podman sized. Every limit and usage read goes
/// through here, so the agent's own memory is never charged to the sandbox.
pub fn accounting_dir() -> Option<String> {
    #[cfg(target_os = "linux")]
    if std::path::Path::new(WORK).join("cgroup.controllers").exists() {
        return Some(WORK.to_string());
    }
    cgroup_dir()
}

fn num(dir: &str, file: &str) -> u64 {
    read(&format!("{dir}/{file}")).and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

/// `usage_usec` out of `cpu.stat`.
fn cpu_usec(dir: &str) -> u64 {
    read(&format!("{dir}/cpu.stat"))
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("usage_usec ")).and_then(|v| v.trim().parse().ok()))
        .unwrap_or(0)
}

/// Cumulative `oom_kill` count of our cgroup, and how many are new since the
/// last call. `post_mortem` asks after a SIGKILL: a non-zero delta is the one
/// reliable way to tell "the memory limit killed it" from "somebody killed it".
static OOM_SEEN: AtomicU64 = AtomicU64::new(0);

/// The memory ceiling this sandbox is actually under, for an alert that has to
/// name a number. `PUT /limits` where qafas said so, the cgroup's own
/// `memory.max` on the vm tier where the container runtime set it.
pub fn mem_limit_mib(ctx: &crate::Ctx) -> u64 {
    if let Some(l) = *ctx.limits.read().expect("limits") {
        return l.mem_mib;
    }
    accounting_dir().map_or(0, |d| num(&d, "memory.max") / (1024 * 1024))
}

pub fn oom_kills_since_last_check() -> u64 {
    let Some(dir) = accounting_dir() else { return 0 };
    let now = read(&format!("{dir}/memory.events"))
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("oom_kill ")?.trim().parse::<u64>().ok()))
        .unwrap_or(0);
    now.saturating_sub(OOM_SEEN.swap(now, Relaxed))
}

// ------------------------------------------------------------------ apply

/// `PUT /limits`. Returns the enforcement word for `SandboxInfo`: `kernel` when
/// a cgroup took the values, `daemon` when only the watchdog did. `Err` is a
/// refused resize the caller must not paper over — a sandbox handed out with a
/// disk cap that did not apply is a sandbox with no disk cap.
///
/// The watchdog is armed only for what the kernel is *not* holding. Arming it
/// alongside a cgroup is not belt and braces: the two race, and under nested
/// KVM the sampler wins, killing the group before the guest OOM killer reacts
/// and reporting a watchdog kill where a cgroup kill was what the contract
/// promised.
pub fn apply(ctx: &crate::Ctx, l: &SandboxLimits) -> Result<&'static str, String> {
    *ctx.limits.write().expect("limits") = Some(*l);
    let kernel = match cgroup_apply(l) {
        Ok(()) => true,
        Err(e) => {
            tracing::info!(error = %e, "no cgroup for this sandbox; memory is watchdog-enforced");
            false
        }
    };
    let disk_capped = remount_scratch(l.disk_mib)?;
    ctx.mon.set_budget(
        if kernel { 0 } else { l.mem_mib * 1024 * 1024 },
        if disk_capped { 0 } else { l.disk_mib * 1024 * 1024 },
        if kernel { 0 } else { l.pids },
        scratch_dir(),
    );
    Ok(if kernel { "kernel" } else { "daemon" })
}

/// Builds `sbx/{agent,work}`, parks this process in `agent` and writes the three
/// ceilings on `work`. Execs do not inherit it — they join `work` themselves
/// between fork and exec (`spawn::join_work_cgroup`) — which is what keeps the
/// agent out of the OOM killer's reach when the workload fills its memory.
#[cfg(target_os = "linux")]
fn cgroup_apply(l: &SandboxLimits) -> std::io::Result<()> {
    if !nix::unistd::geteuid().is_root() {
        return Err(std::io::Error::other("not root; the runtime owns this cgroup"));
    }
    // Delegating the controllers to children has to happen on the root before
    // the leaf can use them.
    let _ = std::fs::write("/sys/fs/cgroup/cgroup.subtree_control", "+cpu +memory +pids");
    std::fs::create_dir_all(AGENT)?;
    std::fs::create_dir_all(WORK)?;
    // Out of `sbx` before it delegates: the kernel refuses `subtree_control` on
    // a cgroup that still holds processes ("no internal processes").
    std::fs::write(format!("{AGENT}/cgroup.procs"), std::process::id().to_string())?;
    std::fs::write(format!("{LEAF}/cgroup.subtree_control"), "+cpu +memory +pids")?;
    write_ceilings(std::path::Path::new(WORK), l)?;
    OOM_SEEN.store(0, Relaxed);
    Ok(())
}

/// The three files a sandbox size maps onto, written into one cgroup v2
/// directory. qafas's native tier writes the same trio into its own per-sandbox
/// leaf, and a size that means two different things on two tiers is a bug
/// waiting for a support ticket.
#[cfg(target_os = "linux")]
pub fn write_ceilings(dir: &std::path::Path, l: &SandboxLimits) -> std::io::Result<()> {
    std::fs::write(dir.join("cpu.max"), format!("{} 100000", (l.cpus * 100_000.0).round() as i64))?;
    std::fs::write(dir.join("memory.max"), (l.mem_mib * 1024 * 1024).to_string())?;
    std::fs::write(dir.join("pids.max"), l.pids.to_string())
}

#[cfg(not(target_os = "linux"))]
fn cgroup_apply(_l: &SandboxLimits) -> std::io::Result<()> {
    Err(std::io::Error::other("no cgroup v2 on this platform"))
}

/// Every tmpfs this sandbox can write to, sized to `disk_mib`.
///
/// On the remote tier the writable root is an overlay whose upper layer is the
/// tmpfs guest-agent mounts at `/overlay` (`init::overlay_root`) with no
/// `size=`, so it defaults to half the guest's RAM — `df -m /` reports that
/// tmpfs, and remounting `/` cannot change it because `/` is the overlay, not
/// the tmpfs. `/overlay` is the mount that has to move, and it is the one
/// `disk_mib` means on that tier.
///
/// `Ok(true)`: at least one tmpfs was found and sized, so nothing else has to
/// watch the disk. `Ok(false)`: there is no tmpfs here to cap (macOS native),
/// so the watchdog does. `Err`: one was found and refused the new size — the
/// usual cause is a shrink below what is already written, which the kernel
/// answers with `EINVAL`.
#[cfg(target_os = "linux")]
pub fn remount_scratch(disk_mib: u64) -> Result<bool, String> {
    if !nix::unistd::geteuid().is_root() {
        return Ok(false);
    }
    let opts = format!("size={disk_mib}m");
    let flags = nix::mount::MsFlags::MS_REMOUNT | nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV;
    let mut sized = false;
    for target in tmpfs_scratch_mounts() {
        nix::mount::mount(Some("tmpfs"), target.as_str(), Some("tmpfs"), flags, Some(opts.as_str())).map_err(|e| {
            format!("cannot resize {target} to {disk_mib} MiB: {e} (in use: {} bytes)", scratch_bytes(&target))
        })?;
        sized = true;
    }
    if !sized {
        // Silence here is how the remote tier shipped an uncapped writable root
        // once already: `/overlay` had no mount point of its own after
        // `pivot_root`, so there was nothing to find and nothing said so.
        tracing::warn!(disk_mib, "no scratch tmpfs found to size; disk falls back to the watchdog");
    }
    Ok(sized)
}

/// Which of the scratch candidates are actually tmpfs right now, in the order
/// they should be resized. Read from `/proc/mounts` rather than assumed: the
/// overlay only exists on the remote tier, and remounting something that is not
/// a tmpfs would fail for a reason that has nothing to do with the size.
#[cfg(target_os = "linux")]
fn tmpfs_scratch_mounts() -> Vec<String> {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else { return Vec::new() };
    // `/.sbx/overlay` is the bind `init::overlay_root` leaves behind for exactly
    // this: it is the only name the overlay's upper tmpfs still has after the
    // pivot, and resizing that superblock is what resizes `/`.
    let want = ["/.sbx/overlay".to_string(), "/overlay".to_string(), scratch_dir(), "/tmp".to_string()];
    let mut out: Vec<String> = Vec::new();
    for line in mounts.lines() {
        let mut f = line.split_whitespace();
        let (Some(_src), Some(target), Some(fstype)) = (f.next(), f.next(), f.next()) else { continue };
        if fstype == "tmpfs" && want.iter().any(|w| w == target) && !out.iter().any(|o| o == target) {
            out.push(target.to_string());
        }
    }
    out
}

#[cfg(not(target_os = "linux"))]
pub fn remount_scratch(_disk_mib: u64) -> Result<bool, String> {
    Ok(false)
}

/// The writable scratch this sandbox is charged for (protocol §3a `disk_mib`):
/// `SBX_SCRATCH` where the native tier names its `/tmp/sbx-<id>` — which holds
/// the fake HOME as well as `TMPDIR` — and `/tmp` otherwise, the vm tier's
/// tmpfs. Read out of this process's own environment, which is qafas's
/// curated one; a request's `env` reaches children, never us.
pub fn scratch_dir() -> String {
    ["SBX_SCRATCH", "TMPDIR"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "/tmp".into())
}

// ------------------------------------------------------------------ usage

/// `GET /usage`. Cgroup files where there are any, `/proc`-derived sums from
/// procmon where there are not (macOS native).
pub fn usage(ctx: &crate::Ctx) -> SandboxUsage {
    let mut u = SandboxUsage { ts: crate::now_rfc3339(), ..Default::default() };
    match accounting_dir() {
        Some(dir) => {
            u.mem_bytes = num(&dir, "memory.current");
            // `memory.peak` needs a 5.19 kernel; without it the current value is
            // the honest answer rather than a zero.
            u.mem_peak_bytes = num(&dir, "memory.peak").max(u.mem_bytes);
            u.cpu_millis = cpu_usec(&dir) / 1000;
            u.pids = num(&dir, "pids.current") as u32;
        }
        None => {
            let (rss, cpu, n) = ctx.mon.totals();
            u.mem_bytes = rss;
            u.mem_peak_bytes = rss;
            u.cpu_millis = cpu;
            u.pids = n;
        }
    }
    u.disk_bytes = scratch_bytes(&scratch_dir());
    u
}

/// v5.1 §1 `sandbox.usage`. How often the agent pushes a sample of its own onto
/// the event stream while something is running.
const PUSH_EVERY: std::time::Duration = std::time::Duration::from_secs(2);

/// Starts the push, once per sandbox, on its first exec. The daemon's 5 s pull
/// stays: it is what covers an *idle* sandbox, which this task deliberately says
/// nothing about. Between them `SandboxInfo.usage` never lags a live burst by
/// more than `PUSH_EVERY`, which is what makes a spike visible at all.
pub fn start_usage_push(ctx: &std::sync::Arc<crate::Ctx>) {
    if ctx.usage_push.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let ctx = ctx.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(PUSH_EVERY).await;
            let Some(corr) = ctx.mon.live_corr() else { continue };
            push_usage(&ctx, &corr);
        }
    });
}

/// One sample on the event stream, attributed to the tool call that caused it.
/// Also called when an exec ends, so the last numbers of a burst are on the
/// stream rather than only in whichever pull comes next.
pub fn push_usage(ctx: &crate::Ctx, corr: &crate::Corr) {
    ctx.ev.emit(corr, proto::EventType::SandboxUsage, serde_json::to_value(usage(ctx)).unwrap_or_default());
}

/// How much of the scratch is in use. A tmpfs answers exactly and for nothing
/// through `statvfs`; a plain directory (macOS native, where the scratch is a
/// directory under `/tmp`) has to be walked.
pub fn scratch_bytes(dir: &str) -> u64 {
    if cfg!(target_os = "linux") {
        if let Ok(s) = nix::sys::statvfs::statvfs(dir) {
            return (s.blocks() - s.blocks_free()) as u64 * s.fragment_size();
        }
        return 0;
    }
    walk_bytes(std::path::Path::new(dir))
}

/// design: a recursive walk, called once a second at most and over a scratch
/// directory with tens of files. `statvfs` on a tmpfs covers every other tier;
/// give macOS its own volume if this ever has to scale.
fn walk_bytes(p: &std::path::Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(p) else { return 0 };
    rd.flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => walk_bytes(&e.path()),
            Ok(t) if t.is_file() => e.metadata().map(|m| m.len()).unwrap_or(0),
            _ => 0,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scratch measurement has to see a file that is actually there,
    /// whichever half of `scratch_bytes` this platform takes.
    #[test]
    fn scratch_bytes_counts_what_is_written() {
        let d = std::env::temp_dir().join(format!("sbx-disk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("sub/a"), vec![0u8; 64 * 1024]).unwrap();
        assert!(walk_bytes(&d) >= 64 * 1024, "a walked directory counts its files");
        // Not a tmpfs here, so only the walk is asserted; `statvfs` is exercised
        // live on the vm tier, where `/tmp` is the scratch.
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// The cgroup half, where there is one to write (guest-only: root on a
    /// cgroup v2 host, so it runs in the microVM and is skipped everywhere the
    /// daemon could not have done it either). The three ceilings land on the
    /// *work* leaf, this agent ends up in the sibling `agent` leaf instead of
    /// sharing the workload's, and the numbers `usage` reports come from `work`.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_writable_cgroup_puts_the_ceilings_on_a_leaf_of_its_own() {
        let l = SandboxLimits { cpus: 1.0, mem_mib: 1024, disk_mib: 1024, pids: 256 };
        if cgroup_apply(&l).is_err() {
            return; // no cgroup v2 root we may write: the watchdog path covers it
        }
        assert_eq!(read(&format!("{WORK}/memory.max")).unwrap().trim(), "1073741824");
        assert_eq!(read(&format!("{WORK}/cpu.max")).unwrap().trim(), "100000 100000");
        assert_eq!(read(&format!("{WORK}/pids.max")).unwrap().trim(), "256");
        assert_eq!(cgroup_dir().as_deref(), Some(AGENT), "the agent is not in the workload's leaf");
        assert_eq!(accounting_dir().as_deref(), Some(WORK), "but the numbers come from it");
    }

    /// A sandbox with no cgroup at all must still answer `GET /usage` — the
    /// contract makes `usage` optional in content, never in shape.
    #[test]
    fn usage_is_answerable_without_a_cgroup() {
        let ctx = crate::Ctx::new(
            crate::spawn::Hardened::default(),
            crate::Emitter::null(),
            crate::rules::Rules::guest("/tmp", "/tmp"),
        );
        let u = usage(&ctx);
        assert!(u.ts.ends_with('Z'), "{u:?}");
    }
}
