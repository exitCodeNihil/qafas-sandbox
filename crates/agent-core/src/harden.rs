//! What every process spawned inside the VM/container tier gets before
//! `execve`: uid 1000, no-new-privs, its own process group (the caller's job),
//! and the seccomp deny-list of D8/D18.
//!
//! Two filters, not one, because they need two different actions and a seccomp
//! filter has exactly one match action. The kernel evaluates every installed
//! filter and takes the strongest verdict, so stacking them gives:
//!
//!   * `KILL_PROCESS` for syscalls with no benign use in a coding agent. The
//!     attempt is stopped *and* visible: the process dies with SIGSYS and
//!     `exec.rs` turns that into `security.alert{rule:"seccomp.violation"}`.
//!   * `EPERM` for io_uring, which libuv probes on startup (D18). Killing node
//!     for a probe would be a bug, not a detection.
//!
//! Both programs are built once at startup so the `pre_exec` closure only calls
//! prctl(2) on already-allocated BPF.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule, TargetArch,
};

pub const AGENT_UID: u32 = 1000;
pub const AGENT_GID: u32 = 1000;

static FILTERS: OnceLock<Vec<BpfProgram>> = OnceLock::new();

#[cfg(target_arch = "aarch64")]
const ARCH: TargetArch = TargetArch::aarch64;
#[cfg(target_arch = "x86_64")]
const ARCH: TargetArch = TargetArch::x86_64;

/// No benign use inside a sandbox: memory of another process, namespace and
/// mount machinery, the kernel's own programmable surfaces. Killing on these
/// makes an attempt loud instead of a silently-retried EPERM.
fn killed() -> Vec<i64> {
    vec![
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_fsopen,
        libc::SYS_fsmount,
        libc::SYS_fsconfig,
        libc::SYS_fspick,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_bpf,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_userfaultfd,
        libc::SYS_perf_event_open,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
    ]
}

/// Denied, but survivably: something legitimate probes for it.
fn refused() -> Vec<i64> {
    vec![libc::SYS_io_uring_setup, libc::SYS_io_uring_enter, libc::SYS_io_uring_register]
}

/// `clone(2)` with any CLONE_NEW* flag is a new namespace: the one syscall an
/// ordinary fork shares with an unprivileged-userns exploit, so it is filtered by
/// argument. `clone3(2)` takes its flags in a struct seccomp cannot inspect; it
/// gets ENOSYS, which every libc answers by falling back to `clone`.
const NS_FLAGS: &[u64] = &[
    libc::CLONE_NEWUSER as u64,
    libc::CLONE_NEWNS as u64,
    libc::CLONE_NEWPID as u64,
    libc::CLONE_NEWNET as u64,
    libc::CLONE_NEWIPC as u64,
    libc::CLONE_NEWUTS as u64,
    libc::CLONE_NEWCGROUP as u64,
];

fn build_clone_ns() -> anyhow::Result<BpfProgram> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let mut clone_rules = Vec::new();
    for f in NS_FLAGS {
        clone_rules.push(SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(*f),
            *f,
        )?])?);
    }
    rules.insert(libc::SYS_clone, clone_rules);
    Ok(SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::KillProcess, ARCH)?.try_into()?)
}

fn build(nrs: Vec<i64>, action: SeccompAction) -> anyhow::Result<BpfProgram> {
    // seccompiler rejects empty rule vectors, so every syscall gets one rule that
    // is trivially true (arg0 >= 0 as a u64).
    let always = || SeccompRule::new(vec![SeccompCondition::new(0, SeccompCmpArgLen::Qword, SeccompCmpOp::Ge, 0)?]);
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for nr in nrs {
        rules.insert(nr, vec![always()?]);
    }
    Ok(SeccompFilter::new(rules, SeccompAction::Allow, action, ARCH)?.try_into()?)
}

/// Compile both filters once. `SBX_NO_SECCOMP=1` disables them (debugging, D8).
pub fn init_filter() {
    FILTERS.get_or_init(|| {
        if std::env::var("SBX_NO_SECCOMP").as_deref() == Ok("1") {
            tracing::warn!("SBX_NO_SECCOMP=1: seccomp filters disabled");
            return Vec::new();
        }
        let mut out = Vec::new();
        for (what, r) in [
            ("kill", build(killed(), SeccompAction::KillProcess)),
            ("errno", build(refused(), SeccompAction::Errno(libc::EPERM as u32))),
            ("clone-ns", build_clone_ns()),
            ("clone3", build(vec![libc::SYS_clone3], SeccompAction::Errno(libc::ENOSYS as u32))),
        ] {
            match r {
                Ok(p) => out.push(p),
                Err(e) => tracing::error!(error = %e, filter = what, "seccomp build failed; running without it"),
            }
        }
        out
    });
}

/// Runs between fork and exec. Must stay allocation-free.
///
/// `seccomp = false` for Chromium, which needs its own sandbox syscalls (D8).
pub fn apply(seccomp: bool) -> std::io::Result<()> {
    // Must precede seccomp: an unprivileged process may only install a filter
    // when no_new_privs is set.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::geteuid() } == 0 {
        unsafe {
            libc::setgroups(0, std::ptr::null());
            if libc::setgid(AGENT_GID) != 0 || libc::setuid(AGENT_UID) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    if seccomp {
        for prog in FILTERS.get().map(|v| v.as_slice()).unwrap_or(&[]) {
            seccompiler::apply_filter(prog).map_err(|e| std::io::Error::other(e.to_string()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_filters_compile_for_this_arch() {
        let kill = build(killed(), SeccompAction::KillProcess).expect("kill filter");
        let errno = build(refused(), SeccompAction::Errno(1)).expect("errno filter");
        assert!(kill.len() > killed().len(), "one jump per denied syscall at minimum");
        assert!(errno.len() > refused().len());
        // io_uring must never be in the kill set: libuv probes it (D18).
        for nr in refused() {
            assert!(!killed().contains(&nr), "io_uring syscall {nr} must return EPERM, not kill");
        }
        assert!(killed().contains(&libc::SYS_ptrace));
        assert!(killed().contains(&libc::SYS_unshare));
        assert!(build_clone_ns().expect("clone filter").len() > NS_FLAGS.len());
    }
}
