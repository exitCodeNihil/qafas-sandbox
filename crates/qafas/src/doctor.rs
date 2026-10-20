//! `qafas doctor` — what this host can actually do, and what it cannot.
//!
//! It is also the source of the `Caps` the tier policy runs against, so the
//! table a human reads is the table the daemon obeys. Exit code 1 when no tier
//! works, because a daemon that starts but can never serve a sandbox is a worse
//! outcome than one that refuses to start.

use std::sync::Arc;

use crate::backend::native;
use crate::backend::podman::Podman;
use crate::config::Config;
use crate::policy::Caps;

#[derive(serde::Serialize)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

fn check(name: &'static str, ok: bool, detail: impl Into<String>) -> Check {
    Check { name, ok, detail: detail.into() }
}

fn have(bin: &str) -> Option<String> {
    agent_core::procmon::which(bin).map(|p| p.display().to_string())
}

/// Can we talk to the container runtime (podman, or Docker Engine 26+)? Cheap:
/// `doctor` stops at "the socket exists and answers"; `serve` checks which
/// runtime it is and refuses a Docker that is too old.
async fn podman_ok(cfg: &Config) -> (bool, String) {
    let Ok(sock) = crate::backend::podman::discover_socket() else {
        return (false, "no podman or Docker socket (set SBX_RUNTIME_SOCK)".into());
    };
    match tokio::net::UnixStream::connect(&sock).await {
        Ok(_) => (true, format!("{sock}, image {}", cfg.template_image)),
        Err(e) => (false, format!("{sock}: {e}")),
    }
}

/// What a vm-tier runtime puts between a sandbox and the kernel that runs it.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Isolation {
    /// runc, crun, youki...: namespaces and seccomp on the host's (or the podman machine's) kernel.
    SharedKernel,
    /// gVisor or Kata: a user-space kernel, or a VM per sandbox.
    Sandboxed(&'static str),
}

/// By name, and only the two families `docs/security.md` has an opinion on.
/// ponytail: a name list (also matches `io.containerd.runsc.v1`, `kata-qemu`, a full path);
/// a runtime it does not know, such as `crun-vm` or `krun`, reads as a shared kernel until it is added.
pub fn classify_runtime(name: &str) -> Isolation {
    let n = name.to_ascii_lowercase();
    if n.contains("runsc") || n.contains("gvisor") {
        Isolation::Sandboxed("gVisor")
    } else if n.contains("kata") {
        Isolation::Sandboxed("Kata")
    } else {
        Isolation::SharedKernel
    }
}

/// The `vm runtime` line: which runtime sandboxes get, and what that isolates.
fn runtime_detail(engine: &str, runtime: &str, configured: bool) -> String {
    let which = if configured { runtime.to_string() } else { format!("engine default, {runtime}") };
    let vm = cfg!(target_os = "macos");
    let verdict = match (classify_runtime(runtime), vm) {
        (Isolation::SharedKernel, false) => "shared host kernel: a container boundary, not a VM".to_string(),
        (Isolation::SharedKernel, true) => {
            "shared kernel inside the engine's VM: the VM is the boundary from this Mac".to_string()
        }
        (Isolation::Sandboxed(k), false) => format!("sandboxed ({k}): the host kernel is not the sandbox's kernel"),
        (Isolation::Sandboxed(k), true) => format!("sandboxed ({k}) inside the engine's VM"),
    };
    format!("{engine}: {which}: {verdict}")
}

/// The runtime the vm tier's sandboxes will run under, as the engine reports it; a failure when
/// `SBX_VM_RUNTIME` names one the engine does not have (or, on podman, would silently not apply).
/// `None` where the vm tier is off or there is no engine to ask: the `podman` line says why.
async fn vm_runtime_check(cfg: &Config) -> Option<Check> {
    if !cfg.serves("vm") {
        return None;
    }
    let engine = Podman::new(Arc::new(cfg.clone())).ok()?;
    Some(match engine.runtime_status().await {
        Ok(st) => check("vm runtime", true, runtime_detail(&st.engine, &st.runtime, st.configured)),
        Err(e) => check("vm runtime", false, format!("{e:#}")),
    })
}

/// Why `serve` must not start, when it must not: the vm tier would be served and its configured
/// runtime is not usable. A silent fallback to the default runtime is the worse outcome.
pub fn vm_runtime_refusal(checks: &[Check], caps: &Caps) -> Option<String> {
    let bad = checks.iter().find(|c| c.name == "vm runtime" && !c.ok)?;
    caps.vm.then(|| format!("vm runtime: {}", bad.detail))
}

pub async fn run_checks(cfg: &Config) -> Vec<Check> {
    let mut out = Vec::new();

    // --- native
    if cfg!(target_os = "macos") {
        let sb = std::path::Path::new("/usr/bin/sandbox-exec").exists();
        out.push(check("seatbelt", sb, if sb { "/usr/bin/sandbox-exec" } else { "not present" }));
        let tmpl = std::path::Path::new(&cfg.seatbelt_profile).exists();
        out.push(check(
            "seatbelt profile",
            tmpl,
            format!("{}{}", cfg.seatbelt_profile, if tmpl { "" } else { " (missing)" }),
        ));
        let logs = crate::sblog::probe().await;
        out.push(check(
            "unified log reader",
            logs,
            if logs {
                "log stream available; denials become alerts"
            } else {
                "log(1) unavailable: denials will confine but not alert"
            },
        ));
    } else {
        let bw = have("bwrap");
        out.push(check("bubblewrap", bw.is_some(), bw.clone().unwrap_or("not on PATH".into())));
        let abi = native::linux::abi();
        out.push(check(
            "landlock",
            abi >= 2,
            match abi {
                // The network is confined by the sandbox's own namespace (bwrap
                // --unshare-net); Landlock's network rules apply only unwrapped.
                a if a >= 2 => format!("ABI v{a}: filesystem rules; network confined by its own network namespace"),
                _ => "unsupported kernel".into(),
            },
        ));
        out.push(check("seccomp", true, "deny-list compiled into the binary (D8)"));
        let uid = nix::unistd::Uid::effective();
        out.push(check(
            "native user",
            !uid.is_root(),
            match uid.is_root() {
                true => {
                    "root: native runs commands as the daemon's own user, so a root daemon does not serve it".into()
                }
                false => format!("uid {uid}"),
            },
        ));
        if let (Some(bw), false) = (&bw, uid.is_root()) {
            let (ok, detail) = native::linux::bwrap_probe(bw);
            out.push(check("bwrap sandbox", ok, detail));
        }
    }

    // --- vm
    let (pod, detail) = podman_ok(cfg).await;
    out.push(check("podman", pod, detail));
    if pod {
        out.extend(vm_runtime_check(cfg).await);
    }

    // --- remote
    let kvm = std::path::Path::new("/dev/kvm").exists();
    out.push(check("kvm", kvm, if kvm { "/dev/kvm" } else { "no /dev/kvm (remote tier needs a Linux host)" }));
    let fc = std::path::Path::new(&cfg.fc_bin).exists();
    out.push(check("firecracker", fc, format!("{}{}", cfg.fc_bin, if fc { "" } else { " (missing)" })));

    // --- telemetry and policy
    let bpf = have("bpftrace");
    let btf = std::path::Path::new("/sys/kernel/btf/vmlinux").exists();
    out.push(check(
        "bpftrace",
        bpf.is_some() && btf,
        match (&bpf, btf) {
            (Some(p), true) => format!("{p} with BTF"),
            (Some(p), false) => format!("{p} but no /sys/kernel/btf/vmlinux"),
            (None, _) => "not on PATH; process tracking falls back to sampling".into(),
        },
    ));
    let pol = std::path::Path::new(&cfg.policy).exists();
    out.push(check(
        "egress policy",
        pol,
        format!("{}{}", cfg.policy, if pol { "" } else { " (missing: everything is denied)" }),
    ));
    let tmpl = std::path::Path::new(&cfg.templates).exists();
    out.push(check(
        "tool templates",
        tmpl,
        format!("{}{}", cfg.templates, if tmpl { "" } else { " (missing: every tool reports missing)" }),
    ));
    out.push(check(
        "config file",
        true,
        crate::config::config_path()
            .map(|p| p.display().to_string())
            .unwrap_or("none; environment and defaults only".into()),
    ));

    out
}

/// What the hardware and the installed tools allow, before configuration and
/// before D25 picks one pooled runtime. `caps` subtracts from this; `host_caps`
/// reports it as `supported`.
fn able(checks: &[Check]) -> Caps {
    let ok = |n: &str| checks.iter().any(|c| c.name == n && c.ok);
    Caps {
        native: if cfg!(target_os = "macos") {
            ok("seatbelt") && ok("seatbelt profile")
        } else {
            ok("bubblewrap") && native::linux::abi() >= 2 && ok("native user") && ok("bwrap sandbox")
        },
        vm: ok("podman"),
        remote: ok("firecracker") && ok("kvm"),
        native_browser: false,
    }
}

/// The numeric field of a `/proc/meminfo` line (kB for sizes, a count for
/// `HugePages_Total`); 0 where there is no such file (macOS).
fn meminfo_field(key: &str) -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(key) && l[key.len()..].starts_with(':'))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

pub fn mem_mib() -> u64 {
    if cfg!(target_os = "macos") {
        std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u64>().ok())
            .unwrap_or(0)
            / (1024 * 1024)
    } else {
        meminfo_field("MemTotal") / 1024
    }
}

/// v4c §3a. The same checks, as the struct the host sends at registration and
/// `GET /caps` returns. `supported` is what the host *could* serve; `Caps` (and
/// so `tiers`) is what it *will*.
pub fn host_caps(checks: &[Check]) -> proto::HostCaps {
    let ok = |n: &str| checks.iter().any(|c| c.name == n && c.ok);
    let able = able(checks);
    proto::HostCaps {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        cpus: std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(0),
        mem_mib: mem_mib(),
        kvm: ok("kvm"),
        firecracker: ok("firecracker"),
        podman: ok("podman"),
        process_sandbox: able.native,
        bpftrace: ok("bpftrace"),
        hugepages_mib: meminfo_field("HugePages_Total") * meminfo_field("Hugepagesize") / 1024,
        supported: able.tiers().iter().map(|t| t.to_string()).collect(),
    }
}

/// The tiers this host can serve, from the same checks. Configuration can
/// subtract but never add: a tier the host cannot run is never advertised.
pub fn caps(cfg: &Config, checks: &[Check]) -> Caps {
    let able = able(checks);
    let mut caps = Caps {
        native: cfg.serves("native") && able.native,
        vm: cfg.serves("vm") && able.vm,
        remote: cfg.serves("remote") && able.remote,
        native_browser: cfg.native_browser && have("chrome-headless-shell").is_some(),
    };
    // D25: a host serves one pooled runtime. Firecracker is the product default,
    // so when both are servable `remote` wins and `vm` is dropped.
    if caps.vm && caps.remote {
        caps.vm = false;
        tracing::warn!("vm (podman) dropped: this host serves firecracker; set SBX_TIERS=remote to silence");
    }
    caps
}

pub async fn run(cfg: Arc<Config>, json: bool) -> anyhow::Result<()> {
    let checks = run_checks(&cfg).await;
    let caps = caps(&cfg, &checks);

    // v4c: the machine-readable form, for provisioning scripts deciding `tiers`.
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "checks": checks,
                "caps": host_caps(&checks),
                "configured": cfg.tiers,
                "serving": caps.tiers(),
            }))?
        );
        if caps.tiers().is_empty() || vm_runtime_refusal(&checks, &caps).is_some() {
            std::process::exit(1);
        }
        return Ok(());
    }

    println!("qafas {} on {}", proto::VERSION, std::env::consts::OS);
    println!();
    for c in &checks {
        println!("  {} {:<20} {}", if c.ok { "ok  " } else { "FAIL" }, c.name, c.detail);
    }
    println!();
    println!("  configured tiers : {}", cfg.tiers.join(", "));
    println!(
        "  serving tiers    : {}",
        if caps.tiers().is_empty() { "(none)".into() } else { caps.tiers().join(", ") }
    );
    println!("  native browser   : {}", if caps.native_browser { "yes" } else { "no (chromium requests go to vm)" });
    println!("  listen           : {}", cfg.listen);
    println!("  scratch          : {}", cfg.scratch_dir);
    println!("  idle ttl         : {}s", cfg.ttl_secs);

    if caps.tiers().is_empty() {
        eprintln!("\nno tier is available; qafas cannot serve anything on this host");
        std::process::exit(1);
    }
    if let Some(why) = vm_runtime_refusal(&checks, &caps) {
        eprintln!("\nqafas serve would refuse to start: {why}");
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FileConfig;

    #[test]
    fn configuration_can_subtract_a_tier_but_never_add_one() {
        let mut cfg = Config::resolve(FileConfig::default());
        cfg.tiers = vec!["native".into(), "vm".into(), "remote".into()];
        let checks = vec![
            check("seatbelt", true, ""),
            check("seatbelt profile", true, ""),
            check("bubblewrap", true, ""),
            check("podman", false, ""),
            check("firecracker", true, ""),
            check("kvm", true, ""),
        ];
        let c = caps(&cfg, &checks);
        assert!(!c.vm, "podman is down, so the vm tier is not advertised");
        assert!(c.remote);

        cfg.tiers = vec!["vm".into()];
        let c = caps(&cfg, &checks);
        assert!(!c.native && !c.remote, "configuration removed them");
        assert!(!c.vm, "and podman is still down");
    }

    /// D25: one pooled runtime per host, and it is Firecracker when both work.
    #[test]
    fn remote_wins_over_vm_when_both_are_servable() {
        let mut cfg = Config::resolve(FileConfig::default());
        cfg.tiers = vec!["native".into(), "vm".into(), "remote".into()];
        let both = vec![check("podman", true, ""), check("firecracker", true, ""), check("kvm", true, "")];
        let c = caps(&cfg, &both);
        assert!(c.remote && !c.vm, "remote wins, vm is dropped: {:?}", c.tiers());

        // Only podman: vm stays, nothing to warn about.
        let pod_only = vec![check("podman", true, ""), check("firecracker", false, ""), check("kvm", false, "")];
        assert!(caps(&cfg, &pod_only).vm);
    }

    /// v4c §3a: `supported` is what the host could do — before configuration and
    /// before D25 drops `vm`. That is the difference the Hosts page shows.
    #[test]
    fn host_caps_report_what_the_hardware_allows_not_what_is_served() {
        let mut cfg = Config::resolve(FileConfig::default());
        cfg.tiers = vec!["remote".into()];
        let checks = vec![
            check("seatbelt", true, ""),
            check("seatbelt profile", true, ""),
            check("bubblewrap", true, ""),
            check("podman", true, ""),
            check("firecracker", true, ""),
            check("kvm", true, ""),
            check("bpftrace", false, ""),
        ];
        let hc = host_caps(&checks);
        let has = |t: &str| hc.supported.iter().any(|s| s == t);
        assert!(has("vm") && has("remote"), "config subtracts, capabilities do not: {:?}", hc.supported);
        assert_eq!(caps(&cfg, &checks).tiers(), ["remote"], "but only remote is served");
        assert_eq!(has("native"), hc.process_sandbox);
        #[cfg(target_os = "macos")]
        assert!(hc.process_sandbox, "sandbox-exec and a profile are both in the checks");
        assert!(hc.podman && hc.kvm && hc.firecracker && !hc.bpftrace);
        assert_eq!((hc.os.as_str(), hc.arch.as_str()), (std::env::consts::OS, std::env::consts::ARCH));
        assert!(hc.cpus > 0 && hc.mem_mib > 0, "this machine has a cpu and some memory");
    }

    /// gVisor and Kata read as sandboxed, whatever the engine calls them (a bare name, a shim name,
    /// a path); everything else is a container on a shared kernel.
    #[test]
    fn runtimes_are_classified_by_what_isolates_the_sandbox() {
        for gvisor in ["runsc", "runsc-kvm", "runsc-ptrace", "gvisor", "/usr/local/bin/runsc", "io.containerd.runsc.v1"]
        {
            assert_eq!(classify_runtime(gvisor), Isolation::Sandboxed("gVisor"), "{gvisor}");
        }
        for kata in ["kata", "kata-runtime", "kata-qemu", "kata-fc", "io.containerd.kata.v2"] {
            assert_eq!(classify_runtime(kata), Isolation::Sandboxed("Kata"), "{kata}");
        }
        for shared in ["crun", "runc", "youki", "/usr/bin/crun", ""] {
            assert_eq!(classify_runtime(shared), Isolation::SharedKernel, "{shared:?}");
        }
        // The line says which of the two it is, and says so about the engine default too.
        assert!(runtime_detail("podman 5.6.2", "crun", false).contains("engine default, crun"));
        let gv = runtime_detail("Docker 28.3.1", "runsc", true);
        assert!(gv.contains("sandboxed (gVisor)") && !gv.contains("shared"), "{gv}");
        let shared = runtime_detail("Docker 28.3.1", "runc", true);
        assert!(
            shared.contains("shared") && shared.contains(if cfg!(target_os = "macos") { "VM" } else { "host kernel" })
        );
    }

    /// An unusable configured runtime stops `serve` only when the vm tier would be served: a host
    /// that serves something else is not refused for a setting that does not apply to it.
    #[test]
    fn an_unknown_vm_runtime_refuses_only_where_the_vm_tier_is_served() {
        let bad = vec![check("podman", true, ""), check("vm runtime", false, "no such runtime")];
        let serving = Caps { vm: true, ..Default::default() };
        let why = vm_runtime_refusal(&bad, &serving).expect("refused");
        assert!(why.contains("no such runtime"), "{why}");
        assert!(vm_runtime_refusal(&bad, &Caps { native: true, ..Default::default() }).is_none());
        let good = vec![check("podman", true, ""), check("vm runtime", true, "")];
        assert!(vm_runtime_refusal(&good, &serving).is_none());
        assert!(vm_runtime_refusal(&[check("podman", true, "")], &serving).is_none(), "no check, no refusal");
    }

    #[tokio::test]
    async fn checks_run_and_name_every_tier_on_this_host() {
        let cfg = Config::resolve(FileConfig::default());
        let checks = run_checks(&cfg).await;
        for want in ["podman", "kvm", "firecracker", "bpftrace", "egress policy", "config file"] {
            assert!(checks.iter().any(|c| c.name == want), "no check named {want}");
        }
        #[cfg(target_os = "macos")]
        assert!(checks.iter().any(|c| c.name == "seatbelt" && c.ok), "this Mac has sandbox-exec");
    }
}
