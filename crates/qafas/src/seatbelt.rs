//! Renders `policy/seatbelt.sb.tmpl` for one sandbox.
//!
//! The profile is data, not code (PLAN §5 risks): if a toolchain needs another
//! directory, that is an edit to a text file and a restart, not a release. The
//! only thing this module adds is the per-sandbox path lists and the message
//! tags that let `sblog.rs` turn a kernel denial into an attributed alert.

use std::path::{Path, PathBuf};

/// `SBX/<sandbox id>/<rule>`. The prefix is what the unified-log predicate
/// matches on; the rule is what the alert is called.
pub const MARKER: &str = "SBX";

pub fn tag(id: &str, rule: &str) -> String {
    format!("{MARKER}/{id}/{rule}")
}

/// SBPL string literal. Paths come from the host filesystem and from the
/// caller's `workspace.host_path`, so they are escaped, never interpolated raw.
fn q(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// Seatbelt matches the *resolved* path, so `/tmp/x` must be written as
/// `/private/tmp/x` or the filter never fires. `canonicalize` does it exactly
/// for paths that exist; the prefix map covers the ones that do not yet.
pub fn normalize(p: &str) -> String {
    if let Ok(c) = std::fs::canonicalize(p) {
        return c.display().to_string();
    }
    for (from, to) in [("/tmp/", "/private/tmp/"), ("/var/", "/private/var/"), ("/etc/", "/private/etc/")] {
        if let Some(rest) = p.strip_prefix(from) {
            return format!("{to}{rest}");
        }
    }
    p.to_string()
}

/// One block of Seatbelt path rules. `kind` is the matcher: `subpath` for a
/// directory and everything under it, `literal` for exactly one file.
fn rules(kind: &str, paths: &[String]) -> String {
    paths
        .iter()
        .filter(|p| !p.is_empty())
        .map(|p| format!("  ({kind} {})", q(&normalize(p))))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Everything the template needs to know about one sandbox.
pub struct Profile {
    pub id: String,
    /// The one directory the sandbox may write to, at its real host path (D4).
    pub workspace: String,
    /// `/tmp/sbx-<id>`: scratch plus the fake HOME.
    pub scratch: String,
    pub home: String,
    /// The daemon user's real home: only used to allow CoreFoundation's start-up reads.
    pub real_home: String,
    /// Host toolchain directories, readable but not writable.
    pub toolchains: Vec<String>,
    /// Credential directories, denied and reported.
    pub sensitive: Vec<String>,
    /// Planted files whose read is `canary.read`.
    pub canaries: Vec<String>,
    pub proxy_port: u16,
    /// `SBX_NATIVE_LOOPBACK=all`: processes may reach loopback services (their own
    /// dev server), except qafas and the control plane. Default: bind only.
    pub loopback_outbound: bool,
    /// Ports on loopback that stay unreachable even with `loopback_outbound`.
    pub blocked_loopback_ports: Vec<u16>,
}

/// Host directories a coding toolchain reads. Missing ones are harmless: an
/// allow rule for a path that does not exist costs nothing.
pub fn default_toolchains(home: &str) -> Vec<String> {
    [
        ".cargo",
        ".rustup",
        ".nvm",
        ".volta",
        ".bun",
        ".deno",
        ".pyenv",
        ".rbenv",
        ".gradle",
        ".m2",
        ".local/share/uv",
        ".cache/uv",
        ".cache/ms-playwright",
        "Library/Caches/ms-playwright",
        "go/pkg/mod",
    ]
    .iter()
    .map(|d| format!("{home}/{d}"))
    .filter(|p| Path::new(p).exists())
    .collect()
}

/// The credential directories of protocol §1.1, under the *real* home — the one
/// the daemon runs as, which is what a native sandbox could otherwise reach.
pub fn default_sensitive(real_home: &str) -> Vec<String> {
    [".ssh", ".aws", ".config/gh", ".config/gcloud", ".kube", ".docker", ".gnupg", ".netrc", ".npmrc", ".pypirc"]
        .iter()
        .map(|d| format!("{real_home}/{d}"))
        .collect()
}

/// `confstr(_CS_DARWIN_USER_TEMP_DIR)`: the per-user temp dir Apple's tools use
/// regardless of `TMPDIR`. Empty off macOS, which makes the regex match nothing.
pub fn darwin_user_temp_dir() -> String {
    #[cfg(target_os = "macos")]
    {
        let mut buf = vec![0u8; 1024];
        let n =
            unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if n > 0 && n as usize <= buf.len() {
            buf.truncate(n as usize - 1);
            let s = String::from_utf8_lossy(&buf).trim_end_matches('/').to_string();
            return normalize(&s);
        }
    }
    String::new()
}

impl Profile {
    pub fn render(&self, template: &str) -> String {
        let mut read_allow = vec![self.workspace.clone(), self.scratch.clone()];
        read_allow.extend(self.toolchains.iter().cloned());
        // node, go and cargo walk up from the workspace looking for a manifest and
        // abort on EPERM (where ENOENT would just mean "keep looking"). Those
        // manifests are the one thing readable in the workspace's ancestors.
        let mut manifests = Vec::new();
        let mut dir = std::path::Path::new(&self.workspace).parent();
        while let Some(d) = dir {
            for m in ["package.json", "go.mod", "go.work", "Cargo.toml", "pyproject.toml", "deno.json", "tsconfig.json"]
            {
                manifests.push(d.join(m).display().to_string());
            }
            dir = d.parent();
        }
        let write_allow = vec![self.workspace.clone(), self.scratch.clone(), self.home.clone()];

        // A profile with an empty deny block would be a syntax error, and an
        // empty deny block is also a bug worth being loud about. `/dev/null` is
        // a literal nothing will ever try to read as a credential.
        let mut deny = self.sensitive.clone();
        if deny.is_empty() {
            deny.push("/dev/null/never".into());
        }
        let mut canaries = self.canaries.clone();
        // The workspace's own production env file is denied rather than planted:
        // we do not write files into a directory the user owns.
        canaries.push(format!("{}/.env.production", self.workspace));

        template
            .replace("{{TAG_DENIED}}", &tag(&self.id, proto::rules::SANDBOX_DENIED))
            .replace("{{TAG_ESCAPE}}", &tag(&self.id, proto::rules::WORKSPACE_ESCAPE))
            .replace("{{TAG_SENSITIVE_READ}}", &tag(&self.id, proto::rules::SENSITIVE_PATH_READ))
            .replace("{{TAG_CANARY}}", &tag(&self.id, proto::rules::CANARY_READ))
            .replace("{{TAG_RECON}}", &tag(&self.id, proto::rules::HOST_RECON))
            .replace("{{READ_ALLOW}}", &format!("{}\n{}", rules("subpath", &read_allow), rules("literal", &manifests)))
            .replace("{{WRITE_ALLOW}}", &rules("subpath", &write_allow))
            .replace("{{READ_DENY}}", &rules("subpath", &deny))
            .replace("{{CANARY_DENY}}", &rules("literal", &canaries))
            .replace("{{PROXY_PORT}}", &self.proxy_port.to_string())
            .replace("{{LOOPBACK_OUT}}", &self.loopback_out())
            .replace("{{REAL_HOME}}", &normalize(&self.real_home))
            .replace("{{SCRATCH}}", &normalize(&self.scratch))
            .replace("{{DARWIN_TMP}}", &darwin_user_temp_dir())
    }

    fn loopback_out(&self) -> String {
        if !self.loopback_outbound {
            return String::new();
        }
        let mut out = vec!["(allow network-outbound (remote ip \"localhost:*\"))".to_string()];
        for p in &self.blocked_loopback_ports {
            out.push(format!(
                "(deny network-outbound (remote ip \"localhost:{p}\") (with message {}))",
                q(&tag(&self.id, proto::rules::SANDBOX_DENIED))
            ));
        }
        out.join("\n")
    }

    /// Renders and writes the profile next to the sandbox's scratch dir.
    pub fn write(&self, template: &str) -> std::io::Result<PathBuf> {
        let path = PathBuf::from(&self.scratch).join("profile.sb");
        std::fs::write(&path, self.render(template))?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policy/seatbelt.sb.tmpl"))
            .expect("policy/seatbelt.sb.tmpl")
    }

    fn profile() -> Profile {
        Profile {
            id: "sbx_test".into(),
            workspace: "/Users/me/repo".into(),
            scratch: "/private/tmp/sbx-sbx_test".into(),
            home: "/private/tmp/sbx-sbx_test/home".into(),
            real_home: "/Users/tester".into(),
            toolchains: vec!["/Users/me/.cargo".into()],
            sensitive: vec!["/Users/me/.ssh".into(), "/Users/me/.aws".into()],
            canaries: vec!["/private/tmp/sbx-sbx_test/home/.ssh/id_rsa".into()],
            proxy_port: 3128,
            loopback_outbound: false,
            blocked_loopback_ports: vec![7700, 7800],
        }
    }

    /// Snapshot in the only sense that matters: the rules that make the profile
    /// a boundary, in the order that makes SBPL honour them.
    #[test]
    fn rendered_profile_snapshot() {
        let p = profile().render(&template());
        let at = |needle: &str| p.find(needle).unwrap_or_else(|| panic!("missing: {needle}"));

        assert!(p.starts_with("; Seatbelt profile"));
        at(r#"(deny default (with message "SBX/sbx_test/sandbox.denied"))"#);
        at(r#"(subpath "/Users/me/repo")"#);
        at(r#"(subpath "/Users/me/.cargo")"#);
        at(r#"(deny file-write* (subpath "/") (with message "SBX/sbx_test/workspace.escape"))"#);
        at(r#"(subpath "/Users/me/.ssh")"#);
        at(r#""SBX/sbx_test/sensitive_path.read""#);
        at(r#"(literal "/private/tmp/sbx-sbx_test/home/.ssh/id_rsa")"#);
        at(r#"(literal "/Users/me/repo/.env.production")"#);
        at(r#"(allow network-outbound (remote ip "localhost:3128"))"#);
        assert!(!p.contains("{{"), "every placeholder must be substituted:\n{p}");
        assert!(p.contains("(allow network-inbound (local ip \"localhost:*\"))"));
        assert!(!p.contains("localhost:*\"))\n(deny"), "loopback outbound is opt-in");
        let mut open = profile();
        open.loopback_outbound = true;
        let p = open.render(&template());
        assert!(p.contains("(allow network-outbound (remote ip \"localhost:*\"))"));
        assert!(
            p.find("localhost:7700").unwrap() > p.find("(allow network-outbound (remote ip \"localhost:*\"))").unwrap(),
            "the daemon port deny comes after the allow so it wins"
        );

        // Order is the policy. Writes are denied before the workspace re-allows
        // them, and the credential denies come after the read allow list.
        assert!(at("(deny default") < at("(allow file-read*"));
        assert!(at("(deny file-write* (subpath \"/\")") < at("(allow file-write*"));
        assert!(at("(allow file-read*") < at("SBX/sbx_test/sensitive_path.read"));
        // Ancestor manifests are readable, and still lose to the sensitive-path denies below them.
        assert!(at("(literal \"/Users/me/package.json\")") < at("SBX/sbx_test/sensitive_path.read"));
        assert!(at("SBX/sbx_test/sensitive_path.read") < at("SBX/sbx_test/canary.read"));
    }

    #[test]
    fn paths_are_escaped_and_normalised() {
        assert_eq!(q(r#"/a/"b\c"#), r#""/a/\"b\\c""#);
        // A workspace name cannot close the string literal and inject a rule:
        // the whole hostile value has to come back as one escaped literal.
        let mut pr = profile();
        pr.workspace = r#"/Users/me/re"po") (allow file-write* (subpath "/"#.into();
        let out = pr.render(&template());
        assert!(
            out.contains(r#"(subpath "/Users/me/re\"po\") (allow file-write* (subpath \"/")"#),
            "the hostile workspace must render as one escaped literal:\n{out}",
        );
        // And the profile still has exactly one real allow rule for writes.
        assert_eq!(out.matches("\n(allow file-write*").count(), 1);

        assert_eq!(normalize("/tmp/does-not-exist-sbx"), "/private/tmp/does-not-exist-sbx");
        assert_eq!(normalize("/usr/bin"), "/usr/bin");
    }

    #[test]
    fn an_empty_deny_list_still_renders_valid_sbpl() {
        let mut p = profile();
        p.sensitive.clear();
        p.canaries.clear();
        let out = p.render(&template());
        assert!(!out.contains("(deny file-read*\n\n"), "an empty filter block is a syntax error");
        assert!(out.contains(".env.production"), "the workspace canary is always present");
    }

    /// The real check: the rendered profile is one `sandbox-exec` accepts and it
    /// actually confines. Only meaningful on macOS.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_profile_compiles_and_confines() {
        let dir = std::env::temp_dir().join(format!("sbx-prof-{}", std::process::id()));
        let _ = std::fs::create_dir_all(dir.join("home"));
        let ws = dir.join("ws");
        let _ = std::fs::create_dir_all(&ws);
        let p = Profile {
            id: "sbx_prof".into(),
            workspace: ws.display().to_string(),
            scratch: dir.display().to_string(),
            home: dir.join("home").display().to_string(),
            real_home: std::env::var("HOME").unwrap_or_default(),
            toolchains: vec![],
            sensitive: default_sensitive(&std::env::var("HOME").unwrap_or_default()),
            canaries: vec![dir.join("home/.ssh/id_rsa").display().to_string()],
            proxy_port: 3128,
            loopback_outbound: false,
            blocked_loopback_ports: vec![],
        };
        let path = p.write(&template()).expect("write profile");

        let run = |cmd: &str| {
            std::process::Command::new("/usr/bin/sandbox-exec")
                .arg("-f")
                .arg(&path)
                .args(["/bin/bash", "-c", cmd])
                .env("HOME", dir.join("home"))
                .output()
                .expect("sandbox-exec")
        };
        let ok = run("echo alive");
        assert!(ok.status.success(), "profile rejected: {}", String::from_utf8_lossy(&ok.stderr));
        assert_eq!(String::from_utf8_lossy(&ok.stdout).trim(), "alive");

        let inside = run(&format!("touch {}/ok.txt && echo wrote", ws.display()));
        assert!(inside.status.success(), "the workspace must be writable: {inside:?}");

        let proof = format!("{}/sbx-should-not-exist", std::env::var("HOME").expect("HOME"));
        let outside = run(&format!("touch {proof} && echo wrote"));
        assert!(!outside.status.success(), "a write outside the workspace must fail");
        assert!(!std::path::Path::new(&proof).exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
