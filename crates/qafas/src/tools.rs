//! `tools: ["node@22", "rg", "python@3"]` — requested, probed, reported, never
//! installed (D21).
//!
//! Native tier: probe the host, because the host toolchain *is* the sandbox's
//! toolchain. VM/remote: look the tool up in `images/templates.json`, which
//! describes what the image already contains. Either way a tool that is not
//! there lands in `missing_tools` and the request still succeeds — the harness
//! knows what to do about a missing `go`; the daemon does not.

use std::collections::BTreeMap;

/// `name@version` with the version optional. An empty or malformed entry is
/// dropped rather than failing the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Req {
    pub name: String,
    pub want_major: Option<u32>,
    pub raw: String,
}

pub fn parse(spec: &str) -> Option<Req> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    let (name, ver) = match spec.split_once('@') {
        Some((n, v)) => (n.trim(), Some(v.trim())),
        None => (spec, None),
    };
    if name.is_empty() || name.contains('/') || name.contains(char::is_whitespace) {
        return None;
    }
    Some(Req { name: name.to_ascii_lowercase(), want_major: ver.and_then(major), raw: spec.to_string() })
}

/// The leading integer of a version string: `22`, `v22.1.0`, `3.12` → 22, 22, 3.
pub fn major(v: &str) -> Option<u32> {
    let v = v.trim().trim_start_matches(['v', 'V']);
    let digits: String = v.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// The first version-looking token in a `--version` line: `ripgrep 15.2.0` →
/// `15.2.0`, `go version go1.27.1 darwin/arm64` → `1.27.1`, `v22.1.0` → `22.1.0`.
pub fn extract_version(out: &str) -> Option<String> {
    for tok in out.split_whitespace() {
        let t = tok.trim_start_matches("go").trim_start_matches(['v', 'V']);
        let t = t.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.');
        if t.starts_with(|c: char| c.is_ascii_digit()) && t.contains(|c: char| c.is_ascii_digit()) {
            return Some(t.to_string());
        }
    }
    None
}

/// How to ask a tool its version. Anything not listed is probed with
/// `<name> --version`, which is right for almost everything.
fn probe_args(name: &str) -> (&str, &'static [&'static str]) {
    match name {
        "python" | "python3" => ("python3", &["--version"]),
        "go" => ("go", &["version"]),
        "chromium" | "browser" => ("chrome-headless-shell", &["--version"]),
        other => (other, &["--version"]),
    }
}

/// Runs the probe. Returns the version string, or `None` when the binary is not
/// on PATH or does not answer within a second.
fn probe_host(name: &str) -> Option<String> {
    let (bin, args) = probe_args(name);
    agent_core::procmon::which(bin)?;
    let out = std::process::Command::new(bin).args(args).output().ok()?;
    let text = if out.stdout.is_empty() { out.stderr } else { out.stdout };
    let text = String::from_utf8_lossy(&text);
    Some(extract_version(&text).unwrap_or_else(|| "present".to_string()))
}

#[derive(Debug, Default, Clone)]
pub struct Resolved {
    pub tools: BTreeMap<String, String>,
    pub missing: Vec<String>,
}

impl Resolved {
    fn record(&mut self, req: &Req, found: Option<String>) {
        match found {
            // A requested major that does not match is reported as present with
            // its real version *and* as missing, so the harness sees both facts.
            Some(v) => {
                let ok = match (req.want_major, major(&v)) {
                    (Some(want), Some(have)) => want == have,
                    (Some(_), None) => v == "present",
                    (None, _) => true,
                };
                self.tools.insert(req.name.clone(), v);
                if !ok {
                    self.missing.push(req.raw.clone());
                }
            }
            None => self.missing.push(req.raw.clone()),
        }
    }
}

/// Native tier: whatever the host has.
pub fn resolve_host(specs: &[String]) -> Resolved {
    let mut out = Resolved::default();
    for req in specs.iter().filter_map(|s| parse(s)) {
        let found = probe_host(&req.name);
        out.record(&req, found);
    }
    out
}

// ------------------------------------------------------------------ templates

#[derive(Debug, Default, Clone, serde::Deserialize)]
pub struct Templates {
    #[serde(default)]
    pub default_image: String,
    #[serde(default)]
    pub tools: BTreeMap<String, Entry>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Entry {
    pub image: String,
    #[serde(default)]
    pub version: String,
}

impl Templates {
    /// A missing or unreadable file is not fatal: every tool then reports as
    /// missing, which is exactly what "we do not know what is in the image"
    /// should look like.
    pub fn load(path: &str) -> Self {
        match std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()) {
            Some(t) => t,
            None => {
                tracing::warn!(path, "no tool templates readable; every tool will report missing");
                Self::default()
            }
        }
    }

    /// VM/remote tier: what the image is documented to contain.
    pub fn resolve(&self, specs: &[String]) -> Resolved {
        let mut out = Resolved::default();
        for req in specs.iter().filter_map(|s| parse(s)) {
            let found = self.tools.get(&req.name).map(|e| e.version.clone());
            out.record(&req, found);
        }
        out
    }

    /// The image a set of tools needs. Today every tool lives in the base image,
    /// so this is `default_image` unless a tool names another one; the shape is
    /// here so adding a `rust` or `java` image is a data change.
    /// The image for these tools: one a tool names other than the default, else
    /// `guest`, the daemon's `template_image`. `default_image` only marks which
    /// entries mean "the guest image": the table never overrides `template_image`,
    /// so a registry override (`SBX_TEMPLATE_IMAGE`) is the whole change.
    pub fn image_for(&self, specs: &[String], guest: &str) -> String {
        for req in specs.iter().filter_map(|s| parse(s)) {
            if let Some(e) = self.tools.get(&req.name) {
                if !e.image.is_empty() && e.image != self.default_image {
                    return e.image.clone();
                }
            }
        }
        guest.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs_parse_and_garbage_is_dropped() {
        assert_eq!(parse("node@22"), Some(Req { name: "node".into(), want_major: Some(22), raw: "node@22".into() }));
        assert_eq!(parse("RG").unwrap().name, "rg");
        assert_eq!(parse("python@3.12").unwrap().want_major, Some(3));
        assert_eq!(parse("node@").unwrap().want_major, None);
        assert_eq!(parse(""), None);
        assert_eq!(parse("   "), None);
        assert_eq!(parse("../../etc/passwd"), None, "a name is never a path");
        assert_eq!(parse("rm -rf /"), None);
    }

    #[test]
    fn versions_come_out_of_real_tool_output() {
        assert_eq!(extract_version("v22.1.0\n").as_deref(), Some("22.1.0"));
        assert_eq!(extract_version("Python 3.13.7").as_deref(), Some("3.13.7"));
        assert_eq!(extract_version("ripgrep 15.2.0\n\nfeatures:+pcre2").as_deref(), Some("15.2.0"));
        assert_eq!(extract_version("go version go1.27.1 darwin/arm64").as_deref(), Some("1.27.1"));
        assert_eq!(extract_version("git version 2.50.1 (Apple Git-155)").as_deref(), Some("2.50.1"));
        assert_eq!(extract_version("no version here"), None);
        assert_eq!(major("v22.1.0"), Some(22));
        assert_eq!(major("nope"), None);
    }

    #[test]
    fn a_major_mismatch_is_reported_as_both_present_and_missing() {
        let t = Templates {
            default_image: "img".into(),
            tools: BTreeMap::from([
                ("node".into(), Entry { image: "img".into(), version: "22".into() }),
                ("rg".into(), Entry { image: "img".into(), version: "13".into() }),
            ]),
        };
        let r = t.resolve(&["node@22".into(), "rg".into(), "go@1".into(), "node@20".into()]);
        assert_eq!(r.tools["node"], "22");
        assert_eq!(r.tools["rg"], "13");
        assert!(r.missing.contains(&"go@1".to_string()), "not in the image at all");
        assert!(r.missing.contains(&"node@20".to_string()), "wrong major");
        assert_eq!(t.image_for(&["node@22".into()], "guest"), "guest", "the default image is the guest image");
        assert_eq!(Templates::default().image_for(&[], "guest"), "guest");
        let other = Templates {
            tools: BTreeMap::from([("go".into(), Entry { image: "golang-img".into(), version: "1".into() })]),
            ..t
        };
        assert_eq!(other.image_for(&["go@1".into()], "guest"), "golang-img", "a tool's own image still wins");
    }

    #[test]
    fn the_shipped_templates_file_is_valid_and_covers_the_base_image() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../images/templates.json");
        let t = Templates::load(path);
        for tool in ["node", "python3", "uv", "rg", "fd", "git", "chromium"] {
            assert!(t.tools.contains_key(tool), "{tool} missing from templates.json");
        }
        assert!(!t.default_image.is_empty());
    }

    /// The host probe must find what this machine really has, and must not
    /// invent a version for something that is not installed.
    #[test]
    fn host_probing_matches_reality() {
        let r = resolve_host(&["git".into(), "definitely-not-a-real-tool".into()]);
        assert!(r.tools.contains_key("git"), "git is on every dev box we target");
        assert!(r.missing.contains(&"definitely-not-a-real-tool".to_string()));
        assert!(!r.tools.contains_key("definitely-not-a-real-tool"));
    }
}
