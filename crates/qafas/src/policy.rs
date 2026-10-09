//! Which tier serves a request: the rules below, in order. This file is their
//! only statement and only implementation —
//! qafas applies it per host, the control plane applies the same rows across
//! hosts.
//!
//! The one invariant that is not negotiable: **`trust: untrusted` never gets
//! `native`** (D16). A shared-kernel sandbox is the right default for a repo the
//! developer already trusts and the wrong boundary for anything else, so an
//! explicit `native` on untrusted input is refused rather than quietly honoured
//! or quietly downgraded.

use proto::{Isolation, Trust};

/// What this host can actually serve right now: configuration ∩ reality.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Caps {
    pub native: bool,
    pub vm: bool,
    pub remote: bool,
    /// The native tier may serve `chromium` (`SBX_NATIVE_BROWSER=1` plus a
    /// headless shell on the host).
    pub native_browser: bool,
}

impl Caps {
    pub fn has(&self, tier: Isolation) -> bool {
        match tier {
            Isolation::Native => self.native,
            Isolation::Vm => self.vm,
            Isolation::Remote => self.remote,
            Isolation::Auto => self.native || self.vm || self.remote,
        }
    }

    pub fn tiers(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.native {
            v.push("native");
        }
        if self.vm {
            v.push("vm");
        }
        if self.remote {
            v.push("remote");
        }
        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub tier: Isolation,
    pub reason: &'static str,
}

/// A request this host cannot honour. The control plane retries on a host that
/// advertises the tier; a direct caller gets 409.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable(pub String);

/// Everything the table looks at.
#[derive(Debug, Clone, Default)]
pub struct Ask {
    pub isolation: Isolation,
    pub trust: Trust,
    pub tools: Vec<String>,
    pub workspace: String,
}

fn wants_browser(tools: &[String]) -> bool {
    tools.iter().any(|t| {
        let n = t.split('@').next().unwrap_or("").trim().to_ascii_lowercase();
        n == "chromium" || n == "browser" || n == "chrome"
    })
}

/// Row 5: a workspace outside the caller's home, or on a network filesystem, is
/// not something to hand a shared-kernel sandbox — the paths a Seatbelt or
/// Landlock rule set can express stop being a meaningful boundary.
pub fn workspace_is_local(path: &str, home: &str) -> bool {
    if path.is_empty() {
        return true;
    }
    let under_home = !home.is_empty() && (path == home || path.starts_with(&format!("{home}/")));
    under_home && !is_network_fs(path)
}

#[cfg(target_os = "macos")]
fn is_network_fs(path: &str) -> bool {
    let Ok(c) = std::ffi::CString::new(path) else { return true };
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return false;
    }
    let name: String = st.f_fstypename.iter().take_while(|c| **c != 0).map(|c| *c as u8 as char).collect();
    matches!(name.as_str(), "nfs" | "smbfs" | "afpfs" | "webdav" | "ftp" | "osxfusefs")
}

#[cfg(target_os = "linux")]
fn is_network_fs(path: &str) -> bool {
    const NFS: i64 = 0x6969;
    const CIFS: i64 = 0xFF53_4D42;
    const FUSE: i64 = 0x6573_5546;
    const V9FS: i64 = 0x0189_3;
    let Ok(c) = std::ffi::CString::new(path) else { return true };
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return false;
    }
    matches!(st.f_type as i64, NFS | CIFS | FUSE | V9FS)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn is_network_fs(_path: &str) -> bool {
    false
}

/// The table. `home` is the daemon user's home directory.
pub fn select(ask: &Ask, caps: &Caps, home: &str) -> Result<Decision, Unavailable> {
    let untrusted = ask.trust == Trust::Untrusted;

    // Row 1/2, plus the untrusted invariant, which outranks an explicit request.
    if ask.isolation != Isolation::Auto {
        if ask.isolation == Isolation::Native && untrusted {
            return Err(Unavailable("trust=untrusted cannot use the native tier; ask for vm or remote".into()));
        }
        if caps.has(ask.isolation) {
            return Ok(Decision { tier: ask.isolation, reason: "requested" });
        }
        return Err(Unavailable(format!("tier unavailable: this host serves {:?}", caps.tiers())));
    }

    let first = |cands: &[Isolation], reason: &'static str| -> Option<Decision> {
        cands.iter().find(|t| caps.has(**t)).map(|t| Decision { tier: *t, reason })
    };

    // Row 3.
    if untrusted {
        return first(&[Isolation::Vm, Isolation::Remote], "untrusted")
            .ok_or_else(|| Unavailable("no isolated tier available for untrusted input".into()));
    }
    // Row 4.
    if wants_browser(&ask.tools) && !caps.native_browser {
        if let Some(d) = first(&[Isolation::Vm, Isolation::Remote], "browser") {
            return Ok(d);
        }
    }
    // Row 5.
    if !workspace_is_local(&ask.workspace, home) {
        if let Some(d) = first(&[Isolation::Vm, Isolation::Remote], "workspace_location") {
            return Ok(d);
        }
    }
    // Row 6.
    if caps.native {
        return Ok(Decision { tier: Isolation::Native, reason: "default_fast" });
    }
    // Row 7.
    first(&[Isolation::Vm, Isolation::Remote], "fallback").ok_or_else(|| Unavailable("this host serves no tier".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: Caps = Caps { native: true, vm: true, remote: true, native_browser: false };
    const VM_ONLY: Caps = Caps { native: false, vm: true, remote: false, native_browser: false };
    const NATIVE_ONLY: Caps = Caps { native: true, vm: false, remote: false, native_browser: false };

    fn ask(iso: Isolation, trust: Trust) -> Ask {
        Ask { isolation: iso, trust, tools: vec![], workspace: "/home/me/repo".into() }
    }

    #[test]
    fn untrusted_never_resolves_to_native() {
        // Row 3: auto downgrades.
        let d = select(&ask(Isolation::Auto, Trust::Untrusted), &ALL, "/home/me").unwrap();
        assert_eq!((d.tier, d.reason), (Isolation::Vm, "untrusted"));
        // And with only native and remote available it goes remote, not native.
        let caps = Caps { native: true, vm: false, remote: true, native_browser: false };
        let d = select(&ask(Isolation::Auto, Trust::Untrusted), &caps, "/home/me").unwrap();
        assert_eq!(d.tier, Isolation::Remote);
        // An explicit native is refused outright, even on a host that serves it.
        let e = select(&ask(Isolation::Native, Trust::Untrusted), &ALL, "/home/me").unwrap_err();
        assert!(e.0.contains("untrusted"), "{e:?}");
        // A host with nothing but native cannot serve untrusted at all.
        assert!(select(&ask(Isolation::Auto, Trust::Untrusted), &NATIVE_ONLY, "/home/me").is_err());
    }

    #[test]
    fn explicit_tiers_are_honoured_or_409() {
        for t in [Isolation::Native, Isolation::Vm, Isolation::Remote] {
            let d = select(&ask(t, Trust::Trusted), &ALL, "/home/me").unwrap();
            assert_eq!((d.tier, d.reason), (t, "requested"));
        }
        let e = select(&ask(Isolation::Remote, Trust::Trusted), &VM_ONLY, "/home/me").unwrap_err();
        assert!(e.0.contains("tier unavailable"), "{e:?}");
    }

    #[test]
    fn browser_and_workspace_rows_push_to_vm() {
        let mut a = ask(Isolation::Auto, Trust::Trusted);
        a.tools = vec!["node@22".into(), "chromium".into()];
        let d = select(&a, &ALL, "/home/me").unwrap();
        assert_eq!((d.tier, d.reason), (Isolation::Vm, "browser"));

        // Unless the host advertises a native browser.
        let caps = Caps { native_browser: true, ..ALL };
        assert_eq!(select(&a, &caps, "/home/me").unwrap().tier, Isolation::Native);

        // A workspace outside home is not a native-tier workspace.
        let mut a = ask(Isolation::Auto, Trust::Trusted);
        a.workspace = "/srv/shared/repo".into();
        let d = select(&a, &ALL, "/home/me").unwrap();
        assert_eq!((d.tier, d.reason), (Isolation::Vm, "workspace_location"));
        assert!(workspace_is_local("/home/me/repo", "/home/me"));
        assert!(workspace_is_local("/home/me", "/home/me"));
        assert!(!workspace_is_local("/home/melon/repo", "/home/me"), "prefix must be a path boundary");
        assert!(workspace_is_local("", "/home/me"), "no workspace is not a reason to downgrade");
    }

    #[test]
    fn the_default_is_native_and_the_fallback_is_vm() {
        let d = select(&ask(Isolation::Auto, Trust::Trusted), &ALL, "/home/me").unwrap();
        assert_eq!((d.tier, d.reason), (Isolation::Native, "default_fast"));
        let d = select(&ask(Isolation::Auto, Trust::Trusted), &VM_ONLY, "/home/me").unwrap();
        assert_eq!((d.tier, d.reason), (Isolation::Vm, "fallback"));
        assert!(select(&ask(Isolation::Auto, Trust::Trusted), &Caps::default(), "/home/me").is_err());
        assert_eq!(ALL.tiers(), ["native", "vm", "remote"]);
    }

    #[test]
    fn browser_tool_names() {
        assert!(wants_browser(&["chromium".into()]));
        assert!(wants_browser(&["node@22".into(), "Browser".into()]));
        assert!(!wants_browser(&["node@22".into(), "rg".into()]));
    }
}
