//! Configuration, in one place, with one precedence rule:
//!
//!   **environment  >  `qafas.toml`  >  built-in default**
//!
//! The file is looked for at `$SBX_CONFIG`, then `./qafas.toml`, then
//! `/etc/qafas/qafas.toml`, then `~/.config/qafas/qafas.toml`; the
//! first that exists wins and the rest are ignored. A malformed file is a fatal
//! error, not a silent fallback — a daemon that quietly runs with the wrong
//! egress policy is worse than one that refuses to start.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

/// Every field optional: this is the file, not the resolved configuration.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub listen: Option<String>,
    pub token: Option<String>,
    pub host_id: Option<String>,
    pub cp_url: Option<String>,
    pub host_token: Option<String>,
    pub tiers: Option<Vec<String>>,
    pub pool_size: Option<u32>,
    pub pool_recent_secs: Option<u64>,
    pub pool_recent_max: Option<u64>,
    pub base_memory_snapshot: Option<bool>,
    pub ttl_secs: Option<u64>,
    /// v4 timer defaults (§3a), used when the create request is silent.
    pub auto_stop_secs: Option<u64>,
    pub auto_delete_secs: Option<u64>,
    pub max_age_secs: Option<u64>,
    pub long_running_secs: Option<u64>,
    pub template_image: Option<String>,
    pub templates: Option<String>,
    pub policy: Option<String>,
    pub seatbelt_profile: Option<String>,
    pub scratch_dir: Option<String>,
    pub max_upload_mb: Option<u64>,
    pub proxy_dns: Option<Vec<String>>,
    pub native_browser: Option<bool>,
    pub native_permissive: Option<bool>,
    pub tls: Option<bool>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub ca_file: Option<String>,
    pub state_dir: Option<String>,
    pub public_url: Option<String>,
    pub token_ttl_secs: Option<u64>,
    pub guest_agent_bin: Option<String>,
    pub snapshot_rootfs_mb: Option<u64>,
    /// v5. `[sizes.<name>]` blocks replace the compiled table wholesale.
    pub sizes: Option<proto::sizes::Table>,
    pub max_cpus: Option<f64>,
    pub max_mem_mib: Option<u64>,
    pub max_disk_mib: Option<u64>,
    #[serde(default)]
    pub firecracker: FcConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FcConfig {
    pub bin: Option<String>,
    pub jailer: Option<String>,
    pub kernel: Option<String>,
    pub rootfs: Option<String>,
    pub jail_dir: Option<String>,
    /// Where `archive` parks a stopped VM's snapshot. Default `<jail_dir>/archive`.
    pub archive_dir: Option<String>,
    pub mem_mib: Option<u32>,
    /// Back guest memory with 2 MB huge pages (`vm.nr_hugepages` must be
    /// reserved on the host). `SBX_FC_HUGEPAGES=1`; default on when any are reserved.
    pub hugepages: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Tiers this host is willing to serve, in preference order.
    pub tiers: Vec<String>,
    pub listen: SocketAddr,
    pub token: String,
    pub host_id: String,
    pub cp_url: Option<String>,
    pub host_token: String,
    pub pool_size: u32,
    /// v4 §3a warm policy: a template acquired within this many seconds keeps
    /// one warm sandbox ready even with `warm: 0`. `SBX_POOL_RECENT_SECS`.
    pub pool_recent_secs: u64,
    /// How many templates may hold that recency slot at once (LRU beyond it).
    /// `SBX_POOL_RECENT_MAX`.
    pub pool_recent_max: usize,
    /// v4 §3a: capture `base`'s memory at daemon start so every `base` sandbox
    /// is a restore. `SBX_BASE_MEMORY_SNAPSHOT`, default on; the remote tier
    /// only, and skipped when huge pages are on. `false` keeps the boot path.
    pub base_memory_snapshot: bool,
    /// Idle TTL for a sandbox with no explicit `ttl_secs`. Only consulted when
    /// the resolved `auto_stop_secs` is 0 (§3a), so the two never race.
    pub ttl_secs: u64,
    /// v4 §3a. Idle → stop, on every tier; `0` disables sleeping.
    pub auto_stop_secs: u64,
    /// Grace period a stopped or archived sandbox gets before it is destroyed.
    pub auto_delete_secs: u64,
    /// Wall clock from create, any state → destroy. `0` = no limit.
    pub max_age_secs: u64,
    /// Running longer than this raises `sandbox.long_running`, again at every
    /// further multiple. `0` disables the alert.
    pub long_running_secs: u64,
    pub template_image: String,
    /// `images/templates.json`: tool → image tag for the vm/remote tiers.
    pub templates: String,
    pub policy: String,
    /// Seatbelt profile template (`policy/seatbelt.sb.tmpl`).
    pub seatbelt_profile: String,
    /// Parent of every `sbx-<id>` scratch directory.
    pub scratch_dir: String,
    /// Cap on one `/fs/tar` or `/fs/write` upload, MiB. Enforced here before the
    /// body is forwarded and again in the guest (`agent_core::max_upload_bytes`),
    /// which buffers the whole thing and, on the remote tier, extracts it onto a
    /// tmpfs. `SBX_MAX_UPLOAD_MB`.
    pub max_upload_mb: u64,
    /// Optional explicit resolvers for the egress proxy container. Empty means
    /// "use the podman network's", which is the normal case.
    pub proxy_dns: Vec<String>,
    /// Let the native tier serve `chromium`: one browser per process is shared there.
    pub native_browser: bool,
    /// Debug escape hatch: the OS sandbox logs instead of denying (PLAN §5 risks).
    pub native_permissive: bool,
    /// Serve HTTPS + WSS instead of plain HTTP (docs/security.md M31).
    pub tls: bool,
    /// Operator-supplied certificate and key. Both or neither; empty means
    /// "generate a self-signed pair into `state_dir/tls` and keep it".
    pub tls_cert: String,
    pub tls_key: String,
    /// CA bundle an `https://` `cp_url` must chain to; empty: the system bundle.
    pub ca_file: String,
    /// Where the daemon keeps state it must not regenerate, i.e. the self-signed
    /// certificate whose fingerprint clients pin.
    pub state_dir: String,
    /// Overrides the URL handed to the control plane and to pi. Needed whenever
    /// the listen address is not the address clients dial (port forwards, NAT).
    pub public_url: String,
    /// Lifetime of a scoped sandbox token.
    pub token_ttl_secs: u64,
    /// The guest-agent binary injected into a user image when a snapshot is
    /// built from it (`SBX_GUEST_AGENT_BIN`); empty means "the image has one".
    pub guest_agent_bin: String,
    /// Size of the ext4 a remote-tier image snapshot is built into, MiB.
    pub snapshot_rootfs_mb: u64,
    /// v5 §3a. Named sizes a create may ask for. `SBX_SIZES` (JSON) or
    /// `[sizes.<name>]` replaces `proto::sizes::default_table()` wholesale.
    pub sizes: proto::sizes::Table,
    /// v5 §3a. Host ceilings every resolved `SandboxLimits` is checked against,
    /// whatever the control plane already allowed. `pids: 0` means unbounded.
    pub max_limits: proto::SandboxLimits,
    // Firecracker (read only by the Linux-only backend).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fc_bin: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fc_jailer: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fc_kernel: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fc_rootfs: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fc_jail_dir: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fc_archive_dir: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fc_mem_mib: u32,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fc_hugepages: bool,
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

/// The first config file that exists, and where it came from.
pub fn config_path() -> Option<PathBuf> {
    let mut cands: Vec<PathBuf> = Vec::new();
    if let Some(p) = env("SBX_CONFIG") {
        cands.push(p.into());
    }
    cands.push("qafas.toml".into());
    cands.push("/etc/qafas/qafas.toml".into());
    if let Some(h) = env("HOME") {
        cands.push(PathBuf::from(h).join(".config/qafas/qafas.toml"));
    }
    cands.into_iter().find(|p| p.is_file())
}

/// Root-owned when we are root, per-user otherwise: the daemon must be able to
/// write its certificate without anyone having to `mkdir` first.
fn default_state_dir() -> String {
    if nix::unistd::Uid::effective().is_root() {
        return "/var/lib/qafas".to_string();
    }
    match env("HOME") {
        Some(h) => format!("{h}/.qafas"),
        None => "/tmp/qafas".to_string(),
    }
}

/// Tiers a host serves by default when nothing says otherwise.
fn default_tiers() -> Vec<String> {
    if cfg!(target_os = "macos") {
        vec!["native".into(), "vm".into()]
    } else {
        vec!["native".into(), "vm".into(), "remote".into()]
    }
}

/// v5 §3a. `SBX_SIZES` beats `[sizes.*]` beats the compiled table. A table
/// without `medium` is refused (it is the default every silent create resolves
/// to) and a malformed `SBX_SIZES` is logged and ignored rather than fatal —
/// the daemon still has a correct table to fall back on.
fn sizes(from_file: Option<proto::sizes::Table>) -> proto::sizes::Table {
    let from_env = env("SBX_SIZES").and_then(|v| match serde_json::from_str::<proto::sizes::Table>(&v) {
        Ok(t) => Some(t),
        Err(e) => {
            tracing::error!(error = %e, "SBX_SIZES is not a size table; using the built-in sizes");
            None
        }
    });
    match from_env.or(from_file) {
        Some(t) if t.contains_key(proto::sizes::DEFAULT) => t,
        Some(_) => {
            tracing::error!("the size table has no {:?}; using the built-in sizes", proto::sizes::DEFAULT);
            proto::sizes::default_table()
        }
        None => proto::sizes::default_table(),
    }
}

fn parse_tiers(s: &str) -> Vec<String> {
    s.split(',').map(|t| t.trim().to_ascii_lowercase()).filter(|t| !t.is_empty()).collect()
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let path = config_path();
        let file: FileConfig = match &path {
            Some(p) => {
                toml::from_str(&std::fs::read_to_string(p)?).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?
            }
            None => FileConfig::default(),
        };
        if let Some(p) = &path {
            tracing::info!(config = %p.display(), "configuration file loaded");
        }
        Ok(Self::resolve(file))
    }

    /// Layers environment over file over default. Split out so it is testable
    /// without touching the filesystem.
    pub fn resolve(f: FileConfig) -> Self {
        let s = |key: &str, from_file: Option<String>, default: &str| -> String {
            env(key).or(from_file).unwrap_or_else(|| default.to_string())
        };
        let listen = s("SBX_LISTEN", f.listen, "127.0.0.1:7700");
        let listen: SocketAddr = listen.parse().unwrap_or_else(|_| {
            tracing::error!(listen, "SBX_LISTEN is not host:port; falling back to 127.0.0.1:7700");
            SocketAddr::from(([127, 0, 0, 1], proto::QAFAS_PORT))
        });

        // `SBX_BACKEND` is the v1 name and named exactly one backend. It stays
        // as a deprecated alias: `SBX_BACKEND=firecracker` means "serve only the
        // remote tier".
        let tiers = match (env("SBX_TIERS"), env("SBX_BACKEND"), f.tiers) {
            (Some(t), _, _) => parse_tiers(&t),
            (None, Some(b), _) => {
                tracing::warn!(backend = %b, "SBX_BACKEND is deprecated; use SBX_TIERS");
                parse_tiers(&match b.as_str() {
                    "podman" => "vm".to_string(),
                    "firecracker" => "remote".to_string(),
                    other => other.to_string(),
                })
            }
            (None, None, Some(t)) => t.into_iter().map(|t| t.to_ascii_lowercase()).collect(),
            (None, None, None) => default_tiers(),
        };

        let num = |key: &str, from_file: Option<u64>, default: u64| -> u64 {
            env(key).and_then(|v| v.parse().ok()).or(from_file).unwrap_or(default)
        };
        let flag = |key: &str, from_file: Option<bool>, default: bool| -> bool {
            env(key).map(|v| v == "1" || v.eq_ignore_ascii_case("true")).or(from_file).unwrap_or(default)
        };
        // v5 §3a: the ceilings default to what this host actually has, so a
        // direct daemon client (or a compromised key) cannot outrun the box.
        let host_cpus = f64::from(std::thread::available_parallelism().map_or(1, |n| n.get() as u32));
        let host_mem = crate::doctor::mem_mib().max(1);

        Self {
            tiers,
            listen,
            token: s("SBX_TOKEN", f.token, "dev"),
            host_id: s("SBX_HOST_ID", f.host_id, "mac-local"),
            cp_url: env("SBX_CP_URL").or(f.cp_url).filter(|s| !s.is_empty()),
            host_token: s("SBX_HOST_TOKEN", f.host_token, ""),
            pool_size: num("SBX_POOL_SIZE", f.pool_size.map(u64::from), 2) as u32,
            pool_recent_secs: num("SBX_POOL_RECENT_SECS", f.pool_recent_secs, 3600),
            pool_recent_max: num("SBX_POOL_RECENT_MAX", f.pool_recent_max, 4) as usize,
            base_memory_snapshot: flag("SBX_BASE_MEMORY_SNAPSHOT", f.base_memory_snapshot, true),
            ttl_secs: num("SBX_TTL_SECS", f.ttl_secs, 3600),
            auto_stop_secs: num("SBX_AUTO_STOP_SECS", f.auto_stop_secs, 1800),
            auto_delete_secs: num("SBX_AUTO_DELETE_SECS", f.auto_delete_secs, 86400),
            max_age_secs: num("SBX_MAX_AGE_SECS", f.max_age_secs, 0),
            long_running_secs: num("SBX_LONG_RUNNING_SECS", f.long_running_secs, 14400),
            template_image: s("SBX_TEMPLATE_IMAGE", f.template_image, "localhost/sbx-base:dev"),
            templates: s("SBX_TEMPLATES", f.templates, "images/templates.json"),
            policy: s("SBX_POLICY", f.policy, "policy/egress.json"),
            seatbelt_profile: s("SBX_SEATBELT_PROFILE", f.seatbelt_profile, "policy/seatbelt.sb.tmpl"),
            scratch_dir: s("SBX_SCRATCH_DIR", f.scratch_dir, "/tmp"),
            max_upload_mb: num("SBX_MAX_UPLOAD_MB", f.max_upload_mb, 512),
            proxy_dns: env("SBX_PROXY_DNS")
                .map(|v| v.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect())
                .or(f.proxy_dns)
                .unwrap_or_default(),
            native_browser: flag("SBX_NATIVE_BROWSER", f.native_browser, false),
            native_permissive: flag("SBX_NATIVE_PERMISSIVE", f.native_permissive, false),
            tls: flag("SBX_TLS", f.tls, false),
            tls_cert: s("SBX_TLS_CERT", f.tls_cert, ""),
            tls_key: s("SBX_TLS_KEY", f.tls_key, ""),
            ca_file: s("SBX_CA_FILE", f.ca_file, ""),
            state_dir: s("SBX_STATE_DIR", f.state_dir, &default_state_dir()),
            public_url: s("SBX_PUBLIC_URL", f.public_url, "").trim_end_matches('/').to_string(),
            token_ttl_secs: num("SBX_TOKEN_TTL_SECS", f.token_ttl_secs, proto::hmac_token::DEFAULT_TTL_SECS),
            guest_agent_bin: s("SBX_GUEST_AGENT_BIN", f.guest_agent_bin, ""),
            snapshot_rootfs_mb: num("SBX_SNAPSHOT_ROOTFS_MB", f.snapshot_rootfs_mb, 2048),
            sizes: sizes(f.sizes),
            max_limits: proto::SandboxLimits {
                cpus: env("SBX_MAX_CPUS").and_then(|v| v.parse().ok()).or(f.max_cpus).unwrap_or(host_cpus),
                mem_mib: num("SBX_MAX_MEM_MIB", f.max_mem_mib, host_mem),
                disk_mib: num("SBX_MAX_DISK_MIB", f.max_disk_mib, host_mem),
                pids: 0,
            },
            fc_bin: s("SBX_FC_BIN", f.firecracker.bin, "/usr/bin/firecracker"),
            fc_jailer: s("SBX_FC_JAILER", f.firecracker.jailer, "/usr/bin/jailer"),
            fc_kernel: s("SBX_FC_KERNEL", f.firecracker.kernel, "images/out/vmlinux"),
            fc_rootfs: s("SBX_FC_ROOTFS", f.firecracker.rootfs, "images/out/rootfs.ext4"),
            fc_jail_dir: s("SBX_FC_JAIL", f.firecracker.jail_dir.clone(), "/srv/jail"),
            fc_archive_dir: s(
                "SBX_FC_ARCHIVE_DIR",
                f.firecracker.archive_dir,
                &format!("{}/archive", s("SBX_FC_JAIL", f.firecracker.jail_dir, "/srv/jail")),
            ),
            fc_mem_mib: std::env::var("SBX_FC_MEM_MIB")
                .ok()
                .and_then(|v| v.parse().ok())
                .or(f.firecracker.mem_mib)
                .unwrap_or(2048),
            // Opt-in: Firecracker cannot restore a snapshot onto hugetlbfs memory with
            // the file backend, so huge pages cost stop/start (a UFFD handler is the
            // upgrade). Worth it only on nested KVM, where 4 KB stage-2 faults are 400x slower.
            fc_hugepages: std::env::var("SBX_FC_HUGEPAGES").ok().is_some_and(|v| v == "1" || v == "true")
                || f.firecracker.hugepages.unwrap_or(false),
        }
    }

    /// Base URL pi is handed back. A wildcard listen address is not dialable, and
    /// behind a port forward neither is the real one — hence `SBX_PUBLIC_URL`.
    pub fn scheme(&self) -> &'static str {
        if self.tls {
            "https"
        } else {
            "http"
        }
    }

    pub fn public_base(&self) -> String {
        if !self.public_url.is_empty() {
            return self.public_url.clone();
        }
        let scheme = self.scheme();
        if self.listen.ip().is_unspecified() {
            format!("{scheme}://127.0.0.1:{}", self.listen.port())
        } else {
            format!("{scheme}://{}", self.listen)
        }
    }

    /// v5 §3a. The `medium` row: what a pool create boots with, and what a
    /// create that names nothing resolves to.
    pub fn default_limits(&self) -> proto::SandboxLimits {
        self.sizes.get(proto::sizes::DEFAULT).copied().unwrap_or(proto::SandboxLimits {
            cpus: 2.0,
            mem_mib: 2048,
            disk_mib: 2048,
            pids: 512,
        })
    }

    /// The biggest scratch any configured size can ask for. A pooled container's
    /// tmpfs is sized at this once, because a uid-1000 agent cannot remount it
    /// when the sandbox is handed out; the memory cgroup is what bounds real use
    /// (§3a, accepted soft edge — per-size pools are the upgrade).
    pub fn max_size_disk_mib(&self) -> u64 {
        self.sizes.values().map(|l| l.disk_mib).max().unwrap_or(2048)
    }

    pub fn serves(&self, tier: &str) -> bool {
        self.tiers.iter().any(|t| t == tier)
    }

    /// The backend name reported in `SandboxInfo.backend` and `/healthz` for a
    /// host that still speaks the v1 vocabulary.
    pub fn primary_backend(&self) -> &'static str {
        if self.serves("remote") && !self.serves("vm") {
            "firecracker"
        } else if self.serves("vm") {
            "podman"
        } else {
            "native"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The env-var half of precedence, run in a child process: `set_var` is
    /// process-global and would otherwise leak into every other test that reads
    /// the environment — which is most of them, since that is how the daemon is
    /// configured. The child is this same binary, re-executed for one test.
    #[test]
    fn env_beats_the_file() {
        let out = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", "config::tests::env_precedence_in_a_child", "--ignored"])
            .env("SBX_TOKEN", "from-env")
            .env("SBX_POOL_SIZE", "3")
            .env("SBX_TIERS", "Native")
            .output()
            .expect("re-running the test binary");
        let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "{stdout}{stderr}");
        assert!(stdout.contains("1 passed"), "the child must have run it: {stdout}");
    }

    /// The assertions of the test above, in the process that has the variables.
    /// `#[ignore]` so an ordinary run never reaches it without them.
    #[test]
    #[ignore]
    fn env_precedence_in_a_child() {
        let f = FileConfig {
            token: Some("from-file".into()),
            pool_size: Some(7),
            tiers: Some(vec!["vm".into()]),
            ..Default::default()
        };
        let c = Config::resolve(f);
        assert_eq!(c.token, "from-env", "env beats the file");
        assert_eq!(c.pool_size, 3);
        assert_eq!(c.tiers, ["native"], "and it is normalised the same way");
        assert_eq!(c.host_id, "mac-local", "what no variable names still comes from the default");
    }

    #[test]
    fn precedence_is_file_then_default() {
        let f = FileConfig {
            token: Some("from-file".into()),
            pool_size: Some(7),
            tiers: Some(vec!["VM".into()]),
            ..Default::default()
        };
        let c = Config::resolve(f);
        assert_eq!(c.token, "from-file", "file beats the default");
        assert_eq!(c.pool_size, 7);
        assert_eq!(c.tiers, ["vm"], "tier names are normalised");
        assert_eq!(c.host_id, "mac-local", "and the default still applies elsewhere");
        assert_eq!(c.ttl_secs, 3600);
        // v4 timer defaults (§3a): sleep after 30 min, delete a day later.
        assert_eq!((c.auto_stop_secs, c.auto_delete_secs), (1800, 86400));
        assert_eq!((c.max_age_secs, c.long_running_secs), (0, 14400));
        assert!(c.serves("vm") && !c.serves("native"));
        assert_eq!(c.primary_backend(), "podman");
    }

    #[test]
    fn the_deprecated_backend_alias_still_selects_a_tier() {
        assert_eq!(parse_tiers("native, vm ,"), ["native", "vm"]);
        let c = Config::resolve(FileConfig::default());
        assert!(c.serves("native") && c.serves("vm"), "{:?}", c.tiers);
        assert_eq!(c.primary_backend(), "podman");
    }

    /// The URL handed to the control plane and to pi has to be dialable, and has
    /// to say https when TLS is on — a client that pins the fingerprint but dials
    /// http gets no TLS at all.
    #[test]
    fn public_base_follows_tls_and_yields_to_an_explicit_url() {
        let mut c = Config::resolve(FileConfig::default());
        assert_eq!(c.public_base(), "http://127.0.0.1:7700");
        c.tls = true;
        assert_eq!(c.public_base(), "https://127.0.0.1:7700");
        c.listen = "0.0.0.0:7700".parse().unwrap();
        assert_eq!(c.public_base(), "https://127.0.0.1:7700", "a wildcard listener is not dialable");
        c.public_url = "https://box-1.internal:8443".into();
        assert_eq!(c.public_base(), "https://box-1.internal:8443");
        assert_eq!(c.token_ttl_secs, 12 * 3600);
    }

    #[test]
    fn a_broken_config_file_is_an_error_not_a_silent_default() {
        let e = toml::from_str::<FileConfig>("pool_size = \"lots\"").unwrap_err();
        assert!(e.to_string().contains("pool_size"), "{e}");
        // An unknown key is rejected too: a typo must not disable a control.
        assert!(toml::from_str::<FileConfig>("tokne = \"x\"").is_err());
    }

    /// v5 §3a. The table is replaceable wholesale, but never into a state where
    /// a silent create has nothing to resolve to: a table without `medium` is
    /// refused in favour of the built-in one rather than failing every create.
    #[test]
    fn the_size_table_always_keeps_a_default() {
        let c = Config::resolve(FileConfig::default());
        assert_eq!(c.sizes, proto::sizes::default_table());
        assert_eq!(c.default_limits().mem_mib, 2048, "medium is the pre-v5 unit");
        assert_eq!(c.max_size_disk_mib(), 4096, "the pooled tmpfs is sized at the largest size");

        let tiny = proto::SandboxLimits { cpus: 0.25, mem_mib: 64, disk_mib: 64, pids: 32 };
        let no_medium = proto::sizes::Table::from([("tiny".to_string(), tiny)]);
        assert_eq!(sizes(Some(no_medium)), proto::sizes::default_table());

        let ok = proto::sizes::Table::from([
            ("tiny".to_string(), tiny),
            ("medium".to_string(), proto::SandboxLimits { cpus: 1.0, mem_mib: 999, disk_mib: 8, pids: 7 }),
        ]);
        let c = Config::resolve(FileConfig { sizes: Some(ok), ..Default::default() });
        assert_eq!(c.default_limits().mem_mib, 999, "an operator table replaces the built-in one");
        assert_eq!(c.max_size_disk_mib(), 64);
        // Ceilings default to what the host has, so they are never zero.
        assert!(c.max_limits.cpus >= 1.0 && c.max_limits.mem_mib > 0 && c.max_limits.disk_mib > 0);
    }

    #[test]
    fn the_example_deployment_file_parses() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/qafas.toml");
        let text = std::fs::read_to_string(path).expect("deploy/qafas.toml");
        let f: FileConfig = toml::from_str(&text).expect("deploy/qafas.toml must parse");
        let c = Config::resolve(f);
        assert!(!c.tiers.is_empty());
    }

    /// The packaged /etc/qafas/qafas.toml parses, points at the Firecracker
    /// bundle, and takes a key an operator appends at the end (`tls = true`)
    /// at the top level — a trailing `[firecracker]` table would swallow it.
    #[test]
    fn the_packaged_file_parses_and_takes_appended_keys() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packaging/qafas.toml");
        let text = std::fs::read_to_string(path).expect("packaging/qafas.toml") + "\ntls = true\n";
        let c = Config::resolve(toml::from_str(&text).expect("packaging/qafas.toml + an appended key must parse"));
        assert!(c.tls);
        assert_eq!(c.fc_rootfs, "/var/lib/qafas/firecracker/rootfs.ext4");
        assert_eq!(c.fc_jail_dir, "/var/lib/qafas/jail");
    }
}
