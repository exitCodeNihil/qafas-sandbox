//! THE contract. Mirrored field-for-field in `sdk/ts/src/types.ts` and
//! `controlplane/internal/events/types.go`; human copy in `docs/protocol.md`.
//! Frozen at Gate A. Change all four in one commit.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const VERSION: &str = "0.1.0"; // x-release-please-version
pub const GUEST_AGENT_PORT: u16 = 7777;
pub const QAFAS_PORT: u16 = 7700;
pub const CONTROLPLANE_PORT: u16 = 7800;
pub const EGRESS_PROXY_PORT: u16 = 3128;
/// What pulls the interpreters into a fresh guest's page cache. The guest runs
/// it in the background at init; v4, qafas runs it synchronously before a
/// template memory capture, so the photograph is of a warm VM.
pub const WARM_CMD: &str = "node -e 0; python3 -c 0; git --version; bash -lc true";
pub const HDR_PI_SESSION: &str = "x-pi-session";
pub const HDR_TOOL_CALL_ID: &str = "x-tool-call-id";
/// v2. Which library is talking: `pi/0.83`, `sdk-ts/0.1`. Logged, never trusted.
pub const HDR_CLIENT: &str = "x-sbx-client";
/// v4. The per-sandbox secret qafas proves itself to the guest-agent with on
/// the podman tier, where the agent port is published on the host's loopback
/// (§2). Minted at create, handed to the guest as `SBX_AGENT_TOKEN`, which is in
/// `PROTECTED_ENV` so no exec can read or override it.
pub const HDR_AGENT_TOKEN: &str = "x-sbx-agent-token";

/// `null` and absent both mean "default" for optional collections: SDKs in
/// languages that serialise `None` as `null` must not get a 400 for it.
fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

// ---------------------------------------------------------------- events

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    #[serde(rename = "sandbox.created")]
    SandboxCreated,
    #[serde(rename = "sandbox.ready")]
    SandboxReady,
    #[serde(rename = "sandbox.destroyed")]
    SandboxDestroyed,
    #[serde(rename = "exec.start")]
    ExecStart,
    #[serde(rename = "exec.end")]
    ExecEnd,
    #[serde(rename = "file.read")]
    FileRead,
    #[serde(rename = "file.write")]
    FileWrite,
    #[serde(rename = "file.edit")]
    FileEdit,
    #[serde(rename = "browser.navigate")]
    BrowserNavigate,
    #[serde(rename = "egress.allow")]
    EgressAllow,
    #[serde(rename = "egress.deny")]
    EgressDeny,
    #[serde(rename = "pool.refill")]
    PoolRefill,
    #[serde(rename = "error")]
    Error,
    // v2: in-sandbox telemetry and detection
    #[serde(rename = "sandbox.tier_selected")]
    SandboxTierSelected,
    #[serde(rename = "process.start")]
    ProcessStart,
    #[serde(rename = "process.exit")]
    ProcessExit,
    #[serde(rename = "file.access")]
    FileAccess,
    #[serde(rename = "net.connect")]
    NetConnect,
    #[serde(rename = "security.alert")]
    SecurityAlert,
    // v3: lifecycle, snapshots, preview
    #[serde(rename = "sandbox.stopped")]
    SandboxStopped,
    #[serde(rename = "sandbox.started")]
    SandboxStarted,
    #[serde(rename = "sandbox.paused")]
    SandboxPaused,
    #[serde(rename = "sandbox.resumed")]
    SandboxResumed,
    #[serde(rename = "sandbox.archived")]
    SandboxArchived,
    #[serde(rename = "snapshot.building")]
    SnapshotBuilding,
    #[serde(rename = "snapshot.ready")]
    SnapshotReady,
    #[serde(rename = "snapshot.error")]
    SnapshotError,
    #[serde(rename = "preview.created")]
    PreviewCreated,
    /// v5.1. Pushed by the guest agent while an exec is live; `data` is a `SandboxUsage`.
    #[serde(rename = "sandbox.usage")]
    SandboxUsage,
}

impl EventType {
    pub fn as_str(self) -> &'static str {
        match self {
            EventType::SandboxCreated => "sandbox.created",
            EventType::SandboxReady => "sandbox.ready",
            EventType::SandboxDestroyed => "sandbox.destroyed",
            EventType::ExecStart => "exec.start",
            EventType::ExecEnd => "exec.end",
            EventType::FileRead => "file.read",
            EventType::FileWrite => "file.write",
            EventType::FileEdit => "file.edit",
            EventType::BrowserNavigate => "browser.navigate",
            EventType::EgressAllow => "egress.allow",
            EventType::EgressDeny => "egress.deny",
            EventType::PoolRefill => "pool.refill",
            EventType::Error => "error",
            EventType::SandboxTierSelected => "sandbox.tier_selected",
            EventType::ProcessStart => "process.start",
            EventType::ProcessExit => "process.exit",
            EventType::FileAccess => "file.access",
            EventType::NetConnect => "net.connect",
            EventType::SecurityAlert => "security.alert",
            EventType::SandboxStopped => "sandbox.stopped",
            EventType::SandboxStarted => "sandbox.started",
            EventType::SandboxPaused => "sandbox.paused",
            EventType::SandboxResumed => "sandbox.resumed",
            EventType::SandboxArchived => "sandbox.archived",
            EventType::SnapshotBuilding => "snapshot.building",
            EventType::SnapshotReady => "snapshot.ready",
            EventType::SnapshotError => "snapshot.error",
            EventType::PreviewCreated => "preview.created",
            EventType::SandboxUsage => "sandbox.usage",
        }
    }
}

/// One audit event. `id` is a ULID; `ts` RFC 3339 UTC with milliseconds.
/// `pi_session` / `tool_call_id` are copied from the request headers
/// `X-Pi-Session` / `X-Tool-Call-Id` (empty string when absent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub ts: String,
    pub host_id: String,
    pub sandbox_id: String,
    pub pi_session: String,
    pub tool_call_id: String,
    #[serde(rename = "type")]
    pub r#type: EventType,
    pub data: Value,
}

/// Body of `POST /sandboxes/{id}/events` (pi extension → qafas) for
/// events qafas cannot observe itself (e.g. `browser.navigate`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientEvent {
    #[serde(rename = "type")]
    pub r#type: EventType,
    pub data: Value,
}

// ---------------------------------------------------------------- exec

/// `POST /exec` (buffered).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecReq {
    pub cmd: String,
    /// Optional since v4c: empty or absent runs in the sandbox's home/workspace.
    #[serde(default)]
    pub cwd: String,
    #[serde(default, deserialize_with = "null_default")]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResp {
    pub exit: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PtySize {
    pub cols: u16,
    pub rows: u16,
}

/// `/exec/ws` frames, both directions. JSON text frames; `data` is base64.
/// `design:` base64-in-JSON; move to binary frames only if measured.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ExecFrame {
    // client → agent
    Start {
        cmd: String,
        cwd: String,
        #[serde(default, deserialize_with = "null_default")]
        env: BTreeMap<String, String>,
        #[serde(default)]
        pty: Option<PtySize>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    Stdin {
        data: String,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
    Signal {
        sig: String,
    },
    // agent → client
    Stdout {
        data: String,
    },
    Stderr {
        data: String,
    },
    Exit {
        code: i32,
        #[serde(default)]
        signal: Option<String>,
        duration_ms: u64,
        #[serde(default)]
        timed_out: bool,
    },
}

// ---------------------------------------------------------------- fs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsStat {
    pub is_dir: bool,
    pub size: u64,
    pub mode: u32,
    pub mtime: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MkdirReq {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Healthz {
    pub ok: bool,
    pub uid: u32,
    pub version: String,
}

// ---------------------------------------------------------------- qafas

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSpec {
    pub host_path: String,
}

/// Isolation tier. `Auto` lets qafas pick by policy (`crates/qafas/src/policy.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Isolation {
    #[default]
    Auto,
    /// OS process sandbox on the host: Seatbelt (macOS), Landlock + seccomp + bwrap (Linux).
    /// v4: the product name `process` is accepted on input; output is always `native`.
    #[serde(alias = "process")]
    Native,
    /// Container inside a VM (podman machine on macOS) or container on Linux. Alias `docker`.
    #[serde(alias = "docker")]
    Vm,
    /// Firecracker microVM on a remote host. Alias `firecracker`.
    #[serde(alias = "firecracker")]
    Remote,
}

impl Isolation {
    pub fn as_str(self) -> &'static str {
        match self {
            Isolation::Auto => "auto",
            Isolation::Native => "native",
            Isolation::Vm => "vm",
            Isolation::Remote => "remote",
        }
    }
}

/// How much the harness trusts the code in the workspace. Untrusted never gets `native`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trust {
    #[default]
    Trusted,
    Untrusted,
}

/// `POST /sandboxes` (qafas) and `POST /api/sandboxes` (control plane).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSandboxReq {
    pub template: String,
    #[serde(default)]
    pub workspace: Option<WorkspaceSpec>,
    #[serde(default)]
    pub pi_session: String,
    /// v2. Requested tier; `auto` by default.
    #[serde(default)]
    pub isolation: Isolation,
    #[serde(default)]
    pub trust: Trust,
    /// v2. Tools the agent needs, e.g. `["node@22","python@3.12","rg","git","chromium"]`.
    /// The reply says which resolved (`tools`) and which did not (`missing_tools`).
    #[serde(default, deserialize_with = "null_default")]
    pub tools: Vec<String>,
    /// v2. Extra egress allow globs for this sandbox (from the harness, never the model).
    /// Always subject to the private-range deny list.
    #[serde(default, deserialize_with = "null_default")]
    pub egress_allow: Vec<String>,
    /// v2. Idle TTL; qafas destroys the sandbox after this long without activity.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// v3. Human name, unique among this host's live sandboxes; the id when absent.
    #[serde(default)]
    pub name: Option<String>,
    /// v3. Free-form key/values, returned on `SandboxInfo`, filterable in the dashboard.
    #[serde(default, deserialize_with = "null_default")]
    pub labels: BTreeMap<String, String>,
    /// v3. Environment for every exec in this sandbox (protected names are dropped, D-env).
    #[serde(default, deserialize_with = "null_default")]
    pub env: BTreeMap<String, String>,
    /// v3. Idle this long → `stop` (remote tier; other tiers ignore it and use `ttl_secs`).
    #[serde(default)]
    pub auto_stop_secs: Option<u64>,
    /// v3. Stopped this long → `archive`.
    #[serde(default)]
    pub auto_archive_secs: Option<u64>,
    /// v3. `Some(0)`: ephemeral, destroyed as soon as it stops. `Some(n)`: stopped or
    /// archived for n seconds → destroyed. `None`: kept until `ttl`/`max_age`/delete.
    #[serde(default)]
    pub auto_delete_secs: Option<u64>,
    /// v3. Wall-clock lifetime from creation, whatever the state.
    #[serde(default)]
    pub max_age_secs: Option<u64>,
    /// v5. A named size (`micro|mini|medium|high`, `sizes::default_table`). From the
    /// harness or the API, never the model (D22 applies to resources as to egress).
    #[serde(default)]
    pub size: Option<String>,
    /// v5. Custom ceilings instead of `size`; both given → 400, neither → `medium`.
    /// The control plane resolves a name to these numbers and forwards both.
    #[serde(default)]
    pub limits: Option<SandboxLimits>,
}

/// qafas `201` reply. Control plane adds `host_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSandboxResp {
    pub id: String,
    pub endpoint: String,
    pub token: String,
    pub backend: String,
    pub workspace_path: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    /// v2. Tier actually selected (`native|vm|remote`).
    #[serde(default)]
    pub isolation: String,
    /// v2. tool name → version string (or "present").
    #[serde(default)]
    pub tools: BTreeMap<String, String>,
    #[serde(default)]
    pub missing_tools: Vec<String>,
    /// v2. The host's TLS certificate fingerprint, so the harness can pin it.
    #[serde(default)]
    pub tls_fingerprint: String,
    /// v5. Size name (or `custom`) and the ceilings actually applied.
    #[serde(default)]
    pub size: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<SandboxLimits>,
    /// v5.1. The record as the daemon holds it right after create (name, labels,
    /// resolved timers, enforcement); authoritative over anything the client sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<Box<SandboxInfo>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxState {
    Creating,
    Ready,
    Busy,
    /// v3. Memory kept, vCPUs halted (remote tier only).
    Paused,
    /// v3. Snapshotted to disk, no VM process; `start` restores it.
    Stopped,
    /// v3. Snapshot moved to the archive dir; `start` restores it (slower).
    Archived,
    Destroyed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxInfo {
    pub id: String,
    pub backend: String,
    pub template: String,
    pub state: SandboxState,
    pub workspace_path: String,
    pub pi_session: String,
    pub created_at: String,
    #[serde(default)]
    pub ready_at: Option<String>,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    /// v2. `native|vm|remote`.
    #[serde(default)]
    pub isolation: String,
    /// v2. Last request or process activity, RFC 3339.
    #[serde(default)]
    pub last_activity: Option<String>,
    /// v3.
    #[serde(default)]
    pub name: String,
    #[serde(default, deserialize_with = "null_default")]
    pub labels: BTreeMap<String, String>,
    /// v3. When `state` last changed, RFC 3339.
    #[serde(default)]
    pub state_changed_at: Option<String>,
    #[serde(default)]
    pub auto_stop_secs: Option<u64>,
    #[serde(default)]
    pub auto_archive_secs: Option<u64>,
    #[serde(default)]
    pub auto_delete_secs: Option<u64>,
    #[serde(default)]
    pub max_age_secs: Option<u64>,
    /// v4. Seconds since the last activity, and since the last start or create
    /// while running (0 when it is not), so a client can show "stops in …".
    #[serde(default)]
    pub idle_secs: u64,
    #[serde(default)]
    pub running_secs: u64,
    /// v5. `micro|mini|medium|high` or `custom`; empty from a pre-v5 daemon.
    #[serde(default)]
    pub size: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<SandboxLimits>,
    /// v5. `kernel` (cgroup v2 on vm/remote/Linux native) or `daemon` (macOS native:
    /// qafas's watchdog kills the group over the limit; CPU is not capped).
    #[serde(default)]
    pub enforcement: String,
    /// v5. Latest boundary sample; absent until the first one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<SandboxUsage>,
}

// ---------------------------------------------------------------- v3 snapshots

/// What a snapshot is built from. Exactly one field is set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotSource {
    /// OCI image reference with a tag or digest (`latest` refused).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Dockerfile text, built with the daemon's podman.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<String>,
    /// A live sandbox on this host: its filesystem (vm) or memory+filesystem (remote).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSnapshotReq {
    /// `[a-z0-9][a-z0-9._-]{0,63}`; also the `template` a create request names.
    pub name: String,
    pub source: SnapshotSource,
    /// v4. Restored sandboxes to keep ready for this template (0 = only the
    /// recency rule applies). Persisted; `PUT /snapshots/{name}` changes it.
    #[serde(default)]
    pub warm: u32,
    /// v4c. Which runtime builds and serves this template: `remote` (Firecracker)
    /// or `vm` (Docker). Aliases accepted. The control plane fans the build out to
    /// hosts of that runtime only; default is the fleet's default runtime. A
    /// `sandbox_id` source implies the owning host's runtime.
    #[serde(default)]
    pub runtime: Option<Isolation>,
    /// v4. After an `image`/`dockerfile` build on a Firecracker host, boot the
    /// image once, wait for the guest agent, and capture memory so every sandbox
    /// starts by restore instead of a kernel boot. Default true; ignored elsewhere.
    #[serde(default = "default_true")]
    pub memory_snapshot: bool,
}

fn default_true() -> bool {
    true
}

/// v4 `PUT /snapshots/{name}`: the mutable part of a snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateSnapshotReq {
    pub warm: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotState {
    Building,
    Active,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotInfo {
    pub name: String,
    pub state: SnapshotState,
    /// `image`: a filesystem image, boots fresh. `vm`: a memory+filesystem capture,
    /// restored; sub-100 ms create.
    pub kind: String,
    pub source: SnapshotSource,
    pub created_at: String,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Control plane adds it: which host holds this snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    /// v4. Restored sandboxes kept ready for this template on this host.
    #[serde(default)]
    pub warm: u32,
    /// v4. An `image` snapshot that also holds a memory capture: sandboxes start
    /// by restore. Always true for `vm` snapshots.
    #[serde(default)]
    pub memory_snapshot: bool,
    /// v4. Warm sandboxes waiting right now (from the pool; per host).
    #[serde(default)]
    pub warm_ready: u32,
    /// v4c. The runtime this copy serves: the host's pooled tier (`remote`|`vm`).
    #[serde(default)]
    pub runtime: String,
    /// v5.2. The last security scan of this template on this host; absent until
    /// one has run (security.md M43).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<TemplateSecurity>,
}

/// v5.2. One check of the template security scan (`images/probe/scan.sh`).
/// `class` is `boundary` (the tier's promise: any failure is grade `F`) or
/// `hygiene` (what the image carries).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityCheck {
    pub id: String,
    pub class: String,
    pub ok: bool,
    #[serde(default)]
    pub detail: String,
}

/// v5.2. A template's scan: every check, and the grade they add up to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemplateSecurity {
    /// `A` | `B` | `C` | `F` — see `grade`.
    pub grade: String,
    pub scanned_at: String,
    /// What was scanned (image id, or rootfs size+mtime on the remote tier), so a
    /// cached result is only reused for the same bits.
    #[serde(default)]
    pub image_digest: String,
    pub findings: Vec<SecurityCheck>,
}

/// v5.2. `F` if any `boundary` check failed; otherwise `A` with no failed
/// `hygiene` check, `B` with one or two, `C` with more. A letter, not a score:
/// a number invites comparisons the checks cannot support.
pub fn security_grade(checks: &[SecurityCheck]) -> &'static str {
    if checks.iter().any(|c| !c.ok && c.class == "boundary") {
        return "F";
    }
    match checks.iter().filter(|c| !c.ok).count() {
        0 => "A",
        1 | 2 => "B",
        _ => "C",
    }
}

/// v4c. What a host can do, from `qafas doctor`; sent at registration so the
/// dashboard shows why a host serves the runtimes it serves.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostCaps {
    pub os: String,
    pub arch: String,
    pub cpus: u32,
    pub mem_mib: u64,
    pub kvm: bool,
    pub firecracker: bool,
    pub podman: bool,
    /// Seatbelt (macOS) or Landlock+bwrap (Linux): the process runtime.
    pub process_sandbox: bool,
    pub bpftrace: bool,
    pub hugepages_mib: u64,
    /// Runtimes the capabilities allow (`native`, `vm`, `remote`), before config.
    #[serde(default)]
    pub supported: Vec<String>,
}

// ---------------------------------------------------------------- v5 sizes and limits

/// v5. Resource ceilings of one sandbox (docs/protocol.md §3a "v5 sizes and limits"). Set
/// at create and re-applied when a pooled sandbox is handed out; enforced where the
/// workload cannot reach: cgroup v2 on `vm`/`remote`/Linux `native`, qafas's watchdog
/// on macOS `native` (`SandboxInfo.enforcement`).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SandboxLimits {
    /// CPUs, whole or fractional in 0.25 steps (`cpu.max` = cpus × 100000 per 100000).
    pub cpus: f64,
    pub mem_mib: u64,
    /// Writable scratch: `/tmp` tmpfs on `vm`, the overlay root on `remote`, `/tmp/sbx-<id>`
    /// on `native`. RAM-backed on `vm`/`remote`, so never effectively above `mem_mib`.
    pub disk_mib: u64,
    /// Process count. `0` on input means "the nearest named size's" (`sizes::resolve`).
    #[serde(default)]
    pub pids: u32,
}

/// v5. Point-in-time usage read at the boundary (cgroup files, `/proc`), never asked of
/// the workload. `cpu_millis` is cumulative CPU time.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SandboxUsage {
    pub cpu_millis: u64,
    pub mem_bytes: u64,
    pub mem_peak_bytes: u64,
    pub disk_bytes: u64,
    pub pids: u32,
    /// RFC 3339, when the sample was taken.
    #[serde(default)]
    pub ts: String,
}

/// v5. What a host has promised to its live sandboxes (Σ `SandboxLimits`); the control
/// plane computes it and refuses placements that would exceed `HostCaps × overcommit`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct HostCommitted {
    pub cpus: f64,
    pub mem_mib: u64,
}

/// v5. Named sizes. `SBX_SIZES` (JSON `{"name":{"cpus","mem_mib","disk_mib","pids"}}`)
/// replaces the table wholesale on both binaries; `medium` must stay present (the default,
/// and the pre-v5 unit: 2 CPU / 2 GiB / 512 pids).
pub mod sizes {
    use super::SandboxLimits;
    use std::collections::BTreeMap;

    pub type Table = BTreeMap<String, SandboxLimits>;
    pub const DEFAULT: &str = "medium";
    pub const CUSTOM: &str = "custom";
    pub const CPU_STEP: f64 = 0.25;

    pub fn default_table() -> Table {
        [
            ("micro", 0.5, 512, 512, 128),
            ("mini", 1.0, 1024, 1024, 256),
            ("medium", 2.0, 2048, 2048, 512),
            ("high", 4.0, 4096, 4096, 1024),
        ]
        .into_iter()
        .map(|(n, cpus, mem_mib, disk_mib, pids)| (n.to_string(), SandboxLimits { cpus, mem_mib, disk_mib, pids }))
        .collect()
    }

    /// Resolves a create request to `(size name, limits)`. A client gives one of
    /// `size`/`limits` (neither means `medium`); the control plane forwards both, `limits`
    /// being the numbers it resolved, so both together means "these numbers, labelled
    /// `size`" and `limits` is validated like a custom request. The `Err` text is the 400 body.
    pub fn resolve(
        size: Option<&str>,
        limits: Option<SandboxLimits>,
        table: &Table,
    ) -> Result<(String, SandboxLimits), String> {
        match (size, limits) {
            (Some(name), Some(l)) => resolve(None, Some(l), table).map(|(_, l)| (name.to_string(), l)),
            (Some(name), None) => table.get(name).map(|l| (name.to_string(), *l)).ok_or_else(|| {
                format!("unknown size {name:?}; sizes: {}", table.keys().cloned().collect::<Vec<_>>().join(", "))
            }),
            (None, Some(mut l)) => {
                if !(l.cpus >= CPU_STEP && (l.cpus / CPU_STEP).fract() == 0.0) {
                    return Err(format!("cpus must be a multiple of {CPU_STEP}, at least {CPU_STEP}"));
                }
                if l.mem_mib < 64 {
                    return Err("mem_mib must be at least 64".into());
                }
                if l.disk_mib == 0 {
                    return Err("disk_mib must be at least 1".into());
                }
                if l.pids == 0 {
                    l.pids = table
                        .values()
                        .filter(|s| s.mem_mib >= l.mem_mib)
                        .map(|s| s.pids)
                        .min()
                        .or_else(|| table.values().map(|s| s.pids).max())
                        .unwrap_or(512);
                }
                Ok((CUSTOM.to_string(), l))
            }
            (None, None) => table
                .get(DEFAULT)
                .map(|l| (DEFAULT.to_string(), *l))
                .ok_or_else(|| format!("size table has no {DEFAULT:?}")),
        }
    }

    /// `l` fits under `cap` in every dimension (API-key caps, host ceilings).
    pub fn fits(l: &SandboxLimits, cap: &SandboxLimits) -> bool {
        l.cpus <= cap.cpus
            && l.mem_mib <= cap.mem_mib
            && l.disk_mib <= cap.disk_mib
            && (cap.pids == 0 || l.pids <= cap.pids)
    }
}

// ---------------------------------------------------------------- v3 sessions

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CreateSessionReq {
    /// Caller-chosen id (`[A-Za-z0-9_-]{1,64}`); generated when absent.
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionExecReq {
    pub cmd: String,
    /// `true`: reply 202 with the command id at once; poll or stream its logs.
    #[serde(default)]
    pub r#async: bool,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CommandState {
    Running,
    Done,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCommand {
    pub command_id: String,
    pub cmd: String,
    pub state: CommandState,
    #[serde(default)]
    pub exit: Option<i32>,
    pub started_at: String,
    #[serde(default)]
    pub ended_at: Option<String>,
    /// Present on `GET .../commands/{cid}` only; capped like `/exec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub cwd: String,
    pub created_at: String,
    #[serde(default)]
    pub commands: Vec<SessionCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInputReq {
    /// Bytes for the running command's stdin; `\n` included if a line is meant.
    pub data: String,
}

// ---------------------------------------------------------------- v3 preview

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePreviewReq {
    pub port: u16,
    /// Default 12 h.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewInfo {
    /// `<base>/preview/{id}/{port}/`; append the path. The first request may carry
    /// `?sbx_preview=<token>`; a cookie keeps later ones authenticated.
    pub url: String,
    pub token: String,
    pub port: u16,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolStat {
    pub warm: u32,
    pub target: u32,
    /// v4. These warm sandboxes are restored from a memory capture rather than
    /// booted, i.e. this template's acquire is sub-100 ms.
    #[serde(default)]
    pub restore: bool,
}

/// v4 `GET /pool` → `{"<template>": PoolStat}` (keyed by template name).
pub type PoolStats = BTreeMap<String, PoolStat>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QafasHealthz {
    pub ok: bool,
    pub backend: String,
    pub host_id: String,
    /// v2. SHA-256 of the DER of the certificate this daemon serves, lowercase hex.
    /// Empty when TLS is off. The control plane pins it at registration (M31).
    #[serde(default)]
    pub tls_fingerprint: String,
    /// v2. Tiers this host can serve, e.g. `["native","vm"]`.
    #[serde(default)]
    pub tiers: Vec<String>,
    #[serde(default)]
    pub version: String,
}

// ---------------------------------------------------------------- control plane

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRegister {
    pub host_id: String,
    pub url: String,
    pub backend: String,
    pub capacity: u32,
    /// v2. Tiers this host can serve.
    #[serde(default)]
    pub tiers: Vec<String>,
    /// v2. SHA-256 of the DER of this host's TLS certificate, lowercase hex; empty
    /// when the host serves plain HTTP. Trust on first use, bounded by SBX_HOST_TOKEN.
    #[serde(default)]
    pub tls_fingerprint: String,
    /// v4c. Capabilities behind `tiers`.
    #[serde(default)]
    pub caps: HostCaps,
    /// v2. What this host enforces and watches, for operators: `{ egress, rules, watch }`
    /// (see `agent_core::rules::policy_summary`). Opaque to the control plane.
    #[serde(default)]
    pub policy: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub pool: PoolStats,
    pub sandboxes: Vec<SandboxInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub url: String,
    pub backend: String,
    pub capacity: u32,
    pub pool: PoolStats,
    pub last_seen: String,
    #[serde(default)]
    pub tiers: Vec<String>,
    #[serde(default)]
    pub tls_fingerprint: String,
    /// v5. Σ `limits` of this host's live sandboxes, computed by the control plane.
    #[serde(default)]
    pub committed: HostCommitted,
}

// ---------------------------------------------------------------- v2 alerts

/// `security.alert` severities; the `data` payload is `{severity, rule, msg, pid?, path?, evidence}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Detection rule names (the `rule` field of `security.alert`). Kept as constants so the
/// three implementations and the dashboard agree on spelling.
pub mod rules {
    pub const SECCOMP_VIOLATION: &str = "seccomp.violation";
    pub const SENSITIVE_PATH_WRITE: &str = "sensitive_path.write";
    pub const SENSITIVE_PATH_READ: &str = "sensitive_path.read";
    pub const CANARY_READ: &str = "canary.read";
    pub const EGRESS_DENY_BURST: &str = "egress.deny_burst";
    pub const METADATA_PROBE: &str = "metadata.probe";
    pub const ESCAPE_PROBE: &str = "escape.probe";
    pub const PTRACE_ATTEMPT: &str = "ptrace.attempt";
    pub const MOUNT_ATTEMPT: &str = "mount.attempt";
    pub const SETUID_EXEC: &str = "setuid.exec";
    pub const WORKSPACE_ESCAPE: &str = "workspace.escape";
    pub const RESOURCE_LIMIT: &str = "resource.limit";
    pub const SANDBOX_DENIED: &str = "sandbox.denied";
    /// Host reconnaissance from inside a sandbox: interface/route enumeration,
    /// hardware/OS inventory tools. Medium: information, not escape.
    pub const HOST_RECON: &str = "host.recon";
    /// v4, operational: running longer than `SBX_LONG_RUNNING_SECS`.
    pub const SANDBOX_LONG_RUNNING: &str = "sandbox.long_running";
    /// v5.2: a template's security scan failed a boundary check (grade `F`).
    pub const TEMPLATE_INSECURE: &str = "template.insecure";

    /// (rule, default severity, what it means) — shipped to the control plane in
    /// `HostRegister.policy` so the dashboard can show operators what is watched.
    pub const CATALOGUE: &[(&str, &str, &str)] = &[
        (SECCOMP_VIOLATION, "critical", "Process killed by seccomp: ptrace, mount, namespaces, bpf, keyctl or another blocked syscall"),
        (CANARY_READ, "critical", "A planted decoy credential (~/.ssh/id_rsa, ~/.aws/credentials, ~/.netrc) was read"),
        (ESCAPE_PROBE, "critical", "Touching container/VM escape surfaces: docker.sock, /proc/sysrq-trigger, cgroup release_agent, nsenter, unshare, runc"),
        (PTRACE_ATTEMPT, "critical", "ptrace/debug attach attempt on another process"),
        (MOUNT_ATTEMPT, "critical", "mount/pivot_root/setns attempt"),
        (SANDBOX_DENIED, "high", "The boundary refused an action: Seatbelt/nftables/bwrap denial, direct network bypassing the proxy"),
        (METADATA_PROBE, "high", "Cloud metadata endpoint referenced (169.254.169.254, metadata.google.internal, ...)"),
        (EGRESS_DENY_BURST, "high", "Many egress denials in a short window: scanning or exfiltration attempts"),
        (WORKSPACE_ESCAPE, "high", "Write outside the workspace and scratch directories"),
        (SENSITIVE_PATH_WRITE, "high", "Write to shell rc files, /etc, cron, systemd, launchd or SSH configuration"),
        (SENSITIVE_PATH_READ, "medium", "Read of credential or secret material: ~/.ssh, ~/.aws, ~/.netrc, gh/gcloud/kube configs, /etc/shadow"),
        (SETUID_EXEC, "medium", "setuid binary executed: sudo, su, doas, passwd, mount, pkexec"),
        (HOST_RECON, "medium", "Host reconnaissance: interface/route enumeration, hardware and OS inventory, net.* sysctls, port scanners"),
        (RESOURCE_LIMIT, "low", "CPU, memory, pids or disk limit hit"),
        (SANDBOX_LONG_RUNNING, "medium", "Operational: a sandbox has been running longer than SBX_LONG_RUNNING_SECS (fires again at every further multiple)"),
        (TEMPLATE_INSECURE, "high", "A template failed a boundary check of its security scan (grade F): untrusted work cannot use it"),
    ];
}

// ---------------------------------------------------------------- egress

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EgressPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny_cidrs_extra: Vec<String>,
    /// v5.3: private ranges (RFC1918, IPv6 unique-local) an allowed name may
    /// resolve into — internal mirrors on an air-gapped network. Host file only;
    /// loopback, link-local and CGNAT stay denied whatever it lists.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_private_cidrs: Vec<String>,
}

// ---------------------------------------------------------------- tokens

/// Scoped sandbox token: `base64url(sandbox_id:exp) ":" base64url(hmac_sha256(secret, payload))`.
pub mod hmac_token {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use subtle::ConstantTimeEq;

    pub const DEFAULT_TTL_SECS: u64 = 12 * 3600;

    fn mac(secret: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut m = Hmac::<Sha256>::new_from_slice(secret).expect("hmac accepts any key length");
        m.update(payload);
        m.finalize().into_bytes().to_vec()
    }

    pub fn mint(secret: &str, sandbox_id: &str, exp_unix: u64) -> String {
        let payload = format!("{sandbox_id}:{exp_unix}");
        format!("{}:{}", B64.encode(payload.as_bytes()), B64.encode(mac(secret.as_bytes(), payload.as_bytes())))
    }

    /// Returns `Some(sandbox_id)` when the signature is valid and not expired.
    pub fn verify(secret: &str, token: &str, now_unix: u64) -> Option<String> {
        let (p64, s64) = token.rsplit_once(':')?;
        let payload = B64.decode(p64).ok()?;
        let sig = B64.decode(s64).ok()?;
        let expect = mac(secret.as_bytes(), &payload);
        if sig.len() != expect.len() || sig.ct_eq(&expect).unwrap_u8() != 1 {
            return None;
        }
        let payload = String::from_utf8(payload).ok()?;
        let (id, exp) = payload.rsplit_once(':')?;
        let exp: u64 = exp.parse().ok()?;
        if now_unix >= exp || id.is_empty() {
            return None;
        }
        Some(id.to_string())
    }

    /// Constant-time equality for the static admin tokens.
    pub fn eq_ct(a: &str, b: &str) -> bool {
        a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).unwrap_u8() == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_grade_is_f_on_any_boundary_failure_else_counts_hygiene() {
        let c =
            |class: &str, ok: bool| SecurityCheck { id: "x".into(), class: class.into(), ok, detail: String::new() };
        let clean = vec![c("boundary", true), c("hygiene", true)];
        assert_eq!(security_grade(&clean), "A");
        assert_eq!(security_grade(&[c("boundary", true), c("hygiene", false), c("hygiene", false)]), "B");
        assert_eq!(security_grade(&vec![c("hygiene", false); 5]), "C");
        // One failed boundary check outranks everything else, however clean.
        assert_eq!(security_grade(&[c("boundary", false), c("hygiene", true)]), "F");
        assert_eq!(security_grade(&[]), "A");
    }

    #[test]
    fn token_roundtrip() {
        let t = hmac_token::mint("secret", "sbx_1", 1_000);
        // Must equal Go events.MintToken("secret","sbx_1",time.Unix(1000,0)).
        assert_eq!(t, "c2J4XzE6MTAwMA:tm-NRb6ITQ3aqXmoYk1NGnx6IpoOs3K5NDLGYyXa398");
        assert_eq!(hmac_token::verify("secret", &t, 999).as_deref(), Some("sbx_1"));
        assert_eq!(hmac_token::verify("secret", &t, 1_000), None, "expired");
        assert_eq!(hmac_token::verify("other", &t, 999), None, "wrong secret");
        assert_eq!(hmac_token::verify("secret", "garbage", 1), None);
        let mut tampered = t.clone();
        tampered.replace_range(0..1, "Z");
        assert_eq!(hmac_token::verify("secret", &tampered, 999), None);
        assert!(hmac_token::eq_ct("dev", "dev") && !hmac_token::eq_ct("dev", "dev2"));
    }

    #[test]
    fn event_wire_format() {
        let e = Event {
            id: "01J".into(),
            ts: "2026-09-08T10:00:00.123Z".into(),
            host_id: "mac-local".into(),
            sandbox_id: "sbx_7f3a".into(),
            pi_session: "s".into(),
            tool_call_id: "t".into(),
            r#type: EventType::ExecEnd,
            data: serde_json::json!({"exit":0}),
        };
        let j = serde_json::to_value(&e).unwrap();
        assert_eq!(j["type"], "exec.end");
        assert_eq!(j["data"]["exit"], 0);
        let back: Event = serde_json::from_value(j).unwrap();
        assert_eq!(back.r#type, EventType::ExecEnd);
    }

    #[test]
    fn exec_frames() {
        let f: ExecFrame =
            serde_json::from_str(r#"{"type":"start","cmd":"ls","cwd":"/","pty":{"cols":80,"rows":24}}"#).unwrap();
        assert!(matches!(f, ExecFrame::Start { pty: Some(PtySize { cols: 80, rows: 24 }), .. }));
        let s = serde_json::to_string(&ExecFrame::Exit { code: 0, signal: None, duration_ms: 5, timed_out: false })
            .unwrap();
        assert_eq!(s, r#"{"type":"exit","code":0,"signal":null,"duration_ms":5,"timed_out":false}"#);
        let s: SandboxState = serde_json::from_str(r#""ready""#).unwrap();
        assert_eq!(s, SandboxState::Ready);
    }

    #[test]
    fn v2_defaults_keep_v1_bodies_valid() {
        let r: CreateSandboxReq = serde_json::from_str(r#"{"template":"base","pi_session":"s"}"#).unwrap();
        assert_eq!(r.isolation, Isolation::Auto);
        assert_eq!(r.trust, Trust::Trusted);
        assert!(r.tools.is_empty() && r.ttl_secs.is_none());
        let r: CreateSandboxReq = serde_json::from_str(
            r#"{"template":"base","tools":null,"egress_allow":null,"workspace":null,"ttl_secs":null}"#,
        )
        .unwrap();
        assert!(r.tools.is_empty() && r.egress_allow.is_empty(), "null means default");
        let e: ExecReq = serde_json::from_str(r#"{"cmd":"true","cwd":"/","env":null,"timeout_ms":null}"#).unwrap();
        assert!(e.env.is_empty());
        let r: CreateSandboxReq =
            serde_json::from_str(r#"{"template":"base","isolation":"native","trust":"untrusted","tools":["node@22"]}"#)
                .unwrap();
        assert_eq!(r.isolation, Isolation::Native);
        assert_eq!(serde_json::to_value(EventType::SecurityAlert).unwrap(), "security.alert");
        assert!(Severity::Critical > Severity::Low);
    }

    #[test]
    fn v5_sizes() {
        let t = sizes::default_table();
        let (n, l) = sizes::resolve(None, None, &t).unwrap();
        assert_eq!((n.as_str(), l.cpus, l.mem_mib, l.pids), ("medium", 2.0, 2048, 512), "medium is the pre-v5 unit");
        let (n, both) = sizes::resolve(Some("mini"), Some(t["mini"]), &t).unwrap();
        assert_eq!((n.as_str(), both), ("mini", t["mini"]), "control plane forwards size + resolved limits");
        assert!(
            sizes::resolve(Some("mini"), Some(SandboxLimits { cpus: 0.3, mem_mib: 1, disk_mib: 0, pids: 0 }), &t)
                .is_err(),
            "forwarded limits are still validated"
        );
        assert!(sizes::resolve(Some("huge"), None, &t).unwrap_err().contains("micro"));
        let (n, c) =
            sizes::resolve(None, Some(SandboxLimits { cpus: 0.75, mem_mib: 900, disk_mib: 100, pids: 0 }), &t).unwrap();
        assert_eq!((n.as_str(), c.pids), ("custom", 256), "pids default to the nearest size by memory");
        assert!(
            sizes::resolve(None, Some(SandboxLimits { cpus: 0.3, mem_mib: 900, disk_mib: 100, pids: 0 }), &t).is_err()
        );
        assert!(sizes::fits(&c, &t["mini"]) && !sizes::fits(&t["high"], &t["mini"]));
        let r: CreateSandboxReq = serde_json::from_str(r#"{"template":"base","size":"high"}"#).unwrap();
        assert_eq!(r.size.as_deref(), Some("high"));
        let r: CreateSandboxReq =
            serde_json::from_str(r#"{"template":"base","limits":{"cpus":1,"mem_mib":1024,"disk_mib":512}}"#).unwrap();
        assert_eq!(r.limits.unwrap().pids, 0);
        let i: SandboxInfo = serde_json::from_str(
            r#"{"id":"s","backend":"podman","template":"base","state":"ready","workspace_path":"/w","pi_session":"","created_at":"t","endpoint":"e"}"#,
        )
        .unwrap();
        assert!(i.size.is_empty() && i.usage.is_none() && i.limits.is_none(), "pre-v5 heartbeats stay valid");
        assert!(!serde_json::to_string(&i).unwrap().contains("\"usage\""), "absent usage is not serialised as null");
    }
}
