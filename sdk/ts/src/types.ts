// THE TypeScript mirror of crates/proto/src/lib.rs — field-for-field, so qafas-sandbox
// and the pi extension (which imports this file) never drift on the wire format.
// Frozen at Gate A; v3 additive.
// Change proto first, then this file and controlplane/internal/events/types.go in one commit.

export const VERSION = "0.1.0"; // x-release-please-version
export const GUEST_AGENT_PORT = 7777;
export const QAFAS_PORT = 7700;
export const CONTROLPLANE_PORT = 7800;
export const EGRESS_PROXY_PORT = 3128;
export const HDR_PI_SESSION = "x-pi-session";
export const HDR_TOOL_CALL_ID = "x-tool-call-id";
export const HDR_CLIENT = "x-sbx-client";

// ---------------------------------------------------------------- events

export type EventType =
  | "sandbox.created"
  | "sandbox.ready"
  | "sandbox.destroyed"
  | "exec.start"
  | "exec.end"
  | "file.read"
  | "file.write"
  | "file.edit"
  | "browser.navigate"
  | "egress.allow"
  | "egress.deny"
  | "pool.refill"
  | "error"
  // v2
  | "sandbox.tier_selected"
  | "process.start"
  | "process.exit"
  | "file.access"
  | "net.connect"
  | "security.alert"
  // v3
  | "sandbox.stopped"
  | "sandbox.started"
  | "sandbox.paused"
  | "sandbox.resumed"
  | "sandbox.archived"
  | "snapshot.building"
  | "snapshot.ready"
  | "snapshot.error"
  | "preview.created"
  // v5.1: pushed by the guest agent while an exec is live; data is a SandboxUsage
  | "sandbox.usage";

export interface Event {
  id: string; // ULID
  ts: string; // RFC 3339 UTC, ms
  host_id: string;
  sandbox_id: string;
  pi_session: string;
  tool_call_id: string;
  type: EventType;
  data: unknown;
}

/** Body of `POST /sandboxes/{id}/events` (pi extension → qafas). */
export interface ClientEvent {
  type: EventType;
  data: unknown;
}

// ---------------------------------------------------------------- exec

export interface ExecReq {
  cmd: string;
  cwd: string;
  env?: Record<string, string>;
  timeout_ms?: number | null;
}

export interface ExecResp {
  exit: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
  truncated?: boolean;
}

export interface PtySize {
  cols: number;
  rows: number;
}

/** `/exec/ws` frames. `data` is base64. */
export type ExecFrame =
  | { type: "start"; cmd: string; cwd: string; env?: Record<string, string>; pty?: PtySize | null; timeout_ms?: number | null }
  | { type: "stdin"; data: string }
  | { type: "resize"; cols: number; rows: number }
  | { type: "signal"; sig: string }
  | { type: "stdout"; data: string }
  | { type: "stderr"; data: string }
  | { type: "exit"; code: number; signal?: string | null; duration_ms: number; timed_out?: boolean };

// ---------------------------------------------------------------- fs

export interface FsStat {
  is_dir: boolean;
  size: number;
  mode: number;
  mtime: string;
}

export interface MkdirReq {
  path: string;
}

export interface Healthz {
  ok: boolean;
  uid: number;
  version: string;
}

// ---------------------------------------------------------------- qafas

export interface WorkspaceSpec {
  host_path: string;
}

/** `auto` lets qafas pick by policy (`crates/qafas/src/policy.rs`). */
export type Isolation = "auto" | "native" | "vm" | "remote";
/** Untrusted workspaces never get `native`. */
export type Trust = "trusted" | "untrusted";

export interface CreateSandboxReq {
  template: string;
  workspace?: WorkspaceSpec | null;
  pi_session?: string;
  isolation?: Isolation; // v2, default auto
  trust?: Trust; // v2, default trusted
  tools?: string[]; // v2, e.g. ["node@22","python@3.12","rg","git","chromium"]
  egress_allow?: string[]; // v2, harness-supplied extra allow globs
  ttl_secs?: number | null; // v2, idle TTL
  // v3
  name?: string | null;
  labels?: Record<string, string>;
  env?: Record<string, string>; // env for every exec; protected names dropped
  auto_stop_secs?: number | null; // idle → stop (remote)
  auto_archive_secs?: number | null; // stopped → archive
  auto_delete_secs?: number | null; // 0 = ephemeral (destroy on stop); n = stopped/archived n s → destroy
  max_age_secs?: number | null; // wall clock from creation
  // v5 (§3a "v5 sizes and limits"): one of the two, from the harness/API, never the model
  size?: SizeName | string | null; // named size; default "medium"
  limits?: SandboxLimits | null; // custom ceilings; with `size` → 400
}

export interface CreateSandboxResp {
  id: string;
  endpoint: string;
  token: string;
  backend: string;
  workspace_path: string;
  expires_at: string;
  host_id?: string;
  isolation?: string; // v2: native|vm|remote
  tools?: Record<string, string>; // v2: name → version
  missing_tools?: string[]; // v2
  tls_fingerprint?: string; // v2: SHA-256 of the host certificate's DER, lowercase hex
  size?: string; // v5: name or "custom"
  limits?: SandboxLimits; // v5: ceilings actually applied
  info?: SandboxInfo; // v5.1: the daemon's record right after create (name, labels, resolved timers)
}

export type SandboxState = "creating" | "ready" | "busy" | "paused" | "stopped" | "archived" | "destroyed"; // v3 adds paused|stopped|archived

export interface SandboxInfo {
  id: string;
  backend: string;
  template: string;
  state: SandboxState;
  workspace_path: string;
  pi_session: string;
  created_at: string;
  ready_at?: string | null;
  endpoint: string;
  host_id?: string;
  isolation?: string; // v2
  last_activity?: string | null; // v2
  // v3
  name?: string;
  labels?: Record<string, string>;
  state_changed_at?: string | null;
  auto_stop_secs?: number | null;
  auto_archive_secs?: number | null;
  auto_delete_secs?: number | null;
  max_age_secs?: number | null;
  // v4
  idle_secs?: number | null; // ready|stopped: seconds since last activity
  running_secs?: number | null; // seconds since created_at
  size?: string; // v5: micro|mini|medium|high|custom ("" from a pre-v5 daemon)
  limits?: SandboxLimits; // v5
  enforcement?: "kernel" | "daemon" | string; // v5: daemon = macOS native watchdog, CPU not capped
  usage?: SandboxUsage; // v5: latest boundary sample
}

// ---- v5 sizes and limits (§3a)
export type SizeName = "micro" | "mini" | "medium" | "high";
export const SIZE_NAMES: SizeName[] = ["micro", "mini", "medium", "high"];
export const DEFAULT_SIZE: SizeName = "medium";
export interface SandboxLimits {
  cpus: number; // 0.25 steps; cgroup cpu.max = cpus × 100000 per 100000
  mem_mib: number;
  disk_mib: number; // writable scratch; RAM-backed on vm/remote, so never effectively above mem_mib
  pids?: number; // 0/absent on input = the nearest named size's
}
/** Compiled defaults; `SBX_SIZES` on the binaries replaces the table wholesale. `medium` = the pre-v5 unit. */
export const DEFAULT_SIZES: Record<SizeName, Required<SandboxLimits>> = {
  micro: { cpus: 0.5, mem_mib: 512, disk_mib: 512, pids: 128 },
  mini: { cpus: 1, mem_mib: 1024, disk_mib: 1024, pids: 256 },
  medium: { cpus: 2, mem_mib: 2048, disk_mib: 2048, pids: 512 },
  high: { cpus: 4, mem_mib: 4096, disk_mib: 4096, pids: 1024 },
};
export interface SandboxUsage {
  cpu_millis: number; // cumulative CPU time
  mem_bytes: number;
  mem_peak_bytes: number;
  disk_bytes: number;
  pids: number;
  ts?: string; // RFC 3339 sample time
}
export interface HostCommitted { cpus: number; mem_mib: number } // Σ limits of live sandboxes (control plane)

// ---- v3 api keys (control plane only; §4b)
export interface ApiKeyLimits {
  max_concurrent?: number | null;
  max_per_hour?: number | null;
  allowed_tiers?: string[];
  max_ttl_secs?: number | null;
  allowed_egress?: string[];
  // v5: violations are 403, never clamped
  max_cpus?: number | null;
  max_mem_mib?: number | null;
  max_disk_mib?: number | null;
  allowed_sizes?: string[]; // named sizes this key may request; custom limits still bounded by max_*
}
export interface CreateApiKeyReq {
  name: string;
  scopes: ("sandboxes" | "admin")[];
  limits?: ApiKeyLimits;
  labels?: Record<string, string>;
}
export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  limits: ApiKeyLimits;
  labels: Record<string, string>;
  created_at: string;
  last_used_at?: string | null;
  revoked_at?: string | null;
  live_sandboxes: number;
  created_24h: number;
}
export interface ApiKeyCreated extends ApiKey {
  key: string; // shown once
}
export interface ApiKeyUsage {
  since: string;
  sandboxes_created: number;
  live_sandboxes: number;
  execs: number;
  alerts: Record<string, number>;
  egress: Record<string, number>;
  sandbox_seconds: number;
  by_tier: Record<string, number>;
  last_used_at?: string | null;
}

// ---- v3 snapshots (images)
export interface SnapshotSource {
  image?: string; // OCI ref with tag or digest; "latest" refused
  dockerfile?: string; // Dockerfile text
  sandbox_id?: string; // capture a live sandbox (vm: filesystem; remote: memory+filesystem)
}
export interface CreateSnapshotReq {
  name: string; // [a-z0-9][a-z0-9._-]{0,63}; also the create request's `template`
  source: SnapshotSource;
  warm?: number; // v4: restored sandboxes kept ready for this template (default 0)
  memory_snapshot?: boolean; // v4: capture memory so every create is a restore (default true)
  runtime?: string; // v4c: remote|vm, where to build
}

/** v4 `PUT /snapshots/{name}`: the mutable part of a snapshot. */
export interface HostCaps { // v4c
  os: string; arch: string; cpus: number; mem_mib: number;
  kvm: boolean; firecracker: boolean; podman: boolean; process_sandbox: boolean; bpftrace: boolean;
  hugepages_mib: number; supported: string[];
}
export interface UpdateSnapshotReq {
  warm: number;
}
export type SnapshotState = "building" | "active" | "error";
export interface SnapshotInfo {
  name: string;
  state: SnapshotState;
  kind: "image" | "vm";
  source: SnapshotSource;
  created_at: string;
  bytes?: number;
  error?: string;
  host_id?: string; // control plane
  warm?: number; // v4: restored sandboxes kept ready on this host
  memory_snapshot?: boolean; // v4: an image snapshot that also holds a memory capture
  warm_ready?: number; // v4: warm sandboxes waiting right now
  runtime?: string; // v4c: the runtime this copy serves
  security?: TemplateSecurity; // v5.2: the last security scan on this host
}

/** v5.2. One line of `images/probe/scan.sh`: `boundary` failures grade F. */
export interface SecurityCheck {
  id: string;
  class: "boundary" | "hygiene";
  ok: boolean;
  detail: string;
}

/** v5.2. A template's security scan (docs/security.md M43). */
export interface TemplateSecurity {
  grade: "A" | "B" | "C" | "F";
  scanned_at: string;
  image_digest: string;
  findings: SecurityCheck[];
}

// ---- v3 sessions (persistent shells inside a sandbox)
export interface CreateSessionReq {
  id?: string; // [A-Za-z0-9_-]{1,64}; generated when absent
  cwd?: string;
  env?: Record<string, string>;
}
export interface SessionExecReq {
  cmd: string;
  async?: boolean; // true: 202 {command_id}; poll or stream logs
  timeout_ms?: number | null;
}
export type CommandState = "running" | "done";
export interface SessionCommand {
  command_id: string;
  cmd: string;
  state: CommandState;
  exit?: number | null;
  started_at: string;
  ended_at?: string | null;
  stdout?: string; // GET .../commands/{cid} only
  stderr?: string;
}
export interface SessionInfo {
  id: string;
  cwd: string;
  created_at: string;
  commands: SessionCommand[];
}
export interface SessionInputReq {
  data: string;
}

// ---- v3 preview (signed access to a port inside the sandbox)
export interface CreatePreviewReq {
  port: number;
  ttl_secs?: number | null; // default 12 h
}
export interface PreviewInfo {
  url: string; // <base>/preview/{id}/{port}/ — first request may add ?sbx_preview=<token>; a cookie keeps the rest
  token: string;
  port: number;
  expires_at: string;
}

export interface PoolStat {
  warm: number;
  target: number;
  restore?: boolean; // v4: warm entries are restored, not booted
}

/** v4 `GET /pool` → `{"<template>": PoolStat}` (keyed by template name) */
export type PoolStats = Record<string, PoolStat>;

export interface QafasHealthz {
  ok: boolean;
  backend: string;
  host_id: string;
  tls_fingerprint?: string; // v2
  tiers?: string[]; // v2
  version?: string; // v2
}

// ---------------------------------------------------------------- control plane

export interface HostRegister {
  host_id: string;
  url: string;
  backend: string;
  capacity: number;
  tiers?: string[]; // v2
  tls_fingerprint?: string; // v2
}

export interface Heartbeat {
  pool: PoolStats;
  sandboxes: SandboxInfo[];
}

export interface Host {
  id: string;
  url: string;
  backend: string;
  capacity: number;
  pool: PoolStats;
  last_seen: string;
  tiers?: string[]; // v2
  tls_fingerprint?: string; // v2
}

// ---------------------------------------------------------------- v2 alerts

export type Severity = "low" | "medium" | "high" | "critical";

/** `security.alert` data payload. */
export interface AlertData {
  severity: Severity;
  rule: string; // one of Rules
  msg: string;
  pid?: number;
  path?: string;
  evidence?: unknown;
}

export const Rules = {
  SECCOMP_VIOLATION: "seccomp.violation",
  SENSITIVE_PATH_WRITE: "sensitive_path.write",
  SENSITIVE_PATH_READ: "sensitive_path.read",
  CANARY_READ: "canary.read",
  EGRESS_DENY_BURST: "egress.deny_burst",
  METADATA_PROBE: "metadata.probe",
  ESCAPE_PROBE: "escape.probe",
  PTRACE_ATTEMPT: "ptrace.attempt",
  MOUNT_ATTEMPT: "mount.attempt",
  SETUID_EXEC: "setuid.exec",
  WORKSPACE_ESCAPE: "workspace.escape",
  RESOURCE_LIMIT: "resource.limit",
  SANDBOX_DENIED: "sandbox.denied",
  HOST_RECON: "host.recon",
  SANDBOX_LONG_RUNNING: "sandbox.long_running", // v4
  TEMPLATE_INSECURE: "template.insecure", // v5.2
} as const;

// ---------------------------------------------------------------- egress

export interface EgressPolicy {
  allow: string[];
  deny_cidrs_extra?: string[];
  /** v5.3: private ranges an allowed name may resolve into (internal mirrors). Host file only. */
  allow_private_cidrs?: string[];
}

// ---------------------------------------------------------------- tokens
// Scoped token: base64url("<sandbox_id>:<unix_exp>") + ":" + base64url(hmac_sha256(secret, payload)).
// pi never mints; it only carries the token it was given. Implementations: proto::hmac_token (Rust), events.MintToken (Go).
