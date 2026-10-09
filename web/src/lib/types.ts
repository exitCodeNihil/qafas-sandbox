/**
 * Type definitions matching the protocol.
 * Copied from sdk/ts/src/types.ts for the UI layer.
 */

export type Event = {
  id: string;
  ts: string;
  host_id: string;
  sandbox_id: string;
  pi_session: string;
  tool_call_id: string;
  type: EventType;
  data: Record<string, unknown>;
};

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
  | "security.alert";

/**
 * Sandbox/template name rule, shared by CreateSandboxDrawer and
 * CreateSnapshotDrawer (both validate against the same server-side pattern).
 */
export const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
export const NAME_RE_HELP = "Lowercase letters, digits, . _ - only, starting with a letter or digit (max 64 chars).";

/**
 * The one user-facing vocabulary for a tier (docs/decisions.md D25,
 * crates/qafas/src/policy.rs): the wire value
 * (`isolation`, frozen: native|vm|remote) versus the label a person sees.
 * Firecracker first — it is the product default and the dashboard's
 * preselection order.
 */
export const RUNTIMES: { value: "remote" | "vm" | "native"; label: string; description: string }[] = [
  {
    value: "remote",
    label: "Firecracker microVM",
    description: "Strongest isolation: a separate host, a microVM and the jailer. Templates with memory capture, starts by restore; stop, pause, archive.",
  },
  {
    value: "vm",
    label: "Docker container",
    description: "A podman container on a Docker host or the dev machine. Image and Dockerfile templates.",
  },
  {
    value: "native",
    label: "Process",
    description: "OS process sandbox on the host (Seatbelt / Landlock + seccomp), shared kernel. Fastest; no templates. Never used for untrusted input.",
  },
];

/** The label a person sees for a wire-value tier; falls back to the raw value for anything unrecognized. */
export function runtimeLabel(isolation?: string | null): string {
  return RUNTIMES.find((r) => r.value === isolation)?.label ?? isolation ?? "—";
}

export type SandboxInfo = {
  id: string;
  host_id: string;
  backend: "podman" | "firecracker";
  template: string;
  state: SandboxState;
  workspace_path: string;
  pi_session: string;
  created_at: string;
  ready_at?: string;
  destroyed_at?: string;
  endpoint: string;
  isolation?: "native" | "vm" | "remote"; // v2
  last_activity?: string | null; // v2
  // v3
  name?: string;
  labels?: Record<string, string>;
  state_changed_at?: string;
  auto_stop_secs?: number;
  auto_archive_secs?: number;
  auto_delete_secs?: number;
  max_age_secs?: number;
  ttl_secs?: number;
  trust?: "trusted" | "untrusted";
  env?: Record<string, string>;
  // v3 (§4b) — set when created by a scoped API key; absent means the admin token.
  api_key_id?: string;
  api_key_name?: string;
  // v4 — seconds since last activity / since created, resolved by qafas. Absent on older daemons.
  idle_secs?: number;
  running_secs?: number;
  // v5 (§3a "v5 sizes and limits")
  size?: string; // micro|mini|medium|high|custom ("" from a pre-v5 daemon)
  limits?: SandboxLimits;
  enforcement?: "kernel" | "daemon" | string; // daemon = macOS native watchdog, CPU not capped
  usage?: SandboxUsage; // latest boundary sample
};

// ---------------------------------------------------------------- v5 sizes and limits (§3a)

export type SizeName = "micro" | "mini" | "medium" | "high";
export const SIZE_NAMES: SizeName[] = ["micro", "mini", "medium", "high"];
export const DEFAULT_SIZE: SizeName = "medium";

export type SandboxLimits = {
  cpus: number; // 0.25 steps; cgroup cpu.max = cpus × 100000 per 100000
  mem_mib: number;
  disk_mib: number; // writable scratch; RAM-backed on vm/remote, so never effectively above mem_mib
  pids?: number; // 0/absent on input = the nearest named size's
};

/** Compiled defaults; `SBX_SIZES` on the binaries replaces the table wholesale. `medium` = the pre-v5 unit. */
export const DEFAULT_SIZES: Record<SizeName, Required<SandboxLimits>> = {
  micro: { cpus: 0.5, mem_mib: 512, disk_mib: 512, pids: 128 },
  mini: { cpus: 1, mem_mib: 1024, disk_mib: 1024, pids: 256 },
  medium: { cpus: 2, mem_mib: 2048, disk_mib: 2048, pids: 512 },
  high: { cpus: 4, mem_mib: 4096, disk_mib: 4096, pids: 1024 },
};

export type SandboxUsage = {
  cpu_millis: number; // cumulative CPU time
  mem_bytes: number;
  mem_peak_bytes: number;
  disk_bytes: number;
  pids: number;
  ts?: string; // RFC 3339 sample time
};

/** Σ limits of live sandboxes on a host (control plane). */
export type HostCommitted = { cpus: number; mem_mib: number };

/** v3 lifecycle states. A v2 host only ever reports the first four. */
export type SandboxState = "creating" | "ready" | "busy" | "paused" | "stopped" | "archived" | "destroyed";

/** v3 `SnapshotInfo`. */
export type HostCaps = { // v4c
  os: string; arch: string; cpus: number; mem_mib: number;
  kvm: boolean; firecracker: boolean; podman: boolean; process_sandbox: boolean; bpftrace: boolean;
  hugepages_mib: number; supported: string[];
};
export type SnapshotInfo = {
  name: string;
  state: "building" | "active" | "error";
  kind: "image" | "vm";
  source: { image?: string; dockerfile?: string; sandbox_id?: string } | Record<string, unknown>;
  created_at: string;
  bytes?: number;
  error?: string;
  host_id?: string;
  warm?: number; // v4
  memory_snapshot?: boolean; // v4
  warm_ready?: number; // v4
  runtime?: string; // v4c
  security?: TemplateSecurity; // v5.2
};

/** v5.2 template security scan (docs/security.md M43). `boundary` failures grade F. */
export type SecurityCheck = { id: string; class: "boundary" | "hygiene"; ok: boolean; detail: string };
export type TemplateSecurity = { grade: "A" | "B" | "C" | "F"; scanned_at: string; image_digest: string; findings: SecurityCheck[] };

/** v3 `PreviewInfo`. */
export type PreviewInfo = {
  url: string;
  token: string;
  port: number;
  expires_at: string;
};

export type Host = {
  id: string;
  url: string;
  backend: "podman" | "firecracker";
  capacity: number;
  pool: Record<string, { warm: number; target: number }>;
  last_seen: string;
  tiers?: string[]; // v2
  policy?: HostPolicy; // v2
  caps?: HostCaps; // v4c
  committed?: HostCommitted; // v5
};

export type PolicyRule = { rule: string; severity: Severity; description: string };
export type HostPolicy = {
  egress?: { allow?: string[]; deny_cidrs_extra?: string[]; allow_private_cidrs?: string[] };
  rules?: PolicyRule[];
  watch?: Record<string, string[]>;
};

// ---------------------------------------------------------------- v2 alerts

export type Severity = "low" | "medium" | "high" | "critical";

/** `security.alert` event data payload. */
export type AlertData = {
  severity: Severity;
  rule: string;
  msg: string;
  pid?: number;
  path?: string;
  evidence?: unknown;
};

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

// ---------------------------------------------------------------- v3 API keys (§4b)
// Mirrored from sdk/ts/src/types.ts; alerts/by_tier tightened to the
// concrete key sets the rest of this UI already uses (Severity, tiers).

export type ApiKeyScope = "sandboxes" | "admin";

export type ApiKeyLimits = {
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
};

/** `GET /api/keys`, `GET /api/keys/{id}` row. */
export type ApiKey = {
  id: string;
  name: string;
  prefix: string;
  scopes: ApiKeyScope[];
  limits: ApiKeyLimits;
  labels: Record<string, string>;
  created_at: string;
  last_used_at?: string | null;
  revoked_at?: string | null;
  live_sandboxes: number;
  created_24h: number;
};

/** `POST /api/keys` response — the only time `key` (the full secret) is returned. */
export type ApiKeyCreated = ApiKey & { key: string };

/** `GET /api/keys/{id}/usage?since=` */
export type ApiKeyUsage = {
  since: string;
  sandboxes_created: number;
  live_sandboxes: number;
  execs: number;
  alerts: Record<Severity, number>;
  egress: { allow: number; deny: number };
  sandbox_seconds: number;
  by_tier: Record<"native" | "vm" | "remote", number>;
  last_used_at?: string | null;
};

/** `GET /api/sessions` row. */
export type SessionRow = {
  pi_session: string;
  first_ts: string;
  last_ts: string;
  sandbox_ids: string[];
  hosts: string[];
  events: number;
  execs: number;
  alerts: Record<Severity, number>;
  top_alert: string | null;
  // v3 (§4b) — from the session's first sandbox; absent means the admin token.
  api_key_id?: string;
  api_key_name?: string;
};

/** `GET /api/sessions/{id}` */
export type SessionDetail = SessionRow & { sandboxes: SandboxInfo[] };

/** `GET /api/sessions/{id}/processes` node (recursive). */
export type ProcessNode = {
  pid: number;
  ppid: number;
  argv: string[];
  start_ts: string;
  end_ts: string | null;
  exit: number | null;
  signal?: string | null;
  tool_call_id: string;
  alert: AlertData | null;
  children: ProcessNode[];
};

/** `GET /sandboxes/{id}/processes` (qafas, live, flat). */
export type LiveProcess = {
  pid: number;
  ppid: number;
  uid: number;
  argv: string[];
  started_at: string;
  rss_kb?: number;
};

/** `GET /api/stats` */
export type Stats = {
  sandboxes: { ready: number; busy: number; total: number };
  hosts: number;
  events_1h: number;
  alerts_24h: Record<Severity, number>;
  exec_p50_ms: number;
  exec_p95_ms: number;
  egress: { allow_1h: number; deny_1h: number };
};

// ---------------------------------------------------------------- v2 OTLP trace
// Minimal shape of ExportTraceServiceRequest (protocol.md §1.2) — only the
// fields this UI reads.

export type OtlpAttribute = {
  key: string;
  value: { stringValue?: string; intValue?: string; boolValue?: boolean };
};

export type OtlpSpanEvent = {
  timeUnixNano: string;
  name: string;
  attributes: OtlpAttribute[];
};

export type OtlpSpan = {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  startTimeUnixNano: string;
  endTimeUnixNano?: string;
  attributes: OtlpAttribute[];
  events: OtlpSpanEvent[];
};

export type OtlpTrace = {
  resourceSpans: {
    resource?: { attributes: OtlpAttribute[] };
    scopeSpans: { scope?: { name: string }; spans: OtlpSpan[] }[];
  }[];
};

export function attrString(attrs: OtlpAttribute[], key: string): string | undefined {
  const a = attrs.find((x) => x.key === key)?.value;
  if (!a) return undefined;
  if (a.stringValue !== undefined) return a.stringValue;
  if (a.intValue !== undefined) return a.intValue;
  if (a.boolValue !== undefined) return String(a.boolValue);
  return undefined;
}

// ---------------------------------------------------------------- v4 observability + metrics (§4, D23/D24)

export type ObservabilityProvider = "langfuse" | "otlp";
export type ObservabilityCapture = "all" | "alerts_only";

export type ObservabilityHealth = {
  delivered: number;
  dropped: number;
  last_ok_ts: string | null;
  last_error: string | null;
};

/** `GET /api/settings/observability`. The secret is never returned, only whether one is stored. */
export type ObservabilitySettings = {
  enabled: boolean;
  provider: ObservabilityProvider;
  host?: string;
  public_key?: string;
  secret_key_set: boolean;
  otlp_url?: string;
  otlp_headers?: Record<string, string>;
  capture: ObservabilityCapture;
  health: ObservabilityHealth;
};

/** `PUT /api/settings/observability` body — same shape minus `health`; an absent/empty `secret_key` keeps the stored one. */
export type ObservabilitySettingsInput = Omit<ObservabilitySettings, "secret_key_set" | "health"> & {
  secret_key?: string;
};

/** `POST /api/settings/observability/test` response. */
export type ObservabilityTestResult = { ok: boolean; detail: string };
