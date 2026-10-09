# Protocol — the contract everything keys on

v1 frozen at Gate A (2026-09-08); **v2 additions** (marked v2) frozen 2026-09-08 for phase 2; **v5 additions** (sizes, limits, usage; marked v5, §3a "v5 sizes and limits") frozen 2026-09-15. v1 bodies stay valid: every v2–v5 field has a default. Source of truth is `crates/proto/src/lib.rs`; `sdk/ts/src/types.ts` and `controlplane/internal/events/types.go` mirror it field-for-field. Change here first, then in all three files, in the same commit — and in the Python, Go and Java SDKs where they read the changed fields (`sdk/rust` uses `crates/proto` directly).

Data path: `pi extension → qafas → guest-agent`. The Go control plane is never on the data path; it registers hosts, mints scoped tokens, ingests events, serves the UI.

## 1. Event

```json
{
  "id": "01J8Z3N4K6P7Q9R2S5T8V1W3X6",
  "ts": "2026-09-08T10:00:00.123Z",
  "host_id": "mac-local",
  "sandbox_id": "sbx_7f3a",
  "pi_session": "b1d2…",
  "tool_call_id": "toolu_…",
  "type": "exec.end",
  "data": { "exit": 0, "duration_ms": 41, "bytes_out": 512 }
}
```

| `type` | `data` |
|---|---|
| `sandbox.created` | `{template, backend, workspace}` |
| `sandbox.ready` | `{boot_ms}` |
| `sandbox.destroyed` | `{reason}` |
| `exec.start` | `{cmd, cwd, pty}` |
| `exec.end` | `{exit, duration_ms, bytes_out}` |
| `file.read` / `file.write` / `file.edit` | `{path, bytes}` |
| `browser.navigate` | `{url}` |
| `egress.allow` / `egress.deny` | `{host, port, bytes, reason?}` |
| `pool.refill` | `{template, size}` |
| `error` | `{msg}` |
| v2 `sandbox.tier_selected` | `{requested, selected, reason}` |
| v2 `process.start` | `{pid, ppid, uid, exe, argv:[...], cwd, root_pid}` — `root_pid` is the pid of the exec that owns the process group |
| v2 `process.exit` | `{pid, exit, signal?, duration_ms, rss_max_kb?}` |
| v2 `file.access` | `{pid, path, op: "read"\|"write"\|"unlink"\|"rename"\|"chmod"\|"exec", sensitive: bool}` — only sensitive paths and workspace-escape attempts are reported, never every open |
| v2 `net.connect` | `{pid, dst, port, proto, allowed}` |
| v2 `security.alert` | `{severity: "low"\|"medium"\|"high"\|"critical", rule, msg, pid?, path?, evidence?}` — `rule` is one of `proto::rules` (below) |

### 1.1 Detection rules (`security.alert.rule`)

| rule | severity | fires when |
|---|---|---|
| `seccomp.violation` | high | a process died with SIGSYS: it called a syscall the deny-list kills (ptrace, mount family, bpf, keyctl, userfaultfd, perf_event_open, module loading, process_vm_*). io_uring returns EPERM instead (benign probes by libuv) and fires `low` only if repeated. |
| `sensitive_path.write` | high | write under `.git/hooks`, `.git/config`, `.github/workflows`, `.vscode/tasks.json`, `~/.bashrc`/`~/.zshrc`/`~/.profile`, `~/.ssh`, `~/.aws`, `~/.config/gh`, `/etc` |
| `sensitive_path.read` | medium | read of `~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.netrc`, `/etc/shadow`, `/proc/1/environ` |
| `canary.read` | critical | a planted canary file was opened (`~/.aws/credentials`, `~/.ssh/id_rsa`, `<workspace>/.env.production`) |
| `egress.deny_burst` | medium | ≥ 5 `egress.deny` for one sandbox within 10 s |
| `metadata.probe` | high | any attempt to reach 169.254.169.254, `metadata.google.internal`, `100.100.100.200` |
| `escape.probe` | critical | open/exec of `/var/run/docker.sock`, `/run/podman/*.sock`, `/dev/kvm`, `/proc/1/root`, `/proc/sys/kernel/core_pattern`, `/sys/fs/cgroup/release_agent`, nsenter/unshare/setns binaries |
| `ptrace.attempt` / `mount.attempt` | high | eBPF or SIGSYS attribution of the specific syscall |
| `setuid.exec` | medium | exec of a setuid/setgid binary (sudo, su, passwd, ...) |
| `workspace.escape` | medium | native tier: sandbox denied a filesystem op outside the allowed paths |
| `resource.limit` | low | pids/memory/cpu limit hit |
| `sandbox.denied` | medium | any other sandbox-mechanism denial (Seatbelt violation report, Landlock EACCES on network) |
| `host.recon` | medium | host inventory from inside: interface/route enumeration (`ifconfig`, `netstat -r`, `getifaddrs` — denied on the native tier), `system_profiler`, `ioreg`, `scutil`, `dscl`, `arp`, `launchctl`, `nmap` |
| `sandbox.long_running` | medium | v4, operational: a sandbox has been running (`ready`/`busy`) for longer than `SBX_LONG_RUNNING_SECS` (default 14400). Fires again at every further multiple of the threshold. `age_secs`, `threshold_secs`, `name`, `tier` beside `rule`/`severity`/`msg` like every rule. Same envelope as every alert so it lands in the dashboard, `/api/alerts`, `sbx_alerts_total` and the Prometheus rules. |
| `template.insecure` | high | v5.2: a template security scan failed a `boundary` check (grade `F`). `template`, `failed` (check ids) beside `rule`/`severity`/`msg`; `sandbox_id` is empty. `trust: untrusted` creates on that template are refused (§3a). |

Alerts are events: same `id/ts/host_id/sandbox_id/pi_session/tool_call_id` envelope, so they filter by session and attach to the tool call that caused them.

### 1.2 OpenTelemetry mapping (v2)

v4: the same `ExportTraceServiceRequest` is what the control plane pushes to Langfuse (`<host>/api/public/otel/v1/traces`, basic auth `public_key:secret_key`); Langfuse's OTLP receiver turns one pi session into one trace and each tool call into an observation, security alerts arrive as span events. `capture:"alerts_only"` pushes only sessions that raised an alert. No Langfuse-specific payload exists (D24).

The control plane exposes every session as an OTLP trace (`GET /api/sessions/{id}/trace` and optional push to `SBX_OTLP_URL`): `trace_id = sha256(pi_session)[0..16]`, one span per tool call (`span_id = sha256(tool_call_id)[0..8]`, `exec.start`→`exec.end`, name = first word of `cmd`), child spans per `process.start`/`process.exit` (`span_id = sha256(sandbox_id:pid:start_ts)[0..8]`), span events for `file.access`, `net.connect`, `egress.*`, `security.alert` (attribute `sbx.alert.rule`, `sbx.alert.severity`). Attribute names use the `sbx.` prefix plus standard `process.pid`, `process.command_line`, `session.id`. A tool call that never produced `exec.start`/`exec.end` (a `file.read`/`file.write`/`file.edit` through `/fs/*`, or `browser.navigate`) still gets one span per `tool_call_id`: name = the event type (`fs.write`, `browser.navigate`), start = the first event's `ts`, end = the last event's `ts` with that `tool_call_id` (minimum 1 ms). Events with an empty `tool_call_id` attach to a synthetic `session` root span.

- `id` is a ULID (sortable). `ts` RFC 3339 UTC with milliseconds.
- `data` is free JSON per type in the POC (no per-type structs).
- `pi_session` and `tool_call_id` come from request headers `X-Pi-Session` and `X-Tool-Call-Id`; qafas copies them onto every event it emits for that request. Empty string when absent.

## 2. guest-agent HTTP API

Listens on vsock port `7777` when `/dev/vsock` exists (a Firecracker microVM; v4: the TCP listener is then never bound, so nothing inside the guest can reach the root-owned agent), otherwise on TCP `0.0.0.0:7777` (podman, where the agent already runs as uid 1000). Reachable only through qafas (podman: published loopback port; firecracker: vsock UDS inside the jailer chroot). v4: on podman the published loopback port additionally requires `X-Sbx-Agent-Token`, a per-sandbox secret only qafas knows — handed to the container as `SBX_AGENT_TOKEN`, demanded on every route but `/healthz`, and stripped again before a request is proxied into a dev server; where reachability is the boundary (vsock, the native tier's `0700` unix socket) there is no token and no header. `/fs/write` and `/fs/tar` bodies are capped at `SBX_MAX_UPLOAD_MB` (default 512), which qafas also enforces before forwarding (`413`). v4: both are streamed, the tar is extracted as it arrives and a file is written as it arrives, so guest memory use is constant whatever the size; a rejected tar member aborts the request with `400` and leaves the members already written (as before).

| Route | Request | Response |
|---|---|---|
| `GET /healthz` | — | `200 {"ok":true,"uid":1000,"version":"0.1.0"}` |
| `POST /exec` | `{"cmd":"rg -n foo .","cwd":"/abs" (optional since v4c; home/workspace when absent),"env":{},"timeout_ms":30000}` | `200 {"exit":0,"stdout":"…","stderr":"…","duration_ms":12}`; stdout/stderr each capped at 1 MiB, `truncated:true` when cut |
| `GET /exec/ws` | WebSocket upgrade; frames below | frames below |
| `GET /fs/read?path=` | — | `200 application/octet-stream` or `404` |
| `PUT /fs/write?path=` | raw body | `204`; creates parent dirs |
| `GET /fs/stat?path=` | — | `200 {"is_dir":false,"size":123,"mode":420,"mtime":"…"}` or `404` |
| `GET /fs/list?path=` | — | `200 ["a","b"]` (names only, sorted) |
| `POST /fs/mkdir` | `{"path":"/abs"}` | `204` (recursive) |
| `PUT /fs/tar?path=` | tar stream (uncompressed) | `204`; extracts under `path`, rejects `..` and absolute entries |
| `GET /fs/tar?path=` | — | tar stream of `path` |
| `PUT /workspace` | `{path}` | `204`; v2, qafas → pooled guest at acquire: the directory this sandbox serves (created, owned by the agent user; the rules' workspace boundary). A `PUT /fs/tar` into a guest that has none yet implies it. |
| `GET /browser/cdp` | WebSocket upgrade | relays to Chromium's browser-level DevTools socket; launches Chromium lazily on first connect |

### 2.1 `/exec/ws` frames (JSON text frames)

Client → agent:

```json
{"type":"start","cmd":"npm test","cwd":"/abs","env":{"CI":"1"},"pty":{"cols":120,"rows":40},"timeout_ms":600000}
{"type":"stdin","data":"<base64>"}
{"type":"resize","cols":100,"rows":30}
{"type":"signal","sig":"KILL"}
```

Agent → client:

```json
{"type":"stdout","data":"<base64>"}
{"type":"stderr","data":"<base64>"}
{"type":"exit","code":0,"signal":null,"duration_ms":1830}
```

Rules: exactly one `start` per connection, it must be the first frame. With `pty` set, output arrives only as `stdout`. On timeout the agent kills the process group and sends `exit` with `signal:"KILL"` and `timed_out:true`. Connection close after `exit`. `ponytail:` base64-in-JSON is deliberate; switch to binary frames only if bandwidth is measured to matter.

### 2.2 Error strings pi depends on

The pi extension must throw exactly `new Error("aborted")` when pi's abort signal fired and `new Error("timeout:<seconds>")` on timeout. pi string-matches these.

## 3. qafas HTTP API

Listens on `SBX_LISTEN` (default `127.0.0.1:7700`). Every request needs `Authorization: Bearer <token>` where token is either the static admin token `SBX_TOKEN` or a scoped token (§5). Scoped tokens are valid only for `/sandboxes/{id}/…` of their own sandbox.

| Route | Request | Response |
|---|---|---|
| `POST /sandboxes` | `{"template":"base","workspace":{"host_path":"/Users/me/repo"},"pi_session":"…"}` | `201 {"id":"sbx_7f3a","endpoint":"http://127.0.0.1:7700/sandboxes/sbx_7f3a/agent","token":"<scoped>","backend":"podman","workspace_path":"/Users/me/repo","expires_at":"…"}` |
| `GET /sandboxes` | — | `200 [SandboxInfo]` |
| `GET /sandboxes/{id}` | — | `200 SandboxInfo` |
| `DELETE /sandboxes/{id}` | — | `204` |
| `ANY /sandboxes/{id}/agent/{*rest}` | forwarded verbatim (HTTP and WebSocket upgrade) | guest-agent's response |
| `GET /events/ws` | WebSocket | one Event per text frame, live |
| `GET /pool` | — | `200 {"<template>|<host_path>": {"warm":2,"target":2}}` |
| `GET /healthz` | — | `200 {"ok":true,"backend":"podman","host_id":"mac-local","tls_fingerprint":"<hex>"}` (v2 `tls_fingerprint`: SHA-256 of the DER of the served certificate, lowercase hex, empty without TLS) |
| `POST /sandboxes/{id}/events` | `{"type":"browser.navigate","data":{"url":"…"}}` (`ClientEvent`, from the pi extension; scoped token ok) | `204` |
| `POST /internal/events` | `[Event]` from the egress proxy container (podman mode) | `204` |

`SandboxInfo`: `{id, backend, template, state: "creating"|"ready"|"busy"|"destroyed", workspace_path, pi_session, created_at, ready_at, endpoint, isolation (v2), last_activity (v2)}`.

**v2 TLS.** `SBX_TLS=1` serves the whole surface as HTTPS + WSS; `endpoint` becomes `https://…` (and `wss://` for the two WebSocket routes). The certificate is `SBX_TLS_CERT`/`SBX_TLS_KEY`, or one generated once into `$SBX_STATE_DIR/tls` and kept. `SBX_PUBLIC_URL` overrides the advertised base URL.

**v2 request fields on `POST /sandboxes`** (all optional): `isolation: "auto"|"native"|"vm"|"remote"` (default auto; v4 also accepts the product names `process`|`docker`|`firecracker` on input, replies always use the canonical value), `trust: "trusted"|"untrusted"` (default trusted; untrusted never resolves to `native`), `tools: ["node@22","python@3.12","rg","git","chromium"]`, `egress_allow: [globs]` (harness-supplied; private ranges stay denied), `ttl_secs` (idle TTL; default `SBX_TTL_SECS`, 3600). **v2 reply fields**: `isolation` (selected tier), `tools` (name → version), `missing_tools`. A `native` sandbox's `endpoint` is served in-process by qafas with the identical `/exec`, `/exec/ws`, `/fs/*`, `/browser/cdp` routes. The `201` reply gains the additive field `tls_fingerprint` (the same value `/healthz` reports), so a harness pins without a side channel. Every request may carry `X-Sbx-Client` (`pi/0.83`, `sdk-ts/0.1`); qafas logs it and never trusts it. v4: a scoped (per-sandbox) token sees only its own sandbox on `GET /sandboxes` and `/events/ws`; `/pool`, `/policy` and `/snapshots` need the admin token; `?token=` is honoured only on WebSocket upgrades. v2 qafas also serves `GET /metrics` (Prometheus text; v4: unauthenticated only when the daemon's listener is bound to loopback, otherwise bearer `SBX_TOKEN` is required whoever the peer is — a port forwarder in front of a worker rewrites the peer address) and `GET /sandboxes/{id}/processes` (live process tree `[{pid,ppid,uid,argv,started_at,rss_kb}]`).

**v5 request fields on `POST /sandboxes`**: `size: "micro"|"mini"|"medium"|"high"` or `limits: {cpus, mem_mib, disk_mib, pids?}` (custom; both → `400`, neither → `medium`); the daemon re-validates against its ceilings (`409`). **v5 reply fields**: `size` (name or `custom`), `limits` (as applied); **v5.1**: `info` — the daemon's `SandboxInfo` right after create (name, labels, resolved timers, enforcement), authoritative over the request; the control plane copies it into its row instead of re-deriving defaults. **v5.1 event** `sandbox.usage` (`data` = `SandboxUsage`): pushed by the guest agent on its event stream every 2 s while any exec is live and once at `exec.end`; the daemon updates `SandboxInfo.usage` from it (the 5 s poll remains for idle sandboxes), so `usage.ts` is at most 2 s old during a run. `SandboxInfo` gains `size`, `limits`, `enforcement`, `usage`. Rules in §3a "v5 sizes and limits".

Event emission is done by the proxy layer, keyed on the forwarded path: `/exec*` → `exec.start`/`exec.end` (the WS relay sniffs server frames for `"type":"exit"`), `/fs/read` → `file.read`, `/fs/write` and `/fs/tar` PUT → `file.write`, `/browser/cdp` → `browser.navigate` is emitted by the pi extension via `POST /sandboxes/{id}/events` (not listed above; add as `{type, data}` body, `204`).

## 4. Control plane HTTP API

Listens on `SBX_LISTEN` (default `:7800`). Two tokens: `SBX_HOST_TOKEN` for qafas hosts, `SBX_ADMIN_TOKEN` for the UI and pi.

| Route | Auth | Request → Response |
|---|---|---|
| `POST /api/hosts/register` | host | `{"host_id","url","backend","capacity","tiers"(v2),"tls_fingerprint"(v2)}` → `204` |
| `PUT /api/hosts/{id}/heartbeat` | host | `{"pool":{…},"sandboxes":[SandboxInfo]}` → `204` |
| `POST /api/events` | host | `[Event]` (≤1 s batches) → `204` |
| `POST /api/sandboxes` | admin | `{"template","workspace":{"host_path"},"pi_session"}` → `201 {"id","host_id","endpoint","token","tls_fingerprint"(v2)}`; v4 placement: validates `isolation`/`trust` (aliases accepted), `name` (`[a-z0-9][a-z0-9._-]{0,63}`) and timers (`400`); resolves `auto` once, Firecracker first (`remote` > `vm` > `native`; `untrusted` never `native`; no host advertising the tier → `409`); when `template` is not `base`, keeps only hosts where `GET /snapshots/{name}` is `active` (`409` naming the template and each host's state); then the most free pool. Forwards with the concrete tier and passes the daemon's status and body through unchanged (no more `502` wrapping). Stores the daemon's resolved timers. `tls_fingerprint` is the host's, taken from the host row, so pi pins what the control plane pinned. v5: resolves `size`/`limits` (`400` on the §3a rules), checks the key's `allowed_sizes`/`max_*` (`403`), forwards both `size` and `limits`, and keeps only hosts where `committed + limits ≤ caps × overcommit` (`SBX_OVERCOMMIT_CPU`/`SBX_OVERCOMMIT_MEM`, default 1.0) — none → `503 {"error":"no host has 4 cpus / 4096 MiB free (best: mac-local 2 cpus / 1536 MiB)"}` |
| `GET /api/hosts` | admin | `[Host]` |
| `GET /api/sandboxes?state=` | admin | `[SandboxInfo + host_id]` |
| `GET /api/sandboxes/{id}` | admin | `SandboxInfo + host_id` |
| `GET /api/sandboxes/{id}/events?after=<ulid>&limit=500` | admin | `[Event]` ascending |
| `GET /api/egress?limit=500&pi_session=&sandbox_id=` | admin | `[Event]` of type `egress.*`, newest first (v4c: both filters) |
| `GET /api/events/stream?sandbox_id=&token=` | admin (query, since EventSource cannot set headers) | `text/event-stream`, `data: <Event>` lines, `: ping` every 15 s. v2: also `?pi_session=` and `?types=a,b` filters |
| `GET /healthz` | — | `200` |
| v2 `GET /api/sessions?limit=&q=` | admin | `[{pi_session, first_ts, last_ts, sandbox_ids, hosts, events, execs, alerts:{critical,high,medium,low}, top_alert}]` newest first |
| v2 `GET /api/sessions/{id}` | admin | the row above plus `sandboxes:[SandboxInfo]` |
| v2 `GET /api/sessions/{id}/events?after=&types=&limit=` | admin | `[Event]` ascending across all sandboxes of the session |
| v2 `GET /api/sessions/{id}/trace` | admin | OTLP/JSON `ExportTraceServiceRequest` (§1.2) |
| v2 `GET /api/sessions/{id}/processes` | admin | process tree assembled from `process.*` events: `[{pid, ppid, argv, start_ts, end_ts, exit, tool_call_id, children:[…]}]` |
| v2 `GET /api/alerts?severity=&pi_session=&sandbox_id=&since=&limit=` | admin | `[Event]` of type `security.alert`, newest first |
| v2 `GET /api/stats` | admin | `{sandboxes:{ready,busy,total}, hosts, events_1h, alerts_24h:{…}, exec_p50_ms, exec_p95_ms, egress:{allow_1h,deny_1h}}` |
| v5.2 `POST /api/snapshots/{name}/scan` | admin | fans out to every host that holds the template; `202 [SnapshotInfo]` (each host's row as it stands) |
| v5.1 `GET /api/sandboxes/{id}/exec/ws` | admin or the owning key | the sandbox's streaming/PTY exec (§2.1) proxied as a WebSocket upgrade to the owning host with the host bearer — what `sbx shell <id>` joins through |
| v2 `GET /api/search?q=&limit=` | admin | events whose `cmd`, `path`, `host`, `argv` or `msg` match `q` (FTS5: every term matches as a token prefix, results ranked by bm25; empty `q` browses newest first) |
| v2 `GET /api/events?types=&pi_session=&sandbox_id=&after=&limit=500` | admin | global event list, newest first (used by the Overview latency sparkline: `types=exec.end&limit=200`) |
| v4 `GET /metrics` | admin or host token (Prometheus `bearer_token`) | control plane Prometheus text: `sbxcp_hosts{state}`, `sbxcp_sandboxes{host_id,tier,state}`, `sbxcp_events_total{type}`, `sbxcp_alerts_total{rule,severity}`, `sbxcp_http_requests_total{route,code}`, `sbxcp_http_request_duration_ms` (histogram), `sbxcp_api_key_sandboxes_total{key}`, `sbxcp_db_bytes`, `sbxcp_build_info{version}`, `go_goroutines`, `go_memstats_*`; v5: `sbxcp_host_capacity_cpus{host_id}`, `sbxcp_host_capacity_mem_mib{host_id}` (from `caps`), `sbxcp_host_committed_cpus{host_id}`, `sbxcp_host_committed_mem_mib{host_id}` (Σ `limits` of live sandboxes) |
| v4 `GET /api/hosts/{id}/metrics` | admin or host token | the host's own `/metrics` page, fetched with the pinned TLS and `SBX_TOKEN_SECRET`; `502` when the host is unreachable. Prometheus never talks to a worker directly |
| v4 `GET /api/prometheus/targets` | admin or host token | Prometheus HTTP service discovery: one target per live host, `{"targets":["<cp host:port>"],"labels":{"__metrics_path__":"/api/hosts/<id>/metrics","host_id","backend","tiers"}}`, plus the control plane itself with `__metrics_path__=/metrics` |
| v4 `GET /debug/pprof/{profile}` | admin | Go `net/http/pprof` (`profile`, `heap`, `goroutine`, `trace`, …) |
| v4 `GET /api/settings/observability` | admin | `{enabled, provider:"langfuse"|"otlp", host, public_key, secret_key_set:bool, otlp_url, otlp_headers:{}, capture:"all"|"alerts_only", health:{delivered, dropped, last_ok_ts, last_error}}`. The secret is never returned |
| v4 `PUT /api/settings/observability` | admin | same shape minus `health`; an absent/empty `secret_key` keeps the stored one. Stored in the `settings` table (key `observability`), applied live: the pusher re-reads it every batch. `enabled_at` is stamped when export turns on and only sessions active since then are pushed; turning export on never sends the history. `SBX_OTLP_URL`/`SBX_OTLP_HEADERS` seed the row on first boot only |
| v4 `POST /api/settings/observability/test` | admin | body as `PUT` (omitted fields fall back to stored) → `200 {ok, detail}`. Langfuse: `GET <host>/api/public/health` (reachability) then an empty OTLP batch to `<host>/api/public/otel/v1/traces` with basic auth `public_key:secret_key` (credentials; Langfuse answers 401 on a bad pair). `otlp`: the empty batch alone |

`Host`: `{id, url, backend, capacity, pool, last_seen, tiers (v2), tls_fingerprint (v2), policy (v2), caps (v4c), committed: {cpus, mem_mib} (v5)}`.

### 4a. v3 routes (admin)

| Route | Forwarded to |
|---|---|
| `POST /api/sandboxes/{id}/{stop,start,pause,resume,archive}` | the sandbox's host; row state updated from the reply |
| `POST /api/sandboxes/{id}/exec` | host's `POST /sandboxes/{id}/agent/exec` (admin, or a "sandboxes"-scope key that created the sandbox); body `{cmd,cwd?,env?,timeout_ms?}`; the host token and the caller's own `X-Pi-Session`/`X-Tool-Call-Id` (§7) are forwarded, not new ones; 120s client timeout — the daemon wakes a stopped sandbox itself (transparent start, §3a v4); status and body passed through unchanged |
| `POST /api/sandboxes/{id}/preview` | host; `url` rewritten to `<control plane>/preview/{id}/{port}/` |
| `ANY /preview/{id}/{port}/{*rest}` | host's `/preview/...` (HTTP + WebSocket) |
| `POST /api/snapshots` | every host serving `vm` or `remote`; `202 [SnapshotInfo]` |
| `GET /api/snapshots`, `GET /api/snapshots/{name}` | aggregated from hosts, `host_id` set |
| `DELETE /api/snapshots/{name}` | every host that has it |

Sessions need no control-plane routes: they live under `/sandboxes/{id}/agent/sessions…`, which the SDK reaches through the sandbox `endpoint`.

### 4b. API keys (v3, control plane only)

Every admin route accepts `Authorization: Bearer <SBX_ADMIN_TOKEN>` (the root credential, unchanged) **or** `Bearer <api key>`. A key is `sbx_<prefix 8>_<secret 32>`: the prefix is stored and shown, the secret is stored as SHA-256 and shown once at creation. qafas knows nothing about keys; the control plane is the policy point.

| Route | Auth | Request → Response |
|---|---|---|
| `POST /api/keys` | admin | `{"name","scopes":["sandboxes"]\|["admin"],"limits":{…},"labels"?}` → `201 ApiKeyCreated` (the only time `key` is returned) |
| `GET /api/keys` | admin | `[ApiKey]` |
| `GET /api/keys/{id}` | admin, or the key itself | `ApiKey` |
| `DELETE /api/keys/{id}` | admin | revoke; `204`. Sandboxes it created keep running; new requests with it get `401`. |
| `GET /api/keys/{id}/usage?since=` | admin, or the key itself | `ApiKeyUsage` |
| `GET /api/keys/self` | any key | the caller's `ApiKey` (admin token → `{"id":"admin"}`) |

`ApiKey`: `{id, name, prefix, scopes, limits, labels, created_at, last_used_at, revoked_at?, live_sandboxes, created_24h}`. `ApiKeyCreated` = `ApiKey + {key}`.
`Limits` (all optional; absent = unlimited): `max_concurrent` (live sandboxes: creating/ready/busy/paused/stopped/archived), `max_per_hour` (creates), `allowed_tiers` (`["native","vm","remote"]`; v4: constrains placement, so `auto` resolves within the list; only an explicit `isolation` outside the list gets `403 {"error":"this key may use tiers [..]"}`), `max_ttl_secs` (caps `ttl_secs`, `auto_stop_secs`, `max_age_secs`), `allowed_egress` (globs the key may put in `egress_allow`; anything else `403`); v5: `allowed_sizes` (named sizes the key may request), `max_cpus`, `max_mem_mib`, `max_disk_mib` (ceilings for named and custom limits alike) — a request over any of them is `403 {"error":"this key may use at most 1024 MiB"}` (`… at most 1024 MiB disk`, `… at most 2 cpus`, `… sizes [mini]`), never clamped, so committed capacity always equals what was asked for. When the request names no `size`/`limits`, the default is `medium` if the key may use it, otherwise the smallest size in `allowed_sizes` that also fits the key's `max_*` (mirrors `allowed_tiers`: only an explicit choice outside the list is refused); a key whose limits admit no size at all gets `403` on every create.
`ApiKeyUsage`: `{since, sandboxes_created, live_sandboxes, execs, alerts:{critical,high,medium,low}, egress:{allow,deny}, sandbox_seconds, by_tier:{native,vm,remote}, last_used_at}` — computed from the sandboxes the key created (`sandboxes.api_key_id`) and their events.

Scope rules: `sandboxes` may call `POST /api/sandboxes`, and `GET/DELETE/lifecycle/preview` on sandboxes it created, `GET /api/sandboxes` (filtered to its own), `GET /api/snapshots`, and its own key/usage; everything else `403`. `admin` scope equals the admin token. Limit violations return `429 {"error":"max_concurrent 5 reached"}` for concurrency and rate, `403` for tier/egress/ttl.

`SandboxInfo` from the control plane gains `api_key_id` and `api_key_name`; `GET /api/sandboxes?api_key=<id>` filters. `GET /api/sessions` rows gain `api_key_id`/`api_key_name` (from the first sandbox of the session). `X-Sbx-Client` stays what it is: a hint from the client; the key is the identity.

Clients: SDKs and the pi extension read `SBX_API_KEY` first and fall back to `SBX_ADMIN_TOKEN`; `acquire(..., {apiKey})` / `api_key=` override.

**v2 transport.** An `https://` host is verified with `SBX_CA_FILE` when set, else against the `tls_fingerprint` it registered with (trust on first use, bounded by `SBX_HOST_TOKEN`); `SBX_TLS_INSECURE=1` skips verification and is logged loudly.

## 3a. v3: lifecycle, snapshots, sessions, preview

Additive. Types live in `crates/proto` (`SandboxState`, `SnapshotInfo`, `SessionInfo`, `PreviewInfo`, …) and are mirrored in `sdk/ts/src/types.ts` and `controlplane/internal/events/types.go`. Every new qafas route below also exists on the control plane under `/api/...` with admin auth; the control plane looks the sandbox's host up and forwards (§4a).

### Lifecycle

States: `creating → ready ⇄ busy`, plus `paused`, `stopped`, `archived`, `destroyed`. Transitions are synchronous: the verb returns when the state has changed.

| Route | Tier | Effect |
|---|---|---|
| `POST /sandboxes/{id}/stop` | remote | Pause, full Firecracker snapshot (`vmstate` + `mem`) into the jail, kill the VM process. Filesystem lives in guest memory (tmpfs overlay) so it is inside the snapshot. → `stopped`. `204`. |
| `POST /sandboxes/{id}/start` | remote | Restore from the snapshot (file memory backend; 4 KB pages, the huge-page path needs a UFFD handler and is the upgrade), same tap name and guest IP, guest told it was restored (`POST /restored`). → `ready`. `200 SandboxInfo`. |
| `POST /sandboxes/{id}/pause` | remote | vCPUs halted, memory kept. → `paused`. `204`. |
| `POST /sandboxes/{id}/resume` | remote | → `ready`. `204`. |
| `POST /sandboxes/{id}/archive` | remote | `stop` if running, then move the snapshot to `SBX_FC_ARCHIVE_DIR/<id>/` and free the jail. → `archived`. `start` works from `archived`. `204`. |

v4: `stop`/`start` exist on every tier. `vm`: `podman stop`/`podman start` — the container overlay is kept and processes are gone; note that `/home/agent` and `/tmp` are tmpfs in this image, so as uid 1000 nothing outside the bind-mounted workspace survives a stop (the workspace does). `native`: the shim and every sandbox process are killed; the workspace is the host directory and needs no saving; `start` launches a fresh shim on the same workspace, id, token and endpoint. `pause`/`resume`/`archive` stay remote-only; `native`/`vm` answer `409 {"error":"pause needs the remote tier"}` (the verb named). `DELETE` works from every state. The scoped token survives stop/start; the `endpoint` is unchanged.

**Transparent start (v4, D23).** Any proxied sandbox request (`/exec`, `/exec/ws`, `/fs/*`, `/agent/*`, `/proxy/*`, sessions, preview) that reaches a `stopped` sandbox first runs `start` (event `sandbox.started {"reason":"use"}`), then serves the request. `paused` and `archived` are explicit states and answer `409 {"error":"sandbox is paused"}` / `{"error":"sandbox is archived"}`. So an idle-stopped sandbox looks, to a client, like a slow first call.

**Durability across a daemon restart (v4d).** qafas keeps a record of every live sandbox in `<state_dir>/sandboxes/<id>.json`, written at create and at every state change. At start, `remote` sandboxes recorded as `stopped` or `archived` whose snapshot files are still on disk are re-adopted with the same id, endpoint, token, timers and `state_changed_at` (so `auto_delete` counts from the original stop), and are reported in the next heartbeat unchanged. Everything else that a previous run left (running sandboxes of any tier, records with missing files, `vm`/`native` sandboxes) is swept and reported once as `sandbox.destroyed {"reason":"daemon_restart"}`. An orderly shutdown (SIGTERM, which is how systemd stops the daemon on a restart or a host reboot) leaves stopped and archived `remote` sandboxes in place and **parks** every running one: it is stopped (memory snapshot into its jail, event `sandbox.stopped {"reason":"daemon_shutdown"}`) and marked to resume, and at the next start it is restored and reported `ready` again (event `sandbox.started {"reason":"daemon_restart"}`); a park or resume that fails leaves it `stopped`, where transparent start applies. The park budget is 45 s for all sandboxes together. Only a crash (SIGKILL, power loss) loses running sandboxes; `vm`/`native` sandboxes are destroyed on any restart.

Timers, evaluated every 5 s by qafas (all optional on `POST /sandboxes`, seconds; v4: every tier, with daemon defaults when a field is absent):
- `auto_stop_secs`: `ready` with no activity this long → `stop`. Default `SBX_AUTO_STOP_SECS` (1800; `0` disables).
- `auto_delete_secs`: `0` = ephemeral, destroyed the moment it stops; `n` = `stopped`/`archived` for n → `destroy`. Default `SBX_AUTO_DELETE_SECS` (86400; the grace period after an idle stop).
- `ttl_secs` (v2): no activity this long → `destroy`. Only consulted when `auto_stop_secs` resolves to `0` (then default `SBX_TTL_SECS`, 3600), so the two never race.
- `auto_archive_secs`: `stopped` this long → `archive` (remote only; ignored elsewhere).
- `max_age_secs`: wall clock from `created_at`, any state → `destroy`. Default `SBX_MAX_AGE_SECS` (0 = none).
- `SBX_LONG_RUNNING_SECS` (14400): running longer than this → `security.alert{rule:"sandbox.long_running"}` (§1.1); not a transition.

`SandboxInfo` reports the resolved values (never `null` for `auto_stop_secs`/`auto_delete_secs`), plus `idle_secs` and `running_secs` (v4) so a client can show "stops in …".

Events: `sandbox.stopped|started|paused|resumed|archived` with `{"reason": "api"|"use"|"auto_stop"|"auto_archive"|"auto_delete"|"max_age"}`; `sandbox.destroyed` already carries `reason`. `SandboxInfo` gains `name`, `labels`, `state_changed_at` and the four timers.

`POST /sandboxes` also accepts `name` (unique among the host's live sandboxes, else `409`; the id when absent), `labels`, and `env` (added to every exec; `PROTECTED_ENV` names dropped).

### Snapshots (images)

A snapshot is a named thing a sandbox can be created from. v4: `template` on `POST /sandboxes` is either `base` (the built-in image, listed by `GET /snapshots` as an `active` `image` row) or the name of an `active` snapshot on this host; `building`/`error` → `409`, unknown → `404 {"error":"unknown template \"x\""}`. Nothing falls back silently. The warm pool is keyed by it. A host serves one pooled runtime: when both `vm` and `remote` are servable, `remote` wins and `vm` is dropped from the advertised tiers (D25); hosts advertise real capabilities, never the configured list.

| Route | Request → Response |
|---|---|
| `POST /snapshots` | `{"name","source":{"image":"node:22-bookworm"}}` or `{"dockerfile":"FROM …"}` or `{"sandbox_id":"sbx_x"}` → `202 SnapshotInfo{state:"building"}`. Builds in the background. `latest`/no tag → `400`. Name taken → `409`. |
| `GET /snapshots` | `200 [SnapshotInfo]` |
| `GET /snapshots/{name}` | `200 SnapshotInfo` |
| `DELETE /snapshots/{name}` | `204`; `409` while a live sandbox uses it as its template. |
| v5.2 `POST /snapshots/{name}/scan` | → `202 SnapshotInfo` (the row as it is); the template security scan runs in the background and `security` changes when it is done. Not `active` → `409`, unknown → `404`. |
| v4 `PUT /snapshots/{name}` | `{"warm": n}` → `200 SnapshotInfo`. Sets how many restored sandboxes the pool keeps ready for this template on this host. `base` accepts it too (its default is `SBX_POOL_SIZE`). |

**v4c runtime on templates.** `POST /snapshots` accepts `runtime` (`remote`|`vm`, aliases accepted). The control plane fans the build out to hosts advertising that runtime only (default: the fleet default, `remote` if any host serves it, else `vm`); a `sandbox_id` source goes only to the host that owns the sandbox and takes its runtime; a runtime no host serves → `409`. Each host reports `SnapshotInfo.runtime` = its pooled tier. `GET /api/snapshots?runtime=` filters.

**v4c host capabilities.** `HostRegister.caps` (`HostCaps`: os, arch, cpus, mem_mib, kvm, firecracker, podman, process_sandbox, bpftrace, hugepages_mib, supported) comes from the same checks `qafas doctor` prints; `qafas doctor --json` prints them as JSON for installers. `Host.caps` is returned by `GET /api/hosts`.

**v5.2 template security scan** (security.md M43, D30). Every template has a grade, computed on the host's own runtime: a throwaway sandbox of the template (booted directly on the backend like the memory-capture VM; no workspace, no events, not listed) runs `images/probe/scan.sh` through the ordinary `/exec` path as uid 1000, and each line it prints is a `SecurityCheck {id, class, ok, detail}`. `class: "boundary"` checks what the tier promises (`caps`, `no_new_privs`, `seccomp`, `mount`, `userns`, `runtime_socket`, `egress_direct`, `metadata`, `dns`, `env_llm_keys`, `pid1_environ`); `class: "hygiene"` checks what the image carries (`setid_files`, `file_caps`, `path_writable`, `system_writable`, `baked_secrets`, `sudoers`). `SnapshotInfo.security = TemplateSecurity {grade, scanned_at, image_digest, findings[]}`; `grade` is `F` when any boundary check failed, else `A` (no failed check), `B` (1–2), `C` (3+) — a letter, not a score. Absent until a scan has run. It runs after every build (before the row goes `active`), for `base` at daemon start unless `image_digest` is unchanged, and on `POST /snapshots/{name}/scan`. A check that cannot run in that image (no `curl`, no `getcap`, …) says so in `detail` and counts as passed. **`POST /sandboxes` with `trust: "untrusted"` on a template graded `F` → `409 {"error":"template x failed its security scan (env_llm_keys); trust=untrusted cannot use it …"}`**; trusted creates are not affected, and an unscanned or `A`–`C` template is never refused. Grades are per host and per runtime (a Firecracker rootfs carries neither the image's `ENV` nor file capabilities, so the same Dockerfile can grade differently there); the control plane lists each host's row and the dashboard shows the worst.

**v5 sizes and limits.** A sandbox carries `SandboxLimits {cpus, mem_mib, disk_mib, pids}`. `POST /sandboxes` takes either `size` (a name from the table below, default `medium`) or `limits` (custom: `cpus` ≥ 0.25 in 0.25 steps, `mem_mib` ≥ 64, `disk_mib` ≥ 1, `pids` defaults to the nearest named size by memory); both → `400`. The table is compiled into both binaries and replaced wholesale by `SBX_SIZES` (JSON `{"name":{"cpus","mem_mib","disk_mib","pids"}}`; `medium` must remain):

| name | cpus | mem_mib | disk_mib | pids |
|---|---|---|---|---|
| `micro` | 0.5 | 512 | 512 | 128 |
| `mini` | 1 | 1024 | 1024 | 256 |
| `medium` (default; the pre-v5 unit) | 2 | 2048 | 2048 | 512 |
| `high` | 4 | 4096 | 4096 | 1024 |

`disk_mib` is the writable scratch: the `/tmp` tmpfs on `vm`, the overlay root on `remote`, `/tmp/sbx-<id>` on `native`. On `vm`/`remote` scratch is RAM-backed and charged to the memory cgroup, so it can never exceed `mem_mib` in practice; a pooled `vm` container keeps the tmpfs size it was created with (the largest configured `disk_mib`) and the memory cgroup bounds it. The bind-mounted workspace is never limited.

The control plane resolves a name to numbers, applies the key's `allowed_sizes`/`max_*` (`403`), and forwards **both** `size` and `limits`; a daemon that receives both takes `limits` as the numbers and `size` as the label (the "not both" `400` is the client-facing rule at the control plane; a direct daemon client may send either form). The daemon validates the numbers again against its own ceilings — `SBX_MAX_CPUS`, `SBX_MAX_MEM_MIB`, `SBX_MAX_DISK_MIB` (default: `HostCaps.cpus`/`mem_mib`) and, on `remote`, the template RAM (`SBX_FC_MEM_MIB`) — answering `409 {"error":"mem_mib 4096 exceeds this host's template RAM (2048)"}`. Only the harness or the API sets a size (pi `--size`/`SBX_SIZE`, SDK option, `sbx run --size`); MCP tool schemas never expose it (D22 applies).

Enforcement is set at create and re-applied when a pooled sandbox is handed out, always out of the workload's reach: `vm` — the container's cgroup (`cpu.max`, `memory.max`, `pids.max`, via `POST /libpod/containers/{name}/update` on acquire); `remote` — an in-guest cgroup v2 leaf the root guest agent creates (`PUT /limits`; ceilings on `/sys/fs/cgroup/sbx/work`, the agent itself parked in `sbx/agent` so it is never the OOM victim) and spawns every exec into, plus the overlay tmpfs remounted to `disk_mib` and a host `cpu.max` on the VM's own cgroup (jailer `--cgroup-version 2`); `native` on Linux — a cgroup v2 leaf under `/sys/fs/cgroup/sbx/<id>` and `bwrap --size` for `/tmp`; `native` on macOS — qafas's watchdog (RSS and process count summed over the process group every 100 ms, scratch size every second; the group is killed over the limit with `memory limit … hit (watchdog)`, `process limit … hit (watchdog)` or `disk limit … hit (watchdog)`; CPU is not capped). `SandboxInfo.enforcement` says which: `kernel` or `daemon`. Every enforcement hit (cgroup `memory.events oom_kill`, watchdog kill) raises `security.alert {rule:"resource.limit", severity:"low", msg:"memory limit 1024 MiB hit (oom_kill)"}` in addition to the `process.exit {signal:"KILL"}`.

`SandboxInfo` (201 reply, `GET /sandboxes`, heartbeat) gains `size` (name or `custom`), `limits`, `enforcement` and `usage: {cpu_millis, mem_bytes, mem_peak_bytes, disk_bytes, pids, ts}` — sampled at the boundary (agent `GET /usage` reads the cgroup files and `statvfs` on `vm`/`remote`; qafas reads `/proc`/the cgroup leaf on `native`) on the daemon's 5 s tick, never asked of the workload. `GET /metrics` adds per-sandbox gauges `sbx_sandbox_memory_bytes`, `sbx_sandbox_memory_peak_bytes`, `sbx_sandbox_cpu_seconds_total`, `sbx_sandbox_pids`, `sbx_sandbox_disk_bytes`, `sbx_sandbox_limit_memory_bytes`, `sbx_sandbox_limit_cpus`, `sbx_sandbox_limit_disk_bytes`, all `{id,tier,size,pi_session}`, and extends `sbx_exec_duration_ms` buckets to `…, 1000, 5000, 30000, 300000`. `GET /sandboxes/{id}/processes` `rss_kb` is refreshed every sweep instead of sampled once.

**Workspace is optional on every tier** (`workspace` on `POST /sandboxes`): `native` runs in a scratch directory, `vm` in the container's own `/home/agent` (no bind mount), `remote` in `/home/agent` until a tar is uploaded. A `host_path` is mounted at the identical path only on `native`/`vm`.

**v4 memory snapshots ("start is a restore").** `POST /snapshots` accepts `warm` (default 0) and `memory_snapshot` (default true). On a Firecracker host, after an `image`/`dockerfile` build the daemon boots the image once, waits for the guest agent, runs the page-cache warm-up, and captures memory + state next to the rootfs; the snapshot stays `kind: "image"` and reports `memory_snapshot: true`. Every sandbox created from it, pooled or not, is a restore with a fresh id, IP, canaries and clock (the same path `vm` snapshots use), never a kernel boot. `base` is treated the same way at daemon start (`SBX_BASE_MEMORY_SNAPSHOT`, default true; the capture lives in the state dir and is rebuilt when the rootfs or kernel changes). `memory_snapshot: false` keeps the boot path. Other tiers ignore the field and report `false`.

**v4 warm pool policy.** Per template the pool target is `max(warm, recent)`, where `recent` is 1 while the template was acquired within `SBX_POOL_RECENT_SECS` (default 3600; at most `SBX_POOL_RECENT_MAX`, default 4, templates hold a recency slot; least recently used loses it) and 0 otherwise. `base` targets `SBX_POOL_SIZE`. `GET /pool` keys are template names and each entry carries `warm`, `target` and `restore: bool`. `SnapshotInfo.warm_ready` mirrors `warm` from the pool.

`SnapshotInfo`: `{name, state: building|active|error, kind: image|vm, source, created_at, bytes, error?, host_id? (control plane), v4 warm, v4 memory_snapshot, v4 warm_ready}`. Per backend:
- podman (`vm`): image → `podman pull` + tag; dockerfile → `podman build`; sandbox_id → `podman commit`. All `kind: image`.
- firecracker (`remote`): image/dockerfile → a rootfs ext4 built with the host's podman (what `images/build-rootfs.sh` does), `kind: image`; sandbox_id → pause + full snapshot of that VM (`kind: vm`). Creating from a `vm` snapshot is a restore: the guest gets `POST /restored {id, ip, gw, proxy, now}` and re-plants canaries, reconfigures eth0, sets the clock and hostname; the kernel reseeds its PRNG from VMGenID. Restoring one snapshot many times is what makes this sub-100 ms; the sandbox id, canary tokens and network identity are the per-restore state and are all replaced.
- native: `501`.

Snapshots are per host. The control plane's `POST /api/snapshots` fans the request out to every host serving `vm` or `remote` and `GET /api/snapshots` lists one row per (host, name). Events: `snapshot.building|ready|error` with `{"name"}`.

### Sessions (persistent shells; guest-agent, reached through `/sandboxes/{id}/agent/…`)

| Route | Request → Response |
|---|---|
| `POST /sessions` | `{"id"?, "cwd"?, "env"?}` → `201 {"id"}`; one `bash` per session, alive until deleted or the sandbox stops. |
| `GET /sessions` | `200 [SessionInfo]` |
| `GET /sessions/{id}` | `200 SessionInfo{id, cwd, created_at, commands:[SessionCommand]}` (no output bodies) |
| `POST /sessions/{id}/exec` | `{"cmd","async"?,"timeout_ms"?}` → sync `200 {command_id, exit, stdout, stderr}`; async `202 {command_id}` |
| `GET /sessions/{id}/commands/{cid}` | `200 SessionCommand` with `stdout`/`stderr` (capped like `/exec`) |
| `GET /sessions/{id}/commands/{cid}/logs/ws` | WebSocket; frames as §2.1 (`stdout`/`stderr`/`exit`), replaying what is already buffered then live |
| `POST /sessions/{id}/commands/{cid}/input` | `{"data"}` → `204`; bytes to the shell's stdin while `cid` runs |
| `DELETE /sessions/{id}` | `204`; kills the shell's process group |

Correlation: each `exec` carries its own `X-Tool-Call-Id`; `exec.start`/`exec.end` are emitted per command and procmon attributes the session shell's children to the current command. Only one command runs per session at a time (`409` otherwise). stderr is attributed to the command running when it arrived (a background job's late stderr lands on the next command: ponytail, a pty per command is the upgrade).

### Preview (signed access to a port inside the sandbox)

| Route | Request → Response |
|---|---|
| `POST /sandboxes/{id}/preview` | `{"port", "ttl_secs"?}` → `200 PreviewInfo{url, token, port, expires_at}` |
| `ANY /preview/{id}/{port}/{*rest}` | no bearer token: `?sbx_preview=<token>` on the first request (sets cookie `sbx_preview_<id>_<port>`) or `X-Sbx-Preview: <token>`; HTTP and WebSocket proxied to the guest's `127.0.0.1:{port}` via guest-agent `ANY /proxy/{port}/{*rest}` |

Token: `hmac_token` over `preview:<id>:<port>` with the host's token secret; revoked with the sandbox. The control plane's `POST /api/sandboxes/{id}/preview` returns a URL on the control plane (`/preview/{id}/{port}/`) which forwards to the host, so one hostname serves every sandbox. Event: `preview.created {"port"}`.

## 5. Tokens

- Admin: static `SBX_TOKEN` (qafas) and `SBX_ADMIN_TOKEN` (control plane). Compared in constant time.
- Scoped sandbox token (minted by the control plane with `SBX_TOKEN_SECRET`, which equals the target qafas's `SBX_TOKEN`; also minted by qafas itself when called directly):

```
payload = "<sandbox_id>:<unix_exp>"
token   = base64url(payload) + ":" + base64url(hmac_sha256(secret, payload))
```

Verify: split on the last `:`, recompute, constant-time compare, check `exp`, check `sandbox_id` equals the path's `{id}`. Default lifetime 12 h (`SBX_TOKEN_TTL_SECS`). v2: `DELETE /sandboxes/{id}` puts the id in an in-memory deny set until that lifetime elapses, so a leaked token cannot be replayed against a reused id. Implemented once in `proto::hmac_token` and once in Go (~15 lines).

## 6. Egress policy file (`policy/egress.json`)

```json
{
  "allow": ["github.com", "*.github.com", "registry.npmjs.org", "pypi.org", "files.pythonhosted.org"],
  "deny_cidrs_extra": [],
  "allow_private_cidrs": []
}
```

Always denied regardless of `allow`: loopback, RFC1918, link-local (`169.254.0.0/16`, `fe80::/10`), unspecified, unique-local `fd00::/8`, and `169.254.169.254` explicitly. Matching is on the CONNECT host or the absolute-URI host (wildmatch globs), then on every resolved address.

v5.3 `allow_private_cidrs` (host file only; additive, default empty): an allowed name whose address falls inside one of these ranges is let through even though it is private — the internal package mirror of an air-gapped network. Only RFC1918 and IPv6 unique-local can be opened this way; loopback, link-local (so `169.254.169.254`), CGNAT `100.64.0.0/10`, unspecified and multicast stay denied whatever the list says, and `deny_cidrs_extra` still wins. A create request's `egress_allow` adds names only, never ranges.

## 7. Correlation headers

The pi extension sends on every qafas request:

```
X-Pi-Session: <pi session id or random uuid per process>
X-Tool-Call-Id: <toolCallId passed to execute(), empty for user_bash>
X-Sbx-Client:  <library and version, v2: pi/0.83, sdk-ts/0.1>
```

qafas copies both onto events. The control plane indexes `events(pi_session, ts)`.
