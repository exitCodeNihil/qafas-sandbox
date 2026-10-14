# Security controls

This is the ledger of every security control in Qafas Sandbox: whether it is in place, and where it lives in the code. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

Last reviewed 2026-10-14, after the escape battery (`tests/escape.mjs`, 18 probes) passed on the macOS `native` and `vm` tiers and on the Linux `native` tier: everything contained, every probe that must alert did.

**How to read the tables.** Each control has a stable number (M1, M2, …) that code comments and other docs refer to; the numbers are not in order. The status is one of: **in place** (with the evidence in brackets), **deferred** (a known gap, with its upgrade path), planned, operational note (something the operator does), or n/a.

**Contents:** [Isolation boundary](#isolation-boundary) · [Native tier](#native-tier) · [Network and egress](#network-and-egress) · [Secrets and credentials](#secrets-and-credentials) · [API, tokens and transport](#api-tokens-and-transport) · [Detection](#detection) · [Host and operations](#host-and-operations) · [Escape review](#escape-review) · [TLS caveats](#tls-caveats) · [Known gaps](#known-gaps)

## Isolation boundary

What stands between a sandboxed process and the host, per tier.

| # | Control | Status | Where |
|---|---|---|---|
| M1 | VM boundary for remote/multi-tenant | planned (Gate E) | firecracker backend + jailer |
| M2 | Jailer + VMM seccomp | planned | `backend/firecracker.rs` |
| M7 | seccomp deny-list (io_uring, ptrace, mount, bpf, keyctl, userfaultfd, perf, modules) | **in place** (WP1 differential test: ptrace EPERM, allowed with `SBX_NO_SECCOMP=1`) | `guest-agent/exec.rs` harden |
| M8 | no_new_privs, cap drop, non-root, userns | **in place** (container spec: cap drop, non-root, userns; no_new_privs on every workload process from `harden::apply` — container-wide too on Docker, not on podman, D33; exec runs as uid 1000) | podman/Docker spec + harden |
| M9 | read-only rootfs, tmpfs scratch with size | **in place** (podman spec) | podman spec / rootfs.ext4 + tmpfs |
| M10 | cgroup limits (memory, cpu, pids) | **in place** (sized per sandbox: `micro|mini|medium|high`/custom; v5 sizes table in docs/protocol.md §3a) | podman resource_limits / FC machine-config; qafas watchdog on macOS native; `resource.limit` alert on every hit. macOS native pids: the watchdog kills the group over the size's `pids` (`process limit N hit (watchdog)`, one alert; fork bomb dies at the limit, 2026-09-18) with `RLIMIT_NPROC` = the user's running process count + 512 as a backstop. Remote: ceilings on the sibling leaf `sbx/work`, the agent in `sbx/agent`, so an OOM never takes the agent |
| M25 | seccomp KILL for ptrace, mount family, namespaces (`unshare`, `setns`, `clone` with CLONE_NEW*), bpf, keyctl, userfaultfd, perf, modules; io_uring EPERM; `clone3` ENOSYS | **in place** (vm, remote, and Linux native since 2026-10-14) | `agent-core/src/harden.rs` |
| M30 | Remote tier: shared read-only rootfs, tmpfs overlay in the guest, jailer (uid 1000, pid ns), nftables on the TAP, vsock-only control path | **in place** (Gate E on nested KVM) | `crates/qafas/src/backend/firecracker.rs`, `crates/guest-agent/src/init.rs` |
| M37 | Remote tier: the guest-agent binds vsock only, never TCP, so a sandboxed process (uid 1000) cannot reach the root-owned agent on the guest's own loopback and write `/etc` through `/fs/write` | **in place** | `crates/guest-agent/src/serve.rs` |
| M42 | vm tier on a rootful Linux host: `keep-id` is a no-op there, so the workspace is bind-mounted as an idmapped mount (`idmap=uids=<owner>-1000-1`): the owner appears as uid 1000 inside and writes land as the owner, nobody else's files change meaning. On an SELinux-enforcing host the sandbox container runs with `label=disable` rather than relabelling the operator's directory (`:z` is a permanent change to the host tree). **Gap:** SELinux does not confine sandbox containers on RHEL-family hosts; the boundary there is what it is everywhere else (namespaces, seccomp, the capability set, read-only rootfs, the internal network). Upgrade path: a `container_t`-derived policy that admits the idmapped workspace, then drop `label=disable` | **in place**, SELinux **deferred** | `crates/qafas/src/backend/podman.rs` `workspace_idmap`, `selinux_enforcing` |
| M45 | vm tier on Docker Engine (D32): the same boundary in Docker's dialect — read-only rootfs, `CapDrop: ALL`, `no-new-privileges`, the `sbx-internal` network (`Internal: true`), the size as cgroup limits, SELinux `label=disable` where enforcing, nothing published (qafas reaches the agent through the proxy's relay). Docker has no idmapped bind mounts, so a sandbox runs **as its workspace's owner** instead of as uid 1000, and a root-owned workspace is refused (`409`) rather than run as root. **Deviation from D7:** a user-defined Docker network always injects the embedded resolver `127.0.0.11`; on an internal network Docker ≥ 26.0 forwards nothing outside (CVE-2024-29018), so it answers only container names on `sbx-internal` — older Docker is refused at start. The scan's behavioural `dns` check and `tests/escape.mjs` "dns exfil" test exactly that. **Gap:** template-build pulls are anonymous (Docker keeps credentials client-side) | **in place** (tests: Docker spec, root-owned refusal, version gate, streamed errors) | `backend/podman.rs` `docker_spec`, `refuse_workspace`, `docker_supported` |

## Native tier

The OS process sandbox for a developer's own machine (never for `trust: untrusted`).

| # | Control | Status | Where |
|---|---|---|---|
| M21 | Native tier: Seatbelt deny-by-default profile per sandbox (reads: system + toolchains + workspace; writes: workspace + scratch; network: proxy only) | **in place** | `policy/seatbelt.sb.tmpl`, `crates/qafas/src/seatbelt.rs` |
| M22 | Native tier: one confined agent per sandbox (`qafas shim`), commands are forks of it | **in place** | `crates/qafas/src/shim.rs`, `backend/native.rs` |
| M46 | Native tier on Linux: `bwrap` shows the system read-only and replaces `/home`, `/root` and `/run` with empty tmpfs (no user credentials, no podman, Docker or D-Bus socket), binds the user's toolchains and the `qafas` binary back read-only, covers the credential paths even inside the workspace, and writes only to the workspace and the scratch dir; every command then gets Landlock (filesystem, and TCP connect only to the egress proxy port), the M25 seccomp list and `no_new_privs`; private pid/uts/ipc namespaces; dies with the daemon. A root daemon does not serve `native` (commands run as the daemon's own user), and on Ubuntu 24.04+ bwrap needs an AppArmor profile for user namespaces (deployment.md 5.5); `qafas doctor` checks both | **in place** (escape battery on Ubuntu 24.04 arm64, 2026-10-14: 18 probes, all contained and alerted) | `crates/qafas/src/backend/native.rs` `bwrap_prefix`, `confine`, `crates/qafas/src/shim.rs` |
| M26 | Kernel denial reports → alerts (Seatbelt unified log) with pid → tool-call attribution | **in place** (native) | `crates/qafas/src/sblog.rs` |
| M34 | Native tier host reconnaissance: `net.*` sysctls denied (no interface/route enumeration), inventory tools (`ifconfig`, `netstat`, `system_profiler`, `ioreg`, `scutil`, `dscl`, `arp`, `launchctl`, `nmap`) reported as `host.recon`. `uname`/hostname/CPU count stay readable: runtimes need them. Anything the host must not reveal at all belongs on the `vm`/`remote` tier (`trust: untrusted`) | **in place** | `policy/seatbelt.sb.tmpl`, `agent-core/src/rules.rs` |
| M39 | Native tier: the scratch directory `/tmp/sbx-<id>` (agent socket, fake HOME) is `0700`; `?token=` is honoured only on a WebSocket upgrade, so tokens stay out of access logs, `Referer` and shell history | **in place** (mode test; query-token test) | `crates/qafas/src/backend/native.rs` `make_scratch`, `api.rs` `presented_token` |
| M29 | Untrusted workspaces never run in the native tier; only the harness widens egress | **in place** | `crates/qafas/src/policy.rs`, D22 |

## Network and egress

| # | Control | Status | Where |
|---|---|---|---|
| M3 | Deny-by-default egress, enforced outside the sandbox | **in place** (Gate B: example.com 403, github.com 200, no resolver in sandbox) | `sbx-internal` network / nftables + proxy |
| M4 | Block link-local, metadata, RFC1918, ULA | **in place** (Gate B: 169.254.169.254 → 403) | `proxy.rs` address checks |
| M41 | vm tier on a rootful Linux host: the sandbox network stays `internal` (no host route, no DNAT — the published loopback port leads nowhere there), and qafas reaches guest agents through a relay listener on the egress proxy container, the one component that is dual-homed by design. The relay is a policy-free CONNECT that accepts only peers *outside* the sandbox subnet and only targets *inside* it, so a sandbox gains nothing it did not have (it can already reach its neighbours; M40's per-sandbox token guards the agent either way). Chosen on start by probing; macOS and rootless podman keep the published port. The egress policy now travels to the proxy as content (`SBX_POLICY_JSON`), not as a bind mount of a host path | **in place** (tests: relay refuses inside peers and outside targets, tunnels into the net on Linux) | `crates/qafas/src/proxy.rs` `serve_relay`, `backend/podman.rs` `probe_relay`, `backend/mod.rs` `Connector::Relay` |
| M44 | Internal mirrors on an air-gapped network (v5.3, D31): the host's `egress.json` may list `allow_private_cidrs`; a name already in `allow` whose address falls in one of them passes the private-address rule. Only RFC1918 and IPv6 unique-local can be opened; loopback, link-local (the metadata endpoint), CGNAT, unspecified and multicast stay denied whatever the list says, and `deny_cidrs_extra` still wins. Operator-only: a create request's `egress_allow` adds names, never ranges, so neither a harness nor the model can open the internal network. **Gap:** every sandbox on the host shares the list; per-key or per-template private ranges are the upgrade path | **in place** (test: `allow_private_cidrs_opens_internal_mirrors_and_nothing_else`) | `proxy.rs` `Policy::decide`, `openable` |
| M16 | Egress byte budgets | bytes logged; budgets deferred | `egress.*` events |
| M5 | IMDSv2 hop-limit 1 on cloud hosts | operational note | deployment.md 5.4, host hardening |

## Secrets and credentials

| # | Control | Status | Where |
|---|---|---|---|
| M6 | Secrets never enter the sandbox | negative half in POC (no host env, no `~/.ssh`/`~/.aws` mounts, keys stay in pi on host); injection deferred | D6 |
| M12 | Deny-read credential paths | achieved by not mounting them (podman) / not uploading them (tar excludes, M32) | `sdk/ts/src/pack.ts` |
| M23 | Harness environment never enters the sandbox (SDK allowlist + sandbox-owned HOME/PATH/TMPDIR/proxy vars) | **in place** (containment test asserts it) | `sdk/ts/src/index.ts` `filterEnv`, `agent-core/src/spawn.rs` `PROTECTED_ENV` |
| M24 | Canary credentials in every sandbox HOME; read → `canary.read` critical | **in place** (native: denied + reported; vm: readable honeypot, reported) | `agent-core/src/rules.rs` |
| M32 | Workspace minimisation: the remote tier uploads source and git history only — no `node_modules`/build output, no `.env`, keys, `.ssh`/`.aws`/`.gnupg`, `.netrc`/`.npmrc`/`.pypirc`, `credentials*`/`secrets*`; `.sbxignore` narrows further | **in place** (SDK test asserts the archive members) | `sdk/ts/src/pack.ts`, `sdk/ts/test/pack.test.mjs` |
| M11 | Deny-write on delayed-execution paths (`.git/hooks`, `.vscode/tasks.json`, `.github/workflows`, shell rc) | **deferred** — live bind mount in POC; add harness-side `tool_call` block list in pi extension as cheap first step | phase 2 |
| M13 | `npm install --ignore-scripts` default | image sets `npm_config_ignore_scripts=true`; document override | Dockerfile |
| M14 | Repo config may only narrow privileges | n/a in POC (no repo-provided policy) | — |

## API, tokens and transport

| # | Control | Status | Where |
|---|---|---|---|
| M15 | Harness gate + full tool-call audit with `pi_session`/`tool_call_id` | **in place** (Gate C) | qafas events + control plane |
| M19 | Strict mode, no unsandboxed fallback | **in place** (Gate B test 5 passes) | `user_bash` fail-closed |
| M31 | Remote path is TLS with a pinned certificate: qafas serves HTTPS + WSS (`SBX_TLS=1`), the control plane verifies against `SBX_CA_FILE` or the fingerprint the host registered with, pi pins the fingerprint the control plane returns | **in place** (self-signed + pinning verified end to end: exec over WSS, a wrong pin refused on both hops) | `crates/qafas/src/tls.rs`, `controlplane/internal/registry/registry.go`, `sdk/ts/src/tls.ts` |
| M33 | Per-request client identity (`X-Sbx-Client`) and bounded scoped tokens (`SBX_TOKEN_TTL_SECS`, revoked on destroy) | **in place** | `sdk/ts/src/index.ts`, `crates/qafas/src/api.rs` |
| M35 | A scoped token is one sandbox's, not the host's: `GET /sandboxes` and `/events/ws` are filtered to its own id, `/pool`, `/policy` and `/snapshots` need the admin token | **in place** (test: a scoped token sees one entry, four host routes 403) | `crates/qafas/src/api.rs` `admin_only`, `list`, `events_ws` |
| M36 | The caller's credentials never reach a server the agent wrote: `authorization`, `proxy-authorization`, `x-pi-session`, `x-tool-call-id`, `x-sbx-*` and the `sbx_preview_*` cookies are stripped on the preview hop (other cookies pass) | **in place** (test asserts what the dev server receives) | `crates/agent-core/src/proxy.rs` `strip_client_auth`, `crates/qafas/src/api.rs` `preview_proxy` |
| M38 | Upload cap `SBX_MAX_UPLOAD_MB` (default 512 MiB): qafas rejects an over-cap `content-length` with `413` and limits the forwarded stream; the guest caps `/fs/write` and `/fs/tar` too (the tar is buffered whole and, on the remote tier, extracted onto a tmpfs) | **in place** (test: `413` on an oversize `content-length`) | `crates/qafas/src/api.rs`, `crates/agent-core/src/lib.rs` `max_upload_bytes` |
| M40 | vm tier: the published guest-agent port is protected by a per-sandbox secret. qafas mints 32 random bytes at create, passes them to the container as `SBX_AGENT_TOKEN` (a `PROTECTED_ENV` name, so no exec can read or override it, and it survives stop/start), and sends `X-Sbx-Agent-Token` on every hop to that guest — HTTP, WebSocket relays, sessions, preview, the events stream, `/restored` and `PUT /workspace`. The guest 401s anything without a constant-time match; `/healthz` stays open, and the preview hop strips the header before it reaches a dev server. Native (unix socket in a `0700` dir, M39) and remote (vsock, M37) mint none. The agent unsets the variable and overwrites its bytes in the initial environment block at start, so `/proc/1/environ` (readable by the same uid on this tier) shows a scrubbed value; execs also never inherit sandbox-owned names. | **in place** (tests: guard 401/200/healthz; container spec env; forwarded header present with a token and absent without) | `crates/agent-core/src/lib.rs` `guard`, `crates/qafas/src/backend/podman.rs` `spec`, `api.rs` `send`/`relay` |

## Detection

| # | Control | Status | Where |
|---|---|---|---|
| M27 | Process tracking: every exec with argv and owning tool call (kqueue on macOS; /proc sampling at 25 ms in containers; bpftrace fork/exec/exit lineage on the remote tier; root resolved lineage → session → pgid since every exec is its own session; a re-exec of the same image is not re-announced; unattributable execs are counted, never dropped) | **in place** (native and remote complete; vm misses < 25 ms processes) | `agent-core/src/procmon.rs` |
| M28 | Command-line rules before execution (credential paths, escape probes, metadata hosts, setuid binaries) | **in place** | `agent-core/src/rules.rs` |
| M43 | Template security scan (v5.2, D30): every template — `base` at start, each build, and on demand — is graded A/B/C/F by `images/probe/scan.sh` run as uid 1000 through the real exec path of a throwaway sandbox on the host's runtime. **Boundary** checks (capabilities empty, `no_new_privs`, seccomp filter, `mount`/`unshare -U` denied, no container-runtime socket, no direct egress, no metadata endpoint, no resolver, no model API key in the environment or in `/proc/1/environ`) → any failure is `F`, raises `security.alert{rule:"template.insecure"}` and makes `trust: untrusted` creates on it a `409`. **Hygiene** checks, the linPEAS-style part (unexpected set-id programs, file capabilities, writable `PATH`/system paths, readable private keys / `.env` / cloud credentials baked into the image, passwordless sudo) lower the grade and are listed for the operator. Deliberately not linPEAS itself: its host-privilege-escalation checks are moot under `no_new_privs` + an empty capability set, and an attacker toolkit has no place in an air-gapped image. **Gaps:** no CVE scan (needs a vulnerability DB carried into the air gap; an offline Trivy DB is the upgrade path); the scan grades a template, not a live sandbox (runtime behaviour is what the boundary detections watch); a check whose tool is missing from the image counts as passed | **in place** (tests: grade function, parser, refusal rule, CP fan-out; live: `base` A on Mac vm, rootful Ubuntu vm and Firecracker; a Dockerfile with an API key in `ENV`, a baked key and `.env`, a setuid copy and a file capability → F on vm with all six findings, C on Firecracker where `ENV` and xattrs do not survive the rootfs export) | `images/probe/scan.sh`, `crates/qafas/src/scan.rs`, `api.rs` `insecure_for` |

## Host and operations

| # | Control | Status | Where |
|---|---|---|---|
| M20 | Host hardening (SMT/KSM/swap) | operational note | deployment.md 5.4, host hardening |
| M17 | Snapshot before identity enters VM | n/a (no snapshots in POC) | phase 2 |

## Escape review

Run it with `make escape TIER=native` or `TIER=vm` against a running daemon. The probes: credential reads (real and via symlink), write outside the workspace, git hook write, `/proc/1/environ`, host env leakage, direct network bypassing the proxy, cloud metadata, DNS exfiltration, ptrace, mount, user namespaces, container sockets, setuid `sudo`, io_uring, fork bomb, killing PID 1.

Results: nothing escaped and every probe that must alert did, on both tiers on macOS (2026-09-08, rerun 2026-10-14) and on the Linux `native` tier (Ubuntu 24.04 arm64, 2026-10-14). Known limits found and accepted:

- **VM tier, direct network bypass**: there is no route, so the attempt fails silently; no alert without eBPF (remote tier). The native tier reports it (`sandbox.denied` high on `network-outbound`).
- **VM tier, processes shorter than ~25 ms** are not individually reported (their exec/exit is still inside the parent exec's span).
- **macOS `sudo`**: Seatbelt refuses setuid execs with no log line; detection is by command line (`setuid.exec`).
- **Seatbelt report latency** is about a second; the denial itself is synchronous.

Monitoring tiers (RESEARCH §4): tier 1 = harness gate, qafas proxy events, egress proxy, cgroup; the POC UI shows tier-1 data only. In-guest eBPF and PTY recording are phase 2.

## TLS caveats

The default certificate is self-signed and trusted on first use — the control plane pins whatever the host presents at registration, so the guarantee is only as strong as `SBX_HOST_TOKEN` and the network at that first moment. `SBX_CA_FILE` (an internal CA) removes that window and is what production should use. `SBX_TLS_INSECURE=1` disables verification entirely and exists for debugging only. The Node SDK pins by adding the verified certificate to the process CA set, so a pin applies process-wide rather than per connection.

## Closed: the client→sandbox data path (2026-09-09)

The vm tier's guest-agent port is published on `127.0.0.1` and gvproxy forwards it to the Mac, so any local process that found the port used to get `/exec` and `/fs/*` in that sandbox, including the bind-mounted workspace. A published TCP port cannot be closed the way M39 closes the native tier's `agent.sock` (`0700`), so M40 puts a per-sandbox secret in front of it instead. The remote tier was never affected (vsock, M37). Residual on the vm tier: the guest-agent there runs as uid 1000, the same uid as every exec, so reaching it was never an escalation.

## Known gaps

Stated plainly:

- Exfiltration through an allowlisted domain.
- The workspace is live on both local tiers, so sandboxed code can write files the host later executes (M11 detects the common paths, does not prevent).
- No TLS termination so no credential injection.
- The native tier shares the host kernel (Seatbelt and Landlock are policy boundaries, not virtualisation boundaries — that is why untrusted workspaces never get it).
- The podman backend shares one VM kernel across concurrent local sandboxes.
