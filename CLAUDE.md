# Qafas Sandbox — project brief

Fast, secure execution sandbox for LLM coding agents. One Rust daemon (`qafas`) with three isolation tiers: `native` (OS process sandbox, like Claude Code and Codex), `vm` (containers: the podman machine on macOS, Docker Engine or podman on Linux), `remote` (Firecracker microVMs on Linux/KVM). A browser inside the sandbox, in-sandbox telemetry and escape detection, a Go control plane with sessions/traces/alerts, a React dashboard, a TypeScript SDK, and a `pi` harness extension as the reference client.

**Target deployment:** air-gapped / on-prem environments at a fixed, declared scale — small to medium fleets first (one control plane + SQLite, a handful to a few dozen worker hosts). It can grow past that, but elastic, hyperscale or hosted-SaaS use is not the initial target. Design consequences: no cloud dependency or phone-home, every artifact can be carried in offline, capacity is a calculation (sizes × declared host caps, no overcommit by default), not autoscaling.

This is a standalone repository and product. Do not read or import from `../llm-router`.

## Read first
1. `README.md` — what it is, and the one-machine quick start (packages, Docker, macOS from source).
2. `docs/protocol.md` — the contract (v1–v5.3). Change it only via the lead, in one commit with `crates/proto`, `sdk/ts/src/types.ts`, `controlplane/internal/events/types.go` (and `web/src/lib/types.ts`).
3. `docs/decisions.md` — D1–D32, decisions already made; do not re-open them.
4. `docs/security.md` — controls in place vs deferred (M1–M45); `SECURITY.md` — how to report.
5. `docs/deployment.md` — production: roles, ports, permissions, install methods, TLS, Firecracker workers, operations. `docs/airgap.md` — the offline install.

## Working model
- **Lead (Fable) plans, reviews and validates every gate.** Implementation is delegated to Opus (daemon), Sonnet (control plane, SDK, bench, dashboard) and Haiku (build, deploy, docs). Nobody starts before the contract is committed.
- Implementation agents report; the lead runs the gate commands personally and records what was observed in the commit or the PR.
- Ponytail rules: minimum code that works, reuse before write, no speculative abstractions, one runnable check per non-trivial module, `ponytail:` comment on every deliberate shortcut naming the ceiling and the upgrade path.

## Stack (decided)
Rust 1.89 workspace (`crates/proto`, `crates/agent-core`, `crates/guest-agent`, `crates/qafas`; static musl for both `aarch64` and `x86_64`), Go 1.26 stdlib control plane with SQLite (`modernc.org/sqlite`), React 19 + Vite + StyleX + `@astryxdesign` UI, TypeScript SDK (`sdk/ts`) and pi extension (loaded by pi's jiti, no build). Ports: guest-agent 7777, qafas 7700, control plane 7800, UI dev 5173, egress proxy 3128.

## Hard rules
- LLM API keys never enter a sandbox. pi runs on the host.
- `user_bash` handler in the pi extension must never throw (pi falls back to host execution). Return a failed result instead.
- Egress is deny-by-default and enforced outside the sandbox; the sandbox has no DNS resolver of its own (on Docker, the embedded resolver answers only sandbox-network names: D32).
- The workspace is mounted or extracted at the identical absolute path inside the sandbox. No path translation layer.
- Chromium is never launched with `--single-process`.
- Every qafas event carries `pi_session` and `tool_call_id` from the request headers.
- `trust: untrusted` never resolves to the `native` tier. Only the harness (never the model) can widen egress.
- Detection signals from the boundary (proxy, sandbox denials, seccomp kills) are authoritative; in-sandbox telemetry is enrichment.

## Machine notes (dev Mac)
M5 Pro, 24 GB, macOS 26. `podman-machine-default` is applehv, currently 2 vCPU / 1.9 GB — resize to 6 / 8192 before browser work. Rust has only the darwin target installed; run `make tools` first. Playwright 1.63 browsers cached under `~/Library/Caches/ms-playwright`. pi 0.83 at `/opt/homebrew/lib/node_modules/@earendil-works/pi-coding-agent` (its `examples/extensions/gondolin/index.ts` is the extension pattern to copy).

## Commands
`make tools` · `make machine` · `make guest-agent` · `make image` · `make qafas` · `make cp` · `make web` · `make sdk` · `make dev-local` · `make test` · `make demo` · `make bench` · `make doctor` · `scripts/package.sh <version>` (deb/rpm via nfpm, plus what `deploy/docker/Dockerfile.*` COPY)

## Releasing
[Release Please](https://github.com/googleapis/release-please), as in llm-router. Title every PR as a conventional commit and squash- or rebase-merge it: `fix:` is a patch, `feat:` a minor, `feat!:`/`BREAKING CHANGE` also a minor before 1.0; `chore:`, `docs:`, `ci:`, `test:` don't release. `release.yml` keeps one release PR open on main ("chore(main): release X.Y.Z") that collects them into `CHANGELOG.md` and the version everywhere it is written (`release-please-config.json` `extra-files`: `VERSION`, Cargo.toml/lock, the SDKs, the three protocol mirrors, `deploy/docker/.env.example`, the install docs' `V=` lines). Merging it tags vX.Y.Z and opens the GitHub release as a draft; the same run builds and attaches the deb/rpm packages, the linux and darwin tarballs, the CLI tgz, `sbx-base-<v>-<arch>.tar.zst`, `qafas-firecracker-<v>-<arch>.tar.zst`, `images.txt` with `qafas-save-images.sh`/`qafas-load-images.sh`, pushes `ghcr.io/<owner>/qafas-sandbox/{sbx-base,controlplane,qafas,sbx}`, and `finalize` writes `SHA256SUMS` and publishes. Don't edit `VERSION` or `CHANGELOG.md`, and don't tag by hand. The release PR gets no CI of its own (the workflow token opens it); its commits already passed. The guest image and the daemon must be the same version (the egress proxy runs the image's `qafas`). npm/PyPI publishing is off (`PUBLISH_NPM`/`PUBLISH_PYPI` repo variables) — never turn it on, or make the repo public, without the user. Re-run a release's build: `gh workflow run release.yml -f tag=vX.Y.Z`. Branch protection: `scripts/protect-main.sh` once the repo is public.
