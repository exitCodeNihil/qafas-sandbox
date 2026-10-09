# qafas-sandbox

Node/TypeScript client for [Qafas Sandbox](https://github.com/exitCodeNihil/qafas-sandbox), plus the `sbx` CLI and an MCP server. Talk to the control plane (`:7800`), which places the sandbox and hands back the worker to use, or directly to one worker (`:7700`). The pi extension uses this same client.

## Install

From a release (`qafas-sandbox-<version>.tgz`; it is also inside the `qafas-cli` deb/rpm, which puts `sbx` on the PATH):

```bash
npm install -g ./qafas-sandbox-<version>.tgz      # the CLI
npm install ./qafas-sandbox-<version>.tgz         # the library, in a project
```

Node 22+. No runtime dependencies; uses the global `fetch` and `WebSocket`.

## 30 seconds

```ts
import { Sandbox } from "qafas-sandbox";

// No cwd: the sandbox gets its own /home/agent and nothing is uploaded implicitly.
const sb = await Sandbox.create("http://127.0.0.1:7800", undefined, "my-session", { runtime: "docker" });
try {
	await sb.upload("./fixtures", `${sb.workspacePath}/fixtures`);
	console.log(await sb.run("npm test")); // throws on a nonzero exit, returns stdout
	await sb.download(`${sb.workspacePath}/fixtures/report.json`, "./report.json");
} finally {
	await sb.delete();
}
```

- `runtime` is `"process" | "docker" | "firecracker"` (the wire's `native | vm | remote`, which `isolation` also takes). Omit it and the control plane picks, Firecracker first.
- Pass a `cwd` as the second argument to start from a local directory: it is mounted at the same path (`native`, `vm`) or tarred and uploaded (`remote`).
- `acquire()` / `withSandbox()` are the same path with a callback that always destroys; the handle also covers sessions, stop/start, snapshots (`Image`), preview URLs and the browser (CDP). The types in `src/types.ts` mirror the wire contract, `docs/protocol.md`.

## Configuration

| variable | |
|---|---|
| `SBX_URL` | the control plane (`http://cp:7800`) or a worker (`http://worker:7700`); the CLI's default is `http://localhost:7800` |
| `SBX_API_KEY` | an API key from the dashboard — preferred: scoped to its own sandboxes and limits |
| `SBX_ADMIN_TOKEN` | the control plane's admin token, when there is no key |
| `SBX_TOKEN` | a worker's own token, when talking to a worker directly |
| `SBX_CA_FILE` | a CA bundle for an `https://` control plane or worker on an internal CA (`NODE_EXTRA_CA_CERTS` works too); a worker's self-signed certificate is pinned automatically from the fingerprint the control plane returns |
| `SBX_ENV_PASS` | extra host environment variable names to pass into a sandbox (`FOO,BAR`); by default only terminal, locale and git identity settings pass, so model API keys never do |

## The `sbx` CLI

```bash
sbx doctor                                    # what the target is, which tiers are up
sbx run [--isolation vm] [--size mini] -- 'pytest -q'     # create, run in the current directory, destroy
sbx shell [<sandbox_id>] [--keep]             # an interactive shell; --keep leaves it running; an id rejoins
sbx ls                                        # every sandbox the control plane knows
sbx events <sandbox_id> [--follow]            # process, file and network timeline
sbx mcp [--isolation …] [--template <name>]   # an MCP server on stdio
```

## Coding agents

`sbx mcp` exposes `sandbox_exec`, `sandbox_read`, `sandbox_write`, `sandbox_ls` and `sandbox_grep` over MCP (stdio). One sandbox is created on the first tool call, with the agent's working directory as its workspace, and destroyed when the agent exits. Ready-made configuration is in `deploy/harnesses/`:

- **Claude Code** — `claude mcp add sandbox -- sbx mcp --isolation vm`, or route the built-in Bash tool itself into the sandbox with the `PreToolUse` hook in `deploy/harnesses/claude-code/` (`sandbox-bash.sh` + `settings.json`).
- **Codex** — `deploy/harnesses/codex/config.toml` adds the MCP server to `~/.codex/config.toml`.
- **Cursor** — `deploy/harnesses/cursor/mcp.json`, plus the `sandbox.mdc` rule that tells the agent to use it.
- **pi** — the `pi-extension/` in this repository replaces pi's own bash, read, write and browser tools with sandboxed ones.

Give each agent its own API key (`SBX_API_KEY` in the server's `env`), so its sandboxes, usage and alerts are attributed to it on the dashboard.

## Build and test

```bash
npm run build
npm run typecheck
npm test        # node --test test/ — most tests need a reachable qafas (SBX_URL, default :7700)
```
