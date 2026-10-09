// MCP (Model Context Protocol) stdio server over qafas-sandbox. Hand-rolled JSON-RPC 2.0,
// newline-delimited on stdin/stdout — no MCP SDK dependency (design: ~150 lines covers
// initialize/tools-list/tools-call/ping, which is all a tool-only server needs; the
// official SDK would be for resources/prompts/sampling parity, not a fix).
//
// One sandbox per process, acquired lazily on the first tools/call and destroyed on stdin
// close or SIGTERM. Workspace is always process.cwd(). Errors from tool execution are
// returned as MCP tool errors (isError: true), never thrown — a crash here kills the
// client's whole MCP connection.
import * as readline from "node:readline";
import * as path from "node:path";
import { acquire, parseLimits, validateIsolation } from "./index.js";
import type { AcquireResult } from "./index.js";
import type { SandboxLimits } from "./types.js";

const PROTOCOL_VERSION = "2025-06-18";
const SERVER_INFO = { name: "sandbox-mcp", version: "0.4.0" };

interface JsonRpcRequest {
	jsonrpc: "2.0";
	id?: string | number;
	method: string;
	params?: Record<string, unknown>;
}

function reply(id: string | number | undefined, result: unknown) {
	if (id === undefined) return; // notification: no response
	process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, result })}\n`);
}

function replyError(id: string | number | undefined, code: number, message: string) {
	if (id === undefined) return;
	process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } })}\n`);
}

function toolText(text: string, isError = false) {
	return { content: [{ type: "text", text }], isError };
}

function q(s: string): string {
	return `'${s.replace(/'/g, `'\\''`)}'`;
}

// -------------------------------------------------------------- CLI flags / env

function parseFlags(argv: string[]): Record<string, string> {
	const flags: Record<string, string> = {};
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (a.startsWith("--")) {
			const [key, inlineVal] = a.slice(2).split(/=(.*)/s);
			if (inlineVal !== undefined) flags[key] = inlineVal;
			else if (argv[i + 1] !== undefined && !argv[i + 1].startsWith("--")) flags[key] = argv[++i];
			else flags[key] = "true";
		}
	}
	return flags;
}

// -------------------------------------------------------------- tool catalog

const TOOLS = [
	{
		name: "sandbox_exec",
		description: "Run a shell command inside the sandbox and return its stdout/stderr/exit code.",
		inputSchema: {
			type: "object",
			properties: {
				command: { type: "string", description: "Shell command to run" },
				cwd: { type: "string", description: "Working directory (absolute path); defaults to the workspace root" },
				timeout_ms: { type: "number", description: "Timeout in milliseconds" },
			},
			required: ["command"],
		},
	},
	{
		name: "sandbox_read",
		description: "Read a text file from the sandbox filesystem.",
		inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
	},
	{
		name: "sandbox_write",
		description: "Write (create or overwrite) a text file in the sandbox filesystem.",
		inputSchema: {
			type: "object",
			properties: { path: { type: "string" }, content: { type: "string" } },
			required: ["path", "content"],
		},
	},
	{
		name: "sandbox_ls",
		description: "List directory entries in the sandbox filesystem.",
		inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
	},
	{
		name: "sandbox_grep",
		description: "Search file contents in the sandbox using ripgrep.",
		inputSchema: {
			type: "object",
			properties: {
				pattern: { type: "string", description: "Regex pattern (ripgrep syntax)" },
				path: { type: "string", description: "File or directory to search; defaults to the workspace root" },
			},
			required: ["pattern"],
		},
	},
	// sandbox_browser_navigate: skipped — needs playwright-core + a running Chromium in the
	// sandbox, which is more than a stdio MCP server should pull in as a hard dependency.
	// Add it as its own optional entry point if a client needs browser control over MCP.
];

// -------------------------------------------------------------- sandbox lifecycle

let acquired: Promise<AcquireResult> | null = null;

// --isolation/--runtime (alias) pick the tier: auto|native|vm|remote or the product-name
// aliases process|docker|firecracker (docs/protocol.md §3); validated here and passed
// through raw — the server normalises the alias, this SDK never translates it.
// --template/--snapshot (alias) pick a named snapshot to build the sandbox from.
// --size/--limits (v5): the server's own flags, never a tool parameter — the model never
// picks resources (docs/protocol.md §3a "v5 sizes and limits", same rule as egress, D22).
function getSandbox(flags: Record<string, string>): Promise<AcquireResult> {
	if (!acquired) {
		const url = flags.url ?? process.env.SBX_URL ?? "http://127.0.0.1:7700";
		const cwd = process.cwd();
		const piSession = `sbx-mcp-${process.pid}`;
		acquired = acquire(url, cwd, piSession, {
			isolation: validateIsolation(flags.isolation ?? flags.runtime),
			tools: flags.tools ? flags.tools.split(",") : undefined,
			template: flags.template,
			snapshot: flags.snapshot,
			size: flags.size,
			limits: flags.limits ? (parseLimits(flags.limits) as unknown as SandboxLimits) : undefined,
		});
	}
	return acquired;
}

async function destroySandbox() {
	if (!acquired) return;
	try {
		const sb = await acquired;
		await sb.client.destroy();
	} catch {
		// best-effort on shutdown
	}
}

// -------------------------------------------------------------- tool dispatch

async function callTool(name: string, args: Record<string, unknown>, flags: Record<string, string>) {
	const { client, workspacePath } = await getSandbox(flags);
	switch (name) {
		case "sandbox_exec": {
			const command = String(args.command ?? "");
			const cwd = typeof args.cwd === "string" ? args.cwd : workspacePath;
			const timeoutMs = typeof args.timeout_ms === "number" ? args.timeout_ms : undefined;
			const res = await client.execBuffered(command, cwd, { timeoutMs });
			const body = [`exit: ${res.exit}`, res.stdout && `--- stdout ---\n${res.stdout}`, res.stderr && `--- stderr ---\n${res.stderr}`]
				.filter(Boolean)
				.join("\n");
			return toolText(body || `exit: ${res.exit}`);
		}
		case "sandbox_read": {
			const buf = await client.readFile(String(args.path ?? ""));
			return toolText(buf.toString("utf8"));
		}
		case "sandbox_write": {
			await client.writeFile(String(args.path ?? ""), String(args.content ?? ""));
			return toolText(`wrote ${Buffer.byteLength(String(args.content ?? ""))} bytes to ${args.path}`);
		}
		case "sandbox_ls": {
			const names = await client.list(String(args.path ?? ""));
			return toolText(names.join("\n") || "(empty)");
		}
		case "sandbox_grep": {
			const pattern = String(args.pattern ?? "");
			const root = typeof args.path === "string" ? path.resolve(workspacePath, args.path) : workspacePath;
			const cmd = ["rg", "--line-number", "--with-filename", "--color=never", "--", q(pattern), q(root)].join(" ");
			const res = await client.execBuffered(cmd, workspacePath);
			if (res.exit === 1 && !res.stdout.trim()) return toolText("No matches found");
			if (res.exit !== 0 && res.exit !== 1) return toolText(`grep failed (exit ${res.exit}): ${res.stderr || res.stdout}`, true);
			return toolText(res.stdout);
		}
		default:
			return toolText(`unknown tool: ${name}`, true);
	}
}

// -------------------------------------------------------------- JSON-RPC loop

async function handleMessage(msg: JsonRpcRequest, flags: Record<string, string>) {
	try {
		switch (msg.method) {
			case "initialize":
				reply(msg.id, { protocolVersion: PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: SERVER_INFO });
				return;
			case "ping":
				reply(msg.id, {});
				return;
			case "notifications/initialized":
				return; // notification, no response
			case "tools/list":
				reply(msg.id, { tools: TOOLS });
				return;
			case "tools/call": {
				const name = String(msg.params?.name ?? "");
				const args = (msg.params?.arguments as Record<string, unknown>) ?? {};
				try {
					const result = await callTool(name, args, flags);
					reply(msg.id, result);
				} catch (err) {
					// Tool failures are protocol-level successes carrying isError: true — never
					// throw out of tools/call, or the client tears down the whole connection.
					reply(msg.id, toolText(err instanceof Error ? err.message : String(err), true));
				}
				return;
			}
			default:
				replyError(msg.id, -32601, `method not found: ${msg.method}`);
		}
	} catch (err) {
		replyError(msg.id, -32603, err instanceof Error ? err.message : String(err));
	}
}

export async function runMcpServer(argv: string[]): Promise<void> {
	const flags = parseFlags(argv);
	const rl = readline.createInterface({ input: process.stdin, terminal: false });

	// Track in-flight messages so a stdin close (piped input ends right after the last
	// write, well before a slow tools/call like an sandbox acquire resolves) doesn't kill
	// the process out from under a response that's still being written.
	const inFlight = new Set<Promise<unknown>>();

	rl.on("line", (line) => {
		const trimmed = line.trim();
		if (!trimmed) return;
		let msg: JsonRpcRequest;
		try {
			msg = JSON.parse(trimmed);
		} catch {
			replyError(undefined, -32700, "parse error");
			return;
		}
		const p = handleMessage(msg, flags).finally(() => inFlight.delete(p));
		inFlight.add(p);
	});

	const shutdown = async () => {
		await Promise.allSettled([...inFlight]);
		await destroySandbox();
		process.exit(0);
	};
	rl.on("close", shutdown);
	process.on("SIGTERM", shutdown);
	process.on("SIGINT", shutdown);
}
