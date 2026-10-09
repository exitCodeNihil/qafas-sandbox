// Scripted stdin/stdout MCP session against `sbx mcp`, run as a child process. Skips
// cleanly if no qafas is reachable at SANDBOX_URL/SBX_URL (default :7700) — this is a
// live protocol test, not a mock.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(__dirname, "..", "bin", "sbx");
const URL = process.env.SANDBOX_URL ?? process.env.SBX_URL ?? "http://127.0.0.1:7700";

async function daemonUp() {
	try {
		const res = await fetch(`${URL}/healthz`, { signal: AbortSignal.timeout(1000) });
		return res.ok;
	} catch {
		return false;
	}
}

/** Runs `sbx mcp`, sends `requests` one JSON-RPC message per line, and collects one
 * parsed JSON response per line of stdout until `count` responses arrive. */
function runSession(requests, count) {
	return new Promise((resolve, reject) => {
		const child = spawn(process.execPath, [BIN, "mcp", "--url", URL], {
			env: { ...process.env, SBX_TOKEN: process.env.SBX_TOKEN ?? "dev" },
			stdio: ["pipe", "pipe", "pipe"],
		});
		const responses = [];
		let buf = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => {
			buf += chunk.toString();
			let idx;
			while ((idx = buf.indexOf("\n")) >= 0) {
				const line = buf.slice(0, idx);
				buf = buf.slice(idx + 1);
				if (line.trim()) responses.push(JSON.parse(line));
			}
			if (responses.length >= count) {
				child.kill("SIGTERM");
			}
		});
		child.stderr.on("data", (chunk) => {
			stderr += chunk.toString();
		});
		child.on("close", () => resolve({ responses, stderr }));
		child.on("error", reject);

		for (const req of requests) child.stdin.write(`${JSON.stringify(req)}\n`);
	});
}

test("MCP session: initialize -> tools/list -> tools/call sandbox_exec", { skip: !(await daemonUp()) && "no qafas reachable" }, async () => {
	const { responses } = await runSession(
		[
			{ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } },
			{ jsonrpc: "2.0", method: "notifications/initialized" },
			{ jsonrpc: "2.0", id: 2, method: "tools/list" },
			{ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "sandbox_exec", arguments: { command: "node -v" } } },
		],
		3,
	);

	assert.equal(responses.length, 3);

	const init = responses.find((r) => r.id === 1);
	assert.equal(init.result.protocolVersion, "2025-06-18");
	assert.ok(init.result.serverInfo.name);

	const list = responses.find((r) => r.id === 2);
	const names = list.result.tools.map((t) => t.name);
	assert.deepEqual(names.sort(), ["sandbox_exec", "sandbox_grep", "sandbox_ls", "sandbox_read", "sandbox_write"]);

	const call = responses.find((r) => r.id === 3);
	assert.equal(call.result.isError, false);
	assert.match(call.result.content[0].text, /^exit: 0/);
	assert.match(call.result.content[0].text, /v\d+\.\d+\.\d+/);
});

test("MCP tools/call on unknown tool returns isError, does not crash", { skip: !(await daemonUp()) && "no qafas reachable" }, async () => {
	const { responses } = await runSession(
		[
			{ jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
			{ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "sandbox_nope", arguments: {} } },
		],
		2,
	);
	const call = responses.find((r) => r.id === 2);
	assert.equal(call.result.isError, true);
});
