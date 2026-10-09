#!/usr/bin/env node
// Gate B: node pi-extension/scripts/containment.mjs
// Drives `pi --mode rpc -e ./pi-extension` over JSONL on stdin/stdout and asserts the
// five containment properties of the local tiers (decisions.md D4, D6). Split stdout on "\n"
// only (never node:readline: it also splits on U+2028/U+2029, which are legal inside
// JSON strings, per pi's own RPC docs).
//
// Talks to qafas directly (SBX_URL, default :7700) rather than through the control
// plane, matching how Gate B starts things (`SBX_BACKEND=podman SBX_TOKEN=dev
// ./target/release/qafas &`, no control plane). Set SKIP_KILL=1 to skip assertion 5's
// `pkill qafas` (e.g. when testing against a fake daemon that isn't
// qafas and has no isolation of its own — assertions 1/2/4 only prove anything
// against the real qafas/guest-agent; this script exercises the RPC/user_bash
// mechanics either way).
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const EXT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SANDBOX_URL = process.env.SBX_URL ?? "http://127.0.0.1:7700";
const CWD = process.cwd();

let failures = 0;
function check(name, ok, detail = "") {
	console.log(`${ok ? "PASS" : "FAIL"}: ${name}${detail ? ` (${detail})` : ""}`);
	if (!ok) failures++;
}

/** Spawns `pi --mode rpc`, returns { rpcBash(command), kill() }. */
function startPi() {
	const proc = spawn(
		"pi",
		["--mode", "rpc", "--no-session", "--no-context-files", "--sandbox-url", SANDBOX_URL, "-e", EXT_DIR],
		// A secret-looking host variable: it must never be visible inside the sandbox (D6).
		{ cwd: CWD, env: { ...process.env, SBX_TEST_SECRET_TOKEN: "leak-me" }, stdio: ["pipe", "pipe", "inherit"] },
	);
	let buf = "";
	const waiters = new Map(); // id -> resolve
	proc.stdout.on("data", (chunk) => {
		buf += chunk.toString("utf8");
		let idx;
		// biome-ignore lint: intentional \n-only split, not readline (see file header).
		while ((idx = buf.indexOf("\n")) >= 0) {
			const line = buf.slice(0, idx);
			buf = buf.slice(idx + 1);
			if (!line.trim()) continue;
			let msg;
			try {
				msg = JSON.parse(line);
			} catch {
				continue;
			}
			if (msg.type === "response" && waiters.has(msg.id)) {
				waiters.get(msg.id)(msg);
				waiters.delete(msg.id);
			}
		}
	});

	let seq = 0;
	function rpcBash(command, timeoutMs = 30_000) {
		const id = `req-${++seq}`;
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				waiters.delete(id);
				reject(new Error(`timed out waiting for response to ${id}`));
			}, timeoutMs);
			waiters.set(id, (msg) => {
				clearTimeout(timer);
				resolve(msg.data);
			});
			proc.stdin.write(`${JSON.stringify({ id, type: "bash", command })}\n`);
		});
	}

	return { proc, rpcBash, kill: () => proc.kill() };
}

const pi = startPi();

try {
	// 0. The sandbox actually works; otherwise the "unreadable" checks below pass vacuously.
	const probe = await pi.rpcBash("id -u");
	// uid 1000 in the VM tier; the host user in the native tier (Seatbelt does not change uid).
	check("sandbox reachable", probe.exitCode === 0 && /^\d+$/.test(probe.output.trim()), `exit=${probe.exitCode} out=${JSON.stringify(probe.output.trim())}`);

	// 1. ~/.ssh/id_rsa and ~/.aws/credentials are not mounted.
	const ssh = await pi.rpcBash("cat ~/.ssh/id_rsa");
	check("~/.ssh/id_rsa unreadable", ssh.exitCode !== 0, `exit=${ssh.exitCode}`);
	const aws = await pi.rpcBash("cat ~/.aws/credentials");
	check("~/.aws/credentials unreadable", aws.exitCode !== 0, `exit=${aws.exitCode}`);

	// 2. No LLM credentials leak into the sandbox environment.
	const env = await pi.rpcBash("env | grep -c ANTHROPIC");
	check("no ANTHROPIC_* in sandbox env", env.output.trim() === "0", `got=${JSON.stringify(env.output.trim())}`);

	// 2b. The harness's own environment does not cross the boundary.
	const leak = await pi.rpcBash("env | grep -c SBX_TEST_SECRET_TOKEN");
	check("host env vars do not reach the sandbox", leak.output.trim() === "0", `got=${JSON.stringify(leak.output.trim())}`);

	// 3. Writes from the sandbox are visible on the host at the identical path (D4).
	const proofPath = path.join(CWD, "proof-from-sandbox");
	fs.rmSync(proofPath, { force: true });
	await pi.rpcBash(`touch ${JSON.stringify(proofPath)}`);
	check("write from sandbox appears on host", fs.existsSync(proofPath), proofPath);
	fs.rmSync(proofPath, { force: true });

	// 4. The cloud metadata address is denied by the egress proxy.
	const meta = await pi.rpcBash("curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://169.254.169.254/ || echo DENIED");
	check("169.254.169.254 denied", meta.exitCode === 0 && meta.output.trim() !== "200", `got=${JSON.stringify(meta.output.trim())}`);
} finally {
	pi.kill();
}

// 5. Regression test for pi issue #9068: when qafas is unreachable, user_bash must
// fail closed (exitCode 1), never fall back to running on the host.
if (process.env.SKIP_KILL !== "1") {
	spawn("pkill", ["-f", "qafas serve"]).on("error", () => {}); // best-effort
	await new Promise((r) => setTimeout(r, 500));
}
const hostLeakPath = "/tmp/host-leak";
fs.rmSync(hostLeakPath, { force: true });
const pi2 = startPi();
try {
	const leak = await pi2.rpcBash(`touch ${hostLeakPath}`);
	check("user_bash fails closed when sandbox is unreachable", leak.exitCode === 1, `exit=${leak.exitCode}`);
	check("host was not touched (issue #9068 regression)", !fs.existsSync(hostLeakPath));
} finally {
	pi2.kill();
	fs.rmSync(hostLeakPath, { force: true });
}

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
