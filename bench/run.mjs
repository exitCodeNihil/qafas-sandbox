#!/usr/bin/env node
// bench/run.mjs --backend native|vm|remote|e2b [--cases acquire,exec,fs,git,npm,uv,browser]
//   [--url <base>] [--n 200]
//
// Drives qafas/control-plane through qafas-sandbox (never qafas's HTTP API
// directly) so this measures exactly what pi and `sbx` experience. Writes
// bench/results/<date>-<host>-<backend>.json and prints a markdown table.
//
// design: one flat script, no test-runner dependency — seven cases, each ~20 lines.
import { acquire } from "qafas-sandbox";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";
import { parseArgs } from "node:util";

const BENCH_DIR = path.dirname(fileURLToPath(import.meta.url));
// The acquire/exec/fs cases run in a fixture with two files, not in bench/
// itself: fixtures/many-files (10k files) lives under it and a remote acquire
// tars the workspace, which would make "acquire" measure the tar instead.
const SMALL_DIR = path.join(BENCH_DIR, "fixtures", "small");
fs.mkdirSync(SMALL_DIR, { recursive: true });
fs.writeFileSync(path.join(SMALL_DIR, "index.js"), "console.log('bench')\n");
const ALL_CASES = ["acquire", "exec", "fs", "git", "npm", "uv", "browser"];

const { values: flags } = parseArgs({
	options: {
		backend: { type: "string" },
		cases: { type: "string" },
		url: { type: "string" },
		n: { type: "string" },
	},
});
if (!flags.backend) {
	console.error("usage: bench/run.mjs --backend native|vm|remote|e2b [--cases acquire,exec,fs,git,npm,uv,browser] [--url] [--n 200]");
	process.exit(2);
}
const backend = flags.backend;
const cases = (flags.cases ? flags.cases.split(",") : ALL_CASES).filter((c) => ALL_CASES.includes(c));
const n = Number(flags.n ?? 200);
const url = flags.url ?? process.env.SBX_URL ?? "http://localhost:7700";

function percentiles(samplesMs) {
	const sorted = [...samplesMs].sort((a, b) => a - b);
	const pct = (p) => sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
	return { p50: pct(50), p95: pct(95), p99: pct(99), min: sorted[0], max: sorted.at(-1), n: sorted.length };
}

async function timeit(fn) {
	const t0 = performance.now();
	const result = await fn();
	return { ms: performance.now() - t0, result };
}

/** acquire() for this backend: isolation maps 1:1 to the CLI's --backend value, except
 * e2b (handled entirely separately — never goes through qafas-sandbox). */
async function acquireForBackend(cwd, opts = {}) {
	const piSession = `bench-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
	return acquire(url, cwd, piSession, { isolation: backend === "e2b" ? undefined : backend, ...opts });
}

// ---- cases

/** Waits until the daemon's pool (GET /pool, qafas only) holds a warm sandbox,
 * so "warm acquire" measures the pop, not the refill a tight loop would otherwise
 * outrun with SBX_POOL_SIZE=1. Through the control plane there is no pool view:
 * a fixed pause covers a container refill. */
async function waitForWarm() {
	const tok = process.env.SBX_TOKEN ?? "";
	for (let i = 0; i < 100; i++) {
		const r = await fetch(`${url}/pool`, { headers: { Authorization: `Bearer ${tok}` } }).catch(() => null);
		// The control plane answers /pool with the SPA's HTML: no pool view there.
		if (!r || !r.ok || !(r.headers.get("content-type") ?? "").includes("json")) return new Promise((res) => setTimeout(res, 3000));
		const pool = await r.json();
		if (Object.values(pool).some((p) => p.warm > 0)) return;
		await new Promise((res) => setTimeout(res, 100));
	}
}

/** Holds every warm sandbox the pool has so the next acquire has to boot. */
async function drainPool() {
	const tok = process.env.SBX_TOKEN ?? "";
	const held = [];
	for (let i = 0; i < 16; i++) {
		const r = await fetch(`${url}/pool`, { headers: { Authorization: `Bearer ${tok}` } }).catch(() => null);
		if (!r || !r.ok || !(r.headers.get("content-type") ?? "").includes("json")) break; // control plane: no pool view, cold is best-effort
		if (!Object.values(await r.json()).some((p) => p.warm > 0)) break;
		held.push(await acquireForBackend(SMALL_DIR));
	}
	return held;
}

async function caseAcquire(results) {
	const held = await drainPool();
	const cold = await timeit(() => acquireForBackend(SMALL_DIR));
	await cold.result.client.destroy().catch(() => {});
	for (const h of held) await h.client.destroy().catch(() => {});
	const warmSamples = [];
	for (let i = 0; i < 5; i++) {
		await waitForWarm();
		const { ms, result } = await timeit(() => acquireForBackend(SMALL_DIR));
		warmSamples.push(ms);
		await result.client.destroy().catch(() => {});
	}
	results.acquire = { cold_ms: cold.ms, warm: percentiles(warmSamples) };
}

async function caseExec(results) {
	const { result } = await timeit(() => acquireForBackend(SMALL_DIR));
	try {
		const samples = [];
		for (let i = 0; i < n; i++) {
			const { ms } = await timeit(() => result.client.execBuffered("true", SMALL_DIR));
			samples.push(ms);
		}
		results.exec = percentiles(samples);
	} finally {
		await result.client.destroy().catch(() => {});
	}
}

async function caseFs(results) {
	const { result } = await timeit(() => acquireForBackend(SMALL_DIR));
	try {
		const buf = Buffer.alloc(1024 * 1024, 0x42); // 1 MiB
		const writeSamples = [];
		const readSamples = [];
		const remotePath = `${result.workspacePath}/.bench-1mib.bin`;
		for (let i = 0; i < 20; i++) {
			const w = await timeit(() => result.client.writeFile(remotePath, buf));
			writeSamples.push(w.ms);
			const r = await timeit(() => result.client.readFile(remotePath));
			readSamples.push(r.ms);
		}
		await result.client.execBuffered(`rm -f ${JSON.stringify(remotePath)}`, SMALL_DIR).catch(() => {});
		results.fs = { write_1mib: percentiles(writeSamples), read_1mib: percentiles(readSamples) };
	} finally {
		await result.client.destroy().catch(() => {});
	}
}

function ensureManyFiles() {
	const dir = path.join(BENCH_DIR, "fixtures", "many-files");
	const marker = path.join(dir, ".generated");
	if (fs.existsSync(marker)) return dir;
	console.error("# generating bench/fixtures/many-files (10k files)...");
	fs.rmSync(dir, { force: true, recursive: true });
	fs.mkdirSync(dir, { recursive: true });
	for (let i = 0; i < 10_000; i++) {
		const sub = path.join(dir, String(i % 100).padStart(2, "0"));
		fs.mkdirSync(sub, { recursive: true });
		fs.writeFileSync(path.join(sub, `file-${i}.txt`), `bench fixture file ${i}\n`);
	}
	execSync("git init -q && git add -A && git -c user.email=bench@local -c user.name=bench commit -q -m init", { cwd: dir });
	fs.writeFileSync(marker, "");
	return dir;
}

async function caseGit(results) {
	const dir = ensureManyFiles();
	const { result } = await timeit(() => acquireForBackend(dir));
	try {
		const { ms, result: r } = await timeit(() => result.client.execBuffered("git status", dir));
		results.git_status_10k_files = { ms, exit: r.exit };
	} finally {
		await result.client.destroy().catch(() => {});
	}
}

async function caseNpm(results) {
	const dir = path.join(BENCH_DIR, "fixtures", "node-app");
	fs.rmSync(path.join(dir, "node_modules"), { force: true, recursive: true });
	const { result } = await timeit(() => acquireForBackend(dir));
	try {
		const { ms, result: r } = await timeit(() => result.client.execBuffered("npm ci", dir, { timeoutMs: 5 * 60_000 }));
		results.npm_ci = { ms, exit: r.exit, stderr_tail: r.exit !== 0 ? r.stderr.slice(-500) : undefined };
	} finally {
		await result.client.destroy().catch(() => {});
		fs.rmSync(path.join(dir, "node_modules"), { force: true, recursive: true });
	}
}

async function caseUv(results) {
	const dir = path.join(BENCH_DIR, "fixtures", "py-app");
	fs.rmSync(path.join(dir, ".venv"), { force: true, recursive: true });
	const { result } = await timeit(() => acquireForBackend(dir));
	try {
		const { ms, result: r } = await timeit(() => result.client.execBuffered("uv sync", dir, { timeoutMs: 5 * 60_000 }));
		results.uv_sync = { ms, exit: r.exit, stderr_tail: r.exit !== 0 ? r.stderr.slice(-500) : undefined };
		if (r.exit !== 0) console.error(`# uv sync: guest reported exit ${r.exit} (uv/python likely missing in this image) — see stderr_tail in the result file`);
	} finally {
		await result.client.destroy().catch(() => {});
		fs.rmSync(path.join(dir, ".venv"), { force: true, recursive: true });
	}
}

async function caseBrowser(results) {
	let playwright;
	try {
		playwright = await import("playwright-core");
	} catch {
		results.browser = { skipped: "playwright-core not installed" };
		return;
	}
	const { result } = await timeit(() => acquireForBackend(SMALL_DIR, { tools: ["chromium"] }));
	if ((result.missingTools ?? []).includes("chromium")) {
		results.browser = { skipped: `no chromium on the ${result.isolation ?? backend} tier` };
		await result.client.destroy().catch(() => {});
		return;
	}
	try {
		const { ms: connectMs, result: browser } = await timeit(() =>
			playwright.chromium.connectOverCDP(result.client.cdpUrl, { headers: { Authorization: `Bearer ${result.client.token}` } }),
		);
		try {
			const context = browser.contexts()[0] ?? (await browser.newContext());
			const page = context.pages()[0] ?? (await context.newPage());
			const { ms: navMs } = await timeit(() => page.goto("https://example.com", { waitUntil: "domcontentloaded" }));
			results.browser = { connect_ms: connectMs, navigate_example_com_ms: navMs };
		} finally {
			await browser.close().catch(() => {});
		}
	} catch (err) {
		results.browser = { error: err instanceof Error ? err.message : String(err) };
	} finally {
		await result.client.destroy().catch(() => {});
	}
}

async function runE2B(results) {
	if (!process.env.E2B_API_KEY) {
		console.error("bench: --backend e2b requires E2B_API_KEY; skipping.");
		return;
	}
	let e2b;
	try {
		e2b = await import("e2b");
	} catch {
		console.error("bench: --backend e2b requires the `e2b` npm package (not installed — it is intentionally not a hard dependency of bench/). Run: npm i e2b");
		return;
	}
	const samples = [];
	const cold = await timeit(() => e2b.Sandbox.create());
	samples.push(cold.ms);
	try {
		const { ms } = await timeit(() => cold.result.commands.run("true"));
		results.e2b_exec_true_ms = ms;
	} finally {
		await cold.result.kill().catch(() => {});
	}
	results.e2b_acquire_cold_ms = cold.ms;
}

// ---- main

const results = { backend, host: os.hostname(), url, at: new Date().toISOString(), cases: {} };

if (backend === "e2b") {
	await runE2B(results.cases);
} else {
	const runners = { acquire: caseAcquire, exec: caseExec, fs: caseFs, git: caseGit, npm: caseNpm, uv: caseUv, browser: caseBrowser };
	for (const c of cases) {
		console.error(`# running case: ${c}`);
		try {
			await runners[c](results.cases);
		} catch (err) {
			results.cases[c] = { error: err instanceof Error ? err.message : String(err) };
			console.error(`# case ${c} failed: ${results.cases[c].error}`);
		}
	}
}

fs.mkdirSync(path.join(BENCH_DIR, "results"), { recursive: true });
const outPath = path.join(BENCH_DIR, "results", `${results.at.slice(0, 10)}-${results.host}-${backend}.json`);
fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
console.error(`# wrote ${outPath}`);

console.log(`\n| case | metric | value |`);
console.log(`|---|---|---|`);
function flatten(prefix, obj) {
	for (const [k, v] of Object.entries(obj)) {
		if (v && typeof v === "object" && !Array.isArray(v)) flatten(`${prefix}.${k}`, v);
		else console.log(`| ${prefix} | ${k} | ${typeof v === "number" ? v.toFixed(2) : v} |`);
	}
}
for (const [c, v] of Object.entries(results.cases)) {
	if (v && typeof v === "object") flatten(c, v);
	else console.log(`| ${c} | value | ${v} |`);
}
