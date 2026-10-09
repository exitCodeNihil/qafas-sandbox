// upload()/download(): the workspace-boundary guard is pure and needs no daemon; the
// round-trip itself runs against the real local qafas (native tier) when reachable —
// skips cleanly otherwise, same convention as mcp.test.mjs. Always destroys what it acquires.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, readFile, rm } from "node:fs/promises";
import { randomFillSync } from "node:crypto";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SandboxClient, acquire } from "../dist/index.js";

const URL = process.env.SANDBOX_URL ?? process.env.SBX_URL ?? "http://127.0.0.1:7700";

async function daemonUp() {
	try {
		const res = await fetch(`${URL}/healthz`, { signal: AbortSignal.timeout(1000) });
		return res.ok;
	} catch {
		return false;
	}
}
// A reachable daemon still refuses creates without its token: skip rather than fail.
const reachable = (await daemonUp()) && !!process.env.SBX_TOKEN;

test("upload()/download() refuse a remote path outside the workspace unless allowOutside is set", async () => {
	const client = new SandboxClient("http://127.0.0.1:1/sandboxes/sbx_x/agent", "t", "s", "/workspace/repo");
	await assert.rejects(() => client.upload("/does/not/matter", "/etc/passwd"), /outside the workspace/);
	await assert.rejects(() => client.download("/etc/passwd", "/does/not/matter"), /outside the workspace/);
	// A path inside the workspace, or allowOutside:true, must pass the guard (and only then
	// hit the network — which is what actually fails here, against a nothing-listening port).
	await assert.rejects(() => client.upload("/does/not/matter", "/workspace/repo/sub/file.txt"), (err) => !/outside the workspace/.test(err.message));
	await assert.rejects(() => client.upload("/does/not/matter", "/etc/passwd", { allowOutside: true }), (err) => !/outside the workspace/.test(err.message));
});

test("upload/download round-trip a file and a directory on the native tier", { skip: !reachable && "no qafas reachable with SBX_TOKEN set" }, async () => {
	const local = await mkdtemp(join(tmpdir(), "sbx-updown-"));
	await writeFile(join(local, "hello.txt"), "hello sandbox");
	await mkdir(join(local, "sub"));
	await writeFile(join(local, "sub", "nested.txt"), "nested");

	const result = await acquire(URL, process.cwd(), "sdk-ts-updown-test", { isolation: "native" });
	const back = await mkdtemp(join(tmpdir(), "sbx-download-"));
	try {
		const remoteFile = `${result.workspacePath}/.sdk_test_upload.txt`;
		await result.client.upload(join(local, "hello.txt"), remoteFile);
		assert.equal((await result.client.readFile(remoteFile)).toString(), "hello sandbox");

		const remoteDir = `${result.workspacePath}/.sdk_test_updir`;
		await result.client.mkdir(remoteDir);
		await result.client.upload(local, remoteDir);
		const names = await result.client.list(remoteDir);
		assert.ok(names.includes("hello.txt"));
		assert.ok(names.includes("sub"));

		await result.client.download(remoteFile, join(back, "hello.txt"));
		assert.equal(await readFile(join(back, "hello.txt"), "utf8"), "hello sandbox");

		await result.client.download(remoteDir, join(back, "updir"));
		assert.equal(await readFile(join(back, "updir", "hello.txt"), "utf8"), "hello sandbox");
		assert.equal(await readFile(join(back, "updir", "sub", "nested.txt"), "utf8"), "nested");

		await result.client.execBuffered(`rm -rf ${JSON.stringify(remoteFile)} ${JSON.stringify(remoteDir)}`, result.workspacePath);
	} finally {
		await result.client.destroy().catch(() => {});
		await rm(local, { recursive: true, force: true });
		await rm(back, { recursive: true, force: true });
	}
});

test("upload() of a directory streams the tar instead of buffering it", async () => {
	// 20 x 1 MiB random files, written from one reused 1 MiB buffer so the setup itself
	// never holds the whole 20 MiB in one allocation (that would skew the RSS baseline
	// below, not just the code under test).
	const local = await mkdtemp(join(tmpdir(), "sbx-stream-upload-"));
	const chunk = Buffer.alloc(1024 * 1024);
	try {
		for (let i = 0; i < 20; i++) {
			randomFillSync(chunk);
			await writeFile(join(local, `f${i}.bin`), chunk);
		}

		let chunks = 0;
		let totalBytes = 0;
		const server = http.createServer((req, res) => {
			req.on("data", (d) => {
				chunks++;
				totalBytes += d.length;
			});
			req.on("end", () => {
				res.writeHead(200, { "content-type": "application/json" });
				res.end("{}");
			});
		});
		await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
		const { port } = server.address();

		const client = new SandboxClient(`http://127.0.0.1:${port}`, "t", "s", "/workspace");
		const t0 = Date.now();
		await client.upload(local, "/workspace/dir");
		const elapsedMs = Date.now() - t0;

		server.closeAllConnections();
		server.close();

		// ~20 MiB of tar data arrived...
		assert.ok(totalBytes > 19 * 1024 * 1024, `expected ~20 MiB to reach the server, got ${totalBytes} bytes`);
		// ...as many small pieces, not one write of a pre-built 20 MiB Buffer: a Buffer body
		// would still cross the loopback socket in a handful of large reads, nowhere near
		// this many. (process.memoryUsage().rss before/after was tried here too, but on this
		// allocator RSS stays elevated after a genuinely-streamed transfer too — freed
		// buffers aren't necessarily returned to the OS — so it doesn't distinguish the two;
		// chunk arrival over time does.)
		assert.ok(chunks > 100, `expected a chunked/streamed request, got ${chunks} chunk(s) in ${elapsedMs}ms`);
	} finally {
		await rm(local, { recursive: true, force: true });
	}
});
