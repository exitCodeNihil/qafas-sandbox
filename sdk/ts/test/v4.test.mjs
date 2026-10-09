// v4 surface: runtime <-> isolation mapping, Sandbox.create()/delete() (v4, docs/protocol.md §4b). Sandbox.create() is acquire() plus the id/backend/isolation/runtime
// fields on the handle itself — same fake-HTTP-server style as v3.test.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Sandbox, acquire, isolationToRuntime, runtimeToIsolation, validateIsolation } from "../dist/index.js";

function startServer(handler) {
	return new Promise((resolve) => {
		const server = http.createServer((req, res) => {
			const chunks = [];
			req.on("data", (c) => chunks.push(c));
			req.on("end", () => {
				req.rawBody = Buffer.concat(chunks);
				handler(req, res);
			});
		});
		server.listen(0, "127.0.0.1", () => {
			const { port } = server.address();
			resolve({ server, url: `http://127.0.0.1:${port}` });
		});
	});
}

function json(res, status, body) {
	res.writeHead(status, { "content-type": "application/json" });
	res.end(JSON.stringify(body));
}

function closeServer(server) {
	server.closeAllConnections();
	server.close();
}

test("runtime <-> isolation mapping", () => {
	assert.equal(runtimeToIsolation("process"), "native");
	assert.equal(runtimeToIsolation("docker"), "vm");
	assert.equal(runtimeToIsolation("firecracker"), "remote");
	assert.equal(runtimeToIsolation("auto"), undefined);
	assert.equal(runtimeToIsolation(undefined), undefined);

	assert.equal(isolationToRuntime("native"), "process");
	assert.equal(isolationToRuntime("vm"), "docker");
	assert.equal(isolationToRuntime("remote"), "firecracker");
	assert.equal(isolationToRuntime(undefined), undefined);
});

test("runtimeToIsolation rejects a bad runtime string", () => {
	assert.throws(() => runtimeToIsolation("kubernetes"), /invalid runtime "kubernetes"/);
});

test("validateIsolation accepts the wire values and the product-name aliases, passes them through raw, and rejects anything else", () => {
	for (const v of ["auto", "native", "vm", "remote", "process", "docker", "firecracker"]) {
		assert.equal(validateIsolation(v), v);
	}
	assert.equal(validateIsolation(undefined), undefined);
	assert.throws(() => validateIsolation("kubernetes"), /invalid isolation "kubernetes"/);
});

test("Sandbox.create() sends the mapped isolation, runtime wins over isolation, and returns a Sandbox handle", async () => {
	let createBody;
	const { server, url } = await startServer((req, res) => {
		if (req.method === "GET" && req.url === "/healthz") return json(res, 200, { ok: true }); // control-plane shape
		if (req.method === "POST" && req.url === "/api/sandboxes") {
			createBody = JSON.parse(req.rawBody.toString());
			return json(res, 201, {
				id: "sbx_1",
				endpoint: `${url}/sandboxes/sbx_1/agent`,
				token: "scoped",
				backend: "podman",
				workspace_path: "/w",
				expires_at: "later",
				isolation: "vm",
			});
		}
		res.writeHead(404);
		res.end("not found");
	});
	try {
		const sb = await Sandbox.create(url, "/tmp", "sess", { runtime: "docker", isolation: "native" });
		assert.equal(createBody.isolation, "vm"); // runtime ("docker") wins over isolation ("native")
		assert.ok(sb instanceof Sandbox);
		assert.equal(sb.id, "sbx_1");
		assert.equal(sb.backend, "podman");
		assert.equal(sb.isolation, "vm");
		assert.equal(sb.runtime, "docker"); // derived from the resolved isolation
		assert.equal(sb.workspacePath, "/w");
	} finally {
		closeServer(server);
	}
});

test("Sandbox.create() with no runtime/isolation leaves tier selection to qafas (isolation omitted from the request)", async () => {
	let createBody;
	const { server, url } = await startServer((req, res) => {
		if (req.method === "GET" && req.url === "/healthz") return json(res, 200, { ok: true });
		if (req.method === "POST" && req.url === "/api/sandboxes") {
			createBody = JSON.parse(req.rawBody.toString());
			return json(res, 201, { id: "sbx_2", endpoint: `${url}/sandboxes/sbx_2/agent`, token: "t", backend: "seatbelt", workspace_path: "/w", expires_at: "later", isolation: "native" });
		}
		res.writeHead(404);
		res.end("not found");
	});
	try {
		const sb = await Sandbox.create(url, "/tmp", "sess");
		assert.equal(createBody.isolation, undefined);
		assert.equal(sb.runtime, "process"); // isolationToRuntime("native")
	} finally {
		closeServer(server);
	}
});

test("sandbox.delete() calls DELETE on the sandbox's own route", async () => {
	const seen = [];
	const { server, url } = await startServer((req, res) => {
		seen.push(`${req.method} ${req.url}`);
		if (req.method === "DELETE" && req.url === "/sandboxes/sbx_1") return json(res, 204, {});
		res.writeHead(404);
		res.end("not found");
	});
	try {
		const { SandboxClient } = await import("../dist/index.js");
		const client = new SandboxClient(`${url}/sandboxes/sbx_1/agent`, "tok", "sess");
		await client.delete();
		assert.deepEqual(seen, ["DELETE /sandboxes/sbx_1"]);
	} finally {
		closeServer(server);
	}
});

// defect 2: the documented quick start (acquire(url, process.cwd(), session)) used to
// upload the whole cwd unconditionally. acquire()/Sandbox.create() without a cwd must send
// no `workspace` field at all, and must never touch /fs/tar.
test("acquire()/Sandbox.create() without a cwd sends no workspace and uploads nothing", async () => {
	let createBody;
	const seenPaths = [];
	const { server, url } = await startServer((req, res) => {
		seenPaths.push(`${req.method} ${req.url}`);
		if (req.method === "GET" && req.url === "/healthz") return json(res, 200, { ok: true });
		if (req.method === "POST" && req.url === "/api/sandboxes") {
			createBody = JSON.parse(req.rawBody.toString());
			return json(res, 201, {
				id: "sbx_nocwd",
				endpoint: `${url}/sandboxes/sbx_nocwd/agent`,
				token: "tok",
				backend: "firecracker",
				workspace_path: "/home/agent",
				expires_at: "later",
				isolation: "remote", // would trigger an upload if cwd had been sent
			});
		}
		res.writeHead(404);
		res.end("not found");
	});
	try {
		const sb = await Sandbox.create(url, undefined, "sess");
		assert.equal(sb.id, "sbx_nocwd");
		assert.equal("workspace" in createBody, false);
		assert.ok(
			!seenPaths.some((p) => p.includes("/fs/tar")),
			`must not upload anything without a cwd, saw: ${seenPaths.join(", ")}`,
		);
	} finally {
		closeServer(server);
	}
});

// defect 3: a failed post-create workspace upload used to leave the sandbox running with
// no handle to delete it. acquire() must destroy it and rethrow a clear error instead.
test("acquire() destroys the sandbox and rethrows clearly when the workspace upload fails", async () => {
	const seenPaths = [];
	const { server, url } = await startServer((req, res) => {
		seenPaths.push(`${req.method} ${req.url}`);
		if (req.method === "GET" && req.url === "/healthz") return json(res, 200, { ok: true });
		if (req.method === "POST" && req.url === "/api/sandboxes") {
			return json(res, 201, {
				id: "sbx_upfail",
				endpoint: `${url}/sandboxes/sbx_upfail/agent`,
				token: "tok",
				backend: "firecracker",
				workspace_path: "/home/agent",
				expires_at: "later",
				isolation: "remote",
			});
		}
		if (req.method === "PUT" && req.url.startsWith("/sandboxes/sbx_upfail/agent/fs/tar")) {
			return json(res, 413, { error: "body over SBX_MAX_UPLOAD_MB (512 MiB)" });
		}
		if (req.method === "DELETE" && req.url === "/sandboxes/sbx_upfail") return json(res, 204, {});
		res.writeHead(404);
		res.end("not found");
	});
	try {
		const local = await mkdtemp(join(tmpdir(), "sbx-upfail-"));
		await writeFile(join(local, "f.txt"), "x");
		await assert.rejects(() => acquire(url, local, "sess"), /workspace upload failed \(.*413.*\): pass uploadWorkspace:false or a smaller directory \(\.sbxignore\)/);
		assert.ok(
			seenPaths.includes("DELETE /sandboxes/sbx_upfail"),
			`a failed upload must destroy the sandbox, saw: ${seenPaths.join(", ")}`,
		);
	} finally {
		closeServer(server);
	}
});
