// v5 sizes and limits (docs/protocol.md §3a "v5 sizes and limits") against a fake HTTP
// server, same pattern as v3.test.mjs/v4.test.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { acquire } from "../dist/index.js";

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

test("acquire() sends size/limits when given and omits them otherwise; echoes the 201's size/limits onto the result", async () => {
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
				size: "mini",
				limits: { cpus: 1, mem_mib: 1024, disk_mib: 1024, pids: 256 },
				info: { id: "sbx_1", name: "sbx_1", state: "ready" },
			});
		}
		res.writeHead(404);
		res.end("not found");
	});
	try {
		const result = await acquire(url, "/tmp", "sess", { size: "mini" });
		assert.equal(createBody.size, "mini");
		assert.equal("limits" in createBody, false);
		assert.equal(result.size, "mini");
		assert.deepEqual(result.limits, { cpus: 1, mem_mib: 1024, disk_mib: 1024, pids: 256 });
		// v5.1: CreateSandboxResp.info round-trips onto AcquireResult unchanged.
		assert.deepEqual(result.info, { id: "sbx_1", name: "sbx_1", state: "ready" });
	} finally {
		closeServer(server);
	}
});

test("acquire() with custom limits sends limits and omits size", async () => {
	let createBody;
	const { server, url } = await startServer((req, res) => {
		if (req.method === "GET" && req.url === "/healthz") return json(res, 200, { ok: true });
		if (req.method === "POST" && req.url === "/api/sandboxes") {
			createBody = JSON.parse(req.rawBody.toString());
			return json(res, 201, {
				id: "sbx_2",
				endpoint: `${url}/sandboxes/sbx_2/agent`,
				token: "scoped",
				backend: "podman",
				workspace_path: "/w",
				expires_at: "later",
			});
		}
		res.writeHead(404);
		res.end("not found");
	});
	try {
		const result = await acquire(url, "/tmp", "sess", { limits: { cpus: 0.5, mem_mib: 512, disk_mib: 512 } });
		assert.deepEqual(createBody.limits, { cpus: 0.5, mem_mib: 512, disk_mib: 512 });
		assert.equal("size" in createBody, false);
		assert.equal(result.size, undefined);
		assert.equal(result.limits, undefined);
	} finally {
		closeServer(server);
	}
});

test("acquire() with neither size nor limits sends neither field", async () => {
	let createBody;
	const { server, url } = await startServer((req, res) => {
		if (req.method === "GET" && req.url === "/healthz") return json(res, 200, { ok: true });
		if (req.method === "POST" && req.url === "/api/sandboxes") {
			createBody = JSON.parse(req.rawBody.toString());
			return json(res, 201, { id: "sbx_3", endpoint: `${url}/sandboxes/sbx_3/agent`, token: "scoped", backend: "podman", workspace_path: "/w", expires_at: "later" });
		}
		res.writeHead(404);
		res.end("not found");
	});
	try {
		await acquire(url, "/tmp", "sess", {});
		assert.equal("size" in createBody, false);
		assert.equal("limits" in createBody, false);
	} finally {
		closeServer(server);
	}
});
