// v3 surface (lifecycle, preview, sessions, snapshots, typed errors, the Image builder)
// against a tiny fake HTTP server (node:http) — no daemon needs to speak v3 yet
// (docs/protocol.md §3a/§4a; the real qafas/control plane land it separately).
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { Image, SandboxApiError, SandboxClient, acquire, snapshots } from "../dist/index.js";

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

// fetch's undici keeps connections alive by default, which stops a bare server.close()'s
// callback from ever firing (the socket, not the server, is what's still open) — hanging
// the whole test file. Drop every open socket first. Always called from a `finally` below
// so a failed assertion still lets the process exit.
function closeServer(server) {
	server.closeAllConnections();
	server.close();
}

test("v3 lifecycle, info and preview hit qafas's /sandboxes/{id}/* routes (not /agent)", async () => {
	const seen = [];
	const { server, url } = await startServer((req, res) => {
		seen.push(`${req.method} ${req.url}`);
		if (req.method === "POST" && req.url === "/sandboxes/sbx_1/stop") return json(res, 204, {});
		if (req.method === "POST" && req.url === "/sandboxes/sbx_1/start") return json(res, 200, { id: "sbx_1", state: "ready" });
		if (req.method === "POST" && req.url === "/sandboxes/sbx_1/pause") return json(res, 204, {});
		if (req.method === "POST" && req.url === "/sandboxes/sbx_1/resume") return json(res, 204, {});
		if (req.method === "POST" && req.url === "/sandboxes/sbx_1/archive") return json(res, 204, {});
		if (req.method === "GET" && req.url === "/sandboxes/sbx_1") return json(res, 200, { id: "sbx_1", state: "ready", name: "my-box" });
		if (req.method === "POST" && req.url === "/sandboxes/sbx_1/preview") {
			const body = JSON.parse(req.rawBody.toString());
			return json(res, 200, { url: `${url}/preview/sbx_1/${body.port}/`, token: "tok", port: body.port, expires_at: "2026-01-01T00:00:00Z" });
		}
		res.writeHead(404);
		res.end("not found");
	});
	try {
		const client = new SandboxClient(`${url}/sandboxes/sbx_1/agent`, "tok", "sess");
		await client.stop();
		const started = await client.start();
		assert.equal(started.state, "ready");
		await client.pause();
		await client.resume();
		await client.archive();
		const info = await client.info();
		assert.equal(info.name, "my-box");
		const preview = await client.preview(8080, { ttlSecs: 60 });
		assert.equal(preview.port, 8080);
		assert.match(preview.url, /\/preview\/sbx_1\/8080\/$/);

		assert.deepEqual(seen, [
			"POST /sandboxes/sbx_1/stop",
			"POST /sandboxes/sbx_1/start",
			"POST /sandboxes/sbx_1/pause",
			"POST /sandboxes/sbx_1/resume",
			"POST /sandboxes/sbx_1/archive",
			"GET /sandboxes/sbx_1",
			"POST /sandboxes/sbx_1/preview",
		]);
	} finally {
		closeServer(server);
	}
});

test("sessions: create, exec, command, input, delete go through the sandbox's /agent/sessions routes", async () => {
	const seen = [];
	const { server, url } = await startServer((req, res) => {
		seen.push(`${req.method} ${req.url}`);
		if (req.method === "POST" && req.url === "/sandboxes/sbx_1/agent/sessions") return json(res, 201, { id: "sess_1" });
		if (req.method === "POST" && req.url === "/sandboxes/sbx_1/agent/sessions/sess_1/exec") {
			return json(res, 200, { command_id: "c1", cmd: "echo hi", state: "done", exit: 0, stdout: "hi\n", stderr: "", started_at: "t", ended_at: "t" });
		}
		if (req.method === "GET" && req.url === "/sandboxes/sbx_1/agent/sessions/sess_1/commands/c1") {
			return json(res, 200, { command_id: "c1", cmd: "echo hi", state: "done", exit: 0, started_at: "t" });
		}
		if (req.method === "POST" && req.url === "/sandboxes/sbx_1/agent/sessions/sess_1/commands/c1/input") return json(res, 204, {});
		if (req.method === "DELETE" && req.url === "/sandboxes/sbx_1/agent/sessions/sess_1") return json(res, 204, {});
		res.writeHead(404);
		res.end("not found");
	});
	try {
		const client = new SandboxClient(`${url}/sandboxes/sbx_1/agent`, "tok", "sess");
		const session = await client.createSession({ cwd: "/w" });
		assert.equal(session.id, "sess_1");
		const execRes = await session.exec("echo hi");
		assert.equal(execRes.exit, 0);
		assert.equal(execRes.stdout, "hi\n");
		const cmd = await session.command("c1");
		assert.equal(cmd.command_id, "c1");
		await session.input("c1", "aGVsbG8=");
		await session.delete();

		assert.deepEqual(seen, [
			"POST /sandboxes/sbx_1/agent/sessions",
			"POST /sandboxes/sbx_1/agent/sessions/sess_1/exec",
			"GET /sandboxes/sbx_1/agent/sessions/sess_1/commands/c1",
			"POST /sandboxes/sbx_1/agent/sessions/sess_1/commands/c1/input",
			"DELETE /sandboxes/sbx_1/agent/sessions/sess_1",
		]);
	} finally {
		closeServer(server);
	}
});

test("SandboxApiError carries the status and the server's {error} text", async () => {
	const { server, url } = await startServer((req, res) => json(res, 409, { error: "lifecycle needs the remote tier" }));
	try {
		const client = new SandboxClient(`${url}/sandboxes/sbx_1/agent`, "tok", "sess");
		await assert.rejects(
			() => client.stop(),
			(err) => {
				assert.ok(err instanceof SandboxApiError);
				assert.equal(err.status, 409);
				assert.match(err.message, /lifecycle needs the remote tier/);
				return true;
			},
		);
	} finally {
		closeServer(server);
	}
});

test("acquire() serialises v3 fields (name/labels/env/timers) into the create request", async () => {
	let createBody;
	const { server, url } = await startServer((req, res) => {
		if (req.method === "GET" && req.url === "/healthz") return json(res, 200, { ok: true }); // no `backend`: control-plane shape
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
		const result = await acquire(url, "/tmp", "sess", {
			name: "my-box",
			labels: { team: "sdk" },
			env: { FOO: "bar" },
			autoStopSecs: 60,
			autoArchiveSecs: 120,
			autoDeleteSecs: 0,
			maxAgeSecs: 3600,
			snapshot: "node-base",
		});
		assert.equal(result.id, "sbx_1");
		assert.equal(createBody.template, "node-base"); // `snapshot` aliases `template`
		assert.equal(createBody.name, "my-box");
		assert.deepEqual(createBody.labels, { team: "sdk" });
		assert.deepEqual(createBody.env, { FOO: "bar" });
		assert.equal(createBody.auto_stop_secs, 60);
		assert.equal(createBody.auto_archive_secs, 120);
		assert.equal(createBody.auto_delete_secs, 0);
		assert.equal(createBody.max_age_secs, 3600);
	} finally {
		closeServer(server);
	}
});

test("snapshots() targets the control plane's /api/snapshots when baseUrl is a control plane", async () => {
	const seen = [];
	const { server, url } = await startServer((req, res) => {
		seen.push(`${req.method} ${req.url}`);
		if (req.method === "GET" && req.url === "/healthz") return json(res, 200, { ok: true }); // control-plane shape
		if (req.method === "POST" && req.url === "/api/snapshots") {
			const body = JSON.parse(req.rawBody.toString());
			assert.deepEqual(body, { name: "img1", source: { image: "node:22-bookworm" } });
			return json(res, 202, [{ name: "img1", state: "building", kind: "image", source: body.source, created_at: "t" }]);
		}
		if (req.method === "GET" && req.url === "/api/snapshots/img1") {
			return json(res, 200, { name: "img1", state: "active", kind: "image", source: { image: "node:22-bookworm" }, created_at: "t" });
		}
		if (req.method === "DELETE" && req.url === "/api/snapshots/img1") return json(res, 204, {});
		res.writeHead(404);
		res.end("not found");
	});
	try {
		const snaps = snapshots(url, "admintok");
		const created = await snaps.create({ name: "img1", image: "node:22-bookworm" });
		assert.equal(created.name, "img1");
		assert.equal(created.state, "building");
		const ready = await snaps.waitReady("img1", 2000);
		assert.equal(ready.state, "active");
		await snaps.delete("img1");
		// Every snapshots() call re-probes /healthz to detect qafas-vs-control-plane; filter those out.
		assert.deepEqual(
			seen.filter((s) => !s.includes("/healthz")),
			["POST /api/snapshots", "GET /api/snapshots/img1", "DELETE /api/snapshots/img1"],
		);
	} finally {
		closeServer(server);
	}
});

test("snapshots.create passes warm/memorySnapshot through, and setWarm PUTs {warm} (v4)", async () => {
	const seen = [];
	const { server, url } = await startServer((req, res) => {
		seen.push(`${req.method} ${req.url}`);
		if (req.method === "GET" && req.url === "/healthz") return json(res, 200, { ok: true }); // control-plane shape
		if (req.method === "POST" && req.url === "/api/snapshots") {
			const body = JSON.parse(req.rawBody.toString());
			assert.deepEqual(body, { name: "img3", source: { image: "node:22-bookworm" }, warm: 2, memory_snapshot: false });
			return json(res, 202, [
				{ name: "img3", state: "building", kind: "image", source: body.source, created_at: "t", warm: 2, memory_snapshot: false, warm_ready: 0 },
			]);
		}
		if (req.method === "PUT" && req.url === "/api/snapshots/img3") {
			const body = JSON.parse(req.rawBody.toString());
			assert.deepEqual(body, { warm: 5 });
			return json(res, 200, [
				{ name: "img3", state: "active", kind: "image", source: { image: "node:22-bookworm" }, created_at: "t", warm: 5, memory_snapshot: false, warm_ready: 5 },
			]);
		}
		res.writeHead(404);
		res.end("not found");
	});
	try {
		const snaps = snapshots(url, "admintok");
		const created = await snaps.create({ name: "img3", image: "node:22-bookworm", warm: 2, memorySnapshot: false });
		assert.equal(created.warm, 2);
		assert.equal(created.memory_snapshot, false);
		const updated = await snaps.setWarm("img3", 5);
		assert.equal(updated.warm, 5);
		assert.equal(updated.warm_ready, 5);
	} finally {
		closeServer(server);
	}
});

test("snapshots.create accepts an Image builder for `dockerfile`", async () => {
	let body;
	const { server, url } = await startServer((req, res) => {
		if (req.method === "GET" && req.url === "/healthz") return json(res, 200, { ok: true, backend: "podman", host_id: "h" }); // qafas shape
		if (req.method === "POST" && req.url === "/snapshots") {
			body = JSON.parse(req.rawBody.toString());
			return json(res, 202, { name: "img2", state: "building", kind: "image", source: body.source, created_at: "t" });
		}
		res.writeHead(404);
		res.end("not found");
	});
	try {
		const image = Image.base("node:22-bookworm").run("npm i -g pnpm").pipInstall(["requests"]).npmInstall(["typescript"]).workdir("/w").env({ K: "v" }).copyText("/etc/motd", "hi");
		await snapshots(url, "tok").create({ name: "img2", dockerfile: image });
		assert.match(body.source.dockerfile, /^FROM node:22-bookworm\n/);
		assert.match(body.source.dockerfile, /RUN npm i -g pnpm/);
		assert.match(body.source.dockerfile, /RUN pip install --no-cache-dir 'requests'/);
		assert.match(body.source.dockerfile, /RUN npm install -g 'typescript'/);
		assert.match(body.source.dockerfile, /WORKDIR \/w/);
		assert.match(body.source.dockerfile, /ENV K="v"/);
		assert.match(body.source.dockerfile, /base64 -d > '\/etc\/motd'/);
	} finally {
		closeServer(server);
	}
});
