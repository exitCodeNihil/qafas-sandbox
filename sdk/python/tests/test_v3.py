"""v3 surface (lifecycle, preview, sessions, snapshots, typed errors, the Image builder)
against a tiny fake HTTP server (stdlib http.server) — no daemon needs to speak v3 yet
(docs/protocol.md §3a/§4a; the real qafas/control plane land it separately).
"""

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from qafas_sandbox import Image, Sandbox, SandboxError, snapshots  # noqa: E402


def _make_handler(routes):
    """`routes`: dict of "METHOD path" -> (status, body_dict) or a callable(handler) -> (status, body_dict)."""

    class Handler(BaseHTTPRequestHandler):
        seen = []

        def _dispatch(self):
            length = int(self.headers.get("Content-Length", 0))
            self.raw_body = self.rfile.read(length) if length else b""
            key = f"{self.command} {self.path}"
            Handler.seen.append(key)
            entry = routes.get(key)
            if entry is None:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"not found")
                return
            status, body = entry(self) if callable(entry) else entry
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(payload)

        do_GET = _dispatch
        do_POST = _dispatch
        do_DELETE = _dispatch
        do_PUT = _dispatch

        def log_message(self, *a):
            pass

    return Handler


class FakeServer:
    def __init__(self, routes):
        handler = _make_handler(routes)
        self.handler = handler
        self.server = HTTPServer(("127.0.0.1", 0), handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def seen(self):
        return self.handler.seen

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class TestLifecyclePreviewSessions(unittest.TestCase):
    def setUp(self):
        self.srv = FakeServer(
            {
                "POST /sandboxes/sbx_1/stop": (204, {}),
                "POST /sandboxes/sbx_1/start": (200, {"id": "sbx_1", "state": "ready", "backend": "b", "template": "t", "workspace_path": "/w", "pi_session": "s", "created_at": "t", "endpoint": "e"}),
                "POST /sandboxes/sbx_1/pause": (204, {}),
                "POST /sandboxes/sbx_1/resume": (204, {}),
                "POST /sandboxes/sbx_1/archive": (204, {}),
                "GET /sandboxes/sbx_1": (200, {"id": "sbx_1", "state": "ready", "name": "my-box", "backend": "b", "template": "t", "workspace_path": "/w", "pi_session": "s", "created_at": "t", "endpoint": "e"}),
                "POST /sandboxes/sbx_1/preview": lambda h: (200, {"url": f"{self.srv.url}/preview/sbx_1/8080/", "token": "tok", "port": json.loads(h.raw_body)["port"], "expires_at": "2026-01-01T00:00:00Z"}),
                "POST /sandboxes/sbx_1/agent/sessions": (201, {"id": "sess_1"}),
                "POST /sandboxes/sbx_1/agent/sessions/sess_1/exec": (200, {"command_id": "c1", "cmd": "echo hi", "state": "done", "exit": 0, "stdout": "hi\n", "stderr": "", "started_at": "t", "ended_at": "t"}),
                "GET /sandboxes/sbx_1/agent/sessions/sess_1/commands/c1": (200, {"command_id": "c1", "cmd": "echo hi", "state": "done", "exit": 0, "started_at": "t"}),
                "POST /sandboxes/sbx_1/agent/sessions/sess_1/commands/c1/input": (204, {}),
                "DELETE /sandboxes/sbx_1/agent/sessions/sess_1": (204, {}),
            }
        )
        self.sb = Sandbox(f"{self.srv.url}/sandboxes/sbx_1/agent", "tok", "sess", "sbx_1", "b", "/w")

    def tearDown(self):
        self.srv.close()

    def test_lifecycle_info_preview(self):
        self.sb.stop()
        started = self.sb.start()
        self.assertEqual(started.state, "ready")
        self.sb.pause()
        self.sb.resume()
        self.sb.archive()
        info = self.sb.info()
        self.assertEqual(info.name, "my-box")
        preview = self.sb.preview(8080, ttl_secs=60)
        self.assertEqual(preview.port, 8080)
        self.assertTrue(preview.url.endswith("/preview/sbx_1/8080/"))

    def test_sessions(self):
        session = self.sb.create_session(cwd="/w")
        self.assertEqual(session.id, "sess_1")
        cmd = session.exec("echo hi")
        self.assertEqual(cmd.exit, 0)
        self.assertEqual(cmd.stdout, "hi\n")
        got = session.command("c1")
        self.assertEqual(got.command_id, "c1")
        session.input("c1", "aGVsbG8=")
        session.delete()


class TestTypedError(unittest.TestCase):
    def test_sandbox_error_carries_status_and_server_text(self):
        srv = FakeServer({"POST /sandboxes/sbx_1/stop": (409, {"error": "lifecycle needs the remote tier"})})
        try:
            sb = Sandbox(f"{srv.url}/sandboxes/sbx_1/agent", "tok", "sess", "sbx_1", "b", "/w")
            with self.assertRaises(SandboxError) as ctx:
                sb.stop()
            self.assertEqual(ctx.exception.status, 409)
            self.assertIn("lifecycle needs the remote tier", str(ctx.exception))
        finally:
            srv.close()


class TestAcquireV3Fields(unittest.TestCase):
    def test_acquire_serialises_v3_fields(self):
        captured = {}

        def create(h):
            captured["body"] = json.loads(h.raw_body)
            return 201, {"id": "sbx_1", "endpoint": f"{srv.url}/sandboxes/sbx_1/agent", "token": "scoped", "backend": "podman", "workspace_path": "/w", "expires_at": "later", "isolation": "vm"}

        srv = FakeServer({"GET /healthz": (200, {"ok": True}), "POST /api/sandboxes": create})  # no `backend`: control-plane shape
        try:
            from qafas_sandbox import acquire

            sb = acquire(
                srv.url,
                "/tmp",
                "sess",
                name="my-box",
                labels={"team": "sdk"},
                env={"FOO": "bar"},
                auto_stop_secs=60,
                auto_archive_secs=120,
                auto_delete_secs=0,
                max_age_secs=3600,
                snapshot="node-base",
            )
            self.assertEqual(sb.id, "sbx_1")
            body = captured["body"]
            self.assertEqual(body["template"], "node-base")  # `snapshot` aliases `template`
            self.assertEqual(body["name"], "my-box")
            self.assertEqual(body["labels"], {"team": "sdk"})
            self.assertEqual(body["env"], {"FOO": "bar"})
            self.assertEqual(body["auto_stop_secs"], 60)
            self.assertEqual(body["auto_archive_secs"], 120)
            self.assertEqual(body["auto_delete_secs"], 0)
            self.assertEqual(body["max_age_secs"], 3600)
        finally:
            srv.close()


class TestSnapshots(unittest.TestCase):
    def test_snapshots_targets_control_plane(self):
        def create(h):
            body = json.loads(h.raw_body)
            self.assertEqual(body, {"name": "img1", "source": {"image": "node:22-bookworm"}})
            return 202, [{"name": "img1", "state": "building", "kind": "image", "source": body["source"], "created_at": "t"}]

        srv = FakeServer(
            {
                "GET /healthz": (200, {"ok": True}),  # control-plane shape
                "POST /api/snapshots": create,
                "GET /api/snapshots/img1": (200, {"name": "img1", "state": "active", "kind": "image", "source": {"image": "node:22-bookworm"}, "created_at": "t"}),
                "DELETE /api/snapshots/img1": (204, {}),
            }
        )
        try:
            snaps = snapshots(srv.url, "admintok")
            created = snaps.create("img1", image="node:22-bookworm")
            self.assertEqual(created.name, "img1")
            self.assertEqual(created.state, "building")
            ready = snaps.wait_ready("img1", timeout=2)
            self.assertEqual(ready.state, "active")
            snaps.delete("img1")
            self.assertEqual([s for s in srv.seen if "/healthz" not in s], ["POST /api/snapshots", "GET /api/snapshots/img1", "DELETE /api/snapshots/img1"])
        finally:
            srv.close()

    def test_snapshots_create_warm_fields_and_set_warm(self):
        def create(h):
            body = json.loads(h.raw_body)
            self.assertEqual(body, {"name": "img3", "source": {"image": "node:22-bookworm"}, "warm": 2, "memory_snapshot": False})
            return 202, [{"name": "img3", "state": "building", "kind": "image", "source": body["source"], "created_at": "t", "warm": 2, "memory_snapshot": False, "warm_ready": 0}]

        def put(h):
            body = json.loads(h.raw_body)
            self.assertEqual(body, {"warm": 5})
            return 200, [{"name": "img3", "state": "active", "kind": "image", "source": {"image": "node:22-bookworm"}, "created_at": "t", "warm": 5, "memory_snapshot": False, "warm_ready": 5}]

        srv = FakeServer(
            {
                "GET /healthz": (200, {"ok": True}),  # control-plane shape
                "POST /api/snapshots": create,
                "PUT /api/snapshots/img3": put,
            }
        )
        try:
            snaps = snapshots(srv.url, "admintok")
            created = snaps.create("img3", image="node:22-bookworm", warm=2, memory_snapshot=False)
            self.assertEqual(created.warm, 2)
            self.assertEqual(created.memory_snapshot, False)
            updated = snaps.set_warm("img3", 5)
            self.assertEqual(updated.warm, 5)
            self.assertEqual(updated.warm_ready, 5)
        finally:
            srv.close()

    def test_snapshots_create_accepts_image_builder(self):
        captured = {}

        def create(h):
            captured["body"] = json.loads(h.raw_body)
            return 202, {"name": "img2", "state": "building", "kind": "image", "source": captured["body"]["source"], "created_at": "t"}

        srv = FakeServer({"GET /healthz": (200, {"ok": True, "backend": "podman", "host_id": "h"}), "POST /snapshots": create})  # qafas shape
        try:
            image = (
                Image.base("node:22-bookworm")
                .run("npm i -g pnpm")
                .pip_install(["requests"])
                .npm_install(["typescript"])
                .workdir("/w")
                .env({"K": "v"})
                .copy_text("/etc/motd", "hi")
            )
            snapshots(srv.url, "tok").create("img2", dockerfile=image)
            df = captured["body"]["source"]["dockerfile"]
            self.assertTrue(df.startswith("FROM node:22-bookworm\n"))
            self.assertIn("RUN npm i -g pnpm", df)
            self.assertIn("RUN pip install --no-cache-dir 'requests'", df)
            self.assertIn("RUN npm install -g 'typescript'", df)
            self.assertIn("WORKDIR /w", df)
            self.assertIn('ENV K="v"', df)
            self.assertIn("base64 -d > '/etc/motd'", df)
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()
