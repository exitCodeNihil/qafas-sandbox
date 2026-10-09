"""v4 surface: runtime <-> isolation mapping, Sandbox.create()/delete() (v4, docs/protocol.md §4b). Against a tiny fake HTTP server, same style as test_v3.py.
"""

import json
import os
import sys
import tempfile
import unittest
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from qafas_sandbox import Sandbox, acquire, isolation_to_runtime, runtime_to_isolation  # noqa: E402

from test_v3 import FakeServer  # noqa: E402


class TestRuntimeIsolationMapping(unittest.TestCase):
    def test_runtime_to_isolation(self):
        self.assertEqual(runtime_to_isolation("process"), "native")
        self.assertEqual(runtime_to_isolation("docker"), "vm")
        self.assertEqual(runtime_to_isolation("firecracker"), "remote")
        self.assertIsNone(runtime_to_isolation("auto"))
        self.assertIsNone(runtime_to_isolation(None))

    def test_runtime_to_isolation_rejects_bad_runtime(self):
        with self.assertRaises(ValueError):
            runtime_to_isolation("kubernetes")

    def test_isolation_to_runtime(self):
        self.assertEqual(isolation_to_runtime("native"), "process")
        self.assertEqual(isolation_to_runtime("vm"), "docker")
        self.assertEqual(isolation_to_runtime("remote"), "firecracker")
        self.assertIsNone(isolation_to_runtime(None))


class TestSandboxCreateDelete(unittest.TestCase):
    def test_create_sends_mapped_isolation_runtime_wins_and_returns_sandbox(self):
        captured = {}

        def create(h):
            captured["body"] = json.loads(h.raw_body)
            return 201, {"id": "sbx_1", "endpoint": f"{srv.url}/sandboxes/sbx_1/agent", "token": "scoped",
                         "backend": "podman", "workspace_path": "/w", "expires_at": "later", "isolation": "vm"}

        srv = FakeServer({"GET /healthz": (200, {"ok": True}), "POST /api/sandboxes": create})  # control-plane shape
        try:
            sb = Sandbox.create(srv.url, "/tmp", "sess", runtime="docker", isolation="native")
            self.assertEqual(captured["body"]["isolation"], "vm")  # runtime ("docker") wins over isolation ("native")
            self.assertIsInstance(sb, Sandbox)
            self.assertEqual(sb.id, "sbx_1")
            self.assertEqual(sb.backend, "podman")
            self.assertEqual(sb.isolation, "vm")
            self.assertEqual(sb.runtime, "docker")  # derived from the resolved isolation
            self.assertEqual(sb.workspace_path, "/w")
        finally:
            srv.close()

    def test_create_with_no_runtime_isolation_omits_isolation_from_request(self):
        captured = {}

        def create(h):
            captured["body"] = json.loads(h.raw_body)
            return 201, {"id": "sbx_2", "endpoint": f"{srv.url}/sandboxes/sbx_2/agent", "token": "t",
                         "backend": "seatbelt", "workspace_path": "/w", "expires_at": "later", "isolation": "native"}

        srv = FakeServer({"GET /healthz": (200, {"ok": True}), "POST /api/sandboxes": create})
        try:
            sb = Sandbox.create(srv.url, "/tmp", "sess")
            self.assertNotIn("isolation", captured["body"])  # omitted entirely; qafas resolves auto
            self.assertEqual(sb.runtime, "process")  # isolation_to_runtime("native")
        finally:
            srv.close()

    def test_delete_calls_delete_on_the_sandboxes_own_route(self):
        srv = FakeServer({"DELETE /sandboxes/sbx_1": (204, {})})
        try:
            sb = Sandbox(f"{srv.url}/sandboxes/sbx_1/agent", "tok", "sess", "sbx_1", "b", "/w")
            sb.delete()
            self.assertEqual(srv.seen, ["DELETE /sandboxes/sbx_1"])
        finally:
            srv.close()

    # defect 2: the documented quick start (acquire(url, os.getcwd(), session)) used to
    # upload the whole cwd unconditionally (cwd defaulted to os.getcwd() even when the
    # caller passed None). acquire()/Sandbox.create() without a cwd must send no
    # "workspace" field at all, and must never touch /fs/tar.
    def test_acquire_without_cwd_sends_no_workspace_and_uploads_nothing(self):
        captured = {}

        def create(h):
            captured["body"] = json.loads(h.raw_body)
            return 201, {
                "id": "sbx_nocwd", "endpoint": f"{srv.url}/sandboxes/sbx_nocwd/agent", "token": "tok",
                "backend": "firecracker", "workspace_path": "/home/agent", "expires_at": "later",
                "isolation": "remote",  # would trigger an upload if cwd had been sent
            }

        srv = FakeServer({"GET /healthz": (200, {"ok": True}), "POST /api/sandboxes": create})
        try:
            sb = acquire(srv.url, None, "sess")
            self.assertEqual(sb.id, "sbx_nocwd")
            self.assertNotIn("workspace", captured["body"])
            self.assertFalse(any("/fs/tar" in p for p in srv.seen), f"must not upload anything without a cwd, saw: {srv.seen}")
        finally:
            srv.close()

    # defect 3: a failed post-create workspace upload used to leave the sandbox running
    # with no handle to delete it. acquire() must destroy it and rethrow a clear error.
    def test_acquire_destroys_sandbox_and_rethrows_clearly_when_upload_fails(self):
        with tempfile.TemporaryDirectory() as local:
            with open(os.path.join(local, "f.txt"), "w") as f:
                f.write("x")
            tar_path = f"/sandboxes/sbx_upfail/agent/fs/tar?path={urllib.parse.quote(local)}"

            def create(h):
                return 201, {
                    "id": "sbx_upfail", "endpoint": f"{srv.url}/sandboxes/sbx_upfail/agent", "token": "tok",
                    "backend": "firecracker", "workspace_path": "/home/agent", "expires_at": "later",
                    "isolation": "remote",
                }

            srv = FakeServer({
                "GET /healthz": (200, {"ok": True}),
                "POST /api/sandboxes": create,
                f"PUT {tar_path}": (413, {"error": "body over SBX_MAX_UPLOAD_MB (512 MiB)"}),
                "DELETE /sandboxes/sbx_upfail": (204, {}),
            })
            try:
                with self.assertRaises(RuntimeError) as ctx:
                    acquire(srv.url, local, "sess")
                self.assertIn("workspace upload failed", str(ctx.exception))
                self.assertIn("413", str(ctx.exception))
                self.assertIn("upload_workspace=False", str(ctx.exception))
                self.assertIn("DELETE /sandboxes/sbx_upfail", srv.seen, f"a failed upload must destroy the sandbox, saw: {srv.seen}")
            finally:
                srv.close()


if __name__ == "__main__":
    unittest.main()
