"""v5 sizes and limits (docs/protocol.md §3a "v5 sizes and limits") against a fake HTTP
server, same pattern as test_v3.py.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from test_v3 import FakeServer  # noqa: E402

from qafas_sandbox import acquire  # noqa: E402
from qafas_sandbox.types import SandboxLimits  # noqa: E402


class TestAcquireV5Fields(unittest.TestCase):
    def test_size_sent_and_echoed(self):
        captured = {}

        def create(h):
            captured["body"] = json.loads(h.raw_body)
            return 201, {
                "id": "sbx_1",
                "endpoint": f"{srv.url}/sandboxes/sbx_1/agent",
                "token": "scoped",
                "backend": "podman",
                "workspace_path": "/w",
                "expires_at": "later",
                "isolation": "vm",
                "size": "mini",
                "limits": {"cpus": 1, "mem_mib": 1024, "disk_mib": 1024, "pids": 256},
                "info": {"id": "sbx_1", "name": "sbx_1", "state": "ready"},
            }

        srv = FakeServer({"GET /healthz": (200, {"ok": True}), "POST /api/sandboxes": create})
        try:
            sb = acquire(srv.url, "/tmp", "sess", size="mini")
            body = captured["body"]
            self.assertEqual(body["size"], "mini")
            self.assertNotIn("limits", body)
            self.assertEqual(sb.size, "mini")
            self.assertEqual(sb.limits, SandboxLimits(cpus=1, mem_mib=1024, disk_mib=1024, pids=256))
            # v5.1: CreateSandboxResp.info round-trips onto Sandbox.create_info unchanged
            # (not .info — that name is already the live GET /sandboxes/{id} method).
            self.assertEqual(sb.create_info, {"id": "sbx_1", "name": "sbx_1", "state": "ready"})
        finally:
            srv.close()

    def test_custom_limits_sent_as_dict_or_dataclass(self):
        captured = {}

        def create(h):
            captured["body"] = json.loads(h.raw_body)
            return 201, {"id": "sbx_2", "endpoint": f"{srv.url}/sandboxes/sbx_2/agent", "token": "scoped", "backend": "podman", "workspace_path": "/w", "expires_at": "later"}

        srv = FakeServer({"GET /healthz": (200, {"ok": True}), "POST /api/sandboxes": create})
        try:
            sb = acquire(srv.url, "/tmp", "sess", limits=SandboxLimits(cpus=0.5, mem_mib=512, disk_mib=512))
            body = captured["body"]
            self.assertEqual(body["limits"], {"cpus": 0.5, "mem_mib": 512, "disk_mib": 512, "pids": None})
            self.assertNotIn("size", body)
            self.assertIsNone(sb.size)
            self.assertIsNone(sb.limits)
        finally:
            srv.close()

    def test_neither_size_nor_limits_sends_neither(self):
        captured = {}

        def create(h):
            captured["body"] = json.loads(h.raw_body)
            return 201, {"id": "sbx_3", "endpoint": f"{srv.url}/sandboxes/sbx_3/agent", "token": "scoped", "backend": "podman", "workspace_path": "/w", "expires_at": "later"}

        srv = FakeServer({"GET /healthz": (200, {"ok": True}), "POST /api/sandboxes": create})
        try:
            acquire(srv.url, "/tmp", "sess")
            body = captured["body"]
            self.assertNotIn("size", body)
            self.assertNotIn("limits", body)
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()
