"""Live tests against a running qafas on :7700 (token "dev" in dev). Skips
cleanly if unreachable — this is not a mock-based unit test suite, it's the
runnable check for the SDK against the real wire protocol.

    SANDBOX_URL=http://127.0.0.1:7700 SBX_TOKEN=dev python3 -m unittest -v
"""

import os
import sys
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from qafas_sandbox import acquire  # noqa: E402

URL = os.environ.get("SANDBOX_URL", "http://127.0.0.1:7700")
os.environ.setdefault("SBX_TOKEN", "dev")


def _daemon_up() -> bool:
    try:
        urllib.request.urlopen(f"{URL}/healthz", timeout=1)
        return True
    except (urllib.error.URLError, OSError):
        return False


@unittest.skipUnless(_daemon_up(), f"no qafas reachable at {URL}")
class TestSandboxClient(unittest.TestCase):
    def setUp(self):
        self.sb = acquire(URL, os.getcwd(), "sdk-python-test")

    def tearDown(self):
        self.sb.destroy()

    def test_acquire_native(self):
        self.assertTrue(self.sb.id.startswith("sbx_"))
        self.assertEqual(self.sb.backend, "native")

    def test_exec_buffered(self):
        r = self.sb.exec_buffered("echo hello")
        self.assertEqual(r.exit, 0)
        self.assertIn("hello", r.stdout)

    def test_exec_stdlib_fallback(self):
        # exec() without the `stream` extra installed falls back to buffered.
        r = self.sb.exec("echo via-exec")
        self.assertEqual(r.exit, 0)
        self.assertIn("via-exec", r.stdout)

    def test_write_read_roundtrip(self):
        path = f"{self.sb.workspace_path}/.sdk_test_tmp.txt"
        self.sb.write_file(path, "roundtrip-ok")
        self.assertEqual(self.sb.read_file(path), b"roundtrip-ok")
        self.sb.exec_buffered(f"rm -f {path}")

    def test_listdir(self):
        names = self.sb.listdir(self.sb.workspace_path)
        self.assertIsInstance(names, list)

    def test_processes(self):
        procs = self.sb.processes()
        self.assertIsInstance(procs, list)


if __name__ == "__main__":
    unittest.main()
