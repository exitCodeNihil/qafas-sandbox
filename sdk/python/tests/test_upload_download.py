"""upload()/download(): the workspace-boundary guard is pure and needs no daemon; the
round-trip itself runs against the real local qafas (native tier) when reachable —
skips cleanly otherwise, same convention as test_client.py. Always destroys what it
acquires.
"""

import os
import shutil
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from qafas_sandbox import Sandbox, acquire  # noqa: E402

URL = os.environ.get("SANDBOX_URL", "http://127.0.0.1:7700")
os.environ.setdefault("SBX_TOKEN", "dev")


def _daemon_up() -> bool:
    try:
        urllib.request.urlopen(f"{URL}/healthz", timeout=1)
        return True
    except (urllib.error.URLError, OSError):
        return False


class TestWorkspaceGuard(unittest.TestCase):
    def test_upload_download_refuse_outside_workspace_unless_allowed(self):
        sb = Sandbox("http://127.0.0.1:1/sandboxes/sbx_x/agent", "t", "s", "sbx_x", "b", "/workspace/repo")
        with self.assertRaises(ValueError):
            sb.upload("/does/not/matter", "/etc/passwd")
        with self.assertRaises(ValueError):
            sb.download("/etc/passwd", "/does/not/matter")
        # Inside the workspace, or allow_outside=True, must pass the guard — and only then
        # hit the network, which is what actually fails here (nothing listens on port 1).
        with self.assertRaises(Exception) as ctx:
            sb.upload("/does/not/matter", "/workspace/repo/sub/file.txt")
        self.assertNotIsInstance(ctx.exception, ValueError)
        with self.assertRaises(Exception) as ctx:
            sb.upload("/does/not/matter", "/etc/passwd", allow_outside=True)
        self.assertNotIsInstance(ctx.exception, ValueError)


@unittest.skipUnless(_daemon_up(), f"no qafas reachable at {URL}")
class TestUploadDownloadRoundTrip(unittest.TestCase):
    def test_file_and_directory_round_trip_on_native_tier(self):
        local = tempfile.mkdtemp(prefix="sbx-updown-")
        back = tempfile.mkdtemp(prefix="sbx-download-")
        sb = acquire(URL, os.getcwd(), "sdk-python-updown-test", isolation="native")
        try:
            with open(os.path.join(local, "hello.txt"), "w") as f:
                f.write("hello sandbox")
            os.mkdir(os.path.join(local, "sub"))
            with open(os.path.join(local, "sub", "nested.txt"), "w") as f:
                f.write("nested")

            remote_file = f"{sb.workspace_path}/.sdk_test_upload.txt"
            sb.upload(os.path.join(local, "hello.txt"), remote_file)
            self.assertEqual(sb.read_file(remote_file), b"hello sandbox")

            remote_dir = f"{sb.workspace_path}/.sdk_test_updir"
            sb.mkdir(remote_dir)
            sb.upload(local, remote_dir)
            names = sb.listdir(remote_dir)
            self.assertIn("hello.txt", names)
            self.assertIn("sub", names)

            sb.download(remote_file, os.path.join(back, "hello.txt"))
            with open(os.path.join(back, "hello.txt")) as f:
                self.assertEqual(f.read(), "hello sandbox")

            sb.download(remote_dir, os.path.join(back, "updir"))
            with open(os.path.join(back, "updir", "hello.txt")) as f:
                self.assertEqual(f.read(), "hello sandbox")
            with open(os.path.join(back, "updir", "sub", "nested.txt")) as f:
                self.assertEqual(f.read(), "nested")

            sb.exec_buffered(f"rm -rf {remote_file!r} {remote_dir!r}")
        finally:
            sb.destroy()
            shutil.rmtree(local, ignore_errors=True)
            shutil.rmtree(back, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
