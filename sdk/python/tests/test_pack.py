"""pack_workspace(): the ignore-rule engine ported from sdk/ts/src/pack.ts (anchored,
directory-only `secrets/`, negated `!keep`) — mirrors sdk/ts/test/pack.test.mjs so both
packers exclude the same files. The one thing this must never do is upload a credential.
"""

import os
import sys
import tarfile
import tempfile
import unittest
from io import BytesIO

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from qafas_sandbox import pack_workspace  # noqa: E402


def _write(root: str, rel: str, body: str = "x") -> None:
    full = os.path.join(root, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as f:
        f.write(body)


def _members(tar_bytes: bytes) -> list:
    with tarfile.open(fileobj=BytesIO(tar_bytes)) as tar:
        return sorted(tar.getnames())


class TestPackWorkspace(unittest.TestCase):
    def test_default_ignore_excludes_secrets_and_build_output(self):
        root = tempfile.mkdtemp(prefix="sbx-pack-")
        _write(root, "src/main.py")
        _write(root, ".git/config")
        _write(root, ".env", "OPENAI_API_KEY=sk-live")
        _write(root, ".env.example", "OPENAI_API_KEY=")
        _write(root, "node_modules/left-pad/index.js")
        _write(root, "dist/bundle.js")
        _write(root, "deploy/server.key")
        _write(root, ".ssh/id_rsa")
        _write(root, "credentials.json")
        _write(root, "debug.log")

        members = _members(pack_workspace(root))
        self.assertEqual(members, [".env.example", ".git/config", "src/main.py"])

    def test_sbxignore_supports_anchored_dir_only_and_negated_rules(self):
        root = tempfile.mkdtemp(prefix="sbx-pack-")
        _write(root, "src/main.py")
        _write(root, "secrets/db.json")  # dir-only rule "secrets/" excludes the whole tree
        _write(root, "notes/keep.txt")  # negated "!keep.txt" survives a broader exclude
        _write(root, "notes/draft.txt")
        _write(root, "vendor/notes/draft.txt")  # anchored "notes/draft.txt" must NOT match this nested copy
        _write(root, ".sbxignore", "secrets/\nnotes/draft.txt\n!keep.txt\n")

        members = _members(pack_workspace(root))
        self.assertEqual(members, [".sbxignore", "notes/keep.txt", "src/main.py", "vendor/notes/draft.txt"])


if __name__ == "__main__":
    unittest.main()


class SymlinkMembers(unittest.TestCase):
    def test_symlinks_travel_as_links_and_are_not_followed(self):
        import io, os, tarfile, tempfile
        from qafas_sandbox import pack_workspace
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "real"))
            open(os.path.join(d, "real", "f.txt"), "w").write("x")
            os.symlink("real", os.path.join(d, "linkdir"))
            os.symlink("real/f.txt", os.path.join(d, "linkfile"))
            os.symlink("/etc/passwd", os.path.join(d, "outside"))
            names = {m.name: m for m in tarfile.open(fileobj=io.BytesIO(pack_workspace(d))).getmembers()}
            self.assertTrue(names["linkdir"].issym() and names["linkdir"].linkname == "real")
            self.assertTrue(names["linkfile"].issym())
            self.assertTrue(names["outside"].issym() and names["outside"].linkname == "/etc/passwd")
            self.assertNotIn("linkdir/f.txt", names, "a symlinked directory is not descended into")
            self.assertIn("real/f.txt", names)

