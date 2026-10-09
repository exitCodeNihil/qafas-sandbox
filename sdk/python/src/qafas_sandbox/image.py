"""Declarative Dockerfile builder for snapshots.create(dockerfile=...) (docs/protocol.md
§3a "Snapshots"). Mirrors sdk/ts/src/image.ts. design: string concatenation, not a
Dockerfile AST — a snapshot build is a one-shot podman build/rootfs step server-side,
there is nothing here that needs parsing back.
"""

from __future__ import annotations

import base64
from typing import Dict, List


def _sh_quote(s: str) -> str:
    """Single-quotes `s` for a POSIX shell, escaping embedded quotes."""
    return "'" + s.replace("'", "'\\''") + "'"


class Image:
    def __init__(self, base: str):
        self._lines: List[str] = [f"FROM {base}"]

    @classmethod
    def base(cls, image: str) -> "Image":
        return cls(image)

    def run(self, cmd: str) -> "Image":
        self._lines.append(f"RUN {cmd}")
        return self

    def workdir(self, directory: str) -> "Image":
        self._lines.append(f"WORKDIR {directory}")
        return self

    def env(self, vars: Dict[str, str]) -> "Image":
        for k, v in vars.items():
            self._lines.append(f'ENV {k}="{v}"')
        return self

    def pip_install(self, pkgs: List[str]) -> "Image":
        if pkgs:
            self._lines.append(f"RUN pip install --no-cache-dir {' '.join(_sh_quote(p) for p in pkgs)}")
        return self

    def npm_install(self, pkgs: List[str]) -> "Image":
        if pkgs:
            self._lines.append(f"RUN npm install -g {' '.join(_sh_quote(p) for p in pkgs)}")
        return self

    def copy_text(self, dest_path: str, content: str) -> "Image":
        """Writes `content` to `dest_path` in the image. A Dockerfile COPY needs a build
        context file that doesn't exist here, so this embeds the content as base64 and
        decodes it in a RUN step instead."""
        b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
        self._lines.append(f"RUN mkdir -p \"$(dirname {_sh_quote(dest_path)})\" && echo {_sh_quote(b64)} | base64 -d > {_sh_quote(dest_path)}")
        return self

    def to_dockerfile(self) -> str:
        return "\n".join(self._lines) + "\n"

    def __str__(self) -> str:
        return self.to_dockerfile()
