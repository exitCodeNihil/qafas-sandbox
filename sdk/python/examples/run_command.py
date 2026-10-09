#!/usr/bin/env python3
"""Minimal example: acquire a sandbox, run one command, print output, destroy.

    SANDBOX_URL=http://127.0.0.1:7700 SBX_TOKEN=dev python3 examples/run_command.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from qafas_sandbox import acquire  # noqa: E402

if __name__ == "__main__":
    with acquire(os.environ.get("SANDBOX_URL", "http://127.0.0.1:7700"), os.getcwd(), "sdk-python-example") as sb:
        print(f"sandbox {sb.id} ({sb.backend}/{sb.isolation}) workspace={sb.workspace_path}")
        result = sb.exec_buffered("uname -a && node -v")
        print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        sys.exit(result.exit)
