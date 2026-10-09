# qafas-sandbox (Python)

Sync Python client for [Qafas Sandbox](https://github.com/exitCodeNihil/qafas-sandbox): the control plane (`:7800`), which places the sandbox and hands back the worker to use, or one worker (`:7700`) directly. Stdlib HTTP (`urllib`); streaming exec and live events are an optional extra.

## Install

From the repository or a source checkout (it is not published to PyPI):

```bash
pip install ./sdk/python                 # stdlib only
pip install "./sdk/python[stream]"       # + streaming exec()/logs() and events() (websockets)
```

Import as `qafas_sandbox`.

## 30 seconds

```python
from qafas_sandbox import Sandbox

# No cwd: the sandbox gets its own /home/agent and nothing is uploaded implicitly.
sb = Sandbox.create("http://127.0.0.1:7800", None, "my-session", runtime="docker")
try:
    sb.upload("./fixtures", f"{sb.workspace_path}/fixtures")
    result = sb.exec_buffered("pytest -q")
    print(result.stdout, result.exit)
    sb.download(f"{sb.workspace_path}/fixtures/report.json", "./report.json")
finally:
    sb.delete()
```

- `runtime` is `"process" | "docker" | "firecracker"` (the wire's `native | vm | remote`, which `isolation` also takes). Omit it and the control plane picks, Firecracker first.
- Pass a `cwd` as the second argument to start from a local directory: it is mounted at the same path (`native`, `vm`) or tarred and uploaded (`remote`, unless `upload_workspace=False`).
- `acquire()` is the same path as a context manager; the handle also covers lifecycle and sleep/wake, sessions, snapshots (the `Image` Dockerfile builder) and preview URLs. The types mirror the wire contract, `docs/protocol.md`.

Configuration: `SBX_API_KEY` (an API key from the dashboard, preferred) or `SBX_ADMIN_TOKEN` against the control plane, `SBX_TOKEN` against a worker, and `SBX_CA_FILE` for an `https://` control plane or worker on an internal CA.

## Tests and examples

```bash
python3 -m unittest discover -s tests -v   # most tests need a reachable qafas (SANDBOX_URL/SBX_TOKEN, default :7700/dev)
python3 examples/run_command.py
python3 examples/agent_loop.py
```
