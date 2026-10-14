# qafas-sandbox (Python)

Sync Python client for [Qafas Sandbox](https://github.com/exitCodeNihil/qafas-sandbox). Stdlib HTTP (`urllib`); streaming exec and live events are an optional extra.

## Install

```bash
pip install qafas-sandbox                # stdlib only
pip install "qafas-sandbox[stream]"      # + streaming exec()/logs() and events() (websockets)
```

Offline, from a source checkout: `pip install ./sdk/python` (or `"./sdk/python[stream]"`).

Import as `qafas_sandbox`.

## Quick start

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
- `acquire()` is the same path as a context manager.

## Connecting

Point the client at the control plane (`:7800`), which places the sandbox and hands back the worker to use, or directly at one worker (`:7700`).

| variable | |
|---|---|
| `SANDBOX_URL` | the default URL |
| `SBX_API_KEY` | an API key from the dashboard, for the control plane (preferred) |
| `SBX_ADMIN_TOKEN` | the control plane's admin token, when there is no key |
| `SBX_TOKEN` | a worker's own token, when talking to a worker directly |
| `SBX_CA_FILE` | a CA bundle for an `https://` control plane or worker on an internal CA |

## Common operations

| task | call |
|---|---|
| run a command, wait for the result | `sb.exec_buffered(cmd)` |
| stream output as it arrives (the `stream` extra) | `sb.exec(cmd, on_output=fn)` |
| files | `read_file`, `write_file`, `listdir`, `stat`, `mkdir`, `upload`, `download` |
| shell sessions | `sb.create_session()`, then `exec`, `logs`, `input`, `delete` on the session |
| lifecycle and sleep/wake | `stop`, `start`, `pause`, `resume`, `archive`, `info`, `delete` |
| live events (the `stream` extra) | `sb.events()` |
| preview URL | `sb.preview(port)` |
| browser (CDP) | `sb.cdp_url` |
| snapshots | `snapshots(url, token)`, with the `Image` Dockerfile builder |

## Tests and examples

```bash
python3 -m unittest discover -s tests -v   # most tests need a reachable qafas (SANDBOX_URL/SBX_TOKEN, default :7700/dev)
python3 examples/run_command.py
python3 examples/agent_loop.py
```

## Links

- [Qafas Sandbox](https://github.com/exitCodeNihil/qafas-sandbox#readme): what it is and how to run it.
- [Wire protocol](https://github.com/exitCodeNihil/qafas-sandbox/blob/main/docs/protocol.md) (`docs/protocol.md`): the types mirror it.
