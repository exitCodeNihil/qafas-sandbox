"""Sync client for qafas / control plane. Stdlib HTTP (urllib); streaming
exec and the events generator use the optional `websockets` extra
(`pip install qafas-sandbox[stream]`) and fall back to buffered/absent
otherwise. See docs/protocol.md for the wire contract this mirrors.
"""

from __future__ import annotations

import base64
import dataclasses
import io
import json
import os
import re
import ssl
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterator, List, Optional, Sequence, Union

from .image import Image
from .types import (
    HDR_PI_SESSION,
    HDR_TOOL_CALL_ID,
    Event,
    ExecResult,
    FsStat,
    Isolation,
    OnOutput,
    PreviewInfo,
    SandboxInfo,
    SandboxLimits,
    SessionCommand,
    SnapshotInfo,
    Trust,
)


def _tls_context() -> Optional[ssl.SSLContext]:
    """`SBX_CA_FILE`: the CA an https control plane or worker chains to (an internal PKI)."""
    ca = os.environ.get("SBX_CA_FILE")
    return ssl.create_default_context(cafile=ca) if ca else None


def _ws_tls(url: str) -> Dict[str, Any]:
    """`ssl=` for websockets' connect: only a wss:// URL may carry one."""
    ctx = _tls_context()
    return {"ssl": ctx} if ctx and url.startswith("wss://") else {}


def _http(method: str, url: str, headers: Optional[Dict[str, str]] = None, body: Optional[bytes] = None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, method=method, headers=headers or {}, data=body)
    try:
        with urllib.request.urlopen(req, context=_tls_context()) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _extract_error(body: bytes) -> Optional[str]:
    try:
        j = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    return j["error"] if isinstance(j, dict) and isinstance(j.get("error"), str) else None


class SandboxError(RuntimeError):
    """Non-2xx response from qafas/control plane, carrying the status and the
    server's `{error}` text when it sent one."""

    def __init__(self, status: int, body: bytes = b""):
        self.status = status
        self.body = body.decode(errors="replace") if isinstance(body, (bytes, bytearray)) else str(body)
        super().__init__(f"HTTP {status}: {_extract_error(body) or self.body}")


def _json_request(method: str, url: str, headers: Dict[str, str], obj: Any = None) -> Any:
    body = json.dumps(obj).encode() if obj is not None else None
    h = dict(headers)
    if body is not None:
        h["content-type"] = "application/json"
    status, data = _http(method, url, h, body)
    if status >= 400:
        raise SandboxError(status, data)
    if not data:
        return None
    return json.loads(data)


def _agent_base(endpoint: str) -> str:
    """Strip the trailing /agent so callers can hit qafas-level /sandboxes/{id}/* routes."""
    return endpoint[: -len("/agent")] if endpoint.endswith("/agent") else endpoint


def _qafas_root(endpoint: str) -> str:
    """Strip the trailing /sandboxes/{id}/agent so callers can hit qafas-root routes
    like /events/ws (not scoped under /sandboxes/{id}/)."""
    idx = endpoint.find("/sandboxes/")
    return endpoint[:idx] if idx != -1 else endpoint


# Daytona/E2B-style tier name <-> this project's `isolation`. Purely a client-side
# relabelling -- never sent on the wire; acquire()/Sandbox.create() translate it to
# `isolation` before the request. "auto"/absent leaves tier selection to qafas.
RUNTIME_VALUES = ("auto", "process", "docker", "firecracker")
RUNTIME_TO_ISOLATION: Dict[str, str] = {"process": "native", "docker": "vm", "firecracker": "remote"}
ISOLATION_TO_RUNTIME: Dict[str, str] = {v: k for k, v in RUNTIME_TO_ISOLATION.items()}


def runtime_to_isolation(runtime: Optional[str]) -> Optional[str]:
    """Mirrors the TS SDK's runtimeToIsolation: raises naming the accepted values for
    anything but auto|process|docker|firecracker, instead of silently ignoring a typo."""
    if runtime is None:
        return None
    if runtime not in RUNTIME_VALUES:
        raise ValueError(f'invalid runtime "{runtime}": expected one of {"|".join(RUNTIME_VALUES)}')
    return RUNTIME_TO_ISOLATION.get(runtime) if runtime != "auto" else None


def isolation_to_runtime(isolation: Optional[str]) -> Optional[str]:
    return ISOLATION_TO_RUNTIME.get(isolation) if isolation else None


def _assert_inside_workspace(remote_path: str, workspace_path: Optional[str], allow_outside: bool) -> None:
    """Refuses a remote path outside `workspace_path` unless `allow_outside` — qafas/
    guest-agent enforce the real boundary; this only catches an obvious typo before a
    wasted round trip."""
    if allow_outside or not workspace_path:
        return
    rel = os.path.relpath(remote_path, workspace_path)
    if rel == "." or (not rel.startswith("..") and not os.path.isabs(rel)):
        return
    raise ValueError(f"{remote_path} is outside the workspace ({workspace_path}); pass allow_outside=True to override")


class Sandbox:
    """A single acquired sandbox. Use as a context manager to auto-destroy."""

    def __init__(self, endpoint: str, token: str, pi_session: str, id: str, backend: str, workspace_path: str,
                 isolation: Optional[str] = None, tools: Optional[Dict[str, str]] = None, missing_tools: Optional[List[str]] = None,
                 size: Optional[str] = None, limits: Optional[SandboxLimits] = None, create_info: Optional[Dict[str, Any]] = None):
        self.endpoint = endpoint
        self.token = token
        self.pi_session = pi_session
        self.id = id
        self.backend = backend
        self.workspace_path = workspace_path
        self.isolation = isolation
        self.tools = tools or {}
        self.missing_tools = missing_tools or []
        self.size = size  # v5: name or "custom"
        self.limits = limits  # v5: ceilings actually applied
        # v5.1: the daemon's record right after create — named create_info, not info, so it
        # doesn't shadow the info() method (GET /sandboxes/{id}, a live refresh) below.
        self.create_info = create_info

    @property
    def runtime(self) -> Optional[str]:
        """The tier qafas actually picked, relabelled to the `runtime` naming (derived from `isolation`)."""
        return isolation_to_runtime(self.isolation)

    @classmethod
    def create(cls, url: Optional[str] = None, cwd: Optional[str] = None, pi_session: Optional[str] = None, **kwargs: Any) -> "Sandbox":
        """Same as acquire() — a Daytona/E2B-style entry point returning a Sandbox handle.
        Accepts the same kwargs as acquire() (including `runtime`); implemented in terms of
        it, not duplicated."""
        return acquire(url, cwd, pi_session, **kwargs)

    def __enter__(self) -> "Sandbox":
        return self

    def __exit__(self, *exc) -> None:
        self.destroy()

    def _headers(self, tool_call_id: str = "") -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            HDR_PI_SESSION: self.pi_session,
            HDR_TOOL_CALL_ID: tool_call_id,
        }

    # ---------------------------------------------------------------- exec

    def exec_buffered(self, cmd: str, cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None,
                       timeout: Optional[float] = None, tool_call_id: str = "") -> ExecResult:
        """POST /exec. Stdlib only; use this if the `stream` extra is not installed."""
        body: Dict[str, Any] = {"cmd": cmd, "cwd": cwd or self.workspace_path}
        if env:
            body["env"] = env
        if timeout:
            body["timeout_ms"] = int(timeout * 1000)
        resp = _json_request("POST", f"{self.endpoint}/exec", self._headers(tool_call_id), body)
        return ExecResult(exit=resp["exit"], stdout=resp["stdout"], stderr=resp["stderr"],
                           duration_ms=resp["duration_ms"], truncated=resp.get("truncated", False))

    def exec(self, cmd: str, cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None,
              timeout: Optional[float] = None, on_output: Optional[OnOutput] = None, tool_call_id: str = "") -> ExecResult:
        """Runs `cmd`. Streams over /exec/ws (calling on_output per chunk) when the
        `websockets` package is installed, otherwise falls back to exec_buffered()."""
        try:
            import websockets.sync.client  # noqa: F401
        except ImportError:
            return self.exec_buffered(cmd, cwd=cwd, env=env, timeout=timeout, tool_call_id=tool_call_id)
        return self._exec_stream(cmd, cwd=cwd, env=env, timeout=timeout, on_output=on_output, tool_call_id=tool_call_id)

    def _exec_stream(self, cmd: str, cwd: Optional[str], env: Optional[Dict[str, str]], timeout: Optional[float],
                      on_output: Optional[OnOutput], tool_call_id: str) -> ExecResult:
        from websockets.sync.client import connect

        ws_url = self.endpoint.replace("http", "ws", 1) + "/exec/ws"
        stdout_buf, stderr_buf = bytearray(), bytearray()
        exit_code, duration_ms, timed_out = 1, 0, False

        with connect(ws_url, additional_headers=self._headers(tool_call_id), **_ws_tls(ws_url)) as ws:
            start: Dict[str, Any] = {"type": "start", "cmd": cmd, "cwd": cwd or self.workspace_path}
            if env:
                start["env"] = env
            if timeout:
                start["timeout_ms"] = int(timeout * 1000)
            ws.send(json.dumps(start))
            for raw in ws:
                frame = json.loads(raw)
                t = frame.get("type")
                if t in ("stdout", "stderr"):
                    chunk = base64.b64decode(frame["data"])
                    (stdout_buf if t == "stdout" else stderr_buf).extend(chunk)
                    if on_output:
                        on_output(chunk, t)
                elif t == "exit":
                    exit_code = frame.get("code", 1)
                    duration_ms = frame.get("duration_ms", 0)
                    timed_out = bool(frame.get("timed_out", False))
                    break

        return ExecResult(exit=exit_code, stdout=stdout_buf.decode(errors="replace"),
                           stderr=stderr_buf.decode(errors="replace"), duration_ms=duration_ms, timed_out=timed_out)

    # ------------------------------------------------------------------ fs

    def read_file(self, path: str) -> bytes:
        status, data = _http("GET", f"{self.endpoint}/fs/read?path={urllib.parse.quote(path)}", self._headers())
        if status == 404:
            raise FileNotFoundError(path)
        if status >= 400:
            raise SandboxError(status, data)
        return data

    def write_file(self, path: str, content: Union[str, bytes]) -> None:
        body = content.encode() if isinstance(content, str) else content
        status, data = _http("PUT", f"{self.endpoint}/fs/write?path={urllib.parse.quote(path)}", self._headers(), body)
        if status >= 400:
            raise SandboxError(status, data)

    def upload_bytes(self, path: str, content: bytes) -> None:
        """Alias of write_file, named for symmetry with read_file/upload/download."""
        self.write_file(path, content)

    def mkdir(self, path: str) -> None:
        _json_request("POST", f"{self.endpoint}/fs/mkdir", self._headers(), {"path": path})

    def stat(self, path: str) -> FsStat:
        status, data = _http("GET", f"{self.endpoint}/fs/stat?path={urllib.parse.quote(path)}", self._headers())
        if status == 404:
            raise FileNotFoundError(path)
        if status >= 400:
            raise SandboxError(status, data)
        d = json.loads(data)
        return FsStat(is_dir=d["is_dir"], size=d["size"], mode=d["mode"], mtime=d["mtime"])

    def listdir(self, path: str) -> List[str]:
        status, data = _http("GET", f"{self.endpoint}/fs/list?path={urllib.parse.quote(path)}", self._headers())
        if status == 404:
            raise FileNotFoundError(path)
        if status >= 400:
            raise SandboxError(status, data)
        return json.loads(data)

    def upload_tar(self, path: str, tar: bytes) -> None:
        status, data = _http("PUT", f"{self.endpoint}/fs/tar?path={urllib.parse.quote(path)}", self._headers(), tar)
        if status >= 400:
            raise SandboxError(status, data)

    def download_tar(self, path: str) -> bytes:
        status, data = _http("GET", f"{self.endpoint}/fs/tar?path={urllib.parse.quote(path)}", self._headers())
        if status >= 400:
            raise SandboxError(status, data)
        return data

    def upload(self, local_path: str, remote_path: str, allow_outside: bool = False) -> None:
        """Uploads a local file or directory to `remote_path`. A directory is packed
        with the same rules as a remote-tier workspace upload (`pack_workspace`:
        `.sbxignore` + DEFAULT_IGNORE) and sent as a tar; a file goes straight through
        write_file(). Refuses a `remote_path` outside this sandbox's workspace unless
        `allow_outside=True` — qafas/guest-agent already enforce the real boundary
        server-side, this is just a client-side foot-gun guard against a typo'd path."""
        _assert_inside_workspace(remote_path, self.workspace_path, allow_outside)
        if os.path.isdir(local_path):
            self.upload_tar(remote_path, pack_workspace(local_path))
        else:
            with open(local_path, "rb") as f:
                self.write_file(remote_path, f.read())

    def download(self, remote_path: str, local_path: str, allow_outside: bool = False) -> None:
        """Downloads `remote_path` (file or directory) to `local_path`. Mirrors upload()'s
        boundary guard, on the remote side of the path this time."""
        _assert_inside_workspace(remote_path, self.workspace_path, allow_outside)
        st = self.stat(remote_path)
        if st.is_dir:
            unpack_tar(self.download_tar(remote_path), local_path)
        else:
            parent = os.path.dirname(local_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(local_path, "wb") as f:
                f.write(self.read_file(remote_path))

    # ------------------------------------------------------------ qafas

    def processes(self) -> List[Dict[str, Any]]:
        """v2: GET /sandboxes/{id}/processes — live process tree."""
        return _json_request("GET", f"{_agent_base(self.endpoint)}/processes", self._headers())

    def events(self) -> Iterator[Event]:
        """Live events for this sandbox, from qafas's /events/ws firehose,
        filtered client-side to this sandbox_id. Requires the `stream` extra."""
        try:
            from websockets.sync.client import connect
        except ImportError as e:
            raise RuntimeError("events() needs the `stream` extra: pip install qafas-sandbox[stream]") from e

        ws_url = _qafas_root(self.endpoint).replace("http", "ws", 1) + "/events/ws"
        with connect(ws_url, additional_headers={"Authorization": f"Bearer {self.token}"}, **_ws_tls(ws_url)) as ws:
            for raw in ws:
                try:
                    d = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if d.get("sandbox_id") == self.id:
                    yield Event.from_json(d)

    @property
    def cdp_url(self) -> str:
        return self.endpoint.replace("http", "ws", 1) + "/browser/cdp"

    # ------------------------------------------------------------- v3: lifecycle

    def info(self) -> SandboxInfo:
        """GET /sandboxes/{id} — current SandboxInfo, including v3 state/timers."""
        status, data = _http("GET", _agent_base(self.endpoint), self._headers())
        if status >= 400:
            raise SandboxError(status, data)
        return SandboxInfo.from_json(json.loads(data))

    def stop(self) -> None:
        """remote tier only; native/vm answer 409 (docs/protocol.md §3a "Lifecycle")."""
        self._lifecycle("stop")

    def start(self) -> SandboxInfo:
        status, data = _http("POST", f"{_agent_base(self.endpoint)}/start", self._headers())
        if status >= 400:
            raise SandboxError(status, data)
        return SandboxInfo.from_json(json.loads(data))

    def pause(self) -> None:
        self._lifecycle("pause")

    def resume(self) -> None:
        self._lifecycle("resume")

    def archive(self) -> None:
        self._lifecycle("archive")

    def _lifecycle(self, verb: str) -> None:
        status, data = _http("POST", f"{_agent_base(self.endpoint)}/{verb}", self._headers())
        if status >= 400:
            raise SandboxError(status, data)

    def destroy(self) -> None:
        """Idempotent: a 404, or the worker's 401 for a token revoked with its sandbox, means already gone."""
        status, data = _http("DELETE", _agent_base(self.endpoint), {"Authorization": f"Bearer {self.token}"})
        if status == 401 and b"token revoked with its sandbox" in data:
            return
        if status >= 400 and status != 404:
            raise SandboxError(status, data)

    def delete(self) -> None:
        """Alias of destroy() — the name Daytona/E2B users expect."""
        self.destroy()

    # -------------------------------------------------------------- v3: preview

    def preview(self, port: int, ttl_secs: Optional[int] = None) -> PreviewInfo:
        """POST /sandboxes/{id}/preview — signed URL for a port inside the sandbox."""
        body: Dict[str, Any] = {"port": port}
        if ttl_secs is not None:
            body["ttl_secs"] = ttl_secs
        resp = _json_request("POST", f"{_agent_base(self.endpoint)}/preview", self._headers(), body)
        return PreviewInfo.from_json(resp)

    # ------------------------------------------------------------- v3: sessions

    def create_session(self, id: Optional[str] = None, cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> "Session":
        """POST /sessions — a persistent shell inside this sandbox, alive until deleted
        or the sandbox stops."""
        body: Dict[str, Any] = {}
        if id:
            body["id"] = id
        if cwd:
            body["cwd"] = cwd
        if env:
            body["env"] = env
        resp = _json_request("POST", f"{self.endpoint}/sessions", self._headers(), body)
        return Session(self, resp["id"])


class Session:
    """A persistent shell inside a sandbox (docs/protocol.md §3a "Sessions"). Reached
    through the owning Sandbox's endpoint/token, so it never needs its own auth."""

    def __init__(self, sandbox: Sandbox, id: str):
        self._sb = sandbox
        self.id = id

    def exec(self, cmd: str, async_: bool = False, timeout_ms: Optional[int] = None) -> SessionCommand:
        """POST /sessions/{id}/exec. Sync (default): returns exit/stdout/stderr. Async:
        returns immediately with just command_id set; poll command() or stream logs().
        Only one command runs per session at a time."""
        body: Dict[str, Any] = {"cmd": cmd}
        if async_:
            body["async"] = True
        if timeout_ms is not None:
            body["timeout_ms"] = timeout_ms
        resp = _json_request("POST", f"{self._sb.endpoint}/sessions/{self.id}/exec", self._sb._headers(), body)
        return SessionCommand.from_json(resp)

    def command(self, cid: str) -> SessionCommand:
        """GET /sessions/{id}/commands/{cid} — includes stdout/stderr (capped like /exec)."""
        resp = _json_request("GET", f"{self._sb.endpoint}/sessions/{self.id}/commands/{cid}", self._sb._headers())
        return SessionCommand.from_json(resp)

    def input(self, cid: str, data: str) -> None:
        """POST .../commands/{cid}/input — bytes to the shell's stdin while `cid` is the running command."""
        _json_request("POST", f"{self._sb.endpoint}/sessions/{self.id}/commands/{cid}/input", self._sb._headers(), {"data": data})

    def logs(self, cid: str, on_output: Optional[OnOutput] = None) -> SessionCommand:
        """Streams stdout/stderr for `cid` over WebSocket (replaying buffered output then
        live) when the `websockets` extra is installed; otherwise polls
        GET .../commands/{cid} until state == "done". Returns the final SessionCommand."""
        try:
            import websockets.sync.client  # noqa: F401
        except ImportError:
            return self._poll_logs(cid, on_output)
        return self._stream_logs(cid, on_output)

    def _poll_logs(self, cid: str, on_output: Optional[OnOutput]) -> SessionCommand:
        seen_out = seen_err = 0
        while True:
            cmd = self.command(cid)
            if on_output:
                out, err = cmd.stdout or "", cmd.stderr or ""
                if len(out) > seen_out:
                    on_output(out[seen_out:].encode(), "stdout")
                    seen_out = len(out)
                if len(err) > seen_err:
                    on_output(err[seen_err:].encode(), "stderr")
                    seen_err = len(err)
            if cmd.state == "done":
                return cmd
            time.sleep(0.5)

    def _stream_logs(self, cid: str, on_output: Optional[OnOutput]) -> SessionCommand:
        from websockets.sync.client import connect

        ws_url = self._sb.endpoint.replace("http", "ws", 1) + f"/sessions/{self.id}/commands/{cid}/logs/ws"
        with connect(ws_url, additional_headers=self._sb._headers(), **_ws_tls(ws_url)) as ws:
            for raw in ws:
                frame = json.loads(raw)
                t = frame.get("type")
                if t in ("stdout", "stderr") and on_output:
                    on_output(base64.b64decode(frame["data"]), t)
                elif t == "exit":
                    break
        return self.command(cid)  # authoritative final state/stdout/stderr from the server

    def delete(self) -> None:
        """DELETE /sessions/{id} — kills the shell's process group."""
        status, data = _http("DELETE", f"{self._sb.endpoint}/sessions/{self.id}", self._sb._headers())
        if status >= 400 and status != 404:
            raise SandboxError(status, data)


def control_plane_token(api_key: Optional[str] = None) -> str:
    """The bearer for the control plane: an API key identifies the application (protocol
    §4b); the admin token is the root credential and the fallback."""
    return api_key or os.environ.get("SBX_API_KEY") or os.environ.get("SBX_ADMIN_TOKEN", "")


def acquire(url: Optional[str] = None, cwd: Optional[str] = None, pi_session: Optional[str] = None, *,
            api_key: Optional[str] = None,
            isolation: Optional[Isolation] = None, runtime: Optional[str] = None, trust: Trust = "trusted", tools: Sequence[str] = (),
            egress_allow: Sequence[str] = (), ttl_secs: Optional[int] = None, token: Optional[str] = None,
            template: str = "base", snapshot: Optional[str] = None, name: Optional[str] = None,
            labels: Optional[Dict[str, str]] = None, env: Optional[Dict[str, str]] = None,
            auto_stop_secs: Optional[int] = None, auto_archive_secs: Optional[int] = None,
            auto_delete_secs: Optional[int] = None, max_age_secs: Optional[int] = None,
            size: Optional[str] = None, limits: Optional[Union[Dict[str, Any], SandboxLimits]] = None,
            upload_workspace: bool = True) -> Sandbox:
    """Acquire a sandbox. `url` may point at the control plane (:7800) or, for
    local/dev use, straight at qafas (:7700) — detected the same way as the
    Node SDK: GET /healthz has a `backend` field on qafas, not on the control
    plane. Falls back to SANDBOX_URL / SBX_TOKEN / SBX_ADMIN_TOKEN env vars.

    v3 knobs: `snapshot` aliases `template` (the snapshot name to build from); `name`,
    `labels`, `env` (added to every exec; PROTECTED_ENV names dropped server-side); the
    idle/lifetime timers `auto_stop_secs`/`auto_archive_secs`/`auto_delete_secs`/`max_age_secs`
    (docs/protocol.md §3a "Lifecycle"). v4: `runtime` ("process"|"docker"|"firecracker",
    Daytona/E2B naming) maps to `isolation` ("native"|"vm"|"remote") and wins when both
    are given; raises naming the accepted values for anything else. With neither `runtime`
    nor `isolation` given, the request carries no `isolation` field at all — the control
    plane resolves `auto` Firecracker-first (docs/decisions.md D25), same contract as the
    TS SDK's acquire()/Sandbox.create().

    `cwd` is optional (unlike `url`/`pi_session`, it is never defaulted to the current
    directory): pass it explicitly to mount/upload a workspace; omit it and the sandbox
    gets its own /home/agent, no workspace sent, nothing uploaded (docs/protocol.md §3a
    "Workspace is optional on every tier").

    v5: `size` ("micro"|"mini"|"medium"|"high") or `limits` (a dict or `SandboxLimits`
    with cpus/mem_mib/disk_mib/pids) picks the sandbox's resource ceilings; giving both is
    a 400, giving neither defaults to "medium". Only the caller of acquire() picks this —
    never expose it as a tool parameter a model can set (docs/protocol.md §3a)."""
    base = url or os.environ.get("SANDBOX_URL", "http://127.0.0.1:7700")
    pi_session = pi_session or f"sbx-py-{os.getpid()}"

    status, data = _http("GET", f"{base}/healthz")
    if status >= 400:
        raise SandboxError(status, data)
    healthz = json.loads(data) if data else {}
    is_qafas = isinstance(healthz, dict) and "backend" in healthz

    resolved_isolation = runtime_to_isolation(runtime) or isolation
    req: Dict[str, Any] = {
        "template": snapshot or template,
        "pi_session": pi_session,
        "trust": trust,
    }
    if cwd is not None:
        req["workspace"] = {"host_path": cwd}
    if resolved_isolation is not None:
        req["isolation"] = resolved_isolation
    if tools:
        req["tools"] = list(tools)
    if egress_allow:
        req["egress_allow"] = list(egress_allow)
    if ttl_secs is not None:
        req["ttl_secs"] = ttl_secs
    if name:
        req["name"] = name
    if labels:
        req["labels"] = labels
    if env:
        req["env"] = env
    if auto_stop_secs is not None:
        req["auto_stop_secs"] = auto_stop_secs
    if auto_archive_secs is not None:
        req["auto_archive_secs"] = auto_archive_secs
    if auto_delete_secs is not None:
        req["auto_delete_secs"] = auto_delete_secs
    if max_age_secs is not None:
        req["max_age_secs"] = max_age_secs
    if size is not None:
        req["size"] = size
    if limits is not None:
        req["limits"] = dataclasses.asdict(limits) if dataclasses.is_dataclass(limits) else dict(limits)
    path = "/sandboxes" if is_qafas else "/api/sandboxes"
    tok = token or (os.environ.get("SBX_TOKEN", "") if is_qafas else control_plane_token(api_key))

    resp = _json_request("POST", f"{base}{path}", {"Authorization": f"Bearer {tok}"}, req)
    sb = Sandbox(
        endpoint=resp["endpoint"],
        token=resp["token"],
        pi_session=pi_session,
        id=resp["id"],
        backend=resp["backend"],
        workspace_path=resp["workspace_path"],
        isolation=resp.get("isolation"),
        tools=resp.get("tools"),
        missing_tools=resp.get("missing_tools"),
        size=resp.get("size"),
        limits=SandboxLimits(**resp["limits"]) if resp.get("limits") else None,
        create_info=resp.get("info"),
    )
    # A microVM has no bind mount: the cwd travels as a tar, minus build output and
    # credentials. Only when the caller actually passed a cwd (no cwd -> no workspace
    # sent above -> nothing here to upload either).
    if cwd is not None and sb.isolation == "remote" and upload_workspace:
        try:
            sb.upload_tar(cwd, pack_workspace(cwd))
        except Exception as e:
            # Don't leak a running sandbox the caller has no handle to (defect 3).
            try:
                sb.destroy()
            except Exception:
                pass
            raise RuntimeError(
                f"workspace upload failed ({e}): pass upload_workspace=False or a smaller directory (.sbxignore)"
            ) from e
    return sb


# ---------------------------------------------------------------- v3: snapshots


class Snapshots:
    """Snapshots (named images a sandbox can be created from) are top-level, not tied to
    any one acquired sandbox — `url` gets the same qafas-vs-control-plane detection as
    acquire(). `token` defaults to SBX_TOKEN/SBX_ADMIN_TOKEN the same way."""

    def __init__(self, url: str, token: Optional[str] = None):
        self._url = url
        self._token = token

    def _root_and_headers(self) -> "tuple[str, Dict[str, str]]":
        status, data = _http("GET", f"{self._url}/healthz")
        if status >= 400:
            raise SandboxError(status, data)
        healthz = json.loads(data) if data else {}
        is_qafas = isinstance(healthz, dict) and "backend" in healthz
        tok = self._token or (os.environ.get("SBX_TOKEN", "") if is_qafas else control_plane_token())
        root = f"{self._url}/snapshots" if is_qafas else f"{self._url}/api/snapshots"
        return root, {"Authorization": f"Bearer {tok}"}

    def create(self, name: str, image: Optional[str] = None, dockerfile: Optional[Union[str, Image]] = None,
               sandbox_id: Optional[str] = None, warm: Optional[int] = None,
               memory_snapshot: Optional[bool] = None) -> SnapshotInfo:
        source: Dict[str, str] = {}
        if image:
            source["image"] = image
        if dockerfile:
            source["dockerfile"] = dockerfile.to_dockerfile() if isinstance(dockerfile, Image) else dockerfile
        if sandbox_id:
            source["sandbox_id"] = sandbox_id
        body: Dict[str, Any] = {"name": name, "source": source}
        if warm is not None:
            body["warm"] = warm
        if memory_snapshot is not None:
            body["memory_snapshot"] = memory_snapshot
        root, headers = self._root_and_headers()
        resp = _json_request("POST", root, headers, body)
        # The control plane fans a create out to every vm/remote host: 202 [SnapshotInfo]; qafas: 202 SnapshotInfo.
        resp_body = resp[0] if isinstance(resp, list) else resp
        return SnapshotInfo.from_json(resp_body)

    def list(self) -> List[SnapshotInfo]:
        root, headers = self._root_and_headers()
        resp = _json_request("GET", root, headers)
        return [SnapshotInfo.from_json(s) for s in resp]

    def get(self, name: str) -> SnapshotInfo:
        root, headers = self._root_and_headers()
        resp = _json_request("GET", f"{root}/{urllib.parse.quote(name)}", headers)
        return SnapshotInfo.from_json(resp)

    def delete(self, name: str) -> None:
        root, headers = self._root_and_headers()
        status, data = _http("DELETE", f"{root}/{urllib.parse.quote(name)}", headers)
        if status >= 400 and status != 404:
            raise SandboxError(status, data)

    def set_warm(self, name: str, n: int) -> SnapshotInfo:
        """v4 PUT /snapshots/{name} {"warm": n} — sets the pool's warm target live."""
        root, headers = self._root_and_headers()
        resp = _json_request("PUT", f"{root}/{urllib.parse.quote(name)}", headers, {"warm": n})
        # The control plane fans the PUT out to every host that has the snapshot: 200 [SnapshotInfo]; qafas: 200 SnapshotInfo.
        body = resp[0] if isinstance(resp, list) else resp
        return SnapshotInfo.from_json(body)

    def wait_ready(self, name: str, timeout: float = 120.0) -> SnapshotInfo:
        """Polls get(name) until `state` leaves "building" or `timeout` seconds elapse."""
        deadline = time.monotonic() + timeout
        while True:
            info = self.get(name)
            if info.state != "building":
                return info
            if time.monotonic() > deadline:
                raise TimeoutError(f"snapshot {name} still building after {timeout}s")
            time.sleep(1.0)


def snapshots(url: str, token: Optional[str] = None) -> Snapshots:
    return Snapshots(url, token)


# ---------------------------------------------------------------- workspace tar
# Mirrors sdk/ts/src/pack.ts DEFAULT_IGNORE: what never leaves the machine.
DEFAULT_IGNORE = ["node_modules", ".venv", "venv", "__pycache__", "target", "dist", "build", ".next", ".cache",
                  "*.log", ".env", ".env.*", "!.env.example", "*.pem", "*.key", "id_rsa*", ".aws", ".ssh", ".gnupg",
                  ".netrc", ".npmrc", ".pypirc", "credentials*", "secrets*"]


class _IgnoreRule:
    __slots__ = ("re", "dir_only", "anchored", "negate")

    def __init__(self, pattern: "re.Pattern[str]", dir_only: bool, anchored: bool, negate: bool):
        self.re = pattern
        self.dir_only = dir_only
        self.anchored = anchored
        self.negate = negate


def _compile_ignore_rule(line: str) -> Optional[_IgnoreRule]:
    """Ported from sdk/ts/src/pack.ts `compile()` so both SDKs' `.sbxignore` handling
    matches: `#` comments, `!` re-includes, a trailing `/` for directories only, a `/`
    anywhere anchors the pattern to the workspace root instead of matching the basename."""
    p = line.strip()
    if not p or p.startswith("#"):
        return None
    negate = p.startswith("!")
    if negate:
        p = p[1:]
    dir_only = p.endswith("/")
    if dir_only:
        p = p[:-1]
    anchored = "/" in p
    if p.startswith("/"):
        p = p[1:]
    if not p:
        return None
    pattern = re.escape(p).replace(r"\*", "[^/]*").replace(r"\?", "[^/]")
    return _IgnoreRule(re.compile(f"^{pattern}$"), dir_only, anchored, negate)


def _compile_ignore(lines: Sequence[str]) -> List[_IgnoreRule]:
    rules = [_compile_ignore_rule(line) for line in lines]
    return [r for r in rules if r is not None]


def _is_ignored(rules: List[_IgnoreRule], rel_path: str, is_dir: bool) -> bool:
    """Last matching rule wins, so `!.env.example` survives `.env.*` (mirrors pack.ts's `isIgnored`)."""
    name = rel_path.rsplit("/", 1)[-1]
    ignored = False
    for r in rules:
        if r.dir_only and not is_dir:
            continue
        if r.re.match(rel_path if r.anchored else name):
            ignored = not r.negate
    return ignored


def pack_workspace(cwd: str, extra_ignore: Sequence[str] = ()) -> bytes:
    """Tar of `cwd` (relative paths; symlinks kept as links, never followed) honouring DEFAULT_IGNORE and a `.sbxignore`
    file, matched with the same anchored/directory-only/negated rule engine as
    sdk/ts/src/pack.ts (`compile`/`isIgnored`) so both packers exclude the same files.

    Buffers the whole tar in memory (`io.BytesIO`) and returns `bytes`, unlike sdk/ts's
    `packWorkspaceStream`/`uploadTarStream`, which pipe `tar`'s stdout straight into the
    request body. `urllib.request` (stdlib, what `_http` uses) has no streaming-request-body
    story worth the added code for this; swap for `requests`/`httpx` with a generator body
    if a very large workspace upload ever needs it.
    """
    lines: List[str] = list(DEFAULT_IGNORE)
    try:
        with open(os.path.join(cwd, ".sbxignore")) as f:
            lines += list(f)
    except OSError:
        pass
    lines += list(extra_ignore)
    rules = _compile_ignore(lines)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for root, dirs, files in os.walk(cwd):
            rel_root = os.path.relpath(root, cwd)
            rel_root = "" if rel_root == "." else rel_root.replace(os.sep, "/")
            rel = (lambda n: f"{rel_root}/{n}" if rel_root else n)

            # Symlinked directories travel as link members (never followed), like the
            # TypeScript packer and plain `tar`; a dangling link in the guest is harmless.
            for d in sorted(dirs):
                if os.path.islink(os.path.join(root, d)) and not _is_ignored(rules, rel(d), True):
                    tar.add(os.path.join(root, d), arcname=rel(d), recursive=False)
            dirs[:] = sorted(
                d for d in dirs
                if not os.path.islink(os.path.join(root, d)) and not _is_ignored(rules, rel(d), True)
            )
            for fn in sorted(files):
                full = os.path.join(root, fn)
                if _is_ignored(rules, rel(fn), False):
                    continue
                tar.add(full, arcname=rel(fn), recursive=False)
    return buf.getvalue()


def unpack_tar(data: bytes, dest: str) -> None:
    """Extracts a tar (as produced by pack_workspace/download_tar) into `dest`, refusing
    any member whose path would land outside it (defence in depth — the tar is our own
    request's response, but a compromised or misbehaving host is exactly who this guards
    against)."""
    os.makedirs(dest, exist_ok=True)
    dest_abs = os.path.abspath(dest)
    # Python 3.12+ has a stdlib member filter for exactly this; use it when available and
    # keep our own boundary check either way (requires_python is 3.10, so it isn't a given).
    extract_kwargs = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
        for member in tar.getmembers():
            target = os.path.abspath(os.path.join(dest, member.name))
            if target != dest_abs and not target.startswith(dest_abs + os.sep):
                raise ValueError(f"refusing to extract tar member outside destination: {member.name}")
            tar.extract(member, path=dest, **extract_kwargs)
