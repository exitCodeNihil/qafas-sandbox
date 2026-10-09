"""Mirror of docs/protocol.md wire types used by this client.

Kept intentionally small: only the fields the SDK actually reads/writes.
Full source of truth is crates/proto/src/lib.rs; see sdk/ts/src/types.ts for
the TypeScript mirror. v3 additions (lifecycle timers, snapshots, sessions,
preview) are additive, same as the wire contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

HDR_PI_SESSION = "x-pi-session"
HDR_TOOL_CALL_ID = "x-tool-call-id"

Isolation = str  # "auto" | "native" | "vm" | "remote"
Trust = str  # "trusted" | "untrusted"

OnOutput = Callable[[bytes, str], None]  # (chunk, "stdout"|"stderr")


@dataclass
class ExecResult:
    exit: int
    stdout: str
    stderr: str
    duration_ms: int
    truncated: bool = False
    timed_out: bool = False


@dataclass
class FsStat:
    is_dir: bool
    size: int
    mode: int
    mtime: str


def _from_json(cls, d: dict):
    known = {f for f in cls.__dataclass_fields__}
    return cls(**{k: v for k, v in d.items() if k in known})


# ---- v5 sizes and limits (docs/protocol.md §3a "v5 sizes and limits")
SIZE_NAMES = ("micro", "mini", "medium", "high")
DEFAULT_SIZE = "medium"


@dataclass
class SandboxLimits:
    cpus: float  # 0.25 steps; cgroup cpu.max = cpus x 100000 per 100000
    mem_mib: int
    disk_mib: int  # writable scratch; RAM-backed on vm/remote, so never effectively above mem_mib
    pids: Optional[int] = None  # 0/absent on input = the nearest named size's


@dataclass
class SandboxUsage:
    cpu_millis: int
    mem_bytes: int
    mem_peak_bytes: int
    disk_bytes: int
    pids: int
    ts: Optional[str] = None  # RFC 3339 sample time


# Compiled defaults; SBX_SIZES on the binaries replaces the table wholesale. medium = the pre-v5 unit.
DEFAULT_SIZES: Dict[str, Dict[str, float]] = {
    "micro": {"cpus": 0.5, "mem_mib": 512, "disk_mib": 512, "pids": 128},
    "mini": {"cpus": 1, "mem_mib": 1024, "disk_mib": 1024, "pids": 256},
    "medium": {"cpus": 2, "mem_mib": 2048, "disk_mib": 2048, "pids": 512},
    "high": {"cpus": 4, "mem_mib": 4096, "disk_mib": 4096, "pids": 1024},
}


@dataclass
class SandboxInfo:
    id: str
    backend: str
    template: str
    state: str
    workspace_path: str
    pi_session: str
    created_at: str
    endpoint: str
    ready_at: Optional[str] = None
    host_id: Optional[str] = None
    isolation: Optional[str] = None
    last_activity: Optional[str] = None
    # v3
    name: Optional[str] = None
    labels: Optional[Dict[str, str]] = None
    state_changed_at: Optional[str] = None
    auto_stop_secs: Optional[int] = None
    auto_archive_secs: Optional[int] = None
    auto_delete_secs: Optional[int] = None
    max_age_secs: Optional[int] = None
    # v4
    idle_secs: Optional[int] = None  # ready|stopped: seconds since last activity
    running_secs: Optional[int] = None  # seconds since created_at
    # v5
    size: Optional[str] = None  # micro|mini|medium|high|custom ("" from a pre-v5 daemon)
    limits: Optional[SandboxLimits] = None
    enforcement: Optional[str] = None  # "kernel"|"daemon" (daemon = macOS native watchdog, CPU not capped)
    usage: Optional[SandboxUsage] = None  # latest boundary sample

    @classmethod
    def from_json(cls, d: dict) -> "SandboxInfo":
        info = _from_json(cls, d)
        if isinstance(info.limits, dict):
            info.limits = SandboxLimits(**info.limits)
        if isinstance(info.usage, dict):
            info.usage = SandboxUsage(**info.usage)
        return info


@dataclass
class Event:
    id: str
    ts: str
    host_id: str
    sandbox_id: str
    pi_session: str
    tool_call_id: str
    type: str
    data: Any = field(default=None)

    @classmethod
    def from_json(cls, d: dict) -> "Event":
        return _from_json(cls, d)


# ---------------------------------------------------------------- v3 snapshots (images)


@dataclass
class SnapshotSource:
    image: Optional[str] = None  # OCI ref with tag or digest; "latest" refused
    dockerfile: Optional[str] = None  # Dockerfile text
    sandbox_id: Optional[str] = None  # capture a live sandbox

    def to_json(self) -> Dict[str, str]:
        return {k: v for k, v in (("image", self.image), ("dockerfile", self.dockerfile), ("sandbox_id", self.sandbox_id)) if v}


@dataclass
class SnapshotInfo:
    name: str
    state: str  # "building" | "active" | "error"
    kind: str  # "image" | "vm"
    source: Dict[str, Any]
    created_at: str
    bytes: Optional[int] = None
    error: Optional[str] = None
    host_id: Optional[str] = None  # control plane
    warm: int = 0  # v4
    memory_snapshot: bool = True  # v4
    warm_ready: int = 0  # v4: mirrors the pool's current `warm` for this template

    @classmethod
    def from_json(cls, d: dict) -> "SnapshotInfo":
        return _from_json(cls, d)


# ---------------------------------------------------------------- v3 sessions


@dataclass
class SessionCommand:
    command_id: str
    # An async exec answers 202 {command_id} only (docs/protocol.md §5); the rest arrives via GET.
    cmd: str = ""
    state: str = "running"  # "running" | "done"
    started_at: str = ""
    exit: Optional[int] = None
    ended_at: Optional[str] = None
    stdout: Optional[str] = None  # GET .../commands/{cid} only
    stderr: Optional[str] = None

    @classmethod
    def from_json(cls, d: dict) -> "SessionCommand":
        return _from_json(cls, d)


@dataclass
class SessionInfo:
    id: str
    cwd: str
    created_at: str
    commands: List[SessionCommand]

    @classmethod
    def from_json(cls, d: dict) -> "SessionInfo":
        return cls(id=d["id"], cwd=d["cwd"], created_at=d["created_at"], commands=[SessionCommand.from_json(c) for c in d.get("commands", [])])


# ---------------------------------------------------------------- v3 preview


@dataclass
class PreviewInfo:
    url: str
    token: str
    port: int
    expires_at: str

    @classmethod
    def from_json(cls, d: dict) -> "PreviewInfo":
        return _from_json(cls, d)
