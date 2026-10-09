package qafas

import (
	"encoding/json"
	"fmt"
)

// Mirror of the docs/protocol.md wire types this client uses; sdk/python's types.py
// is the reference. Unknown JSON fields are ignored. Optional numbers that can
// legitimately be 0 are pointers, so "absent" and "0" stay distinct.

const (
	HdrPiSession  = "x-pi-session"
	HdrToolCallID = "x-tool-call-id"
	DefaultSize   = "medium"
)

// SizeNames are the named sandbox sizes (docs/protocol.md "v5 sizes and limits").
var SizeNames = []string{"micro", "mini", "medium", "high"}

// OnOutput receives streamed output; stream is "stdout" or "stderr".
type OnOutput func(chunk []byte, stream string)

// ExecResult is the outcome of Exec / ExecBuffered.
type ExecResult struct {
	Exit       int    `json:"exit"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMs int64  `json:"duration_ms"`
	Truncated  bool   `json:"truncated"`
	TimedOut   bool   `json:"timed_out"`
}

// FsStat is the answer of GET /fs/stat.
type FsStat struct {
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
	Mode  int64  `json:"mode"`
	Mtime string `json:"mtime"`
}

// SandboxLimits are a sandbox's resource ceilings (v5). Pids nil on input means the
// nearest named size's.
type SandboxLimits struct {
	Cpus    float64 `json:"cpus"` // 0.25 steps
	MemMiB  int     `json:"mem_mib"`
	DiskMiB int     `json:"disk_mib"` // writable scratch; RAM-backed on vm/remote
	Pids    *int    `json:"pids,omitempty"`
}

// SandboxUsage is the latest boundary sample (v5).
type SandboxUsage struct {
	CPUMillis    int64  `json:"cpu_millis"`
	MemBytes     int64  `json:"mem_bytes"`
	MemPeakBytes int64  `json:"mem_peak_bytes"`
	DiskBytes    int64  `json:"disk_bytes"`
	Pids         int    `json:"pids"`
	Ts           string `json:"ts,omitempty"` // RFC 3339 sample time
}

func intp(n int) *int { return &n }

// DefaultSizes are the compiled defaults; SBX_SIZES on the binaries replaces the
// table wholesale. medium is the pre-v5 unit.
var DefaultSizes = map[string]SandboxLimits{
	"micro":  {Cpus: 0.5, MemMiB: 512, DiskMiB: 512, Pids: intp(128)},
	"mini":   {Cpus: 1, MemMiB: 1024, DiskMiB: 1024, Pids: intp(256)},
	"medium": {Cpus: 2, MemMiB: 2048, DiskMiB: 2048, Pids: intp(512)},
	"high":   {Cpus: 4, MemMiB: 4096, DiskMiB: 4096, Pids: intp(1024)},
}

// SandboxInfo is the daemon's record of a sandbox (v1 plus v3/v4/v5 fields).
type SandboxInfo struct {
	ID            string `json:"id"`
	Backend       string `json:"backend"`
	Template      string `json:"template"`
	State         string `json:"state"`
	WorkspacePath string `json:"workspace_path"`
	PiSession     string `json:"pi_session"`
	CreatedAt     string `json:"created_at"`
	Endpoint      string `json:"endpoint"`
	ReadyAt       string `json:"ready_at,omitempty"`
	HostID        string `json:"host_id,omitempty"`
	Isolation     string `json:"isolation,omitempty"`
	LastActivity  string `json:"last_activity,omitempty"`
	// v3
	Name            string            `json:"name,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	StateChangedAt  string            `json:"state_changed_at,omitempty"`
	AutoStopSecs    *int              `json:"auto_stop_secs,omitempty"`
	AutoArchiveSecs *int              `json:"auto_archive_secs,omitempty"`
	AutoDeleteSecs  *int              `json:"auto_delete_secs,omitempty"`
	MaxAgeSecs      *int              `json:"max_age_secs,omitempty"`
	// v4
	IdleSecs    *int `json:"idle_secs,omitempty"`    // ready|stopped: seconds since last activity
	RunningSecs *int `json:"running_secs,omitempty"` // seconds since created_at
	// v5
	Size        string         `json:"size,omitempty"` // micro|mini|medium|high|custom ("" from a pre-v5 daemon)
	Limits      *SandboxLimits `json:"limits,omitempty"`
	Enforcement string         `json:"enforcement,omitempty"` // "kernel"|"daemon"
	Usage       *SandboxUsage  `json:"usage,omitempty"`
}

// Event is one frame of qafas's /events/ws firehose. Data is event-specific JSON.
type Event struct {
	ID         string          `json:"id"`
	Ts         string          `json:"ts"`
	HostID     string          `json:"host_id"`
	SandboxID  string          `json:"sandbox_id"`
	PiSession  string          `json:"pi_session"`
	ToolCallID string          `json:"tool_call_id"`
	Type       string          `json:"type"`
	Data       json.RawMessage `json:"data,omitempty"`
}

// SnapshotSource says where a snapshot is built from; set exactly one.
type SnapshotSource struct {
	Image      string `json:"image,omitempty"`      // OCI ref with tag or digest; "latest" refused
	Dockerfile string `json:"dockerfile,omitempty"` // Dockerfile text
	SandboxID  string `json:"sandbox_id,omitempty"` // capture a live sandbox
}

// SnapshotInfo describes a snapshot (a named image a sandbox can be created from).
type SnapshotInfo struct {
	Name           string         `json:"name"`
	State          string         `json:"state"` // "building" | "active" | "error"
	Kind           string         `json:"kind"`  // "image" | "vm"
	Source         map[string]any `json:"source"`
	CreatedAt      string         `json:"created_at"`
	Bytes          *int64         `json:"bytes,omitempty"`
	Error          string         `json:"error,omitempty"`
	HostID         string         `json:"host_id,omitempty"` // control plane
	Warm           int            `json:"warm"`
	MemorySnapshot bool           `json:"memory_snapshot"` // true when the server omits it
	WarmReady      int            `json:"warm_ready"`
}

// SessionCommand is one command of a Session. An async exec answers with only
// CommandID set; the rest arrives via Session.Command.
type SessionCommand struct {
	CommandID string  `json:"command_id"`
	Cmd       string  `json:"cmd"`
	State     string  `json:"state"` // "running" | "done"; "running" when the server omits it
	StartedAt string  `json:"started_at"`
	Exit      *int    `json:"exit,omitempty"`
	EndedAt   *string `json:"ended_at,omitempty"`
	Stdout    *string `json:"stdout,omitempty"` // GET .../commands/{cid} only
	Stderr    *string `json:"stderr,omitempty"`
}

// SessionInfo is the wire record of a session.
type SessionInfo struct {
	ID        string           `json:"id"`
	Cwd       string           `json:"cwd"`
	CreatedAt string           `json:"created_at"`
	Commands  []SessionCommand `json:"commands"`
}

// PreviewInfo is a signed URL for a port inside the sandbox.
type PreviewInfo struct {
	URL       string `json:"url"`
	Token     string `json:"token"`
	Port      int    `json:"port"`
	ExpiresAt string `json:"expires_at"`
}

// UnmarshalJSON defaults State to "running" when the server omits it.
func (c *SessionCommand) UnmarshalJSON(b []byte) error {
	type plain SessionCommand
	p := plain{State: "running"}
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	if p.State == "" {
		p.State = "running"
	}
	*c = SessionCommand(p)
	return nil
}

// UnmarshalJSON defaults MemorySnapshot to true when the server omits it.
func (s *SnapshotInfo) UnmarshalJSON(b []byte) error {
	type plain SnapshotInfo
	p := plain{MemorySnapshot: true}
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*s = SnapshotInfo(p)
	return nil
}

// Error is a non-2xx response from qafas or the control plane.
type Error struct {
	Status int
	Body   string
}

func (e *Error) Error() string {
	if msg := extractError([]byte(e.Body)); msg != "" {
		return fmt.Sprintf("HTTP %d: %s", e.Status, msg)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body)
}

// extractError returns the server's {"error": "..."} text, or "" when there is none.
func extractError(body []byte) string {
	var j struct {
		Error any `json:"error"`
	}
	if json.Unmarshal(body, &j) != nil {
		return ""
	}
	s, _ := j.Error.(string)
	return s
}
