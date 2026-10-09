// Package events mirrors crates/proto/src/lib.rs field-for-field. Frozen at Gate A.
// Change proto first, then this file and sdk/ts/src/types.ts in one commit.
package events

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

const (
	Version          = "0.1.0" // x-release-please-version
	GuestAgentPort   = 7777
	QafasPort        = 7700
	ControlplanePort = 7800
	EgressProxyPort  = 3128
	HdrPiSession     = "X-Pi-Session"
	HdrToolCallID    = "X-Tool-Call-Id"
)

// EventType values.
const (
	SandboxCreated   = "sandbox.created"
	SandboxReady     = "sandbox.ready"
	SandboxDestroyed = "sandbox.destroyed"
	ExecStart        = "exec.start"
	ExecEnd          = "exec.end"
	FileRead         = "file.read"
	FileWrite        = "file.write"
	FileEdit         = "file.edit"
	BrowserNavigate  = "browser.navigate"
	EgressAllow      = "egress.allow"
	EgressDeny       = "egress.deny"
	PoolRefill       = "pool.refill"
	ErrorEvent       = "error"
	// v2
	SandboxTierSelected = "sandbox.tier_selected"
	ProcessStart        = "process.start"
	ProcessExit         = "process.exit"
	FileAccess          = "file.access"
	NetConnect          = "net.connect"
	SecurityAlert       = "security.alert"
	// v3
	SandboxStopped   = "sandbox.stopped"
	SandboxStarted   = "sandbox.started"
	SandboxPaused    = "sandbox.paused"
	SandboxResumed   = "sandbox.resumed"
	SandboxArchived  = "sandbox.archived"
	SnapshotBuilding = "snapshot.building"
	SnapshotReady    = "snapshot.ready"
	SnapshotError    = "snapshot.error"
	PreviewCreated   = "preview.created"
	// v5.1: pushed by the guest agent while an exec is live; data is a SandboxUsage
	SandboxUsageEvent = "sandbox.usage"
)

// Isolation tiers and trust levels (v2).
const (
	IsolationAuto   = "auto"
	IsolationNative = "native"
	IsolationVm     = "vm"
	IsolationRemote = "remote"
	TrustTrusted    = "trusted"
	TrustUntrusted  = "untrusted"
)

// NormalizeIsolation maps an `isolation` value to its canonical wire value (docs/D25:
// native|vm|remote are frozen; process|docker|firecracker are input aliases, the only
// labels a person sees). "" defaults to "auto". ok is false for anything else.
func NormalizeIsolation(s string) (string, bool) {
	switch s {
	case "":
		return IsolationAuto, true
	case IsolationAuto, IsolationNative, IsolationVm, IsolationRemote:
		return s, true
	case "process":
		return IsolationNative, true
	case "docker":
		return IsolationVm, true
	case "firecracker":
		return IsolationRemote, true
	default:
		return "", false
	}
}

// NormalizeTrust maps a `trust` value to its canonical value. "" defaults to "trusted".
// ok is false for anything else.
func NormalizeTrust(s string) (string, bool) {
	switch s {
	case "":
		return TrustTrusted, true
	case TrustTrusted, TrustUntrusted:
		return s, true
	default:
		return "", false
	}
}

// Alert severities and detection rule names (v2). Mirror proto::Severity / proto::rules.
const (
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"

	RuleSeccompViolation   = "seccomp.violation"
	RuleSensitivePathWrite = "sensitive_path.write"
	RuleSensitivePathRead  = "sensitive_path.read"
	RuleCanaryRead         = "canary.read"
	RuleEgressDenyBurst    = "egress.deny_burst"
	RuleMetadataProbe      = "metadata.probe"
	RuleEscapeProbe        = "escape.probe"
	RulePtraceAttempt      = "ptrace.attempt"
	RuleMountAttempt       = "mount.attempt"
	RuleSetuidExec         = "setuid.exec"
	RuleWorkspaceEscape    = "workspace.escape"
	RuleResourceLimit      = "resource.limit"
	RuleSandboxDenied      = "sandbox.denied"
	RuleHostRecon          = "host.recon"
	RuleSandboxLongRunning = "sandbox.long_running" // v4
	RuleTemplateInsecure   = "template.insecure"    // v5.2
)

// AlertData is the data payload of a security.alert event.
type AlertData struct {
	Severity string          `json:"severity"`
	Rule     string          `json:"rule"`
	Msg      string          `json:"msg"`
	PID      int             `json:"pid,omitempty"`
	Path     string          `json:"path,omitempty"`
	Evidence json.RawMessage `json:"evidence,omitempty"`
}

// Event is one audit event. ID is a ULID; TS is RFC 3339 UTC with ms.
type Event struct {
	ID         string          `json:"id"`
	TS         string          `json:"ts"`
	HostID     string          `json:"host_id"`
	SandboxID  string          `json:"sandbox_id"`
	PiSession  string          `json:"pi_session"`
	ToolCallID string          `json:"tool_call_id"`
	Type       string          `json:"type"`
	Data       json.RawMessage `json:"data"`
}

// ClientEvent is the body of POST /sandboxes/{id}/events.
type ClientEvent struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// ---- exec

type ExecReq struct {
	Cmd       string            `json:"cmd"`
	Cwd       string            `json:"cwd"`
	Env       map[string]string `json:"env,omitempty"`
	TimeoutMs *uint64           `json:"timeout_ms,omitempty"`
}

type ExecResp struct {
	Exit       int    `json:"exit"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMs uint64 `json:"duration_ms"`
	Truncated  bool   `json:"truncated"`
}

type PtySize struct {
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// ExecFrame is the /exec/ws frame (all variants flattened; Type selects).
type ExecFrame struct {
	Type       string            `json:"type"`
	Cmd        string            `json:"cmd,omitempty"`
	Cwd        string            `json:"cwd,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	Pty        *PtySize          `json:"pty,omitempty"`
	TimeoutMs  *uint64           `json:"timeout_ms,omitempty"`
	Data       string            `json:"data,omitempty"`
	Cols       uint16            `json:"cols,omitempty"`
	Rows       uint16            `json:"rows,omitempty"`
	Sig        string            `json:"sig,omitempty"`
	Code       int               `json:"code"`
	Signal     *string           `json:"signal"`
	DurationMs uint64            `json:"duration_ms,omitempty"`
	TimedOut   bool              `json:"timed_out,omitempty"`
}

// ---- fs

type FsStat struct {
	IsDir bool   `json:"is_dir"`
	Size  uint64 `json:"size"`
	Mode  uint32 `json:"mode"`
	Mtime string `json:"mtime"`
}

type MkdirReq struct {
	Path string `json:"path"`
}

type Healthz struct {
	OK      bool   `json:"ok"`
	UID     uint32 `json:"uid"`
	Version string `json:"version"`
}

// ---- qafas

type WorkspaceSpec struct {
	HostPath string `json:"host_path"`
}

type CreateSandboxReq struct {
	Template    string         `json:"template"`
	Workspace   *WorkspaceSpec `json:"workspace,omitempty"`
	PiSession   string         `json:"pi_session"`
	Isolation   string         `json:"isolation,omitempty"`    // v2: auto|native|vm|remote
	Trust       string         `json:"trust,omitempty"`        // v2: trusted|untrusted
	Tools       []string       `json:"tools,omitempty"`        // v2
	EgressAllow []string       `json:"egress_allow,omitempty"` // v2
	TTLSecs     *uint64        `json:"ttl_secs,omitempty"`     // v2
	// v3
	Name            *string           `json:"name,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Env             map[string]string `json:"env,omitempty"`
	AutoStopSecs    *uint64           `json:"auto_stop_secs,omitempty"`
	AutoArchiveSecs *uint64           `json:"auto_archive_secs,omitempty"`
	AutoDeleteSecs  *uint64           `json:"auto_delete_secs,omitempty"` // 0 = ephemeral
	MaxAgeSecs      *uint64           `json:"max_age_secs,omitempty"`
	// v5 (§3a "v5 sizes and limits"): one of the two; the control plane resolves a
	// name to Limits and forwards both to the daemon.
	Size   string         `json:"size,omitempty"`
	Limits *SandboxLimits `json:"limits,omitempty"`
}

type CreateSandboxResp struct {
	ID            string            `json:"id"`
	Endpoint      string            `json:"endpoint"`
	Token         string            `json:"token"`
	Backend       string            `json:"backend"`
	WorkspacePath string            `json:"workspace_path"`
	ExpiresAt     string            `json:"expires_at"`
	HostID        string            `json:"host_id,omitempty"`
	Isolation     string            `json:"isolation,omitempty"`     // v2
	Tools         map[string]string `json:"tools,omitempty"`         // v2
	MissingTools  []string          `json:"missing_tools,omitempty"` // v2
	// v2: the host's TLS certificate fingerprint, so the harness pins the same
	// certificate the control plane pinned at registration.
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
	// v5
	Size   string         `json:"size,omitempty"`
	Limits *SandboxLimits `json:"limits,omitempty"`
	// v5.1: the daemon's own record right after create — name, labels, resolved
	// timers, enforcement. Authoritative over the request when present.
	Info *SandboxInfo `json:"info,omitempty"`
}

// SandboxState values: creating | ready | busy | paused | stopped | archived | destroyed (v3 adds paused|stopped|archived).
type SandboxInfo struct {
	ID            string  `json:"id"`
	Backend       string  `json:"backend"`
	Template      string  `json:"template"`
	State         string  `json:"state"`
	WorkspacePath string  `json:"workspace_path"`
	PiSession     string  `json:"pi_session"`
	CreatedAt     string  `json:"created_at"`
	ReadyAt       *string `json:"ready_at"`
	Endpoint      string  `json:"endpoint"`
	HostID        string  `json:"host_id,omitempty"`
	Isolation     string  `json:"isolation,omitempty"`     // v2
	LastActivity  *string `json:"last_activity,omitempty"` // v2
	// v3
	Name            string            `json:"name"`
	Labels          map[string]string `json:"labels,omitempty"`
	StateChangedAt  *string           `json:"state_changed_at,omitempty"`
	AutoStopSecs    *uint64           `json:"auto_stop_secs,omitempty"`
	AutoArchiveSecs *uint64           `json:"auto_archive_secs,omitempty"`
	AutoDeleteSecs  *uint64           `json:"auto_delete_secs,omitempty"`
	MaxAgeSecs      *uint64           `json:"max_age_secs,omitempty"`
	// v4
	IdleSecs    uint64 `json:"idle_secs,omitempty"`
	RunningSecs uint64 `json:"running_secs,omitempty"`
	// v5
	Size        string         `json:"size,omitempty"` // micro|mini|medium|high|custom; "" from a pre-v5 daemon
	Limits      *SandboxLimits `json:"limits,omitempty"`
	Enforcement string         `json:"enforcement,omitempty"` // kernel | daemon
	Usage       *SandboxUsage  `json:"usage,omitempty"`
	// v3 control plane only: which API key created it.
	ApiKeyID   string `json:"api_key_id,omitempty"`
	ApiKeyName string `json:"api_key_name,omitempty"`
}

// ---- v5 sizes and limits (mirrors proto::SandboxLimits / SandboxUsage / HostCommitted / sizes)

// SandboxLimits are one sandbox's ceilings: set at create, re-applied at pool acquire,
// enforced by cgroup v2 (vm/remote/Linux native) or the daemon's watchdog (macOS native).
type SandboxLimits struct {
	Cpus    float64 `json:"cpus"` // 0.25 steps
	MemMiB  uint64  `json:"mem_mib"`
	DiskMiB uint64  `json:"disk_mib"` // writable scratch; RAM-backed on vm/remote
	Pids    uint32  `json:"pids,omitempty"`
}

// SandboxUsage is the latest boundary sample (cgroup files, /proc); CpuMillis is cumulative.
type SandboxUsage struct {
	CpuMillis    uint64 `json:"cpu_millis"`
	MemBytes     uint64 `json:"mem_bytes"`
	MemPeakBytes uint64 `json:"mem_peak_bytes"`
	DiskBytes    uint64 `json:"disk_bytes"`
	Pids         uint32 `json:"pids"`
	TS           string `json:"ts,omitempty"`
}

// HostCommitted is Σ Limits of a host's live sandboxes; placement refuses a host once
// committed+requested would exceed HostCaps × overcommit.
type HostCommitted struct {
	Cpus   float64 `json:"cpus"`
	MemMiB uint64  `json:"mem_mib"`
}

const (
	DefaultSize = "medium"
	CustomSize  = "custom"
	CPUStep     = 0.25
)

// DefaultSizes is the compiled table; SBX_SIZES replaces it wholesale. medium is the
// pre-v5 unit (2 CPU / 2 GiB / 512 pids) and must stay present.
func DefaultSizes() map[string]SandboxLimits {
	return map[string]SandboxLimits{
		"micro":  {Cpus: 0.5, MemMiB: 512, DiskMiB: 512, Pids: 128},
		"mini":   {Cpus: 1, MemMiB: 1024, DiskMiB: 1024, Pids: 256},
		"medium": {Cpus: 2, MemMiB: 2048, DiskMiB: 2048, Pids: 512},
		"high":   {Cpus: 4, MemMiB: 4096, DiskMiB: 4096, Pids: 1024},
	}
}

// ResolveSize maps a create request to (size name, limits): exactly one of size/limits,
// neither means medium. The error text is the 400 body. Same rules as proto::sizes::resolve.
func ResolveSize(size string, limits *SandboxLimits, table map[string]SandboxLimits) (string, SandboxLimits, error) {
	switch {
	case size != "" && limits != nil:
		return "", SandboxLimits{}, errors.New("give either size or limits, not both")
	case size != "":
		l, ok := table[size]
		if !ok {
			names := make([]string, 0, len(table))
			for n := range table {
				names = append(names, n)
			}
			sort.Strings(names)
			return "", SandboxLimits{}, fmt.Errorf("unknown size %q; sizes: %s", size, strings.Join(names, ", "))
		}
		return size, l, nil
	case limits != nil:
		l := *limits
		if steps := l.Cpus / CPUStep; l.Cpus < CPUStep || steps != math.Trunc(steps) {
			return "", SandboxLimits{}, fmt.Errorf("cpus must be a multiple of %v, at least %v", CPUStep, CPUStep)
		}
		if l.MemMiB < 64 {
			return "", SandboxLimits{}, errors.New("mem_mib must be at least 64")
		}
		if l.DiskMiB == 0 {
			return "", SandboxLimits{}, errors.New("disk_mib must be at least 1")
		}
		if l.Pids == 0 {
			var nearest, largest uint32
			for _, s := range table {
				if s.Pids > largest {
					largest = s.Pids
				}
				if s.MemMiB >= l.MemMiB && (nearest == 0 || s.Pids < nearest) {
					nearest = s.Pids
				}
			}
			l.Pids = nearest
			if l.Pids == 0 {
				l.Pids = largest
			}
			if l.Pids == 0 {
				l.Pids = 512
			}
		}
		return CustomSize, l, nil
	default:
		l, ok := table[DefaultSize]
		if !ok {
			return "", SandboxLimits{}, fmt.Errorf("size table has no %q", DefaultSize)
		}
		return DefaultSize, l, nil
	}
}

// Fits reports whether l is within cap in every dimension (API-key caps, host ceilings).
func (l SandboxLimits) Fits(cap SandboxLimits) bool {
	return l.Cpus <= cap.Cpus && l.MemMiB <= cap.MemMiB && l.DiskMiB <= cap.DiskMiB && (cap.Pids == 0 || l.Pids <= cap.Pids)
}

// ---- v3 snapshots

type SnapshotSource struct {
	Image      string `json:"image,omitempty"`
	Dockerfile string `json:"dockerfile,omitempty"`
	SandboxID  string `json:"sandbox_id,omitempty"`
}

type CreateSnapshotReq struct {
	Name           string         `json:"name"`
	Source         SnapshotSource `json:"source"`
	Warm           uint32         `json:"warm,omitempty"`            // v4
	MemorySnapshot *bool          `json:"memory_snapshot,omitempty"` // v4, default true
	Runtime        string         `json:"runtime,omitempty"`         // v4c: remote|vm (aliases accepted)
}

// SnapshotState values: building | active | error.
// UpdateSnapshotReq is v4 PUT /snapshots/{name}.
type UpdateSnapshotReq struct {
	Warm uint32 `json:"warm"`
}

type SnapshotInfo struct {
	Name           string         `json:"name"`
	State          string         `json:"state"`
	Kind           string         `json:"kind"` // image | vm
	Source         SnapshotSource `json:"source"`
	CreatedAt      string         `json:"created_at"`
	Bytes          uint64         `json:"bytes"`
	Error          string         `json:"error,omitempty"`
	HostID         string         `json:"host_id,omitempty"`
	Warm           uint32         `json:"warm"`            // v4
	MemorySnapshot bool           `json:"memory_snapshot"` // v4
	WarmReady      uint32         `json:"warm_ready"`      // v4
	Runtime        string         `json:"runtime"`         // v4c
	// v5.2: the last template security scan on that host (security.md M43).
	Security *TemplateSecurity `json:"security,omitempty"`
}

// SecurityCheck is one line of images/probe/scan.sh (v5.2). Class is "boundary"
// (any failure grades F) or "hygiene".
type SecurityCheck struct {
	ID     string `json:"id"`
	Class  string `json:"class"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// TemplateSecurity is a template's scan and grade: A, B, C or F (v5.2).
type TemplateSecurity struct {
	Grade       string          `json:"grade"`
	ScannedAt   string          `json:"scanned_at"`
	ImageDigest string          `json:"image_digest"`
	Findings    []SecurityCheck `json:"findings"`
}

// ---- v3 api keys (control plane only)

type ApiKeyLimits struct {
	MaxConcurrent *uint32  `json:"max_concurrent,omitempty"`
	MaxPerHour    *uint32  `json:"max_per_hour,omitempty"`
	AllowedTiers  []string `json:"allowed_tiers,omitempty"`
	MaxTTLSecs    *uint64  `json:"max_ttl_secs,omitempty"`
	AllowedEgress []string `json:"allowed_egress,omitempty"`
	// v5: violations are 403, never clamped.
	MaxCpus      *float64 `json:"max_cpus,omitempty"`
	MaxMemMiB    *uint64  `json:"max_mem_mib,omitempty"`
	MaxDiskMiB   *uint64  `json:"max_disk_mib,omitempty"`
	AllowedSizes []string `json:"allowed_sizes,omitempty"`
}

type CreateApiKeyReq struct {
	Name   string            `json:"name"`
	Scopes []string          `json:"scopes"` // ["sandboxes"] | ["admin"]
	Limits ApiKeyLimits      `json:"limits"`
	Labels map[string]string `json:"labels,omitempty"`
}

type ApiKey struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Prefix        string            `json:"prefix"`
	Scopes        []string          `json:"scopes"`
	Limits        ApiKeyLimits      `json:"limits"`
	Labels        map[string]string `json:"labels"`
	CreatedAt     string            `json:"created_at"`
	LastUsedAt    *string           `json:"last_used_at"`
	RevokedAt     *string           `json:"revoked_at,omitempty"`
	LiveSandboxes int               `json:"live_sandboxes"`
	Created24h    int               `json:"created_24h"`
}

type ApiKeyCreated struct {
	ApiKey
	Key string `json:"key"` // shown once
}

type ApiKeyUsage struct {
	Since            string         `json:"since"`
	SandboxesCreated int            `json:"sandboxes_created"`
	LiveSandboxes    int            `json:"live_sandboxes"`
	Execs            int            `json:"execs"`
	Alerts           map[string]int `json:"alerts"` // critical|high|medium|low
	Egress           map[string]int `json:"egress"` // allow|deny
	SandboxSeconds   float64        `json:"sandbox_seconds"`
	ByTier           map[string]int `json:"by_tier"`
	LastUsedAt       *string        `json:"last_used_at"`
}

// ---- v3 preview

type CreatePreviewReq struct {
	Port    uint16  `json:"port"`
	TTLSecs *uint64 `json:"ttl_secs,omitempty"`
}

type PreviewInfo struct {
	URL       string `json:"url"`
	Token     string `json:"token"`
	Port      uint16 `json:"port"`
	ExpiresAt string `json:"expires_at"`
}

type PoolStat struct {
	Warm    uint32 `json:"warm"`
	Target  uint32 `json:"target"`
	Restore bool   `json:"restore"` // v4: warm entries are restored, not booted
}

// PoolStats is v4 GET /pool: {"<template>": PoolStat}.
type PoolStats map[string]PoolStat

type QafasHealthz struct {
	OK      bool     `json:"ok"`
	Backend string   `json:"backend"`
	HostID  string   `json:"host_id"`
	Tiers   []string `json:"tiers,omitempty"`   // v2
	Version string   `json:"version,omitempty"` // v2
}

// ---- control plane

// HostCaps is v4c: what a host can do, from qafas doctor.
type HostCaps struct {
	OS             string   `json:"os"`
	Arch           string   `json:"arch"`
	CPUs           uint32   `json:"cpus"`
	MemMiB         uint64   `json:"mem_mib"`
	KVM            bool     `json:"kvm"`
	Firecracker    bool     `json:"firecracker"`
	Podman         bool     `json:"podman"`
	ProcessSandbox bool     `json:"process_sandbox"`
	Bpftrace       bool     `json:"bpftrace"`
	HugepagesMiB   uint64   `json:"hugepages_mib"`
	Supported      []string `json:"supported"`
}

type HostRegister struct {
	HostID   string   `json:"host_id"`
	URL      string   `json:"url"`
	Backend  string   `json:"backend"`
	Capacity uint32   `json:"capacity"`
	Tiers    []string `json:"tiers,omitempty"` // v2
	// v2: SHA-256 of the DER of the host's TLS certificate, lowercase hex. Empty
	// when the host serves plain HTTP. Trust on first use, bounded by SBX_HOST_TOKEN.
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
	// v2: what the host enforces and watches ({egress, rules, watch}); opaque, shown on the Policy page.
	Policy json.RawMessage `json:"policy,omitempty"`
	Caps   HostCaps        `json:"caps"` // v4c
}

type Heartbeat struct {
	Pool      PoolStats     `json:"pool"`
	Sandboxes []SandboxInfo `json:"sandboxes"`
}

type Host struct {
	ID             string          `json:"id"`
	URL            string          `json:"url"`
	Backend        string          `json:"backend"`
	Capacity       uint32          `json:"capacity"`
	Pool           PoolStats       `json:"pool"`
	LastSeen       string          `json:"last_seen"`
	Tiers          []string        `json:"tiers,omitempty"`           // v2
	TLSFingerprint string          `json:"tls_fingerprint,omitempty"` // v2
	Policy         json.RawMessage `json:"policy,omitempty"`          // v2
	Caps           HostCaps        `json:"caps"`                      // v4c
	Committed      HostCommitted   `json:"committed"`                 // v5
}

// ---- egress

type EgressPolicy struct {
	Allow          []string `json:"allow"`
	DenyCidrsExtra []string `json:"deny_cidrs_extra,omitempty"`
	// v5.3: private ranges an allowed name may resolve into (internal mirrors). Host file only.
	AllowPrivateCidrs []string `json:"allow_private_cidrs,omitempty"`
}

// TokenEqual compares static admin tokens in constant time.
func TokenEqual(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }
