// Package qafas is the Go client for Qafas Sandbox: a control plane (:7800), which
// places the sandbox and hands back the worker to use, or one worker (:7700) directly.
// It mirrors sdk/python (the reference) and the wire contract in docs/protocol.md.
package qafas

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Daytona/E2B-style tier name <-> this project's `isolation`. Purely a client-side
// relabelling, never sent on the wire; Acquire translates it to `isolation`.
var runtimeToIsolation = map[string]string{"process": "native", "docker": "vm", "firecracker": "remote"}

// RuntimeToIsolation maps auto|process|docker|firecracker to ""|native|vm|remote ("" =
// let qafas pick). An empty runtime is "unset" and maps to "". Anything else is an error
// naming the accepted values.
func RuntimeToIsolation(runtime string) (string, error) {
	if runtime == "" || runtime == "auto" {
		return "", nil
	}
	if iso, ok := runtimeToIsolation[runtime]; ok {
		return iso, nil
	}
	return "", fmt.Errorf("invalid runtime %q: expected one of auto|process|docker|firecracker", runtime)
}

// IsolationToRuntime maps native|vm|remote to process|docker|firecracker ("" otherwise).
func IsolationToRuntime(isolation string) string {
	for rt, iso := range runtimeToIsolation {
		if iso == isolation {
			return rt
		}
	}
	return ""
}

// ControlPlaneToken is the bearer for the control plane: an API key identifies the
// application (docs/protocol.md section 4b); the admin token is the root credential and the fallback.
func ControlPlaneToken(apiKey string) string {
	if apiKey != "" {
		return apiKey
	}
	if k := os.Getenv("SBX_API_KEY"); k != "" {
		return k
	}
	return os.Getenv("SBX_ADMIN_TOKEN")
}

// isWorker: GET /healthz has a `backend` field on qafas, not on the control plane.
func isWorker(ctx context.Context, base string) (bool, error) {
	data, err := call(ctx, "GET", base+"/healthz", nil, nil)
	if err != nil {
		return false, err
	}
	if len(data) == 0 {
		return false, nil
	}
	var h any
	if err := json.Unmarshal(data, &h); err != nil {
		return false, err
	}
	m, ok := h.(map[string]any)
	if !ok {
		return false, nil
	}
	_, has := m["backend"]
	return has, nil
}

// AcquireOptions are the optional knobs of Acquire. The zero value is a trusted
// "base" sandbox on whatever tier the server resolves. Numeric fields the wire treats
// as meaningful at 0 (timers, TTL) are pointers: nil = not sent.
type AcquireOptions struct {
	APIKey string // control plane bearer; falls back to $SBX_API_KEY then $SBX_ADMIN_TOKEN
	Token  string // explicit bearer for either server kind; falls back to $SBX_TOKEN on a worker

	// Runtime ("auto"|"process"|"docker"|"firecracker") maps to Isolation
	// ("native"|"vm"|"remote") and wins when both are set. With neither, the request
	// carries no `isolation` key and the server resolves auto (docs/decisions.md D25).
	Runtime   string
	Isolation string

	Trust       string // "trusted" (default) | "untrusted"
	Tools       []string
	EgressAllow []string
	TTLSecs     *int // idle TTL

	Template string // default "base"
	Snapshot string // aliases Template (the snapshot name to build from); wins when set

	Name   string
	Labels map[string]string
	Env    map[string]string // added to every exec; PROTECTED_ENV names dropped server-side

	// v3 idle/lifetime timers (docs/protocol.md "Lifecycle").
	AutoStopSecs    *int
	AutoArchiveSecs *int
	AutoDeleteSecs  *int
	MaxAgeSecs      *int

	// v5 resources: Size ("micro"|"mini"|"medium"|"high") or Limits picks the
	// ceilings; giving both is a 400, neither defaults to "medium". Only the caller of
	// Acquire picks this; never expose it as a tool parameter a model can set.
	Size   string
	Limits *SandboxLimits

	// SkipWorkspaceUpload leaves a remote-tier cwd un-uploaded (default: it is tarred and uploaded).
	SkipWorkspaceUpload bool
}

// Acquire acquires a sandbox. url may point at the control plane (:7800) or straight at
// a worker (:7700), detected via GET /healthz; "" means $SANDBOX_URL, else
// http://127.0.0.1:7700. piSession "" defaults to "sbx-go-<pid>".
//
// cwd is optional and never defaulted to the current directory: pass it to mount
// (native, vm) or upload (remote) a workspace at the same path; "" gives the sandbox its
// own /home/agent with no workspace sent and nothing uploaded. Pass nil opts for defaults.
func Acquire(ctx context.Context, url, cwd, piSession string, opts *AcquireOptions) (*Sandbox, error) {
	if opts == nil {
		opts = &AcquireOptions{}
	}
	o := *opts
	if url == "" {
		url = os.Getenv("SANDBOX_URL")
	}
	if url == "" {
		url = "http://127.0.0.1:7700"
	}
	if piSession == "" {
		piSession = fmt.Sprintf("sbx-go-%d", os.Getpid())
	}
	iso, err := RuntimeToIsolation(o.Runtime)
	if err != nil {
		return nil, err
	}
	if iso == "" {
		iso = o.Isolation
	}

	worker, err := isWorker(ctx, url)
	if err != nil {
		return nil, err
	}

	template := o.Template
	if o.Snapshot != "" {
		template = o.Snapshot
	}
	if template == "" {
		template = "base"
	}
	trust := o.Trust
	if trust == "" {
		trust = "trusted"
	}
	req := map[string]any{"template": template, "pi_session": piSession, "trust": trust}
	if cwd != "" {
		req["workspace"] = map[string]string{"host_path": cwd}
	}
	if iso != "" {
		req["isolation"] = iso
	}
	if len(o.Tools) > 0 {
		req["tools"] = o.Tools
	}
	if len(o.EgressAllow) > 0 {
		req["egress_allow"] = o.EgressAllow
	}
	for k, v := range map[string]*int{"ttl_secs": o.TTLSecs, "auto_stop_secs": o.AutoStopSecs, "auto_archive_secs": o.AutoArchiveSecs,
		"auto_delete_secs": o.AutoDeleteSecs, "max_age_secs": o.MaxAgeSecs} {
		if v != nil {
			req[k] = *v
		}
	}
	if o.Name != "" {
		req["name"] = o.Name
	}
	if len(o.Labels) > 0 {
		req["labels"] = o.Labels
	}
	if len(o.Env) > 0 {
		req["env"] = o.Env
	}
	if o.Size != "" {
		req["size"] = o.Size
	}
	if o.Limits != nil {
		req["limits"] = o.Limits
	}

	path, tok := "/api/sandboxes", o.Token
	if worker {
		path = "/sandboxes"
		if tok == "" {
			tok = os.Getenv("SBX_TOKEN")
		}
	} else if tok == "" {
		tok = ControlPlaneToken(o.APIKey)
	}

	var resp struct {
		ID            string            `json:"id"`
		Endpoint      string            `json:"endpoint"`
		Token         string            `json:"token"`
		Backend       string            `json:"backend"`
		WorkspacePath string            `json:"workspace_path"`
		Isolation     string            `json:"isolation"`
		Tools         map[string]string `json:"tools"`
		MissingTools  []string          `json:"missing_tools"`
		Size          string            `json:"size"`
		Limits        *SandboxLimits    `json:"limits"`
		Info          *SandboxInfo      `json:"info"`
	}
	if err := callJSON(ctx, "POST", url+path, map[string]string{"Authorization": "Bearer " + tok}, req, &resp); err != nil {
		return nil, err
	}
	if resp.ID == "" || resp.Endpoint == "" {
		return nil, fmt.Errorf("create sandbox: reply has no id/endpoint")
	}
	sb := &Sandbox{
		Endpoint: resp.Endpoint, Token: resp.Token, PiSession: piSession, ID: resp.ID, Backend: resp.Backend,
		WorkspacePath: resp.WorkspacePath, Isolation: resp.Isolation, Tools: resp.Tools, MissingTools: resp.MissingTools,
		Size: resp.Size, Limits: resp.Limits, CreateInfo: resp.Info,
	}
	// A microVM has no bind mount: the cwd travels as a tar, minus build output and
	// credentials. Only when the caller passed a cwd.
	if cwd != "" && sb.Isolation == "remote" && !o.SkipWorkspaceUpload {
		err := func() error {
			b, err := PackWorkspace(cwd)
			if err != nil {
				return err
			}
			return sb.UploadTar(ctx, cwd, b)
		}()
		if err != nil {
			// Don't leak a running sandbox the caller has no handle to.
			_ = sb.Destroy(context.WithoutCancel(ctx))
			return nil, fmt.Errorf("workspace upload failed (%w): pass SkipWorkspaceUpload=true or a smaller directory (.sbxignore)", err)
		}
	}
	return sb, nil
}

// Create is the same as Acquire, the Daytona/E2B-style entry point.
func Create(ctx context.Context, url, cwd, piSession string, opts *AcquireOptions) (*Sandbox, error) {
	return Acquire(ctx, url, cwd, piSession, opts)
}

// ---------------------------------------------------------------- snapshots

// Snapshots manages named images a sandbox can be created from. They are top-level, not
// tied to an acquired sandbox; URL gets the same worker-vs-control-plane detection as
// Acquire on every call. Token defaults to $SBX_TOKEN (worker) or ControlPlaneToken("").
type Snapshots struct {
	URL   string
	Token string
}

// NewSnapshots returns a Snapshots client for url (a control plane or a worker).
func NewSnapshots(url, token string) *Snapshots { return &Snapshots{URL: url, Token: token} }

// SnapshotCreateOptions say what to build from (set one source) and how to keep it.
type SnapshotCreateOptions struct {
	Image      string // OCI ref with tag or digest
	Dockerfile string // Dockerfile text
	Build      *Image // a Dockerfile builder, used when Dockerfile is empty
	SandboxID  string // capture a live sandbox

	Warm           *int  // pool's warm target (v4)
	MemorySnapshot *bool // v4
}

func (s *Snapshots) rootAndHeaders(ctx context.Context) (string, map[string]string, error) {
	worker, err := isWorker(ctx, s.URL)
	if err != nil {
		return "", nil, err
	}
	tok, root := s.Token, s.URL+"/api/snapshots"
	if worker {
		root = s.URL + "/snapshots"
		if tok == "" {
			tok = os.Getenv("SBX_TOKEN")
		}
	} else if tok == "" {
		tok = ControlPlaneToken("")
	}
	return root, map[string]string{"Authorization": "Bearer " + tok}, nil
}

// firstSnapshot decodes a worker's single SnapshotInfo or a control plane's list of
// them (it fans create/PUT out to every host: take element 0).
func firstSnapshot(raw json.RawMessage) (*SnapshotInfo, error) {
	var info SnapshotInfo
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
		var list []SnapshotInfo
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, err
		}
		if len(list) == 0 {
			return nil, fmt.Errorf("empty snapshot list in reply")
		}
		return &list[0], nil
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// Create starts a snapshot build (202) and returns its initial record; see WaitReady.
func (s *Snapshots) Create(ctx context.Context, name string, o SnapshotCreateOptions) (*SnapshotInfo, error) {
	src := SnapshotSource{Image: o.Image, Dockerfile: o.Dockerfile, SandboxID: o.SandboxID}
	if src.Dockerfile == "" && o.Build != nil {
		src.Dockerfile = o.Build.ToDockerfile()
	}
	body := map[string]any{"name": name, "source": src}
	if o.Warm != nil {
		body["warm"] = *o.Warm
	}
	if o.MemorySnapshot != nil {
		body["memory_snapshot"] = *o.MemorySnapshot
	}
	root, h, err := s.rootAndHeaders(ctx)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := callJSON(ctx, "POST", root, h, body, &raw); err != nil {
		return nil, err
	}
	return firstSnapshot(raw)
}

// List returns every snapshot.
func (s *Snapshots) List(ctx context.Context) ([]SnapshotInfo, error) {
	root, h, err := s.rootAndHeaders(ctx)
	if err != nil {
		return nil, err
	}
	var out []SnapshotInfo
	err = callJSON(ctx, "GET", root, h, nil, &out)
	return out, err
}

// Get returns one snapshot by name.
func (s *Snapshots) Get(ctx context.Context, name string) (*SnapshotInfo, error) {
	root, h, err := s.rootAndHeaders(ctx)
	if err != nil {
		return nil, err
	}
	var info SnapshotInfo
	if err := callJSON(ctx, "GET", root+"/"+pathSeg(name), h, nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// Delete removes a snapshot; one that is already gone (404) is success.
func (s *Snapshots) Delete(ctx context.Context, name string) error {
	root, h, err := s.rootAndHeaders(ctx)
	if err != nil {
		return err
	}
	status, data, err := do(ctx, "DELETE", root+"/"+pathSeg(name), h, nil)
	if err != nil {
		return err
	}
	if status >= 400 && status != 404 {
		return &Error{Status: status, Body: string(data)}
	}
	return nil
}

// SetWarm sets the pool's warm target live (v4 PUT {"warm": n}).
func (s *Snapshots) SetWarm(ctx context.Context, name string, n int) (*SnapshotInfo, error) {
	root, h, err := s.rootAndHeaders(ctx)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := callJSON(ctx, "PUT", root+"/"+pathSeg(name), h, map[string]int{"warm": n}, &raw); err != nil {
		return nil, err
	}
	return firstSnapshot(raw)
}

// timeoutError satisfies errors.Is(err, context.DeadlineExceeded).
type timeoutError string

func (e timeoutError) Error() string      { return string(e) }
func (timeoutError) Is(target error) bool { return target == context.DeadlineExceeded }
func (timeoutError) Timeout() bool        { return true }

// WaitReady polls Get every second until the state leaves "building" or timeout
// (0 = 120s) elapses; ctx cancellation also stops it.
func (s *Snapshots) WaitReady(ctx context.Context, name string, timeout time.Duration) (*SnapshotInfo, error) {
	if timeout == 0 {
		timeout = 120 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		info, err := s.Get(ctx, name)
		if err != nil {
			return nil, err
		}
		if info.State != "building" {
			return info, nil
		}
		if time.Now().After(deadline) {
			return nil, timeoutError(fmt.Sprintf("snapshot %s still building after %gs", name, timeout.Seconds()))
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
