package qafas

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// Sandbox is a single acquired sandbox. Build one with Acquire; destroy it with
// Destroy (typically deferred). Safe for concurrent use.
type Sandbox struct {
	Endpoint      string // .../sandboxes/{id}/agent
	Token         string // scoped token for this sandbox
	PiSession     string
	ID            string
	Backend       string
	WorkspacePath string
	Isolation     string // the tier qafas picked: native | vm | remote
	Tools         map[string]string
	MissingTools  []string
	Size          string         // v5: name or "custom"
	Limits        *SandboxLimits // v5: ceilings actually applied
	// CreateInfo is the daemon's record right after create (v5.1); named so it does not
	// shadow the Info method (GET /sandboxes/{id}, a live refresh).
	CreateInfo *SandboxInfo
}

// ExecOptions tunes Exec and ExecBuffered. The zero value runs in the workspace.
type ExecOptions struct {
	Cwd        string            // default: the sandbox's WorkspacePath
	Env        map[string]string // added to the command's environment
	Timeout    time.Duration     // 0 = the server default
	ToolCallID string            // sent as x-tool-call-id so events carry it
	OnOutput   OnOutput          // Exec only: called per stdout/stderr chunk
}

// Runtime is the tier qafas picked, relabelled to the `runtime` naming.
func (s *Sandbox) Runtime() string { return IsolationToRuntime(s.Isolation) }

// CDPURL is the browser-level DevTools websocket (Chromium launches on first connect).
func (s *Sandbox) CDPURL() string { return wsURL(s.Endpoint) + "/browser/cdp" }

func (s *Sandbox) headers(toolCallID string) map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + s.Token,
		HdrPiSession:    s.PiSession,
		HdrToolCallID:   toolCallID,
	}
}

// agentBase strips the trailing /agent so callers can hit qafas-level /sandboxes/{id}/* routes.
func agentBase(endpoint string) string { return strings.TrimSuffix(endpoint, "/agent") }

// qafasRoot strips /sandboxes/{id}/agent so callers can hit qafas-root routes like /events/ws.
func qafasRoot(endpoint string) string {
	if i := strings.Index(endpoint, "/sandboxes/"); i != -1 {
		return endpoint[:i]
	}
	return endpoint
}

func (s *Sandbox) agentBase() string { return agentBase(s.Endpoint) }

// ---------------------------------------------------------------- exec

func (o *ExecOptions) orZero() *ExecOptions {
	if o == nil {
		return &ExecOptions{}
	}
	return o
}

func (s *Sandbox) execBody(cmd string, o *ExecOptions) map[string]any {
	cwd := o.Cwd
	if cwd == "" {
		cwd = s.WorkspacePath
	}
	b := map[string]any{"cmd": cmd, "cwd": cwd}
	if len(o.Env) > 0 {
		b["env"] = o.Env
	}
	if o.Timeout != 0 {
		b["timeout_ms"] = o.Timeout.Milliseconds()
	}
	return b
}

// ExecBuffered runs cmd with POST /exec and returns when it has finished.
func (s *Sandbox) ExecBuffered(ctx context.Context, cmd string, o *ExecOptions) (*ExecResult, error) {
	o = o.orZero()
	var r ExecResult
	if err := callJSON(ctx, "POST", s.Endpoint+"/exec", s.headers(o.ToolCallID), s.execBody(cmd, o), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Exec runs cmd over /exec/ws, calling o.OnOutput per chunk, and returns the exit status.
// Output is decoded lossily (invalid UTF-8 becomes U+FFFD).
func (s *Sandbox) Exec(ctx context.Context, cmd string, o *ExecOptions) (*ExecResult, error) {
	o = o.orZero()
	c, err := dialWS(ctx, wsURL(s.Endpoint)+"/exec/ws", s.headers(o.ToolCallID))
	if err != nil {
		return nil, err
	}
	defer c.CloseNow()

	start := s.execBody(cmd, o)
	start["type"] = "start"
	b, _ := json.Marshal(start)
	if err := c.Write(ctx, websocket.MessageText, b); err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	res := &ExecResult{Exit: 1}
	for {
		_, raw, err := c.Read(ctx)
		if err != nil {
			if wsDone(err) {
				break
			}
			return nil, err
		}
		var f struct {
			Type       string `json:"type"`
			Data       string `json:"data"`
			Code       *int   `json:"code"`
			DurationMs int64  `json:"duration_ms"`
			TimedOut   bool   `json:"timed_out"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, err
		}
		switch f.Type {
		case "stdout", "stderr":
			chunk, err := base64.StdEncoding.DecodeString(f.Data)
			if err != nil {
				return nil, err
			}
			if f.Type == "stdout" {
				stdout.Write(chunk)
			} else {
				stderr.Write(chunk)
			}
			if o.OnOutput != nil {
				o.OnOutput(chunk, f.Type)
			}
		case "exit":
			if f.Code != nil {
				res.Exit = *f.Code // a signal-killed process reports code null: stays 1
			}
			res.DurationMs, res.TimedOut = f.DurationMs, f.TimedOut
			res.Stdout, res.Stderr = lossy(stdout.Bytes()), lossy(stderr.Bytes())
			return res, nil
		}
	}
	res.Stdout, res.Stderr = lossy(stdout.Bytes()), lossy(stderr.Bytes())
	return res, nil
}

// ---------------------------------------------------------------- fs

func notFound(err error, p string) error {
	var e *Error
	if errors.As(err, &e) && e.Status == 404 {
		return fmt.Errorf("%w: %s", ErrNotFound, p)
	}
	return err
}

func (s *Sandbox) fsURL(op, p string) string { return s.Endpoint + "/fs/" + op + "?path=" + quote(p) }

// ReadFile returns the file's bytes; a missing file is ErrNotFound.
func (s *Sandbox) ReadFile(ctx context.Context, p string) ([]byte, error) {
	data, err := call(ctx, "GET", s.fsURL("read", p), s.headers(""), nil)
	if err != nil {
		return nil, notFound(err, p)
	}
	return data, nil
}

// WriteFile creates or replaces the file (parent directories are created).
func (s *Sandbox) WriteFile(ctx context.Context, p string, content []byte) error {
	if content == nil {
		content = []byte{}
	}
	_, err := call(ctx, "PUT", s.fsURL("write", p), s.headers(""), content)
	return err
}

// WriteString is WriteFile for a string.
func (s *Sandbox) WriteString(ctx context.Context, p, content string) error {
	return s.WriteFile(ctx, p, []byte(content))
}

// UploadBytes is an alias of WriteFile, named for symmetry with ReadFile/Upload/Download.
func (s *Sandbox) UploadBytes(ctx context.Context, p string, content []byte) error {
	return s.WriteFile(ctx, p, content)
}

// Mkdir creates a directory recursively.
func (s *Sandbox) Mkdir(ctx context.Context, p string) error {
	return callJSON(ctx, "POST", s.Endpoint+"/fs/mkdir", s.headers(""), map[string]string{"path": p}, nil)
}

// Stat describes a path; a missing one is ErrNotFound.
func (s *Sandbox) Stat(ctx context.Context, p string) (*FsStat, error) {
	data, err := call(ctx, "GET", s.fsURL("stat", p), s.headers(""), nil)
	if err != nil {
		return nil, notFound(err, p)
	}
	var st FsStat
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// ListDir returns the names in a directory; a missing one is ErrNotFound.
func (s *Sandbox) ListDir(ctx context.Context, p string) ([]string, error) {
	data, err := call(ctx, "GET", s.fsURL("list", p), s.headers(""), nil)
	if err != nil {
		return nil, notFound(err, p)
	}
	var names []string
	if err := json.Unmarshal(data, &names); err != nil {
		return nil, err
	}
	return names, nil
}

// UploadTar extracts an uncompressed tar under p.
func (s *Sandbox) UploadTar(ctx context.Context, p string, tarBytes []byte) error {
	if tarBytes == nil {
		tarBytes = []byte{}
	}
	_, err := call(ctx, "PUT", s.fsURL("tar", p), s.headers(""), tarBytes)
	return err
}

// DownloadTar returns p (file or directory) as an uncompressed tar.
func (s *Sandbox) DownloadTar(ctx context.Context, p string) ([]byte, error) {
	return call(ctx, "GET", s.fsURL("tar", p), s.headers(""), nil)
}

// assertInsideWorkspace refuses a remote path outside the workspace unless allowOutside
// (qafas/guest-agent enforce the real boundary; this only catches an obvious typo
// before a wasted round trip). Lexical check, skipped when the workspace is unknown.
func assertInsideWorkspace(remote, workspace string, allowOutside bool) error {
	if allowOutside || workspace == "" {
		return nil
	}
	r, w := path.Clean(remote), path.Clean(workspace)
	if r == w || strings.HasPrefix(r, strings.TrimSuffix(w, "/")+"/") {
		return nil
	}
	return fmt.Errorf("%s is outside the workspace (%s); pass allowOutside=true to override", remote, workspace)
}

// Upload sends a local file or directory to remote. A directory is packed with the
// same rules as a remote-tier workspace upload (PackWorkspace: .sbxignore + DefaultIgnore)
// and sent as a tar; a file goes straight through WriteFile. Refuses a remote path outside
// the workspace unless allowOutside.
func (s *Sandbox) Upload(ctx context.Context, local, remote string, allowOutside bool) error {
	if err := assertInsideWorkspace(remote, s.WorkspacePath, allowOutside); err != nil {
		return err
	}
	if st, err := os.Stat(local); err == nil && st.IsDir() {
		tarBytes, err := PackWorkspace(local)
		if err != nil {
			return err
		}
		return s.UploadTar(ctx, remote, tarBytes)
	}
	b, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	return s.WriteFile(ctx, remote, b)
}

// Download fetches remote (file or directory) into local. Mirrors Upload's boundary
// guard on the remote side of the path.
func (s *Sandbox) Download(ctx context.Context, remote, local string, allowOutside bool) error {
	if err := assertInsideWorkspace(remote, s.WorkspacePath, allowOutside); err != nil {
		return err
	}
	st, err := s.Stat(ctx, remote)
	if err != nil {
		return err
	}
	if st.IsDir {
		b, err := s.DownloadTar(ctx, remote)
		if err != nil {
			return err
		}
		return UnpackTar(b, local)
	}
	b, err := s.ReadFile(ctx, remote)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		return err
	}
	return os.WriteFile(local, b, 0o644)
}

// ---------------------------------------------------------------- qafas

// Processes returns the live process tree (GET /sandboxes/{id}/processes).
func (s *Sandbox) Processes(ctx context.Context) ([]map[string]any, error) {
	var out []map[string]any
	err := callJSON(ctx, "GET", s.agentBase()+"/processes", s.headers(""), nil, &out)
	return out, err
}

// Events streams live events for this sandbox from qafas's /events/ws firehose,
// filtered client-side to this sandbox's id (non-JSON frames are skipped). It calls fn
// for each event, in order, on the calling goroutine, and returns when ctx ends
// (ctx.Err()), fn returns an error (that error), or the server closes the stream
// (nil, or the transport error).
func (s *Sandbox) Events(ctx context.Context, fn func(Event) error) error {
	c, err := dialWS(ctx, wsURL(qafasRoot(s.Endpoint))+"/events/ws", map[string]string{"Authorization": "Bearer " + s.Token})
	if err != nil {
		return err
	}
	defer c.CloseNow()
	for {
		_, raw, err := c.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if wsDone(err) {
				return nil
			}
			return err
		}
		var e Event
		if json.Unmarshal(raw, &e) != nil || e.SandboxID != s.ID {
			continue
		}
		if err := fn(e); err != nil {
			return err
		}
	}
}

// ---------------------------------------------------------------- lifecycle

// Info refreshes the sandbox record (GET /sandboxes/{id}), including v3 state/timers.
func (s *Sandbox) Info(ctx context.Context) (*SandboxInfo, error) {
	var info SandboxInfo
	if err := callJSON(ctx, "GET", s.agentBase(), s.headers(""), nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (s *Sandbox) lifecycle(ctx context.Context, verb string) error {
	_, err := call(ctx, "POST", s.agentBase()+"/"+verb, s.headers(""), nil)
	return err
}

// Stop stops the sandbox. Remote tier only; native/vm answer 409 (docs/protocol.md "Lifecycle").
func (s *Sandbox) Stop(ctx context.Context) error { return s.lifecycle(ctx, "stop") }

// Pause pauses the sandbox.
func (s *Sandbox) Pause(ctx context.Context) error { return s.lifecycle(ctx, "pause") }

// Resume resumes a paused sandbox.
func (s *Sandbox) Resume(ctx context.Context) error { return s.lifecycle(ctx, "resume") }

// Archive archives the sandbox.
func (s *Sandbox) Archive(ctx context.Context) error { return s.lifecycle(ctx, "archive") }

// Start starts a stopped sandbox and returns its record.
func (s *Sandbox) Start(ctx context.Context) (*SandboxInfo, error) {
	var info SandboxInfo
	if err := callJSON(ctx, "POST", s.agentBase()+"/start", s.headers(""), nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// Destroy deletes the sandbox; an already-gone one (404) is success.
func (s *Sandbox) Destroy(ctx context.Context) error {
	status, data, err := do(ctx, "DELETE", s.agentBase(), map[string]string{"Authorization": "Bearer " + s.Token}, nil)
	if err != nil {
		return err
	}
	// A destroyed sandbox's scoped token is denied until it expires (docs/protocol.md
	// section 5), so a second Destroy answers 401 with this text instead of 404: also "gone".
	revoked := status == 401 && strings.Contains(string(data), "revoked with its sandbox")
	if status >= 400 && status != 404 && !revoked {
		return &Error{Status: status, Body: string(data)}
	}
	return nil
}

// Delete is an alias of Destroy, the name Daytona/E2B users expect.
func (s *Sandbox) Delete(ctx context.Context) error { return s.Destroy(ctx) }

// Preview returns a signed URL for a port inside the sandbox; ttlSecs nil = the server default.
func (s *Sandbox) Preview(ctx context.Context, port int, ttlSecs *int) (*PreviewInfo, error) {
	body := map[string]any{"port": port}
	if ttlSecs != nil {
		body["ttl_secs"] = *ttlSecs
	}
	var p PreviewInfo
	if err := callJSON(ctx, "POST", s.agentBase()+"/preview", s.headers(""), body, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ---------------------------------------------------------------- sessions

// SessionOptions tunes CreateSession; the zero value is a shell in the workspace.
type SessionOptions struct {
	ID  string
	Cwd string
	Env map[string]string
}

// CreateSession starts a persistent shell inside this sandbox, alive until deleted
// or the sandbox stops.
func (s *Sandbox) CreateSession(ctx context.Context, o *SessionOptions) (*Session, error) {
	body := map[string]any{}
	if o != nil {
		if o.ID != "" {
			body["id"] = o.ID
		}
		if o.Cwd != "" {
			body["cwd"] = o.Cwd
		}
		if len(o.Env) > 0 {
			body["env"] = o.Env
		}
	}
	var resp struct {
		ID string `json:"id"`
	}
	if err := callJSON(ctx, "POST", s.Endpoint+"/sessions", s.headers(""), body, &resp); err != nil {
		return nil, err
	}
	return &Session{sb: s, ID: resp.ID}, nil
}

// Session is a persistent shell inside a sandbox (docs/protocol.md "Sessions"). It is
// reached through the owning Sandbox's endpoint and token.
type Session struct {
	sb *Sandbox
	ID string
}

// SessionExecOptions tunes Session.Exec.
type SessionExecOptions struct {
	Async     bool // return at once with only CommandID set; poll Command or stream Logs
	TimeoutMs *int
}

func (x *Session) url(rest string) string { return x.sb.Endpoint + "/sessions/" + x.ID + rest }

// Exec runs cmd in the session. Only one command runs per session at a time.
func (x *Session) Exec(ctx context.Context, cmd string, o *SessionExecOptions) (*SessionCommand, error) {
	body := map[string]any{"cmd": cmd}
	if o != nil {
		if o.Async {
			body["async"] = true
		}
		if o.TimeoutMs != nil {
			body["timeout_ms"] = *o.TimeoutMs
		}
	}
	var c SessionCommand
	if err := callJSON(ctx, "POST", x.url("/exec"), x.sb.headers(""), body, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Command fetches a command, including stdout/stderr (capped like /exec).
func (x *Session) Command(ctx context.Context, cid string) (*SessionCommand, error) {
	var c SessionCommand
	if err := callJSON(ctx, "GET", x.url("/commands/"+pathSeg(cid)), x.sb.headers(""), nil, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Input sends data to the stdin of the running command cid.
func (x *Session) Input(ctx context.Context, cid, data string) error {
	return callJSON(ctx, "POST", x.url("/commands/"+pathSeg(cid)+"/input"), x.sb.headers(""), map[string]string{"data": data}, nil)
}

// Logs streams stdout/stderr of cid (buffered output replayed, then live) until it exits,
// then returns Command(cid), the authoritative final state.
func (x *Session) Logs(ctx context.Context, cid string, onOutput OnOutput) (*SessionCommand, error) {
	c, err := dialWS(ctx, wsURL(x.url("/commands/"+pathSeg(cid)+"/logs/ws")), x.sb.headers(""))
	if err != nil {
		return nil, err
	}
	defer c.CloseNow()
loop:
	for {
		_, raw, err := c.Read(ctx)
		if err != nil {
			if wsDone(err) {
				break
			}
			return nil, err
		}
		var f struct {
			Type string `json:"type"`
			Data string `json:"data"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, err
		}
		switch f.Type {
		case "stdout", "stderr":
			if onOutput != nil {
				chunk, err := base64.StdEncoding.DecodeString(f.Data)
				if err != nil {
					return nil, err
				}
				onOutput(chunk, f.Type)
			}
		case "exit":
			break loop
		}
	}
	return x.Command(ctx, cid)
}

// Delete kills the shell's process group; an already-gone session (404) is success.
func (x *Session) Delete(ctx context.Context) error {
	status, data, err := do(ctx, "DELETE", x.url(""), x.sb.headers(""), nil)
	if err != nil {
		return err
	}
	if status >= 400 && status != 404 {
		return &Error{Status: status, Body: string(data)}
	}
	return nil
}
