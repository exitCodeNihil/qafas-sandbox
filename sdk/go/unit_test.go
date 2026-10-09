package qafas

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

var bg = context.Background()

// fake is a tiny scripted HTTP server: routes are "METHOD /path" (URL path, decoded).
type fake struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string
	hdrs map[string]http.Header // by route key, last request
}

type reply func(r *http.Request, body []byte) (int, any)

func newFake(t *testing.T, routes map[string]reply) *fake {
	f := &fake{hdrs: map[string]http.Header{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		key := r.Method + " " + r.URL.Path
		f.mu.Lock()
		f.seen = append(f.seen, key)
		f.hdrs[key] = r.Header.Clone()
		f.mu.Unlock()
		h, ok := routes[key]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, "not found")
			return
		}
		status, obj := h(r, body)
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(status)
		if s, ok := obj.(string); ok {
			io.WriteString(w, s)
		} else if obj != nil {
			json.NewEncoder(w).Encode(obj)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fake) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
}

func static(status int, obj any) reply {
	return func(*http.Request, []byte) (int, any) { return status, obj }
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func testSandbox(f *fake, ws string) *Sandbox {
	return &Sandbox{Endpoint: f.URL + "/sandboxes/sbx_1/agent", Token: "tok", PiSession: "sess", ID: "sbx_1", Backend: "b", WorkspacePath: ws}
}

func created(f func() string, id, iso string) map[string]any {
	return map[string]any{"id": id, "endpoint": f() + "/sandboxes/" + id + "/agent", "token": "scoped", "backend": "podman",
		"workspace_path": "/w", "expires_at": "later", "isolation": iso}
}

// ---- runtime mapping, errors, guard, image

func TestRuntimeMapping(t *testing.T) {
	for rt, want := range map[string]string{"process": "native", "docker": "vm", "firecracker": "remote", "auto": "", "": ""} {
		if got, err := RuntimeToIsolation(rt); err != nil || got != want {
			t.Errorf("RuntimeToIsolation(%q) = %q, %v; want %q", rt, got, err, want)
		}
	}
	_, err := RuntimeToIsolation("kubernetes")
	if err == nil || err.Error() != `invalid runtime "kubernetes": expected one of auto|process|docker|firecracker` {
		t.Fatalf("err = %v", err)
	}
	for iso, want := range map[string]string{"native": "process", "vm": "docker", "remote": "firecracker", "": "", "weird": ""} {
		if got := IsolationToRuntime(iso); got != want {
			t.Errorf("IsolationToRuntime(%q) = %q, want %q", iso, got, want)
		}
	}
}

func TestErrorMessage(t *testing.T) {
	cases := []struct{ body, want string }{
		{`{"error":"lifecycle needs the remote tier"}`, "HTTP 409: lifecycle needs the remote tier"},
		{`plain text`, "HTTP 409: plain text"},
		{`{"error":""}`, `HTTP 409: {"error":""}`},
		{`{"error":5}`, `HTTP 409: {"error":5}`},
		{``, "HTTP 409: "},
	}
	for _, c := range cases {
		if got := (&Error{Status: 409, Body: c.body}).Error(); got != c.want {
			t.Errorf("Error(%q) = %q, want %q", c.body, got, c.want)
		}
	}
}

func TestWorkspaceGuard(t *testing.T) {
	sb := &Sandbox{Endpoint: "http://127.0.0.1:1/sandboxes/sbx_x/agent", Token: "t", PiSession: "s", ID: "sbx_x", WorkspacePath: "/workspace/repo"}
	if err := sb.Upload(bg, "/does/not/matter", "/etc/passwd", false); err == nil || !strings.Contains(err.Error(), "outside the workspace") {
		t.Fatalf("upload err = %v", err)
	}
	if err := sb.Download(bg, "/etc/passwd", "/does/not/matter", false); err == nil || !strings.Contains(err.Error(), "outside the workspace") {
		t.Fatalf("download err = %v", err)
	}
	want := "/etc/passwd is outside the workspace (/workspace/repo); pass allowOutside=true to override"
	if err := assertInsideWorkspace("/etc/passwd", "/workspace/repo", false); err == nil || err.Error() != want {
		t.Fatalf("message = %v", err)
	}
	for _, p := range []string{"/workspace/repo", "/workspace/repo/", "/workspace/repo/sub/f.txt", "/workspace/repo/a/../b"} {
		if err := assertInsideWorkspace(p, "/workspace/repo", false); err != nil {
			t.Errorf("%s should be inside: %v", p, err)
		}
	}
	for _, p := range []string{"/workspace/repo2", "/workspace/repo/../x", "/", "relative"} {
		if err := assertInsideWorkspace(p, "/workspace/repo", false); err == nil {
			t.Errorf("%s should be outside", p)
		}
	}
	if assertInsideWorkspace("/etc/passwd", "/workspace/repo", true) != nil || assertInsideWorkspace("/etc/passwd", "", false) != nil {
		t.Error("allowOutside / empty workspace must skip the guard")
	}
	// inside the workspace (or allowed) the guard passes and the network is what fails
	for _, err := range []error{
		sb.Upload(bg, "/does/not/matter", "/workspace/repo/sub/file.txt", false),
		sb.Upload(bg, "/does/not/matter", "/etc/passwd", true),
	} {
		if err == nil || strings.Contains(err.Error(), "outside the workspace") {
			t.Errorf("err = %v", err)
		}
	}
}

func TestImageMatchesPython(t *testing.T) {
	img := NewImage("node:22-bookworm").Run("npm i -g pnpm").PipInstall("requests", "it's").NpmInstall("typescript").
		Workdir("/w").Env(map[string]string{"K": "v"}).Env(map[string]string{"B": "x", "A": "1 2"}).PipInstall().
		CopyText("/etc/my motd", "hi 'there'\nünï")
	want, err := os.ReadFile("testdata/image.dockerfile") // generated by running the Python Image with the same calls
	if err != nil {
		t.Fatal(err)
	}
	if img.ToDockerfile() != string(want) || img.String() != string(want) {
		t.Fatalf("got:\n%s\nwant:\n%s", img.ToDockerfile(), want)
	}
}

// ---- acquire

func TestAcquireRuntimeWinsAndSerialisesFields(t *testing.T) {
	var body map[string]any
	var f *fake
	f = newFake(t, map[string]reply{
		"GET /healthz": static(200, map[string]any{"ok": true}), // control-plane shape
		"POST /api/sandboxes": func(r *http.Request, b []byte) (int, any) {
			body = decode(t, b)
			if r.Header.Get("Authorization") != "Bearer key1" {
				t.Errorf("auth = %q", r.Header.Get("Authorization"))
			}
			resp := created(func() string { return f.URL }, "sbx_1", "vm")
			resp["size"], resp["limits"] = "custom", map[string]any{"cpus": 1.5, "mem_mib": 100, "disk_mib": 200, "pids": 7}
			resp["info"] = map[string]any{"id": "sbx_1", "state": "ready", "auto_stop_secs": 0}
			return 201, resp
		},
	})
	zero, hour := 0, 3600
	pids := 64
	sb, err := Acquire(bg, f.URL, "/tmp", "sess", &AcquireOptions{
		APIKey: "key1", Runtime: "docker", Isolation: "native", Name: "my-box", Labels: map[string]string{"team": "sdk"},
		Env: map[string]string{"FOO": "bar"}, AutoStopSecs: &zero, MaxAgeSecs: &hour, TTLSecs: &zero, Snapshot: "node-base",
		Tools: []string{"git"}, EgressAllow: []string{"*.example.com"}, Limits: &SandboxLimits{Cpus: 1.5, MemMiB: 100, DiskMiB: 200, Pids: &pids},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"template": "node-base", "pi_session": "sess", "trust": "trusted", "workspace": map[string]any{"host_path": "/tmp"},
		"isolation": "vm", "name": "my-box", "labels": map[string]any{"team": "sdk"}, "env": map[string]any{"FOO": "bar"},
		"auto_stop_secs": float64(0), "max_age_secs": float64(3600), "ttl_secs": float64(0), "tools": []any{"git"},
		"egress_allow": []any{"*.example.com"}, "limits": map[string]any{"cpus": 1.5, "mem_mib": float64(100), "disk_mib": float64(200), "pids": float64(64)},
	}
	if !reflect.DeepEqual(body, want) {
		t.Fatalf("body = %v\nwant   %v", body, want)
	}
	if sb.ID != "sbx_1" || sb.Backend != "podman" || sb.Isolation != "vm" || sb.Runtime() != "docker" || sb.Token != "scoped" ||
		sb.Size != "custom" || sb.Limits == nil || sb.Limits.Cpus != 1.5 || *sb.Limits.Pids != 7 || sb.CreateInfo == nil || *sb.CreateInfo.AutoStopSecs != 0 {
		t.Fatalf("sandbox = %+v", sb)
	}
}

func TestAcquireNoIsolationNoWorkspaceNoUpload(t *testing.T) {
	var body map[string]any
	var f *fake
	f = newFake(t, map[string]reply{
		"GET /healthz": static(200, map[string]any{"ok": true}),
		"POST /api/sandboxes": func(r *http.Request, b []byte) (int, any) {
			body = decode(t, b)
			return 201, created(func() string { return f.URL }, "sbx_2", "remote") // would trigger an upload had cwd been sent
		},
	})
	sb, err := Create(bg, f.URL, "", "", &AcquireOptions{Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"isolation", "workspace", "ttl_secs", "tools", "size", "limits", "name"} {
		if _, ok := body[k]; ok {
			t.Errorf("key %q must be absent, body = %v", k, body)
		}
	}
	if body["template"] != "base" || body["trust"] != "trusted" || !strings.HasPrefix(body["pi_session"].(string), "sbx-go-") {
		t.Errorf("defaults wrong: %v", body)
	}
	if sb.PiSession != body["pi_session"] {
		t.Errorf("pi_session = %q", sb.PiSession)
	}
	for _, c := range f.calls() {
		if strings.Contains(c, "/fs/tar") {
			t.Fatalf("nothing may be uploaded without a cwd: %v", f.calls())
		}
	}
}

func TestAcquireWorkerUsesSandboxesAndEnvToken(t *testing.T) {
	t.Setenv("SBX_TOKEN", "worker-tok")
	var f *fake
	f = newFake(t, map[string]reply{
		"GET /healthz": static(200, map[string]any{"ok": true, "backend": "podman", "host_id": "h"}),
		"POST /sandboxes": func(r *http.Request, b []byte) (int, any) {
			if r.Header.Get("Authorization") != "Bearer worker-tok" {
				t.Errorf("auth = %q", r.Header.Get("Authorization"))
			}
			return 201, created(func() string { return f.URL }, "sbx_3", "vm")
		},
	})
	if _, err := Acquire(bg, f.URL, "", "s", nil); err != nil {
		t.Fatal(err)
	}
}

func TestControlPlaneToken(t *testing.T) {
	t.Setenv("SBX_API_KEY", "")
	t.Setenv("SBX_ADMIN_TOKEN", "admin")
	if ControlPlaneToken("") != "admin" || ControlPlaneToken("k") != "k" {
		t.Fatal("admin fallback / explicit key")
	}
	t.Setenv("SBX_API_KEY", "envkey")
	if ControlPlaneToken("") != "envkey" {
		t.Fatal("env key beats admin token")
	}
}

func TestAcquireBadRuntimeNamesAcceptedValues(t *testing.T) {
	_, err := Acquire(bg, "http://127.0.0.1:1", "", "s", &AcquireOptions{Runtime: "x"})
	if err == nil || err.Error() != `invalid runtime "x": expected one of auto|process|docker|firecracker` {
		t.Fatalf("err = %v", err)
	}
}

func TestAcquireDestroysSandboxWhenUploadFails(t *testing.T) {
	local := t.TempDir()
	write(t, local, "f.txt", "x")
	var f *fake
	f = newFake(t, map[string]reply{
		"GET /healthz": static(200, map[string]any{"ok": true}),
		"POST /api/sandboxes": func(*http.Request, []byte) (int, any) {
			return 201, created(func() string { return f.URL }, "sbx_upfail", "remote")
		},
		"PUT /sandboxes/sbx_upfail/agent/fs/tar": static(413, map[string]any{"error": "body over SBX_MAX_UPLOAD_MB (512 MiB)"}),
		"DELETE /sandboxes/sbx_upfail":           static(204, nil),
	})
	_, err := Acquire(bg, f.URL, local, "sess", nil)
	var he *Error
	if err == nil || !errors.As(err, &he) || he.Status != 413 || !strings.Contains(err.Error(), "workspace upload failed") ||
		!strings.Contains(err.Error(), "413") || !strings.Contains(err.Error(), "SkipWorkspaceUpload") {
		t.Fatalf("err = %v", err)
	}
	if !contains(f.calls(), "DELETE /sandboxes/sbx_upfail") {
		t.Fatalf("a failed upload must destroy the sandbox: %v", f.calls())
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// ---- sandbox calls

func TestLifecycleInfoPreviewSessions(t *testing.T) {
	info := map[string]any{"id": "sbx_1", "state": "ready", "name": "my-box", "backend": "b", "template": "t", "workspace_path": "/w", "pi_session": "s", "created_at": "t", "endpoint": "e"}
	f := newFake(t, map[string]reply{
		"POST /sandboxes/sbx_1/stop":    static(204, nil),
		"POST /sandboxes/sbx_1/start":   static(200, info),
		"POST /sandboxes/sbx_1/pause":   static(204, nil),
		"POST /sandboxes/sbx_1/resume":  static(204, nil),
		"POST /sandboxes/sbx_1/archive": static(204, nil),
		"GET /sandboxes/sbx_1":          static(200, info),
		"POST /sandboxes/sbx_1/preview": func(_ *http.Request, b []byte) (int, any) {
			m := decode(t, b)
			if m["ttl_secs"] != float64(60) {
				t.Errorf("ttl_secs = %v", m["ttl_secs"])
			}
			return 200, map[string]any{"url": "u/preview/sbx_1/8080/", "token": "tok", "port": m["port"], "expires_at": "2026-01-01T00:00:00Z"}
		},
		"POST /sandboxes/sbx_1/agent/sessions": func(_ *http.Request, b []byte) (int, any) {
			if m := decode(t, b); m["cwd"] != "/w" || len(m) != 1 {
				t.Errorf("session body = %v", m)
			}
			return 201, map[string]any{"id": "sess_1"}
		},
		"POST /sandboxes/sbx_1/agent/sessions/sess_1/exec": func(_ *http.Request, b []byte) (int, any) {
			m := decode(t, b)
			if m["async"] == true {
				return 202, map[string]any{"command_id": "c2"}
			}
			return 200, map[string]any{"command_id": "c1", "cmd": "echo hi", "state": "done", "exit": 0, "stdout": "hi\n", "stderr": "", "started_at": "t", "ended_at": "t"}
		},
		"GET /sandboxes/sbx_1/agent/sessions/sess_1/commands/c1":        static(200, map[string]any{"command_id": "c1", "cmd": "echo hi", "state": "done", "exit": 0, "started_at": "t"}),
		"POST /sandboxes/sbx_1/agent/sessions/sess_1/commands/c1/input": static(204, nil),
		"DELETE /sandboxes/sbx_1/agent/sessions/sess_1":                 static(404, nil),
	})
	sb := testSandbox(f, "/w")
	for _, fn := range []func(context.Context) error{sb.Stop, sb.Pause, sb.Resume, sb.Archive} {
		if err := fn(bg); err != nil {
			t.Fatal(err)
		}
	}
	started, err := sb.Start(bg)
	if err != nil || started.State != "ready" {
		t.Fatalf("start = %+v, %v", started, err)
	}
	got, err := sb.Info(bg)
	if err != nil || got.Name != "my-box" || got.AutoStopSecs != nil {
		t.Fatalf("info = %+v, %v", got, err)
	}
	ttl := 60
	p, err := sb.Preview(bg, 8080, &ttl)
	if err != nil || p.Port != 8080 || !strings.HasSuffix(p.URL, "/preview/sbx_1/8080/") {
		t.Fatalf("preview = %+v, %v", p, err)
	}
	sess, err := sb.CreateSession(bg, &SessionOptions{Cwd: "/w"})
	if err != nil || sess.ID != "sess_1" {
		t.Fatalf("session = %+v, %v", sess, err)
	}
	c, err := sess.Exec(bg, "echo hi", nil)
	if err != nil || *c.Exit != 0 || *c.Stdout != "hi\n" || c.State != "done" {
		t.Fatalf("exec = %+v, %v", c, err)
	}
	ac, err := sess.Exec(bg, "sleep 1", &SessionExecOptions{Async: true})
	if err != nil || ac.CommandID != "c2" || ac.State != "running" || ac.Exit != nil {
		t.Fatalf("async exec = %+v, %v", ac, err)
	}
	if c, err := sess.Command(bg, "c1"); err != nil || c.CommandID != "c1" {
		t.Fatalf("command = %+v, %v", c, err)
	}
	if err := sess.Input(bg, "c1", "aGVsbG8="); err != nil {
		t.Fatal(err)
	}
	if err := sess.Delete(bg); err != nil { // 404 is success
		t.Fatal(err)
	}
}

func TestTypedErrorAndHeaders(t *testing.T) {
	f := newFake(t, map[string]reply{
		"POST /sandboxes/sbx_1/stop": static(409, map[string]any{"error": "lifecycle needs the remote tier"}),
		"POST /sandboxes/sbx_1/agent/exec": func(_ *http.Request, b []byte) (int, any) {
			return 200, map[string]any{"exit": 3, "stdout": "o", "stderr": "e", "duration_ms": 12, "truncated": true}
		},
		"DELETE /sandboxes/sbx_1": static(204, nil),
	})
	sb := testSandbox(f, "/w")
	err := sb.Stop(bg)
	var he *Error
	if !errors.As(err, &he) || he.Status != 409 || err.Error() != "HTTP 409: lifecycle needs the remote tier" {
		t.Fatalf("err = %v", err)
	}
	r, err := sb.ExecBuffered(bg, "x", &ExecOptions{ToolCallID: "call_9", Timeout: 1500 * time.Millisecond, Env: map[string]string{"A": "b"}})
	if err != nil || r.Exit != 3 || r.Stdout != "o" || r.DurationMs != 12 || !r.Truncated {
		t.Fatalf("exec = %+v, %v", r, err)
	}
	h := f.hdrs["POST /sandboxes/sbx_1/agent/exec"]
	if h.Get("Authorization") != "Bearer tok" || h.Get(HdrPiSession) != "sess" || h.Get(HdrToolCallID) != "call_9" {
		t.Fatalf("headers = %v", h)
	}
	if err := sb.Delete(bg); err != nil {
		t.Fatal(err)
	}
	if got := f.hdrs["DELETE /sandboxes/sbx_1"]; got.Get("Authorization") != "Bearer tok" || got.Get(HdrPiSession) != "" {
		t.Fatalf("destroy must send only Authorization: %v", got)
	}
}

func TestFsCallsAndNotFound(t *testing.T) {
	var gotQuery, gotBody string
	f := newFake(t, map[string]reply{
		"GET /sandboxes/sbx_1/agent/fs/read": func(r *http.Request, _ []byte) (int, any) {
			gotQuery = r.URL.RawQuery
			if r.URL.Query().Get("path") == "/missing" {
				return 404, "nope"
			}
			if r.URL.Query().Get("path") == "/boom" {
				return 500, map[string]any{"error": "kaput"}
			}
			return 200, "raw bytes"
		},
		"PUT /sandboxes/sbx_1/agent/fs/write": func(_ *http.Request, b []byte) (int, any) { gotBody = string(b); return 204, nil },
		"GET /sandboxes/sbx_1/agent/fs/stat":  static(404, nil),
		"GET /sandboxes/sbx_1/agent/fs/list":  static(404, nil),
	})
	sb := testSandbox(f, "")
	b, err := sb.ReadFile(bg, "/a b/c+d")
	if err != nil || strings.TrimSpace(string(b)) != "raw bytes" || gotQuery != "path=/a%20b/c%2Bd" {
		t.Fatalf("read = %q, %v, query %q", b, err, gotQuery)
	}
	if _, err := sb.ReadFile(bg, "/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if _, err := sb.Stat(bg, "/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if _, err := sb.ListDir(bg, "/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	_, err = sb.ReadFile(bg, "/boom")
	var he *Error
	if errors.Is(err, ErrNotFound) || !errors.As(err, &he) || he.Status != 500 {
		t.Fatalf("500 must be a plain *Error, got %v", err)
	}
	if err := sb.WriteString(bg, "/x", "payload"); err != nil || gotBody != "payload" {
		t.Fatalf("write: %v %q", err, gotBody)
	}
}

func TestUploadDownloadDirAndFile(t *testing.T) {
	local, back := t.TempDir(), t.TempDir()
	write(t, local, "hello.txt", "hello sandbox")
	write(t, local, "sub/nested.txt", "nested")
	write(t, local, ".env", "SECRET=1")
	var uploaded []byte
	var remoteTar []byte
	f := newFake(t, map[string]reply{
		"PUT /sandboxes/sbx_1/agent/fs/tar": func(r *http.Request, b []byte) (int, any) { uploaded = b; return 204, nil },
		"GET /sandboxes/sbx_1/agent/fs/tar": func(*http.Request, []byte) (int, any) { return 200, string(remoteTar) },
		"GET /sandboxes/sbx_1/agent/fs/stat": func(r *http.Request, _ []byte) (int, any) {
			return 200, map[string]any{"is_dir": r.URL.Query().Get("path") == "/w/dir", "size": 1, "mode": 420, "mtime": "t"}
		},
		"GET /sandboxes/sbx_1/agent/fs/read": static(200, "file body"),
	})
	sb := testSandbox(f, "/w")
	if err := sb.Upload(bg, local, "/w/dir", false); err != nil {
		t.Fatal(err)
	}
	if got := names(t, uploaded); !reflect.DeepEqual(got, []string{"hello.txt", "sub/nested.txt"}) {
		t.Fatalf("uploaded = %v (.env must stay home)", got)
	}
	remoteTar = uploaded
	if err := sb.Download(bg, "/w/dir", filepath.Join(back, "d"), false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(back, "d", "sub", "nested.txt")); string(b) != "nested" {
		t.Fatalf("nested = %q", b)
	}
	if err := sb.Download(bg, "/w/f.txt", filepath.Join(back, "deep", "er", "f.txt"), false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(back, "deep", "er", "f.txt")); strings.TrimSpace(string(b)) != "file body" {
		t.Fatalf("file = %q", b)
	}
}

// ---- snapshots

func TestSnapshotsControlPlaneListReplies(t *testing.T) {
	src := map[string]any{"image": "node:22-bookworm"}
	f := newFake(t, map[string]reply{
		"GET /healthz": static(200, map[string]any{"ok": true}),
		"POST /api/snapshots": func(_ *http.Request, b []byte) (int, any) {
			if m := decode(t, b); !reflect.DeepEqual(m, map[string]any{"name": "img1", "source": src, "warm": float64(2), "memory_snapshot": false}) {
				t.Errorf("create body = %v", m)
			}
			return 202, []any{map[string]any{"name": "img1", "state": "building", "kind": "image", "source": src, "created_at": "t", "warm": 2, "memory_snapshot": false}}
		},
		"GET /api/snapshots/img1": static(200, map[string]any{"name": "img1", "state": "active", "kind": "image", "source": src, "created_at": "t"}),
		"PUT /api/snapshots/img1": func(_ *http.Request, b []byte) (int, any) {
			if m := decode(t, b); !reflect.DeepEqual(m, map[string]any{"warm": float64(5)}) {
				t.Errorf("put body = %v", m)
			}
			return 200, []any{map[string]any{"name": "img1", "state": "active", "kind": "image", "source": src, "created_at": "t", "warm": 5, "warm_ready": 5}}
		},
		"GET /api/snapshots":         static(200, []any{map[string]any{"name": "img1", "state": "active"}}),
		"DELETE /api/snapshots/img1": static(204, nil),
		"DELETE /api/snapshots/gone": static(404, nil),
	})
	snaps := NewSnapshots(f.URL, "admintok")
	two, no := 2, false
	created, err := snaps.Create(bg, "img1", SnapshotCreateOptions{Image: "node:22-bookworm", Warm: &two, MemorySnapshot: &no})
	if err != nil || created.State != "building" || created.Warm != 2 || created.MemorySnapshot {
		t.Fatalf("create = %+v, %v", created, err)
	}
	ready, err := snaps.WaitReady(bg, "img1", 2*time.Second)
	if err != nil || ready.State != "active" || !ready.MemorySnapshot {
		t.Fatalf("ready = %+v, %v", ready, err) // memory_snapshot defaults to true when omitted
	}
	up, err := snaps.SetWarm(bg, "img1", 5)
	if err != nil || up.Warm != 5 || up.WarmReady != 5 {
		t.Fatalf("set warm = %+v, %v", up, err)
	}
	if l, err := snaps.List(bg); err != nil || len(l) != 1 {
		t.Fatalf("list = %v, %v", l, err)
	}
	if err := snaps.Delete(bg, "img1"); err != nil {
		t.Fatal(err)
	}
	if err := snaps.Delete(bg, "gone"); err != nil {
		t.Fatalf("404 delete must be success: %v", err)
	}
}

func TestSnapshotsWorkerWithImageBuilderAndWaitTimeout(t *testing.T) {
	var df string
	f := newFake(t, map[string]reply{
		"GET /healthz": static(200, map[string]any{"ok": true, "backend": "podman", "host_id": "h"}),
		"POST /snapshots": func(_ *http.Request, b []byte) (int, any) {
			df = decode(t, b)["source"].(map[string]any)["dockerfile"].(string)
			return 202, map[string]any{"name": "img2", "state": "building", "kind": "image", "source": map[string]any{}, "created_at": "t"}
		},
		"GET /snapshots/img2": static(200, map[string]any{"name": "img2", "state": "building", "kind": "image", "source": map[string]any{}, "created_at": "t"}),
	})
	snaps := NewSnapshots(f.URL, "tok")
	if _, err := snaps.Create(bg, "img2", SnapshotCreateOptions{Build: NewImage("node:22-bookworm").PipInstall("requests")}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(df, "FROM node:22-bookworm\n") || !strings.Contains(df, "RUN pip install --no-cache-dir 'requests'") {
		t.Fatalf("dockerfile = %q", df)
	}
	_, err := snaps.WaitReady(bg, "img2", 1500*time.Millisecond)
	if err == nil || err.Error() != "snapshot img2 still building after 1.5s" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

// ---- websocket flows

func wsFake(t *testing.T, handle func(c *websocket.Conn, r *http.Request)) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		handle(c, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func frame(typ string, fields map[string]any) []byte {
	fields["type"] = typ
	b, _ := json.Marshal(fields)
	return b
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestExecStreamsOverWebSocket(t *testing.T) {
	var start map[string]any
	var hdr http.Header
	srv := wsFake(t, func(c *websocket.Conn, r *http.Request) {
		hdr = r.Header
		_, b, err := c.Read(bg)
		if err != nil {
			return
		}
		json.Unmarshal(b, &start)
		for _, f := range [][]byte{
			frame("stdout", map[string]any{"data": b64("hel")}), frame("stderr", map[string]any{"data": b64("err")}),
			frame("stdout", map[string]any{"data": base64.StdEncoding.EncodeToString([]byte{'l', 'o', 0xff})}),
			frame("exit", map[string]any{"code": 7, "duration_ms": 42, "timed_out": true}),
		} {
			c.Write(bg, websocket.MessageText, f)
		}
		c.Close(websocket.StatusNormalClosure, "")
	})
	sb := &Sandbox{Endpoint: srv.URL + "/sandboxes/sbx_1/agent", Token: "tok", PiSession: "sess", ID: "sbx_1", WorkspacePath: "/w"}
	type chunk struct{ s, stream string }
	var chunks []chunk
	r, err := sb.Exec(bg, "echo hi", &ExecOptions{ToolCallID: "tc", Timeout: 2 * time.Second, Env: map[string]string{"A": "b"},
		OnOutput: func(c []byte, stream string) { chunks = append(chunks, chunk{string(c), stream}) }})
	if err != nil {
		t.Fatal(err)
	}
	if r.Exit != 7 || r.DurationMs != 42 || !r.TimedOut || r.Stdout != "hello�" || r.Stderr != "err" {
		t.Fatalf("result = %+v", r)
	}
	if len(chunks) != 3 || chunks[0] != (chunk{"hel", "stdout"}) || chunks[1] != (chunk{"err", "stderr"}) {
		t.Fatalf("chunks = %v", chunks)
	}
	if start["type"] != "start" || start["cmd"] != "echo hi" || start["cwd"] != "/w" || start["timeout_ms"] != float64(2000) || start["env"] == nil {
		t.Fatalf("start = %v", start)
	}
	if hdr.Get("Authorization") != "Bearer tok" || hdr.Get(HdrPiSession) != "sess" || hdr.Get(HdrToolCallID) != "tc" {
		t.Fatalf("headers = %v", hdr)
	}
}

func TestEventsFiltersBySandboxAndStopsOnCallbackError(t *testing.T) {
	srv := wsFake(t, func(c *websocket.Conn, r *http.Request) {
		if r.URL.Path != "/events/ws" || r.Header.Get("Authorization") != "Bearer tok" {
			c.Close(websocket.StatusPolicyViolation, "bad request")
			return
		}
		c.Write(bg, websocket.MessageText, []byte("not json"))
		c.Write(bg, websocket.MessageText, []byte(`{"sandbox_id":"other","type":"exec.started"}`))
		c.Write(bg, websocket.MessageText, []byte(`{"id":"e1","sandbox_id":"sbx_1","type":"exec.started","data":{"cmd":"ls"}}`))
		c.Write(bg, websocket.MessageText, []byte(`{"id":"e2","sandbox_id":"sbx_1","type":"exec.finished"}`))
		<-r.Context().Done()
	})
	sb := &Sandbox{Endpoint: srv.URL + "/sandboxes/sbx_1/agent", Token: "tok", PiSession: "sess", ID: "sbx_1"}
	var got []Event
	stop := errors.New("stop")
	err := sb.Events(bg, func(e Event) error {
		got = append(got, e)
		if len(got) == 2 {
			return stop
		}
		return nil
	})
	if err != stop || len(got) != 2 || got[0].ID != "e1" || got[1].Type != "exec.finished" || !strings.Contains(string(got[0].Data), "ls") {
		t.Fatalf("err = %v, events = %+v", err, got)
	}
	ctx, cancel := context.WithTimeout(bg, 300*time.Millisecond)
	defer cancel()
	if err := sb.Events(ctx, func(Event) error { return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ctx end err = %v", err)
	}
}

func TestSessionLogsStreamThenReturnAuthoritativeCommand(t *testing.T) {
	var cmdSrv *httptest.Server
	cmdSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/logs/ws"):
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer c.CloseNow()
			c.Write(bg, websocket.MessageText, frame("stdout", map[string]any{"data": b64("line1\n")}))
			c.Write(bg, websocket.MessageText, frame("exit", map[string]any{"code": 0}))
			c.Close(websocket.StatusNormalClosure, "")
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/commands/c1"):
			io.WriteString(w, `{"command_id":"c1","state":"done","exit":0,"stdout":"line1\n"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer cmdSrv.Close()
	sb := &Sandbox{Endpoint: cmdSrv.URL + "/sandboxes/sbx_1/agent", Token: "tok", PiSession: "sess", ID: "sbx_1"}
	var out strings.Builder
	got, err := (&Session{sb: sb, ID: "sess_1"}).Logs(bg, "c1", func(c []byte, stream string) { out.Write(c) })
	if err != nil || out.String() != "line1\n" || got.State != "done" || *got.Stdout != "line1\n" {
		t.Fatalf("logs = %+v, %v, out %q", got, err, out.String())
	}
}

func TestWebSocketRefusedUpgradeIsHTTPError(t *testing.T) {
	f := newFake(t, nil) // everything 404s
	sb := testSandbox(f, "/w")
	_, err := sb.Exec(bg, "x", nil)
	var he *Error
	if !errors.As(err, &he) || he.Status != 404 {
		t.Fatalf("err = %v", err)
	}
	if got := sb.CDPURL(); got != strings.Replace(f.URL, "http", "ws", 1)+"/sandboxes/sbx_1/agent/browser/cdp" {
		t.Fatalf("cdp = %s", got)
	}
}

func TestDestroyTreatsRevokedTokenAsGone(t *testing.T) {
	f := newFake(t, map[string]reply{
		"DELETE /sandboxes/sbx_1": static(401, "token revoked with its sandbox"),
		"DELETE /sandboxes/sbx_2": static(401, "bad or missing bearer token"),
	})
	if err := testSandbox(f, "").Destroy(bg); err != nil {
		t.Fatalf("second destroy must be a no-op: %v", err)
	}
	sb2 := testSandbox(f, "")
	sb2.Endpoint = f.URL + "/sandboxes/sbx_2/agent"
	var he *Error
	if err := sb2.Destroy(bg); !errors.As(err, &he) || he.Status != 401 {
		t.Fatalf("a genuinely bad token must still fail: %v", err)
	}
}

func TestUnpackAcceptsDotDirEntry(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "d")
	b := tarOf(t, &tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755}, &tar.Header{Name: "./a.txt", Typeflag: tar.TypeReg, Mode: 0o644})
	if err := UnpackTar(b, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "a.txt")); err != nil {
		t.Fatal(err)
	}
}

func TestVersionConstant(t *testing.T) {
	want, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Skip("no repo VERSION next to the SDK")
	}
	if Version != strings.TrimSpace(string(want)) {
		t.Fatalf("Version %q != VERSION %q", Version, want)
	}
}
