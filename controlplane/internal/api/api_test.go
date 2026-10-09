package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/store"
)

const (
	testAdmin  = "admin-secret"
	testHost   = "host-secret"
	testSecret = "token-secret"
)

func newTestAPI(t *testing.T) (*API, *http.ServeMux) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	hub := events.NewHub()
	a := New(s, hub, testAdmin, testHost, testSecret, nil)
	mux := http.NewServeMux()
	a.Routes(mux)
	return a, mux
}

// doReqTo is doReq against any http.Handler, not just the bare mux — used directly by
// tests that need a request to go through a.HTTPMiddleware(mux) instead (metrics_test.go).
func doReqTo(h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	var r *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	} else {
		r = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func doReq(mux *http.ServeMux, method, path, token string, body any) *httptest.ResponseRecorder {
	return doReqTo(mux, method, path, token, body)
}

func TestAuth(t *testing.T) {
	_, mux := newTestAPI(t)

	// Wrong token -> 401.
	if rec := doReq(mux, "GET", "/api/hosts", "wrong", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong admin token: got %d, want 401", rec.Code)
	}
	// No token -> 401.
	if rec := doReq(mux, "GET", "/api/hosts", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", rec.Code)
	}
	// Right admin token -> 200.
	if rec := doReq(mux, "GET", "/api/hosts", testAdmin, nil); rec.Code != http.StatusOK {
		t.Fatalf("admin token: got %d, want 200", rec.Code)
	}
	// Admin token on a host-only route -> 401.
	if rec := doReq(mux, "POST", "/api/hosts/register", testAdmin, events.HostRegister{HostID: "h1", URL: "http://x", Backend: "podman", Capacity: 1}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin token on host route: got %d, want 401", rec.Code)
	}
	// Host token on the host route -> 204.
	if rec := doReq(mux, "POST", "/api/hosts/register", testHost, events.HostRegister{HostID: "h1", URL: "http://x", Backend: "podman", Capacity: 1}); rec.Code != http.StatusNoContent {
		t.Fatalf("host register: got %d, want 204: %s", rec.Code, rec.Body.String())
	}
	// Healthz needs no auth.
	if rec := doReq(mux, "GET", "/healthz", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("healthz: got %d, want 200", rec.Code)
	}
}

func TestIngestAndQuery(t *testing.T) {
	_, mux := newTestAPI(t)

	if rec := doReq(mux, "POST", "/api/hosts/register", testHost, events.HostRegister{HostID: "h1", URL: "http://x", Backend: "podman", Capacity: 2}); rec.Code != http.StatusNoContent {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}

	// defect 8: a Firecracker host's egress.deny (host_id "lima-kvm") must show up on
	// GET /api/egress carrying pi_session, the same as any other host's events.
	evs := []events.Event{
		{ID: "01A", TS: time.Now().UTC().Format(time.RFC3339), HostID: "h1", SandboxID: "sbx_1", Type: events.ExecStart, Data: json.RawMessage(`{"cmd":"ls"}`)},
		{ID: "01B", TS: time.Now().UTC().Format(time.RFC3339), HostID: "h1", SandboxID: "sbx_1", Type: events.ExecEnd, Data: json.RawMessage(`{"exit":0}`)},
		{ID: "01C", TS: time.Now().UTC().Format(time.RFC3339), HostID: "h1", SandboxID: "sbx_1", Type: events.EgressDeny, Data: json.RawMessage(`{"host":"evil.example"}`)},
		{ID: "01D", TS: time.Now().UTC().Format(time.RFC3339), HostID: "lima-kvm", SandboxID: "sbx_2", PiSession: "e2e-alerts", Type: events.EgressDeny, Data: json.RawMessage(`{"host":"1.1.1.1:53"}`)},
	}
	if rec := doReq(mux, "POST", "/api/events", testHost, evs); rec.Code != http.StatusNoContent {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body.String())
	}

	rec := doReq(mux, "GET", "/api/sandboxes/sbx_1/events", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get events: %d %s", rec.Code, rec.Body.String())
	}
	var got []events.Event
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 events, got %d", len(got))
	}
	if got[0].Type != events.ExecStart || got[2].Type != events.EgressDeny {
		t.Fatalf("unexpected order/types: %+v", got)
	}

	rec = doReq(mux, "GET", "/api/egress", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("egress: %d", rec.Code)
	}
	var egress []events.Event
	json.Unmarshal(rec.Body.Bytes(), &egress)
	if len(egress) != 2 {
		t.Fatalf("want 2 egress.deny rows (h1 and lima-kvm), got %+v", egress)
	}
	var sawLimaKVM bool
	for _, e := range egress {
		if e.Type != events.EgressDeny {
			t.Fatalf("non-egress row leaked through: %+v", e)
		}
		if e.HostID == "lima-kvm" {
			sawLimaKVM = true
			if e.PiSession != "e2e-alerts" {
				t.Fatalf("lima-kvm's egress.deny must carry pi_session, got %+v", e)
			}
		}
	}
	if !sawLimaKVM {
		t.Fatalf("the Firecracker host's egress.deny is missing from GET /api/egress: %+v", egress)
	}
}

// TestExecWSProxiesToOwningHost: GET /api/sandboxes/{id}/exec/ws reaches the owning host's
// /sandboxes/{id}/agent/exec/ws carrying the host bearer, never the caller's, and an
// unauthenticated caller never reaches the host at all (docs/protocol.md §4a, `sbx shell <id>`).
func TestExecWSProxiesToOwningHost(t *testing.T) {
	a, mux := newTestAPI(t)
	fake := newFakeHost(t, mux, "h1", []string{"vm"})
	var gotPath, gotAuth string
	hits := 0
	fake.mux.HandleFunc("GET /sandboxes/{id}/agent/exec/ws", func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	hb := events.Heartbeat{Sandboxes: []events.SandboxInfo{{ID: "sbx_ws1", Backend: "podman", State: "ready"}}}
	if rec := doReq(mux, "PUT", "/api/hosts/h1/heartbeat", testHost, hb); rec.Code != http.StatusNoContent {
		t.Fatalf("heartbeat: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(mux, "GET", "/api/sandboxes/sbx_ws1/exec/ws", testAdmin, nil); rec.Code != http.StatusOK {
		t.Fatalf("proxy: %d %s", rec.Code, rec.Body.String())
	}
	if gotPath != "/sandboxes/sbx_ws1/agent/exec/ws" || gotAuth != "Bearer "+a.tokenSecret {
		t.Fatalf("host saw path=%q auth=%q", gotPath, gotAuth)
	}
	if rec := doReq(mux, "GET", "/api/sandboxes/sbx_ws1/exec/ws", "not-a-token", nil); rec.Code < 400 || hits != 1 {
		t.Fatalf("an unauthenticated caller must be stopped at the control plane: %d, host hits %d", rec.Code, hits)
	}
}

// TestIngestSandboxUsageEventUpdatesRow covers the v5.1 fix: the guest agent pushes
// sandbox.usage every ~2s while an exec is live (docs/protocol.md §3a), fresher than the
// ~10s heartbeat (which stays the fallback for idle sandboxes) — ingesting one must update
// the row's usage column immediately, not wait for the next heartbeat.
func TestIngestSandboxUsageEventUpdatesRow(t *testing.T) {
	_, mux := newTestAPI(t)
	if rec := doReq(mux, "POST", "/api/hosts/register", testHost, events.HostRegister{HostID: "h1", URL: "http://127.0.0.1:1", Backend: "podman", Capacity: 2}); rec.Code != http.StatusNoContent {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	hb := events.Heartbeat{Sandboxes: []events.SandboxInfo{{ID: "sbx_u1", Backend: "podman", State: "ready"}}}
	if rec := doReq(mux, "PUT", "/api/hosts/h1/heartbeat", testHost, hb); rec.Code != http.StatusNoContent {
		t.Fatalf("heartbeat: %d %s", rec.Code, rec.Body.String())
	}

	usage := events.SandboxUsage{CpuMillis: 1234, MemBytes: 555555, MemPeakBytes: 600000, DiskBytes: 1000, Pids: 7, TS: "2026-09-18T10:00:00.000Z"}
	usageData, _ := json.Marshal(usage)
	evs := []events.Event{{ID: "01U", TS: usage.TS, HostID: "h1", SandboxID: "sbx_u1", Type: events.SandboxUsageEvent, Data: usageData}}
	if rec := doReq(mux, "POST", "/api/events", testHost, evs); rec.Code != http.StatusNoContent {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body.String())
	}

	rec := doReq(mux, "GET", "/api/sandboxes/sbx_u1", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get sandbox: %d %s", rec.Code, rec.Body.String())
	}
	var sb events.SandboxInfo
	json.Unmarshal(rec.Body.Bytes(), &sb)
	if sb.Usage == nil || sb.Usage.TS != usage.TS || sb.Usage.MemBytes != usage.MemBytes {
		t.Fatalf("usage not updated from the sandbox.usage event: %+v", sb.Usage)
	}
}

func TestHostPick(t *testing.T) {
	_, mux := newTestAPI(t)

	// Two hosts, one real fake qafas that always succeeds, chosen by pool size.
	newFakeHost(t, mux, "warm", []string{"native"})
	doReq(mux, "POST", "/api/hosts/register", testHost, events.HostRegister{HostID: "empty", URL: "http://127.0.0.1:1", Backend: "podman", Capacity: 2, Tiers: []string{"native"}})
	// Give "warm" a nonzero pool so PickHost prefers it over "empty" (pool defaults to {}).
	hb := events.Heartbeat{Pool: events.PoolStats{"base|/tmp": {Warm: 2, Target: 2}}}
	if rec := doReq(mux, "PUT", "/api/hosts/warm/heartbeat", testHost, hb); rec.Code != http.StatusNoContent {
		t.Fatalf("heartbeat: %d %s", rec.Code, rec.Body.String())
	}

	rec := doReq(mux, "POST", "/api/sandboxes", testAdmin, events.CreateSandboxReq{Template: "base", PiSession: "t"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create sandbox: %d %s", rec.Code, rec.Body.String())
	}
	var resp events.CreateSandboxResp
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.HostID != "warm" {
		t.Fatalf("want host_id=warm (more free pool), got %q", resp.HostID)
	}
	if !strings.HasPrefix(resp.ID, "sbx_life_") {
		t.Fatalf("want a fakeQafas-generated id, got %q", resp.ID)
	}

	// The row is queryable via the admin API.
	rec = doReq(mux, "GET", "/api/sandboxes/"+resp.ID, testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get sandbox: %d %s", rec.Code, rec.Body.String())
	}
}

// TestCreateSandboxFillsPiSessionFromHeader is docs/protocol.md §7: headers carry
// correlation, so a POST /api/sandboxes body that leaves pi_session empty still gets
// attributed via X-Pi-Session.
func TestCreateSandboxFillsPiSessionFromHeader(t *testing.T) {
	_, mux := newTestAPI(t)
	_ = newFakeHost(t, mux, "h1", []string{"remote"})

	body, _ := json.Marshal(events.CreateSandboxReq{Template: "base"}) // no pi_session in the body
	req := httptest.NewRequest("POST", "/api/sandboxes", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdmin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Pi-Session", "sess-from-header")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created events.CreateSandboxResp
	json.Unmarshal(rec.Body.Bytes(), &created)

	getRec := doReq(mux, "GET", "/api/sandboxes/"+created.ID, testAdmin, nil)
	var sb events.SandboxInfo
	json.Unmarshal(getRec.Body.Bytes(), &sb)
	if sb.PiSession != "sess-from-header" {
		t.Fatalf("pi_session not filled from X-Pi-Session: got %q", sb.PiSession)
	}

	// A body that already sets pi_session wins over the header.
	body, _ = json.Marshal(events.CreateSandboxReq{Template: "base", PiSession: "from-body"})
	req = httptest.NewRequest("POST", "/api/sandboxes", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdmin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Pi-Session", "sess-from-header-2")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	json.Unmarshal(rec.Body.Bytes(), &created)
	getRec = doReq(mux, "GET", "/api/sandboxes/"+created.ID, testAdmin, nil)
	json.Unmarshal(getRec.Body.Bytes(), &sb)
	if sb.PiSession != "from-body" {
		t.Fatalf("body pi_session should win over header: got %q", sb.PiSession)
	}
}

// TestCreateSandboxUsesDaemonInfoWhenPresent covers api.go's v5.1 fix (sandboxInfoFromCreate):
// when the daemon's 201 carries Info, the stored row's name/labels/timers/enforcement/
// size/limits come from Info rather than the request; a pre-v5.1 daemon (no Info) keeps the
// old request-echo fallback.
func TestCreateSandboxUsesDaemonInfoWhenPresent(t *testing.T) {
	_, mux := newTestAPI(t)
	fake := newFakeHost(t, mux, "h1", []string{"remote"})

	autoStop := uint64(120)
	fake.overrideCreateInfo(&events.SandboxInfo{
		Name: "daemon-picked-name", Labels: map[string]string{"team": "daemon"},
		AutoStopSecs: &autoStop, Enforcement: "kernel",
		Size: "mini", Limits: &events.SandboxLimits{Cpus: 1, MemMiB: 1024, DiskMiB: 1024, Pids: 256},
	})
	rec := doReq(mux, "POST", "/api/sandboxes", testAdmin, events.CreateSandboxReq{
		Template: "base", PiSession: "t", Name: strPtr("request-name"), Labels: map[string]string{"team": "request"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created events.CreateSandboxResp
	json.Unmarshal(rec.Body.Bytes(), &created)
	getRec := doReq(mux, "GET", "/api/sandboxes/"+created.ID, testAdmin, nil)
	var sb events.SandboxInfo
	json.Unmarshal(getRec.Body.Bytes(), &sb)
	if sb.Name != "daemon-picked-name" || sb.Labels["team"] != "daemon" || sb.Enforcement != "kernel" || sb.Size != "mini" {
		t.Fatalf("row must come from daemon Info: %+v", sb)
	}
	if sb.AutoStopSecs == nil || *sb.AutoStopSecs != 120 {
		t.Fatalf("auto_stop_secs must come from daemon Info: %+v", sb.AutoStopSecs)
	}

	// Pre-v5.1 fallback: no Info echoed, name/labels come from the request instead.
	fake.overrideCreateInfo(nil)
	rec = doReq(mux, "POST", "/api/sandboxes", testAdmin, events.CreateSandboxReq{
		Template: "base", PiSession: "t", Name: strPtr("request-name-2"), Labels: map[string]string{"team": "request"},
	})
	json.Unmarshal(rec.Body.Bytes(), &created)
	getRec = doReq(mux, "GET", "/api/sandboxes/"+created.ID, testAdmin, nil)
	json.Unmarshal(getRec.Body.Bytes(), &sb)
	if sb.Name != "request-name-2" || sb.Labels["team"] != "request" {
		t.Fatalf("pre-v5.1 fallback must come from the request: %+v", sb)
	}
}

func TestEventStreamSSE(t *testing.T) {
	a, mux := newTestAPI(t)
	_ = a

	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/events/stream?sandbox_id=sbx_1&token=" + testAdmin)
	if err != nil {
		t.Fatalf("GET stream: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type: %q", ct)
	}

	// Publish an event via the ingest endpoint in another request and read it off the stream.
	go func() {
		time.Sleep(50 * time.Millisecond)
		client := &http.Client{}
		body, _ := json.Marshal([]events.Event{{ID: "01Z", TS: time.Now().UTC().Format(time.RFC3339), SandboxID: "sbx_1", Type: events.ExecStart, Data: json.RawMessage(`{}`)}})
		req, _ := http.NewRequest("POST", srv.URL+"/api/events", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+testHost)
		req.Header.Set("Content-Type", "application/json")
		client.Do(req)
	}()

	scanner := bufio.NewScanner(resp.Body)
	deadline := time.After(3 * time.Second)
	lines := make(chan string, 8)
	go func() {
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	for {
		select {
		case line := <-lines:
			if strings.HasPrefix(line, "data: ") {
				var e events.Event
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &e); err == nil && e.ID == "01Z" {
					return // success
				}
			}
		case <-deadline:
			t.Fatal("timed out waiting for SSE event")
		}
	}
}

func TestSessionsAndAlertsRoutes(t *testing.T) {
	_, mux := newTestAPI(t)

	evs := []events.Event{
		{ID: "01A", TS: "2026-09-08T10:00:00.000Z", HostID: "h1", SandboxID: "sbx1", PiSession: "sessA", ToolCallID: "tool1", Type: events.ExecStart, Data: json.RawMessage(`{"cmd":"ls"}`)},
		{ID: "01B", TS: "2026-09-08T10:00:00.100Z", HostID: "h1", SandboxID: "sbx1", PiSession: "sessA", ToolCallID: "tool1", Type: events.ExecEnd, Data: json.RawMessage(`{"exit":0,"duration_ms":100}`)},
		{ID: "01C", TS: "2026-09-08T10:00:00.200Z", HostID: "h1", SandboxID: "sbx1", PiSession: "sessA", Type: events.SecurityAlert, Data: json.RawMessage(`{"severity":"high","rule":"sensitive_path.read","msg":"read ~/.ssh"}`)},
	}
	if rec := doReq(mux, "POST", "/api/events", testHost, evs); rec.Code != http.StatusNoContent {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body.String())
	}

	// GET /api/sessions
	rec := doReq(mux, "GET", "/api/sessions", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list sessions: %d %s", rec.Code, rec.Body.String())
	}
	var sessions []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &sessions); err != nil {
		t.Fatalf("decode sessions: %v", err)
	}
	if len(sessions) != 1 || sessions[0]["pi_session"] != "sessA" {
		t.Fatalf("sessions: %+v", sessions)
	}

	// GET /api/sessions/{id}
	rec = doReq(mux, "GET", "/api/sessions/sessA", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get session: %d %s", rec.Code, rec.Body.String())
	}
	rec = doReq(mux, "GET", "/api/sessions/no-such", testAdmin, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing session: want 404, got %d", rec.Code)
	}

	// GET /api/sessions/{id}/events
	rec = doReq(mux, "GET", "/api/sessions/sessA/events", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("session events: %d %s", rec.Code, rec.Body.String())
	}
	var sessEvs []events.Event
	json.Unmarshal(rec.Body.Bytes(), &sessEvs)
	if len(sessEvs) != 3 {
		t.Fatalf("session events: want 3, got %d", len(sessEvs))
	}

	// GET /api/sessions/{id}/trace — a valid OTLP/JSON export with a tool-call span.
	rec = doReq(mux, "GET", "/api/sessions/sessA/trace", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("trace: %d %s", rec.Code, rec.Body.String())
	}
	var otlp struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []map[string]any `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &otlp); err != nil {
		t.Fatalf("decode trace: %v", err)
	}
	if len(otlp.ResourceSpans) != 1 || len(otlp.ResourceSpans[0].ScopeSpans[0].Spans) != 2 { // session root + the exec span
		t.Fatalf("trace shape: %s", rec.Body.String())
	}

	// GET /api/alerts
	rec = doReq(mux, "GET", "/api/alerts", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("alerts: %d %s", rec.Code, rec.Body.String())
	}
	var alerts []events.Event
	json.Unmarshal(rec.Body.Bytes(), &alerts)
	if len(alerts) != 1 || alerts[0].Type != events.SecurityAlert {
		t.Fatalf("alerts: %+v", alerts)
	}

	// GET /api/stats
	rec = doReq(mux, "GET", "/api/stats", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("stats: %d %s", rec.Code, rec.Body.String())
	}

	// GET /api/search
	rec = doReq(mux, "GET", "/api/search?q=ls", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("search: %d %s", rec.Code, rec.Body.String())
	}
	var found []events.Event
	json.Unmarshal(rec.Body.Bytes(), &found)
	if len(found) != 1 || found[0].ID != "01A" {
		t.Fatalf("search q=ls: %+v", found)
	}

	// GET /api/sessions/{id}/processes — empty forest (no process.* events ingested).
	rec = doReq(mux, "GET", "/api/sessions/sessA/processes", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("processes: %d %s", rec.Code, rec.Body.String())
	}
}

// TestListSessionsSandboxIDFilter is defect 6: GET /api/sessions?sandbox_id= used to be
// ignored, returning every session regardless of the filter.
func TestListSessionsSandboxIDFilter(t *testing.T) {
	_, mux := newTestAPI(t)

	evs := []events.Event{
		{ID: "01A", TS: "2026-09-08T10:00:00.000Z", HostID: "h1", SandboxID: "sbx1", PiSession: "sessA", Type: events.ExecStart, Data: json.RawMessage(`{"cmd":"ls"}`)},
		{ID: "01B", TS: "2026-09-08T11:00:00.000Z", HostID: "h1", SandboxID: "sbx2", PiSession: "sessB", Type: events.ExecStart, Data: json.RawMessage(`{"cmd":"ls"}`)},
	}
	if rec := doReq(mux, "POST", "/api/events", testHost, evs); rec.Code != http.StatusNoContent {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body.String())
	}

	rec := doReq(mux, "GET", "/api/sessions?sandbox_id=sbx1", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list sessions: %d %s", rec.Code, rec.Body.String())
	}
	var sessions []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &sessions)
	if len(sessions) != 1 || sessions[0]["pi_session"] != "sessA" {
		t.Fatalf("sandbox_id=sbx1: want only sessA, got %+v", sessions)
	}

	// A sandbox id that touches no session -> empty, not every session.
	rec = doReq(mux, "GET", "/api/sessions?sandbox_id=nonexistent-xyz", testAdmin, nil)
	json.Unmarshal(rec.Body.Bytes(), &sessions)
	if len(sessions) != 0 {
		t.Fatalf("sandbox_id=nonexistent-xyz: want 0 sessions, got %+v", sessions)
	}

	// No filter -> both sessions still come back.
	rec = doReq(mux, "GET", "/api/sessions", testAdmin, nil)
	json.Unmarshal(rec.Body.Bytes(), &sessions)
	if len(sessions) != 2 {
		t.Fatalf("unfiltered: want 2 sessions, got %+v", sessions)
	}
}

func TestExplicitTierUnavailableReturns409(t *testing.T) {
	_, mux := newTestAPI(t)
	doReq(mux, "POST", "/api/hosts/register", testHost, events.HostRegister{HostID: "h1", URL: "http://127.0.0.1:1", Backend: "podman", Capacity: 1, Tiers: []string{"vm"}})

	rec := doReq(mux, "POST", "/api/sandboxes", testAdmin, events.CreateSandboxReq{Template: "base", PiSession: "t", Isolation: "native"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 tier unavailable, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestEventStreamFiltersByPiSessionAndTypes(t *testing.T) {
	_, mux := newTestAPI(t)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/events/stream?pi_session=sessB&types=exec.end&token=" + testAdmin)
	if err != nil {
		t.Fatalf("GET stream: %v", err)
	}
	defer resp.Body.Close()

	go func() {
		time.Sleep(50 * time.Millisecond)
		evs := []events.Event{
			// Wrong session: must not appear.
			{ID: "01P", TS: time.Now().UTC().Format(time.RFC3339), SandboxID: "sbx1", PiSession: "sessOther", Type: events.ExecEnd, Data: json.RawMessage(`{}`)},
			// Right session, wrong type: must not appear.
			{ID: "01Q", TS: time.Now().UTC().Format(time.RFC3339), SandboxID: "sbx1", PiSession: "sessB", Type: events.ExecStart, Data: json.RawMessage(`{}`)},
			// Right session, right type: must appear.
			{ID: "01R", TS: time.Now().UTC().Format(time.RFC3339), SandboxID: "sbx1", PiSession: "sessB", Type: events.ExecEnd, Data: json.RawMessage(`{}`)},
		}
		body, _ := json.Marshal(evs)
		req, _ := http.NewRequest("POST", srv.URL+"/api/events", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+testHost)
		req.Header.Set("Content-Type", "application/json")
		(&http.Client{}).Do(req)
	}()

	scanner := bufio.NewScanner(resp.Body)
	deadline := time.After(3 * time.Second)
	lines := make(chan string, 8)
	go func() {
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	for {
		select {
		case line := <-lines:
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var e events.Event
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &e); err != nil {
				continue
			}
			if e.ID == "01P" || e.ID == "01Q" {
				t.Fatalf("filter leaked a non-matching event: %+v", e)
			}
			if e.ID == "01R" {
				return // success: the one matching event arrived
			}
		case <-deadline:
			t.Fatal("timed out waiting for filtered SSE event")
		}
	}
}

func TestGlobalEventsListNewestFirstWithTypeFilter(t *testing.T) {
	_, mux := newTestAPI(t)
	batch := []map[string]any{
		{"id": "01A", "ts": "2026-01-01T00:00:00.000Z", "host_id": "h", "sandbox_id": "s1", "pi_session": "p", "tool_call_id": "t", "type": "exec.start", "data": map[string]any{}},
		{"id": "01B", "ts": "2026-01-01T00:00:01.000Z", "host_id": "h", "sandbox_id": "s1", "pi_session": "p", "tool_call_id": "t", "type": "exec.end", "data": map[string]any{"duration_ms": 3}},
		{"id": "01C", "ts": "2026-01-01T00:00:02.000Z", "host_id": "h", "sandbox_id": "s1", "pi_session": "p", "tool_call_id": "t2", "type": "exec.end", "data": map[string]any{"duration_ms": 4}},
	}
	if rec := doReq(mux, "POST", "/api/events", testHost, batch); rec.Code != http.StatusNoContent {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body.String())
	}
	rec := doReq(mux, "GET", "/api/events?types=exec.end&limit=200", testAdmin, nil)
	var evs []events.Event
	if err := json.Unmarshal(rec.Body.Bytes(), &evs); err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || evs[0].ID != "01C" {
		t.Fatalf("want 2 exec.end newest first, got %+v", evs)
	}
	if rec := doReq(mux, "DELETE", "/api/sandboxes/nope", testAdmin, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("delete unknown sandbox: want 404, got %d", rec.Code)
	}
}

// ---- v3: lifecycle, preview, snapshots

// fakeQafas is a minimal stand-in for qafas's v3 surface (docs/protocol.md §3a):
// create, the five lifecycle verbs, preview, and snapshots. lifecycleStatus lets a test
// override one verb's reply status/body to exercise error relay.
type fakeQafas struct {
	mux             *http.ServeMux
	lifecycleStatus map[string]int
	snapshots       map[string]events.SnapshotInfo
	lastCreateReq   *events.CreateSandboxReq // last POST /sandboxes body, for api-key limit clamp assertions
	createCount     int
	lastExecHeaders http.Header // last POST /sandboxes/{id}/agent/exec headers, for correlation-header assertions
	lastExecBody    []byte
	deleteInUse     map[string]string // snapshot name -> message: DELETE answers 409 instead of deleting
	createStatus    int               // != 0: POST /sandboxes answers this instead of its normal 201
	createBody      string
	createInfo      *events.SandboxInfo // non-nil: POST /sandboxes echoes it as CreateSandboxResp.Info (v5.1)
	mu              sync.Mutex
}

func newFakeQafas() *fakeQafas {
	f := &fakeQafas{mux: http.NewServeMux(), lifecycleStatus: map[string]int{}, snapshots: map[string]events.SnapshotInfo{}}

	f.mux.HandleFunc("POST /sandboxes", func(w http.ResponseWriter, r *http.Request) {
		var req events.CreateSandboxReq
		json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		reqCopy := req
		f.lastCreateReq = &reqCopy
		f.createCount++
		// A distinct id per call: a test that creates more than one sandbox against the
		// same fake host must not collide on the store's unique id constraint.
		id := fmt.Sprintf("sbx_life_%d", f.createCount)
		status, body, info := f.createStatus, f.createBody, f.createInfo
		f.mu.Unlock()
		if status != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(events.CreateSandboxResp{
			ID: id, Endpoint: "http://127.0.0.1:7700/sandboxes/" + id + "/agent",
			Token: "tok", Backend: "remote", WorkspacePath: "/tmp", ExpiresAt: time.Now().Format(time.RFC3339),
			Isolation: req.Isolation,
			// v5: a real qafas echoes the size/limits it applied (docs/protocol.md §3a).
			Size: req.Size, Limits: req.Limits,
			// v5.1: a real qafas echoes its own record when set for this test (docs/protocol.md §3a).
			Info: info,
		})
	})

	lifecycle := func(verb, okState string) {
		f.mux.HandleFunc("POST /sandboxes/{id}/"+verb, func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			status, override := f.lifecycleStatus[verb]
			f.mu.Unlock()
			if override {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				json.NewEncoder(w).Encode(map[string]string{"error": "daemon says no"})
				return
			}
			if verb == "start" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(events.SandboxInfo{ID: r.PathValue("id"), State: okState})
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}
	lifecycle("stop", "stopped")
	lifecycle("start", "ready")
	lifecycle("pause", "paused")
	lifecycle("resume", "ready")
	lifecycle("archive", "archived")

	f.mux.HandleFunc("POST /sandboxes/{id}/agent/exec", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.lastExecHeaders = r.Header.Clone()
		f.lastExecBody = body
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"exit": 0, "stdout": "ok", "stderr": "", "duration_ms": 1})
	})

	f.mux.HandleFunc("POST /sandboxes/{id}/preview", func(w http.ResponseWriter, r *http.Request) {
		var req events.CreatePreviewReq
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(events.PreviewInfo{
			URL: "http://qafas-should-not-see-this/", Token: "preview-tok", Port: req.Port,
			ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339),
		})
	})
	f.mux.HandleFunc("/preview/{id}/{port}/{rest...}", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sbx_preview_" + r.PathValue("id") + "_" + r.PathValue("port"), Value: "abc", Path: "/some/other/base/"})
		w.Header().Set("X-Echo-Preview-Token", r.Header.Get("X-Sbx-Preview"))
		w.Header().Set("X-Echo-Query", r.URL.RawQuery)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "id=%s port=%s rest=%s", r.PathValue("id"), r.PathValue("port"), r.PathValue("rest"))
	})

	f.mux.HandleFunc("POST /snapshots", func(w http.ResponseWriter, r *http.Request) {
		var req events.CreateSnapshotReq
		json.NewDecoder(r.Body).Decode(&req)
		memSnap := true
		if req.MemorySnapshot != nil {
			memSnap = *req.MemorySnapshot
		}
		info := events.SnapshotInfo{
			Name: req.Name, State: "building", Kind: "image", Source: req.Source, CreatedAt: time.Now().Format(time.RFC3339),
			Warm: req.Warm, MemorySnapshot: memSnap, Runtime: req.Runtime,
		}
		f.mu.Lock()
		f.snapshots[req.Name] = info
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(info)
	})
	f.mux.HandleFunc("PUT /snapshots/{name}", func(w http.ResponseWriter, r *http.Request) {
		var req events.UpdateSnapshotReq
		json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		info, ok := f.snapshots[r.PathValue("name")]
		if ok {
			info.Warm = req.Warm
			info.WarmReady = req.Warm // fake: pretends the pool is already at target
			f.snapshots[r.PathValue("name")] = info
		}
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, info)
	})
	// v5.2: the fake grades every template A on a scan, synchronously.
	f.mux.HandleFunc("POST /snapshots/{name}/scan", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		info, ok := f.snapshots[r.PathValue("name")]
		if ok {
			info.Security = &events.TemplateSecurity{Grade: "A", Findings: []events.SecurityCheck{{ID: "caps", Class: "boundary", OK: true}}}
			f.snapshots[r.PathValue("name")] = info
		}
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusAccepted, info)
	})
	f.mux.HandleFunc("GET /snapshots", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		list := make([]events.SnapshotInfo, 0, len(f.snapshots))
		for _, v := range f.snapshots {
			list = append(list, v)
		}
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, list)
	})
	f.mux.HandleFunc("GET /snapshots/{name}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		info, ok := f.snapshots[r.PathValue("name")]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, info)
	})
	f.mux.HandleFunc("DELETE /snapshots/{name}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		inUseMsg, inUse := f.deleteInUse[r.PathValue("name")]
		f.mu.Unlock()
		if inUse {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": inUseMsg})
			return
		}
		f.mu.Lock()
		_, ok := f.snapshots[r.PathValue("name")]
		delete(f.snapshots, r.PathValue("name"))
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return f
}

// overrideDeleteInUse makes the next DELETE /snapshots/{name} on this host answer 409
// with the given message instead of deleting, to exercise defect-5's relay.
func (f *fakeQafas) overrideDeleteInUse(name, msg string) {
	f.mu.Lock()
	if f.deleteInUse == nil {
		f.deleteInUse = map[string]string{}
	}
	f.deleteInUse[name] = msg
	f.mu.Unlock()
}

// overrideLifecycle makes the next call to POST /sandboxes/{id}/{verb} reply with status
// instead of its normal success reply, to exercise error relay.
func (f *fakeQafas) overrideLifecycle(verb string, status int) {
	f.mu.Lock()
	f.lifecycleStatus[verb] = status
	f.mu.Unlock()
}

// overrideCreate makes the next POST /sandboxes answer status/body instead of its normal
// 201, to exercise daemon-error passthrough (placement_test.go).
func (f *fakeQafas) overrideCreate(status int, body string) {
	f.mu.Lock()
	f.createStatus, f.createBody = status, body
	f.mu.Unlock()
}

// overrideCreateInfo makes POST /sandboxes echo info as CreateSandboxResp.Info (v5.1), to
// exercise the "daemon's own record is authoritative" path in sandboxInfoFromCreate.
func (f *fakeQafas) overrideCreateInfo(info *events.SandboxInfo) {
	f.mu.Lock()
	f.createInfo = info
	f.mu.Unlock()
}

// seedSnapshot pre-loads one snapshot row without going through POST /snapshots, for tests
// that need a snapshot present before the host is ever asked to build one.
func (f *fakeQafas) seedSnapshot(name, state string) {
	f.mu.Lock()
	f.snapshots[name] = events.SnapshotInfo{Name: name, State: state, Kind: "image"}
	f.mu.Unlock()
}

func registerFakeHost(t *testing.T, mux *http.ServeMux, hostID, url string, tiers []string) {
	t.Helper()
	if rec := doReq(mux, "POST", "/api/hosts/register", testHost, events.HostRegister{HostID: hostID, URL: url, Backend: "podman", Capacity: 2, Tiers: tiers}); rec.Code != http.StatusNoContent {
		t.Fatalf("register %s: %d %s", hostID, rec.Code, rec.Body.String())
	}
}

// newFakeHost spins up a fakeQafas, serves it, registers it with mux as hostID/tiers, and
// closes it on test cleanup — the preamble every v3 lifecycle/preview/snapshot test needs.
func newFakeHost(t *testing.T, mux *http.ServeMux, hostID string, tiers []string) *fakeQafas {
	t.Helper()
	fake := newFakeQafas()
	srv := httptest.NewServer(fake.mux)
	t.Cleanup(srv.Close)
	registerFakeHost(t, mux, hostID, srv.URL, tiers)
	return fake
}

func TestLifecycleRoutesUpdateState(t *testing.T) {
	_, mux := newTestAPI(t)
	fake := newFakeHost(t, mux, "h1", []string{"remote"})

	rec := doReq(mux, "POST", "/api/sandboxes", testAdmin, events.CreateSandboxReq{Template: "base", PiSession: "t"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created events.CreateSandboxResp
	json.Unmarshal(rec.Body.Bytes(), &created)
	id := created.ID

	getState := func() string {
		rec := doReq(mux, "GET", "/api/sandboxes/"+id, testAdmin, nil)
		var sb events.SandboxInfo
		json.Unmarshal(rec.Body.Bytes(), &sb)
		return sb.State
	}

	steps := []struct{ verb, want string }{
		{"stop", "stopped"},
		{"start", "ready"},
		{"pause", "paused"},
		{"resume", "ready"},
		{"archive", "archived"},
	}
	for _, step := range steps {
		rec := doReq(mux, "POST", "/api/sandboxes/"+id+"/"+step.verb, testAdmin, nil)
		wantCode := http.StatusNoContent
		if step.verb == "start" {
			wantCode = http.StatusOK
		}
		if rec.Code != wantCode {
			t.Fatalf("%s: got %d, want %d: %s", step.verb, rec.Code, wantCode, rec.Body.String())
		}
		if got := getState(); got != step.want {
			t.Fatalf("after %s: state=%q, want %q", step.verb, got, step.want)
		}
	}

	// Error relay: the daemon's status and body are passed through verbatim.
	fake.overrideLifecycle("stop", http.StatusConflict)
	rec = doReq(mux, "POST", "/api/sandboxes/"+id+"/stop", testAdmin, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("stop (daemon 409): got %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if got := getState(); got != "archived" {
		t.Fatalf("a failed lifecycle call must not change the stored state: got %q", got)
	}

	// Unknown sandbox -> 404, never reaches the host.
	if rec := doReq(mux, "POST", "/api/sandboxes/nope/stop", testAdmin, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("stop unknown sandbox: got %d, want 404", rec.Code)
	}
}

// TestExecForward is docs/protocol.md §4a: POST /api/sandboxes/{id}/exec forwards to the
// owning host's POST /sandboxes/{id}/agent/exec with the host token and the caller's own
// X-Pi-Session/X-Tool-Call-Id (§7), and relays the daemon's status/body unchanged.
func TestExecForward(t *testing.T) {
	_, mux := newTestAPI(t)
	fake := newFakeHost(t, mux, "h1", []string{"remote"})

	rec := doReq(mux, "POST", "/api/sandboxes", testAdmin, events.CreateSandboxReq{Template: "base", PiSession: "t"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created events.CreateSandboxResp
	json.Unmarshal(rec.Body.Bytes(), &created)

	body, _ := json.Marshal(events.ExecReq{Cmd: "echo hi", Cwd: "/home/agent"})
	req := httptest.NewRequest("POST", "/api/sandboxes/"+created.ID+"/exec", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdmin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Pi-Session", "sess-exec")
	req.Header.Set("X-Tool-Call-Id", "tc-1")
	execRec := httptest.NewRecorder()
	mux.ServeHTTP(execRec, req)

	if execRec.Code != http.StatusOK {
		t.Fatalf("exec: got %d, want 200: %s", execRec.Code, execRec.Body.String())
	}
	var out events.ExecResp
	if err := json.Unmarshal(execRec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode exec response: %v", err)
	}
	if out.Stdout != "ok" {
		t.Fatalf("exec response not relayed verbatim: %+v", out)
	}

	fake.mu.Lock()
	gotHeaders, gotBody := fake.lastExecHeaders, fake.lastExecBody
	fake.mu.Unlock()
	if gotHeaders.Get("Authorization") != "Bearer "+testSecret {
		t.Fatalf("host did not get the host token, got %q", gotHeaders.Get("Authorization"))
	}
	if gotHeaders.Get("X-Pi-Session") != "sess-exec" {
		t.Fatalf("X-Pi-Session not forwarded: %q", gotHeaders.Get("X-Pi-Session"))
	}
	if gotHeaders.Get("X-Tool-Call-Id") != "tc-1" {
		t.Fatalf("X-Tool-Call-Id not forwarded: %q", gotHeaders.Get("X-Tool-Call-Id"))
	}
	var gotReq events.ExecReq
	json.Unmarshal(gotBody, &gotReq)
	if gotReq.Cmd != "echo hi" || gotReq.Cwd != "/home/agent" {
		t.Fatalf("exec body not forwarded unchanged: %+v", gotReq)
	}

	// Unknown sandbox -> 404, never reaches the host.
	if rec := doReq(mux, "POST", "/api/sandboxes/nope/exec", testAdmin, events.ExecReq{Cmd: "x"}); rec.Code != http.StatusNotFound {
		t.Fatalf("exec unknown sandbox: got %d, want 404", rec.Code)
	}
}

func TestPreviewURLRewriteAndProxy(t *testing.T) {
	_, mux := newTestAPI(t)
	_ = newFakeHost(t, mux, "h1", []string{"remote"})

	rec := doReq(mux, "POST", "/api/sandboxes", testAdmin, events.CreateSandboxReq{Template: "base", PiSession: "t"})
	var created events.CreateSandboxResp
	json.Unmarshal(rec.Body.Bytes(), &created)
	id := created.ID

	rec = doReq(mux, "POST", "/api/sandboxes/"+id+"/preview", testAdmin, events.CreatePreviewReq{Port: 8080})
	if rec.Code != http.StatusOK {
		t.Fatalf("create preview: %d %s", rec.Code, rec.Body.String())
	}
	var info events.PreviewInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	wantURL := "http://example.com/preview/" + id + "/8080/"
	if info.URL != wantURL {
		t.Fatalf("preview url: got %q, want %q (rewritten onto the control plane, not the host's own URL)", info.URL, wantURL)
	}
	if info.Token != "preview-tok" || info.Port != 8080 {
		t.Fatalf("preview info not relayed: %+v", info)
	}

	// The proxy route itself needs no admin auth: the preview token is the auth.
	cpSrv := httptest.NewServer(mux)
	defer cpSrv.Close()
	resp, err := http.Get(cpSrv.URL + "/preview/" + id + "/8080/some/path?x=1&sbx_preview=" + info.Token)
	if err != nil {
		t.Fatalf("GET preview proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preview proxy status: %d", resp.StatusCode)
	}
	body := make([]byte, 256)
	n, _ := resp.Body.Read(body)
	got := string(body[:n])
	if got != "id="+id+" port=8080 rest=some/path" {
		t.Fatalf("proxied path/params: got %q", got)
	}
	if q := resp.Header.Get("X-Echo-Query"); !strings.Contains(q, "sbx_preview="+info.Token) {
		t.Fatalf("query string not passed through untouched: %q", q)
	}
	var rewrittenCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "sbx_preview_"+id+"_8080" {
			rewrittenCookie = c
		}
	}
	if rewrittenCookie == nil {
		t.Fatal("preview cookie missing from proxied response")
	}
	if rewrittenCookie.Path != "/preview/"+id+"/8080/" {
		t.Fatalf("Set-Cookie Path must be rewritten onto the control plane's own preview mount, got %q", rewrittenCookie.Path)
	}
}

func TestSnapshotsFanOutAcrossHosts(t *testing.T) {
	_, mux := newTestAPI(t)
	_ = newFakeHost(t, mux, "hostA", []string{"vm"})
	_ = newFakeHost(t, mux, "hostB", []string{"remote"})
	// A native-only host must never receive the fan-out.
	registerFakeHost(t, mux, "hostNative", "http://127.0.0.1:1", []string{"native"})

	// v4c: a create fans out to hosts of one runtime only, so put snap1 on both hostA
	// and hostB (below) with two explicit-runtime calls — the rest of this test (GET
	// merge, GET-by-name, PUT, DELETE) still exercises both hosts having it.
	memSnapOff := false
	rec := doReq(mux, "POST", "/api/snapshots", testAdmin, events.CreateSnapshotReq{
		Name: "snap1", Source: events.SnapshotSource{Image: "node:22"}, Warm: 3, MemorySnapshot: &memSnapOff, Runtime: "vm",
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create snapshot (vm): %d %s", rec.Code, rec.Body.String())
	}
	var createdVM []events.SnapshotInfo
	json.Unmarshal(rec.Body.Bytes(), &createdVM)
	if len(createdVM) != 1 || createdVM[0].HostID != "hostA" {
		t.Fatalf("runtime:vm must fan out to hostA only, got %+v", createdVM)
	}

	rec = doReq(mux, "POST", "/api/snapshots", testAdmin, events.CreateSnapshotReq{
		Name: "snap1", Source: events.SnapshotSource{Image: "node:22"}, Warm: 3, MemorySnapshot: &memSnapOff, Runtime: "remote",
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create snapshot (remote): %d %s", rec.Code, rec.Body.String())
	}
	var createdRemote []events.SnapshotInfo
	json.Unmarshal(rec.Body.Bytes(), &createdRemote)
	if len(createdRemote) != 1 || createdRemote[0].HostID != "hostB" {
		t.Fatalf("runtime:remote must fan out to hostB only, got %+v", createdRemote)
	}

	created := append(createdVM, createdRemote...)
	seenHosts := map[string]bool{}
	for _, si := range created {
		seenHosts[si.HostID] = true
		if si.Name != "snap1" {
			t.Fatalf("snapshot name: %+v", si)
		}
		// warm/memory_snapshot must pass through the fan-out unchanged.
		if si.Warm != 3 || si.MemorySnapshot != false {
			t.Fatalf("warm/memory_snapshot not passed through: %+v", si)
		}
	}
	if !seenHosts["hostA"] || !seenHosts["hostB"] {
		t.Fatalf("fan-out must reach both vm and remote hosts (via their own runtime): %+v", created)
	}

	// GET /api/snapshots merges every host's list; hostNative is unreachable and simply
	// contributes nothing to the list form (only GET-by-name turns a failure into a row).
	rec = doReq(mux, "GET", "/api/snapshots", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list snapshots: %d %s", rec.Code, rec.Body.String())
	}
	var list []events.SnapshotInfo
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 2 {
		t.Fatalf("want 2 merged snapshot rows, got %+v", list)
	}

	// GET /api/snapshots/{name} queries every host (not just vm/remote): hostA and hostB
	// answer with the snapshot, hostNative is unreachable and contributes an error row.
	rec = doReq(mux, "GET", "/api/snapshots/snap1", testAdmin, nil)
	var byName []events.SnapshotInfo
	json.Unmarshal(rec.Body.Bytes(), &byName)
	if len(byName) != 3 {
		t.Fatalf("want 3 rows for snap1 (hostA, hostB, hostNative's error row), got %+v", byName)
	}
	var errRows int
	for _, si := range byName {
		if si.HostID == "hostNative" {
			if si.State != "error" || si.Error != "host unreachable" {
				t.Fatalf("unreachable host row: %+v", si)
			}
			errRows++
		}
	}
	if errRows != 1 {
		t.Fatalf("want exactly 1 error row for the unreachable host, got %d", errRows)
	}

	// PUT fans {"warm": n} out to every host that reports the snapshot (hostA, hostB), one
	// row per host, like the create fan-out — hostNative never gets a row since it never
	// reported having it.
	rec = doReq(mux, "PUT", "/api/snapshots/snap1", testAdmin, events.UpdateSnapshotReq{Warm: 5})
	if rec.Code != http.StatusOK {
		t.Fatalf("update snapshot: %d %s", rec.Code, rec.Body.String())
	}
	var updated []events.SnapshotInfo
	json.Unmarshal(rec.Body.Bytes(), &updated)
	if len(updated) != 2 {
		t.Fatalf("want 2 rows (hostA + hostB) from PUT, got %+v", updated)
	}
	for _, si := range updated {
		if si.HostID != "hostA" && si.HostID != "hostB" {
			t.Fatalf("PUT must only reach hosts that have the snapshot: %+v", si)
		}
		if si.Warm != 5 {
			t.Fatalf("warm not applied: %+v", si)
		}
	}

	// An unknown snapshot name reaches no host and is a 404.
	rec = doReq(mux, "PUT", "/api/snapshots/does-not-exist", testAdmin, events.UpdateSnapshotReq{Warm: 1})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("update unknown snapshot: got %d, want 404: %s", rec.Code, rec.Body.String())
	}

	// DELETE fans out and reports 502 with per-host errors when a host fails (hostNative).
	rec = doReq(mux, "DELETE", "/api/snapshots/snap1", testAdmin, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("delete snapshot with one unreachable host: got %d, want 502: %s", rec.Code, rec.Body.String())
	}
	var delErr map[string]any
	json.Unmarshal(rec.Body.Bytes(), &delErr)
	hostsErrs, _ := delErr["hosts"].(map[string]any)
	if _, ok := hostsErrs["hostNative"]; !ok {
		t.Fatalf("delete error body must name the failing host: %+v", delErr)
	}

	// hostA and hostB did delete it, even though the overall call reported 502.
	rec = doReq(mux, "GET", "/api/snapshots/snap1", testAdmin, nil)
	var afterDelete []events.SnapshotInfo
	json.Unmarshal(rec.Body.Bytes(), &afterDelete)
	for _, si := range afterDelete {
		if si.HostID == "hostA" || si.HostID == "hostB" {
			t.Fatalf("hostA/hostB should have deleted snap1, still present: %+v", si)
		}
	}
}

// TestDeleteSnapshotInUseReturns409 is defect 5: when every host holding the snapshot
// answers 409 "in use", the control plane must relay that 409 with the daemon's own
// message, not wrap it as 502 "some hosts failed".
func TestDeleteSnapshotInUseReturns409(t *testing.T) {
	_, mux := newTestAPI(t)
	fake := newFakeHost(t, mux, "h1", []string{"remote"})

	rec := doReq(mux, "POST", "/api/snapshots", testAdmin, events.CreateSnapshotReq{Name: "snap-in-use", Source: events.SnapshotSource{Image: "node:22"}})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create snapshot: %d %s", rec.Code, rec.Body.String())
	}
	fake.overrideDeleteInUse("snap-in-use", "in use by sbx_w6scre9p, sbx_bk0rtcbk")

	rec = doReq(mux, "DELETE", "/api/snapshots/snap-in-use", testAdmin, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("delete in-use snapshot: got %d, want 409: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "in use by sbx_w6scre9p, sbx_bk0rtcbk" {
		t.Fatalf("409 body must carry the daemon's message unchanged, got %+v", body)
	}
}

// TestSnapshotFromSandboxIDGoesToOwningHost is the bug fix (docs/decisions.md D26 "2.
// Template"): a checkpoint of a live sandbox must build only on the host that owns that
// sandbox, not fan out to every vm/remote host (which made every host but the owner
// answer 404). An unknown sandbox_id is a 404 from the control plane, never reaching a host.
func TestSnapshotFromSandboxIDGoesToOwningHost(t *testing.T) {
	_, mux := newTestAPI(t)
	_ = newFakeHost(t, mux, "hostA", []string{"vm"})
	fakeB := newFakeHost(t, mux, "hostB", []string{"remote"})

	rec := doReq(mux, "POST", "/api/sandboxes", testAdmin, events.CreateSandboxReq{Template: "base", PiSession: "t", Isolation: "vm"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create sandbox: %d %s", rec.Code, rec.Body.String())
	}
	var created events.CreateSandboxResp
	json.Unmarshal(rec.Body.Bytes(), &created)

	rec = doReq(mux, "POST", "/api/snapshots", testAdmin, events.CreateSnapshotReq{
		Name: "checkpoint1", Source: events.SnapshotSource{SandboxID: created.ID},
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create snapshot from sandbox_id: %d %s", rec.Code, rec.Body.String())
	}
	var out []events.SnapshotInfo
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out) != 1 || out[0].HostID != "hostA" {
		t.Fatalf("checkpoint must build on the owning host only (hostA), got %+v", out)
	}
	if out[0].Runtime != "vm" {
		t.Fatalf("runtime must be set to the sandbox's own tier, got %q", out[0].Runtime)
	}
	fakeB.mu.Lock()
	bGotIt := len(fakeB.snapshots) != 0
	fakeB.mu.Unlock()
	if bGotIt {
		t.Fatalf("hostB (not the owner) must never receive the checkpoint build")
	}

	// Unknown sandbox -> 404, never reaches a host.
	rec = doReq(mux, "POST", "/api/snapshots", testAdmin, events.CreateSnapshotReq{
		Name: "checkpoint2", Source: events.SnapshotSource{SandboxID: "sbx_nope"},
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("checkpoint of unknown sandbox: got %d, want 404: %s", rec.Code, rec.Body.String())
	}
}

// TestSnapshotRuntimeDefault covers the fleet default (docs/protocol.md §3a v4c): remote
// when any registered host serves it, else vm.
func TestSnapshotRuntimeDefault(t *testing.T) {
	_, mux := newTestAPI(t)
	_ = newFakeHost(t, mux, "hostA", []string{"vm"})

	// Only a vm host: default resolves to vm.
	rec := doReq(mux, "POST", "/api/snapshots", testAdmin, events.CreateSnapshotReq{Name: "s1", Source: events.SnapshotSource{Image: "node:22"}})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create (vm-only fleet): %d %s", rec.Code, rec.Body.String())
	}
	var out []events.SnapshotInfo
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out) != 1 || out[0].HostID != "hostA" || out[0].Runtime != "vm" {
		t.Fatalf("default with only a vm host must resolve to vm: %+v", out)
	}

	// Add a remote host: remote now wins (D25), even though vm is still there.
	_ = newFakeHost(t, mux, "hostB", []string{"remote"})

	rec = doReq(mux, "POST", "/api/snapshots", testAdmin, events.CreateSnapshotReq{Name: "s2", Source: events.SnapshotSource{Image: "node:22"}})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create (mixed fleet): %d %s", rec.Code, rec.Body.String())
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out) != 1 || out[0].HostID != "hostB" || out[0].Runtime != "remote" {
		t.Fatalf("default with a remote host present must resolve to remote: %+v", out)
	}
}

// TestSnapshotRuntimeValidation covers rejection (400) and the no-host 409.
func TestSnapshotRuntimeValidation(t *testing.T) {
	_, mux := newTestAPI(t)
	_ = newFakeHost(t, mux, "hostA", []string{"vm"})

	for _, bad := range []string{"native", "auto", "banana"} {
		rec := doReq(mux, "POST", "/api/snapshots", testAdmin, events.CreateSnapshotReq{Name: "s", Source: events.SnapshotSource{Image: "x"}, Runtime: bad})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("runtime %q: got %d, want 400: %s", bad, rec.Code, rec.Body.String())
		}
	}

	// No remote host is registered: an explicit remote request (and its firecracker
	// alias) is a 409 naming the runtime.
	for _, runtime := range []string{"remote", "firecracker"} {
		rec := doReq(mux, "POST", "/api/snapshots", testAdmin, events.CreateSnapshotReq{Name: "s", Source: events.SnapshotSource{Image: "x"}, Runtime: runtime})
		if rec.Code != http.StatusConflict {
			t.Fatalf("runtime %q with no remote host: got %d, want 409: %s", runtime, rec.Code, rec.Body.String())
		}
		var body map[string]string
		json.Unmarshal(rec.Body.Bytes(), &body)
		if body["error"] != "no host serves the remote runtime" {
			t.Fatalf("409 body: got %+v", body)
		}
	}

	// The docker alias normalises to vm and reaches hostA.
	rec := doReq(mux, "POST", "/api/snapshots", testAdmin, events.CreateSnapshotReq{Name: "s3", Source: events.SnapshotSource{Image: "x"}, Runtime: "docker"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("runtime docker (alias for vm): %d %s", rec.Code, rec.Body.String())
	}
	var out []events.SnapshotInfo
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out) != 1 || out[0].HostID != "hostA" || out[0].Runtime != "vm" {
		t.Fatalf("docker alias must resolve to vm and reach hostA: %+v", out)
	}
}

// TestListSnapshotsRuntimeFilter covers GET /api/snapshots?runtime=.
func TestListSnapshotsRuntimeFilter(t *testing.T) {
	_, mux := newTestAPI(t)
	_ = newFakeHost(t, mux, "hostA", []string{"vm"})
	_ = newFakeHost(t, mux, "hostB", []string{"remote"})

	if rec := doReq(mux, "POST", "/api/snapshots", testAdmin, events.CreateSnapshotReq{Name: "snapVM", Source: events.SnapshotSource{Image: "x"}, Runtime: "vm"}); rec.Code != http.StatusAccepted {
		t.Fatalf("create snapVM: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(mux, "POST", "/api/snapshots", testAdmin, events.CreateSnapshotReq{Name: "snapRemote", Source: events.SnapshotSource{Image: "x"}, Runtime: "remote"}); rec.Code != http.StatusAccepted {
		t.Fatalf("create snapRemote: %d %s", rec.Code, rec.Body.String())
	}

	rec := doReq(mux, "GET", "/api/snapshots?runtime=vm", testAdmin, nil)
	var vmList []events.SnapshotInfo
	json.Unmarshal(rec.Body.Bytes(), &vmList)
	if len(vmList) != 1 || vmList[0].Name != "snapVM" {
		t.Fatalf("runtime=vm filter: %+v", vmList)
	}

	rec = doReq(mux, "GET", "/api/snapshots?runtime=remote", testAdmin, nil)
	var remoteList []events.SnapshotInfo
	json.Unmarshal(rec.Body.Bytes(), &remoteList)
	if len(remoteList) != 1 || remoteList[0].Name != "snapRemote" {
		t.Fatalf("runtime=remote filter: %+v", remoteList)
	}

	rec = doReq(mux, "GET", "/api/snapshots", testAdmin, nil)
	var all []events.SnapshotInfo
	json.Unmarshal(rec.Body.Bytes(), &all)
	if len(all) != 2 {
		t.Fatalf("no filter must return both: %+v", all)
	}
}

// TestHostCapsRoundTrip covers v4c host capabilities: what register sends, GET
// /api/hosts returns back unchanged (docs/protocol.md §3a).
func TestHostCapsRoundTrip(t *testing.T) {
	_, mux := newTestAPI(t)
	caps := events.HostCaps{
		OS: "linux", Arch: "x86_64", CPUs: 8, MemMiB: 16384,
		KVM: true, Firecracker: true, Podman: false, ProcessSandbox: true,
		Bpftrace: true, HugepagesMiB: 2048, Supported: []string{"remote", "native"},
	}
	rec := doReq(mux, "POST", "/api/hosts/register", testHost, events.HostRegister{
		HostID: "h1", URL: "http://x", Backend: "firecracker", Capacity: 4, Tiers: []string{"remote"}, Caps: caps,
	})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}

	rec = doReq(mux, "GET", "/api/hosts", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list hosts: %d %s", rec.Code, rec.Body.String())
	}
	var hosts []events.Host
	json.Unmarshal(rec.Body.Bytes(), &hosts)
	if len(hosts) != 1 {
		t.Fatalf("want 1 host, got %+v", hosts)
	}
	if !reflect.DeepEqual(hosts[0].Caps, caps) {
		t.Fatalf("caps round-trip: got %+v, want %+v", hosts[0].Caps, caps)
	}
}

func TestListSandboxesLabelFilter(t *testing.T) {
	_, mux := newTestAPI(t)
	_ = newFakeHost(t, mux, "h1", []string{"remote"})

	labels := map[string]string{"team": "infra"}
	rec := doReq(mux, "POST", "/api/sandboxes", testAdmin, events.CreateSandboxReq{Template: "base", PiSession: "t", Labels: labels})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}

	rec = doReq(mux, "GET", "/api/sandboxes?label=team=infra", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list by label: %d %s", rec.Code, rec.Body.String())
	}
	var list []events.SandboxInfo
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 || list[0].Labels["team"] != "infra" {
		t.Fatalf("label filter: %+v", list)
	}

	rec = doReq(mux, "GET", "/api/sandboxes?label=team=other", testAdmin, nil)
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 0 {
		t.Fatalf("non-matching label must return no rows, got %+v", list)
	}
}

// ---- v3: API keys (docs/protocol.md §4b)

func createApiKey(t *testing.T, mux *http.ServeMux, req events.CreateApiKeyReq) events.ApiKeyCreated {
	t.Helper()
	rec := doReq(mux, "POST", "/api/keys", testAdmin, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create key: %d %s", rec.Code, rec.Body.String())
	}
	var created events.ApiKeyCreated
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created key: %v", err)
	}
	return created
}

func TestApiKeysCreateUseAndOwnership(t *testing.T) {
	_, mux := newTestAPI(t)
	_ = newFakeHost(t, mux, "h1", []string{"remote"})

	keyA := createApiKey(t, mux, events.CreateApiKeyReq{Name: "team-a", Scopes: []string{"sandboxes"}})
	if !strings.HasPrefix(keyA.Key, "sbx_") || keyA.Prefix == "" || keyA.ID == "" {
		t.Fatalf("created key shape: %+v", keyA)
	}
	if !strings.Contains(keyA.Key, keyA.Prefix) {
		t.Fatalf("returned key must embed the shown prefix: %+v", keyA)
	}

	// GET /api/keys/self with the key itself.
	rec := doReq(mux, "GET", "/api/keys/self", keyA.Key, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("keys/self: %d %s", rec.Code, rec.Body.String())
	}
	var self events.ApiKey
	json.Unmarshal(rec.Body.Bytes(), &self)
	if self.ID != keyA.ID {
		t.Fatalf("keys/self id: got %q want %q", self.ID, keyA.ID)
	}

	// A "sandboxes"-scope key can't call an admin-only route.
	if rec := doReq(mux, "GET", "/api/hosts", keyA.Key, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("key on admin route: got %d, want 403", rec.Code)
	}

	// Use the key to create a sandbox.
	rec = doReq(mux, "POST", "/api/sandboxes", keyA.Key, events.CreateSandboxReq{Template: "base", PiSession: "t"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create sandbox with key: %d %s", rec.Code, rec.Body.String())
	}
	var created events.CreateSandboxResp
	json.Unmarshal(rec.Body.Bytes(), &created)
	id := created.ID

	// The row carries api_key_id/api_key_name.
	rec = doReq(mux, "GET", "/api/sandboxes/"+id, keyA.Key, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get sandbox with key: %d %s", rec.Code, rec.Body.String())
	}
	var sb events.SandboxInfo
	json.Unmarshal(rec.Body.Bytes(), &sb)
	if sb.ApiKeyID != keyA.ID {
		t.Fatalf("sandbox api_key_id: got %q want %q", sb.ApiKeyID, keyA.ID)
	}
	if sb.ApiKeyName != "team-a" {
		t.Fatalf("sandbox api_key_name: got %q", sb.ApiKeyName)
	}

	// GET /api/sandboxes?api_key= filters (admin).
	rec = doReq(mux, "GET", "/api/sandboxes?api_key="+keyA.ID, testAdmin, nil)
	var list []events.SandboxInfo
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 || list[0].ID != id {
		t.Fatalf("list by api_key: %+v", list)
	}
	// The key itself, with no filter at all, only ever sees its own rows.
	rec = doReq(mux, "GET", "/api/sandboxes", keyA.Key, nil)
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 || list[0].ID != id {
		t.Fatalf("list as key: %+v", list)
	}

	// A second key with "sandboxes" scope cannot GET or DELETE the first key's sandbox.
	keyB := createApiKey(t, mux, events.CreateApiKeyReq{Name: "team-b", Scopes: []string{"sandboxes"}})
	if rec := doReq(mux, "GET", "/api/sandboxes/"+id, keyB.Key, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("other key GET sandbox: got %d, want 403", rec.Code)
	}
	if rec := doReq(mux, "DELETE", "/api/sandboxes/"+id, keyB.Key, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("other key DELETE sandbox: got %d, want 403", rec.Code)
	}
	if rec := doReq(mux, "GET", "/api/keys/"+keyA.ID, keyB.Key, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("other key GET key: got %d, want 403", rec.Code)
	}

	// Revoke keyA: it stops working (401), the sandbox it created keeps running.
	if rec := doReq(mux, "DELETE", "/api/keys/"+keyA.ID, testAdmin, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(mux, "GET", "/api/sandboxes/"+id, keyA.Key, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key: got %d, want 401", rec.Code)
	}
	if rec := doReq(mux, "GET", "/api/sandboxes/"+id, testAdmin, nil); rec.Code != http.StatusOK {
		t.Fatalf("sandbox must still exist after its creating key is revoked: %d", rec.Code)
	}
	// A second DELETE (already revoked) is still a clean 204, not a 404 — but this time it
	// hard-deletes the row, so revoked keys don't accumulate forever.
	if rec := doReq(mux, "DELETE", "/api/keys/"+keyA.ID, testAdmin, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("re-revoke: got %d, want 204", rec.Code)
	}
	if rec := doReq(mux, "GET", "/api/keys/"+keyA.ID, testAdmin, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("key must be gone after the second DELETE (hard delete), got %d", rec.Code)
	}
	// A third DELETE finds no row at all now.
	if rec := doReq(mux, "DELETE", "/api/keys/"+keyA.ID, testAdmin, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("delete of an already hard-deleted key: got %d, want 404", rec.Code)
	}
	// Revoking an unknown key is 404.
	if rec := doReq(mux, "DELETE", "/api/keys/no-such", testAdmin, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("revoke unknown key: got %d, want 404", rec.Code)
	}
}

func TestApiKeyTierEgressAndTTLLimits(t *testing.T) {
	_, mux := newTestAPI(t)
	fake := newFakeHost(t, mux, "h1", []string{"remote", "native"})

	maxTTL := uint64(60)
	key := createApiKey(t, mux, events.CreateApiKeyReq{
		Name: "limited", Scopes: []string{"sandboxes"},
		Limits: events.ApiKeyLimits{
			AllowedTiers:  []string{"remote"},
			AllowedEgress: []string{"*.example.com"},
			MaxTTLSecs:    &maxTTL,
		},
	})

	// Disallowed explicit tier -> 403.
	if rec := doReq(mux, "POST", "/api/sandboxes", key.Key, events.CreateSandboxReq{Template: "base", PiSession: "t", Isolation: "native"}); rec.Code != http.StatusForbidden {
		t.Fatalf("disallowed tier: got %d, want 403: %s", rec.Code, rec.Body.String())
	}
	// v4: "auto" (unset) is no longer rejected — it resolves within allowed_tiers instead
	// (docs/protocol.md §4b), landing on "remote" since that's the only tier this key may use.
	autoRec := doReq(mux, "POST", "/api/sandboxes", key.Key, events.CreateSandboxReq{Template: "base", PiSession: "t"})
	if autoRec.Code != http.StatusCreated {
		t.Fatalf("auto tier with allowed_tiers set: got %d, want 201: %s", autoRec.Code, autoRec.Body.String())
	}
	var autoResp events.CreateSandboxResp
	json.Unmarshal(autoRec.Body.Bytes(), &autoResp)
	if autoResp.Isolation != "remote" {
		t.Fatalf("auto should resolve within allowed_tiers to remote, got %q", autoResp.Isolation)
	}
	// Egress glob not in the allow-list -> 403.
	if rec := doReq(mux, "POST", "/api/sandboxes", key.Key, events.CreateSandboxReq{Template: "base", PiSession: "t", Isolation: "remote", EgressAllow: []string{"evil.example"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("disallowed egress: got %d, want 403: %s", rec.Code, rec.Body.String())
	}

	// ttl over the cap is clamped, not rejected: 201, and the forwarded request carries the capped value.
	bigTTL := uint64(600)
	rec := doReq(mux, "POST", "/api/sandboxes", key.Key, events.CreateSandboxReq{Template: "base", PiSession: "t", Isolation: "remote", TTLSecs: &bigTTL})
	if rec.Code != http.StatusCreated {
		t.Fatalf("ttl clamp create: %d %s", rec.Code, rec.Body.String())
	}
	if fake.lastCreateReq == nil || fake.lastCreateReq.TTLSecs == nil || *fake.lastCreateReq.TTLSecs != maxTTL {
		t.Fatalf("ttl_secs must be clamped to %d, forwarded request: %+v", maxTTL, fake.lastCreateReq)
	}
}

func TestApiKeyConcurrentLimit(t *testing.T) {
	a, mux := newTestAPI(t)
	_ = newFakeHost(t, mux, "h1", []string{"remote"})

	maxConcurrent := uint32(1)
	key := createApiKey(t, mux, events.CreateApiKeyReq{Name: "concurrent", Scopes: []string{"sandboxes"}, Limits: events.ApiKeyLimits{MaxConcurrent: &maxConcurrent}})

	rec := doReq(mux, "POST", "/api/sandboxes", key.Key, events.CreateSandboxReq{Template: "base", PiSession: "t"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("first create: %d %s", rec.Code, rec.Body.String())
	}
	var created events.CreateSandboxResp
	json.Unmarshal(rec.Body.Bytes(), &created)
	// max_concurrent counts ready/busy/paused/stopped/archived, not "creating" — move the
	// row to "ready" the way a sandbox.ready event would, so the limit actually bites.
	if err := a.store.SetSandboxState(context.Background(), created.ID, "ready"); err != nil {
		t.Fatalf("SetSandboxState: %v", err)
	}

	rec = doReq(mux, "POST", "/api/sandboxes", key.Key, events.CreateSandboxReq{Template: "base", PiSession: "t"})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second create: got %d, want 429: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "max_concurrent 1 reached" {
		t.Fatalf("429 body: %+v", body)
	}
}

func TestApiKeyPerHourLimit(t *testing.T) {
	_, mux := newTestAPI(t)
	_ = newFakeHost(t, mux, "h1", []string{"remote"})

	maxPerHour := uint32(1)
	key := createApiKey(t, mux, events.CreateApiKeyReq{Name: "hourly", Scopes: []string{"sandboxes"}, Limits: events.ApiKeyLimits{MaxPerHour: &maxPerHour}})

	rec := doReq(mux, "POST", "/api/sandboxes", key.Key, events.CreateSandboxReq{Template: "base", PiSession: "t"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("first create: %d %s", rec.Code, rec.Body.String())
	}
	rec = doReq(mux, "POST", "/api/sandboxes", key.Key, events.CreateSandboxReq{Template: "base", PiSession: "t"})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second create: got %d, want 429: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "max_per_hour 1 reached" {
		t.Fatalf("429 body: %+v", body)
	}
}

func TestApiKeyUsage(t *testing.T) {
	a, mux := newTestAPI(t)
	_ = newFakeHost(t, mux, "h1", []string{"remote"})

	key := createApiKey(t, mux, events.CreateApiKeyReq{Name: "usage", Scopes: []string{"sandboxes"}})

	rec := doReq(mux, "POST", "/api/sandboxes", key.Key, events.CreateSandboxReq{Template: "base", PiSession: "t", Isolation: "remote"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created events.CreateSandboxResp
	json.Unmarshal(rec.Body.Bytes(), &created)
	id := created.ID
	if err := a.store.SetSandboxState(context.Background(), id, "ready"); err != nil {
		t.Fatalf("SetSandboxState: %v", err)
	}

	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	evs := []events.Event{
		{ID: "01A", TS: now, HostID: "h1", SandboxID: id, Type: events.ExecStart, Data: json.RawMessage(`{"cmd":"ls"}`)},
		{ID: "01B", TS: now, HostID: "h1", SandboxID: id, Type: events.SecurityAlert, Data: json.RawMessage(`{"severity":"high","rule":"x","msg":"y"}`)},
		{ID: "01C", TS: now, HostID: "h1", SandboxID: id, Type: events.EgressAllow, Data: json.RawMessage(`{}`)},
		{ID: "01D", TS: now, HostID: "h1", SandboxID: id, Type: events.EgressDeny, Data: json.RawMessage(`{}`)},
	}
	if rec := doReq(mux, "POST", "/api/events", testHost, evs); rec.Code != http.StatusNoContent {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body.String())
	}

	rec = doReq(mux, "GET", "/api/keys/"+key.ID+"/usage", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("usage: %d %s", rec.Code, rec.Body.String())
	}
	var usage events.ApiKeyUsage
	if err := json.Unmarshal(rec.Body.Bytes(), &usage); err != nil {
		t.Fatalf("decode usage: %v", err)
	}
	if usage.SandboxesCreated != 1 {
		t.Fatalf("sandboxes_created: got %d, want 1: %+v", usage.SandboxesCreated, usage)
	}
	if usage.LiveSandboxes != 1 {
		t.Fatalf("live_sandboxes: got %d, want 1: %+v", usage.LiveSandboxes, usage)
	}
	if usage.Execs != 1 {
		t.Fatalf("execs: got %d, want 1: %+v", usage.Execs, usage)
	}
	if usage.Alerts["high"] != 1 {
		t.Fatalf("alerts: %+v", usage.Alerts)
	}
	if usage.Egress["allow"] != 1 || usage.Egress["deny"] != 1 {
		t.Fatalf("egress: %+v", usage.Egress)
	}
	if usage.ByTier["remote"] != 1 {
		t.Fatalf("by_tier: %+v", usage.ByTier)
	}

	// The key itself can read its own usage.
	if rec := doReq(mux, "GET", "/api/keys/"+key.ID+"/usage", key.Key, nil); rec.Code != http.StatusOK {
		t.Fatalf("self usage: %d %s", rec.Code, rec.Body.String())
	}
	// Another key cannot.
	other := createApiKey(t, mux, events.CreateApiKeyReq{Name: "other", Scopes: []string{"sandboxes"}})
	if rec := doReq(mux, "GET", "/api/keys/"+key.ID+"/usage", other.Key, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("other key usage: got %d, want 403", rec.Code)
	}
}

// ---- v5: sizes and limits (docs/protocol.md §3a "v5 sizes and limits", §4, §4b)

func TestCreateSandboxSizeResolvesToMediumByDefault(t *testing.T) {
	_, mux := newTestAPI(t)
	fake := newFakeHost(t, mux, "h1", []string{"remote"})

	rec := doReq(mux, "POST", "/api/sandboxes", testAdmin, events.CreateSandboxReq{Template: "base", PiSession: "t"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var resp events.CreateSandboxResp
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Size != "medium" || resp.Limits == nil || *resp.Limits != events.DefaultSizes()["medium"] {
		t.Fatalf("default size: got %+v", resp)
	}
	if fake.lastCreateReq.Size != "medium" || fake.lastCreateReq.Limits == nil {
		t.Fatalf("forwarded request must carry both size and limits: %+v", fake.lastCreateReq)
	}

	sb := doReq(mux, "GET", "/api/sandboxes/"+resp.ID, testAdmin, nil)
	var info events.SandboxInfo
	json.Unmarshal(sb.Body.Bytes(), &info)
	if info.Size != "medium" || info.Limits == nil || *info.Limits != events.DefaultSizes()["medium"] {
		t.Fatalf("stored row: got %+v", info)
	}
}

func TestCreateSandboxSizeAndLimitsBothIsBadRequest(t *testing.T) {
	_, mux := newTestAPI(t)
	rec := doReq(mux, "POST", "/api/sandboxes", testAdmin, events.CreateSandboxReq{
		PiSession: "t", Size: "mini", Limits: &events.SandboxLimits{Cpus: 1, MemMiB: 512, DiskMiB: 512},
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "give either size or limits, not both") {
		t.Fatalf("size+limits: got %d %s", rec.Code, rec.Body.String())
	}
}

func TestCreateSandboxUnknownSizeListsNames(t *testing.T) {
	_, mux := newTestAPI(t)
	rec := doReq(mux, "POST", "/api/sandboxes", testAdmin, events.CreateSandboxReq{PiSession: "t", Size: "giant"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown size: got %d, want 400: %s", rec.Code, rec.Body.String())
	}
	for _, name := range []string{"micro", "mini", "medium", "high"} {
		if !strings.Contains(rec.Body.String(), name) {
			t.Fatalf("unknown size error must list %q: %s", name, rec.Body.String())
		}
	}
}

func TestCreateSandboxKeyMaxMemMiBForbidsLargerSize(t *testing.T) {
	_, mux := newTestAPI(t)
	_ = newFakeHost(t, mux, "h1", []string{"remote"})

	maxMem := uint64(1024)
	key := createApiKey(t, mux, events.CreateApiKeyReq{Name: "small", Scopes: []string{"sandboxes"}, Limits: events.ApiKeyLimits{MaxMemMiB: &maxMem}})

	rec := doReq(mux, "POST", "/api/sandboxes", key.Key, events.CreateSandboxReq{Template: "base", PiSession: "t", Size: "medium"})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "this key may use at most 1024 MiB") {
		t.Fatalf("max_mem_mib: got %d %s", rec.Code, rec.Body.String())
	}
	// mini (1024 MiB) is exactly at the ceiling and must be allowed.
	if rec := doReq(mux, "POST", "/api/sandboxes", key.Key, events.CreateSandboxReq{Template: "base", PiSession: "t", Size: "mini"}); rec.Code != http.StatusCreated {
		t.Fatalf("mini at the ceiling: got %d %s", rec.Code, rec.Body.String())
	}
}

func TestCreateSandboxKeyAllowedSizesForbidsOthers(t *testing.T) {
	_, mux := newTestAPI(t)
	fake := newFakeHost(t, mux, "h1", []string{"remote"})

	key := createApiKey(t, mux, events.CreateApiKeyReq{Name: "mini-only", Scopes: []string{"sandboxes"}, Limits: events.ApiKeyLimits{AllowedSizes: []string{"mini"}}})

	rec := doReq(mux, "POST", "/api/sandboxes", key.Key, events.CreateSandboxReq{Template: "base", PiSession: "t", Size: "high"})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "this key may use sizes") {
		t.Fatalf("allowed_sizes: got %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(mux, "POST", "/api/sandboxes", key.Key, events.CreateSandboxReq{Template: "base", PiSession: "t", Size: "mini"}); rec.Code != http.StatusCreated {
		t.Fatalf("allowed size: got %d %s", rec.Code, rec.Body.String())
	}

	// v5 (docs/protocol.md §4b): a bare request (no size/limits) doesn't default to
	// medium — medium isn't in allowed_sizes — it falls back to the smallest size the
	// key may use, here the only one: mini.
	bareRec := doReq(mux, "POST", "/api/sandboxes", key.Key, events.CreateSandboxReq{Template: "base", PiSession: "t"})
	if bareRec.Code != http.StatusCreated {
		t.Fatalf("bare request with allowed_sizes=[mini]: got %d %s", bareRec.Code, bareRec.Body.String())
	}
	var bareResp events.CreateSandboxResp
	json.Unmarshal(bareRec.Body.Bytes(), &bareResp)
	if bareResp.Size != "mini" {
		t.Fatalf("bare request should default to mini, got %q", bareResp.Size)
	}
	if fake.lastCreateReq.Size != "mini" {
		t.Fatalf("forwarded request should carry the resolved default: %+v", fake.lastCreateReq)
	}
}

// v5 (docs/protocol.md §4b): a key whose allowed_sizes/max_* admit no size at all is
// refused on every bare create, not just on an explicit out-of-bounds one.
func TestCreateSandboxKeyWithNoAdmissibleSizeIs403OnBareRequest(t *testing.T) {
	_, mux := newTestAPI(t)
	_ = newFakeHost(t, mux, "h1", []string{"remote"})

	maxMem := uint64(1024)
	key := createApiKey(t, mux, events.CreateApiKeyReq{
		Name: "impossible", Scopes: []string{"sandboxes"},
		Limits: events.ApiKeyLimits{AllowedSizes: []string{"high"}, MaxMemMiB: &maxMem},
	})

	rec := doReq(mux, "POST", "/api/sandboxes", key.Key, events.CreateSandboxReq{Template: "base", PiSession: "t"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no admissible size: got %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

// TestScanSnapshotGoesToHostsThatHaveIt (v5.2): the scan is forwarded only to hosts that
// hold the template, answers 202, and the grade comes back on the list afterwards.
func TestScanSnapshotGoesToHostsThatHaveIt(t *testing.T) {
	_, mux := newTestAPI(t)
	a := newFakeHost(t, mux, "hostA", []string{"vm"})
	_ = newFakeHost(t, mux, "hostB", []string{"vm"})
	a.seedSnapshot("tpl", "active")

	rec := doReq(mux, "POST", "/api/snapshots/tpl/scan", testAdmin, nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("scan: %d %s", rec.Code, rec.Body.String())
	}
	var out []events.SnapshotInfo
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out) != 1 || out[0].HostID != "hostA" {
		t.Fatalf("only hostA has tpl, got %+v", out)
	}
	rec = doReq(mux, "GET", "/api/snapshots", testAdmin, nil)
	var list []events.SnapshotInfo
	json.Unmarshal(rec.Body.Bytes(), &list)
	graded := false
	for _, i := range list {
		if i.Name == "tpl" && i.Security != nil && i.Security.Grade == "A" {
			graded = true
		}
	}
	if !graded {
		t.Fatalf("the grade must pass through the template list, got %s", rec.Body.String())
	}
	if rec := doReq(mux, "POST", "/api/snapshots/nope/scan", testAdmin, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown template: got %d, want 404", rec.Code)
	}
}
