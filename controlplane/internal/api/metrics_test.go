// metrics_test.go: v4 GET /metrics, GET /api/prometheus/targets, observability settings
// round trip and the /test endpoint (docs/protocol.md §4 v4).
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/otlp"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/store"
)

// doReqMW is doReqTo but through a.HTTPMiddleware(mux) instead of mux directly, so
// sbxcp_http_requests_total/_duration_ms actually observe the request. Every other test in
// this package calls doReq (bare mux) because they don't care about that middleware; the
// metrics tests need at least one request to go through it to have something to assert on.
func doReqMW(a *API, mux *http.ServeMux, method, path, token string, body any) *httptest.ResponseRecorder {
	return doReqTo(a.HTTPMiddleware(mux), method, path, token, body)
}

// TestMetricsRenderAfterEventBatch: after one event + one alert batch, GET /metrics
// carries the expected series, and both the host and host-token auth paths work.
func TestMetricsRenderAfterEventBatch(t *testing.T) {
	a, mux := newTestAPI(t)
	registerFakeHost(t, mux, "h1", "http://127.0.0.1:1", []string{"native"})

	evs := []events.Event{
		{ID: "01A", TS: time.Now().UTC().Format(time.RFC3339), HostID: "h1", SandboxID: "sbx1", Type: events.ExecStart, Data: json.RawMessage(`{"cmd":"ls"}`)},
		{ID: "01B", TS: time.Now().UTC().Format(time.RFC3339), HostID: "h1", SandboxID: "sbx1", Type: events.SecurityAlert, Data: json.RawMessage(`{"severity":"high","rule":"sensitive_path.read"}`)},
	}
	// Through the middleware, so sbxcp_http_requests_total observes this one.
	if rec := doReqMW(a, mux, "POST", "/api/events", testHost, evs); rec.Code != http.StatusNoContent {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body.String())
	}

	// Admin token works.
	rec := doReq(mux, "GET", "/metrics", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics (admin): %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type: %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`sbxcp_events_total{type="exec.start"} 1`,
		`sbxcp_alerts_total{rule="sensitive_path.read",severity="high"} 1`,
		`sbxcp_hosts{state="live"} 1`, // just registered: last_seen is "now"
		`sbxcp_build_info{version="`,
		"go_goroutines",
		"go_memstats_alloc_bytes",
		"go_memstats_sys_bytes",
		"go_gc_total",
		`sbxcp_http_requests_total{route="POST /api/events",code="204"}`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}

	// Host token also works (Prometheus's own bearer_token).
	if rec := doReq(mux, "GET", "/metrics", testHost, nil); rec.Code != http.StatusOK {
		t.Fatalf("metrics (host token): %d %s", rec.Code, rec.Body.String())
	}
	// No/garbage token is rejected.
	if rec := doReq(mux, "GET", "/metrics", "nope", nil); rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized {
		t.Fatalf("metrics (bad token): got %d, want 401/403", rec.Code)
	}
}

func TestPrometheusTargetsShape(t *testing.T) {
	_, mux := newTestAPI(t)
	registerFakeHost(t, mux, "h1", "http://127.0.0.1:1", []string{"native", "vm"})

	rec := doReq(mux, "GET", "/api/prometheus/targets", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("targets: %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type: %q", ct)
	}
	var targets []sdTarget
	if err := json.Unmarshal(rec.Body.Bytes(), &targets); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("want 2 targets (host h1 + controlplane), got %+v", targets)
	}
	var sawHost, sawCP bool
	for _, tg := range targets {
		if len(tg.Targets) != 1 || tg.Targets[0] == "" {
			t.Fatalf("target host:port: %+v", tg)
		}
		switch tg.Labels["__metrics_path__"] {
		case "/api/hosts/h1/metrics":
			sawHost = true
			if tg.Labels["host_id"] != "h1" || tg.Labels["backend"] != "podman" || tg.Labels["tiers"] != "native,vm" {
				t.Fatalf("host target labels: %+v", tg.Labels)
			}
		case "/metrics":
			sawCP = true
			if tg.Labels["job"] != "controlplane" {
				t.Fatalf("controlplane target labels: %+v", tg.Labels)
			}
		}
	}
	if !sawHost || !sawCP {
		t.Fatalf("targets missing host or controlplane entry: %+v", targets)
	}

	// Host token also authorized (Prometheus's own bearer_token, docs/protocol.md §4 v4).
	if rec := doReq(mux, "GET", "/api/prometheus/targets", testHost, nil); rec.Code != http.StatusOK {
		t.Fatalf("targets (host token): %d %s", rec.Code, rec.Body.String())
	}
}

func TestHostMetricsUnreachableAnd404(t *testing.T) {
	_, mux := newTestAPI(t)
	registerFakeHost(t, mux, "h1", "http://127.0.0.1:1", []string{"native"})

	rec := doReq(mux, "GET", "/api/hosts/h1/metrics", testAdmin, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("unreachable host metrics: got %d, want 502: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] == "" {
		t.Fatalf("502 body must carry {\"error\"}: %s", rec.Body.String())
	}

	if rec := doReq(mux, "GET", "/api/hosts/no-such/metrics", testAdmin, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host: got %d, want 404", rec.Code)
	}
}

func TestPprofRequiresAdmin(t *testing.T) {
	_, mux := newTestAPI(t)
	if rec := doReq(mux, "GET", "/debug/pprof/", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("pprof no token: got %d, want 401", rec.Code)
	}
	// Host token is NOT a valid principal at all here (unlike /metrics's metricsAuth):
	// adminAuth's resolvePrincipal rejects it outright, same as any other unknown token.
	if rec := doReq(mux, "GET", "/debug/pprof/", testHost, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("pprof host token: got %d, want 401", rec.Code)
	}
	rec := doReq(mux, "GET", "/debug/pprof/", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("pprof index (admin): got %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// ---- observability settings

func TestObservabilitySettingsRoundTripMasksSecret(t *testing.T) {
	a, mux := newTestAPI(t)
	// main.go always wires a pusher (docs/protocol.md §4 v4: "always constructed... so
	// enabling from the UI works without a restart"); do the same here so GET carries
	// `health` the way it does in production.
	a.SetPusher(otlp.NewPusher(func() store.ObservabilitySettings {
		s, _ := a.store.GetObservabilitySettings(context.Background())
		return s
	}, a.store, nil))

	// Default (never configured) row.
	rec := doReq(mux, "GET", "/api/settings/observability", testAdmin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get default: %d %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["enabled"] != false || got["secret_key_set"] != false {
		t.Fatalf("default settings: %+v", got)
	}
	if _, hasSecret := got["secret_key"]; hasSecret {
		t.Fatalf("secret_key must never be a key in the response: %+v", got)
	}

	// PUT with a secret.
	put := map[string]any{
		"enabled": true, "provider": "langfuse", "host": "https://cloud.langfuse.com",
		"public_key": "pk-1", "secret_key": "sk-1", "capture": "alerts_only",
	}
	rec = doReq(mux, "PUT", "/api/settings/observability", testAdmin, put)
	if rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	got = map[string]any{} // json.Unmarshal merges into an existing map; reset per response
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["secret_key_set"] != true || got["provider"] != "langfuse" || got["capture"] != "alerts_only" {
		t.Fatalf("put response: %+v", got)
	}
	if _, has := got["health"]; has {
		t.Fatalf("PUT response must omit health (\"same shape minus health\"): %+v", got)
	}

	// GET reflects it, still masked, now with a health block.
	rec = doReq(mux, "GET", "/api/settings/observability", testAdmin, nil)
	got = map[string]any{}
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["secret_key_set"] != true || got["host"] != "https://cloud.langfuse.com" {
		t.Fatalf("get after put: %+v", got)
	}
	if _, hasHealth := got["health"]; !hasHealth {
		t.Fatalf("GET response must carry health: %+v", got)
	}

	// PUT again with an empty secret_key: the stored one must survive.
	put2 := map[string]any{"enabled": true, "provider": "langfuse", "host": "https://cloud.langfuse.com", "public_key": "pk-1", "secret_key": ""}
	rec = doReq(mux, "PUT", "/api/settings/observability", testAdmin, put2)
	if rec.Code != http.StatusOK {
		t.Fatalf("put empty secret: %d %s", rec.Code, rec.Body.String())
	}
	got = map[string]any{}
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["secret_key_set"] != true {
		t.Fatalf("empty secret_key on PUT must keep the stored one: %+v", got)
	}
}

func TestObservabilitySettingsAdminOnly(t *testing.T) {
	_, mux := newTestAPI(t)
	// The host bearer token isn't a resolvable principal at all under adminAuth (only
	// metricsAuth special-cases it), so this is a 401, same as any other unknown token.
	if rec := doReq(mux, "GET", "/api/settings/observability", testHost, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("host token on settings: got %d, want 401", rec.Code)
	}
}

// TestObservabilityTestEndpointDistinguishesCredentials: an httptest server that answers
// 401 on both the langfuse health check and the traces endpoint must come back with a
// detail mentioning credentials, not "unreachable".
func TestObservabilityTestEndpointDistinguishesCredentials(t *testing.T) {
	_, mux := newTestAPI(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/public/health":
			w.WriteHeader(http.StatusOK) // reachable
		case "/api/public/otel/v1/traces":
			w.WriteHeader(http.StatusUnauthorized) // credentials rejected
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	body := map[string]any{
		"provider": "langfuse", "host": srv.URL, "public_key": "pk", "secret_key": "wrong",
	}
	rec := doReq(mux, "POST", "/api/settings/observability/test", testAdmin, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("test: %d %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["ok"] != false {
		t.Fatalf("want ok:false for a 401, got %+v", got)
	}
	detail, _ := got["detail"].(string)
	if !strings.Contains(detail, "credentials") {
		t.Fatalf("detail must mention credentials for a 401, got %q", detail)
	}
	if strings.Contains(detail, "wrong") {
		t.Fatalf("detail must never contain the secret: %q", detail)
	}
}

// TestObservabilityTestEndpointUnreachable: a host that refuses the connection entirely
// must be distinguished from a credentials rejection.
func TestObservabilityTestEndpointUnreachable(t *testing.T) {
	_, mux := newTestAPI(t)
	body := map[string]any{"provider": "otlp", "otlp_url": "http://127.0.0.1:1/v1/traces"}
	rec := doReq(mux, "POST", "/api/settings/observability/test", testAdmin, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("test: %d %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["ok"] != false {
		t.Fatalf("want ok:false for an unreachable collector, got %+v", got)
	}
	detail, _ := got["detail"].(string)
	if !strings.Contains(detail, "unreachable") {
		t.Fatalf("detail must say unreachable, got %q", detail)
	}
}

// TestObservabilityTestFallsBackToStored: omitted fields in the /test body fall back to
// what's already stored (docs/protocol.md §4 v4).
func TestObservabilityTestFallsBackToStored(t *testing.T) {
	_, mux := newTestAPI(t)
	otlpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer otlpSrv.Close()

	put := map[string]any{"provider": "otlp", "otlp_url": otlpSrv.URL}
	if rec := doReq(mux, "PUT", "/api/settings/observability", testAdmin, put); rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}

	// Test with an empty body: must use the stored otlp_url, not fail with "otlp_url required".
	req := httptest.NewRequest("POST", "/api/settings/observability/test", nil)
	req.Header.Set("Authorization", "Bearer "+testAdmin)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("test empty body: %d %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["ok"] != true {
		t.Fatalf("want ok:true using the stored otlp_url, got %+v", got)
	}
}
