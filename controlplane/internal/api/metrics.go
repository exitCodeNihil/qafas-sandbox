// metrics.go: v4 GET /metrics, GET /api/hosts/{id}/metrics, GET /api/prometheus/targets and
// GET /debug/pprof/ (docs/protocol.md §4 v4, docs/decisions.md D24). Hand-written
// Prometheus text (internal/metrics), no client library.
package api

import (
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"time"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/metrics"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/registry"
)

// metricsRoutes registers every v4 monitoring route.
func (a *API) metricsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /metrics", a.metricsAuth(a.handleMetrics))
	mux.HandleFunc("GET /api/hosts/{id}/metrics", a.metricsAuth(a.handleHostMetrics))
	mux.HandleFunc("GET /api/prometheus/targets", a.metricsAuth(a.handlePrometheusTargets))
	// Subtree pattern: covers both "GET /debug/pprof/" (index) and "GET
	// /debug/pprof/{profile}" from docs/protocol.md §4 v4 in one registration.
	mux.HandleFunc("GET /debug/pprof/", a.adminAuth(a.handlePprof))

	mux.HandleFunc("GET /api/settings/observability", a.adminAuth(a.handleGetObservabilitySettings))
	mux.HandleFunc("PUT /api/settings/observability", a.adminAuth(a.handlePutObservabilitySettings))
	mux.HandleFunc("POST /api/settings/observability/test", a.adminAuth(a.handleTestObservabilitySettings))
}

// metricsAuth allows the host bearer token in addition to whatever adminAuth already
// resolves (the admin token, or an "admin"-scope API key) — docs/protocol.md §4 v4:
// "admin or host token (Prometheus bearer_token)".
func (a *API) metricsAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.hostToken != "" && events.TokenEqual(bearerToken(r), a.hostToken) {
			next(w, r)
			return
		}
		a.adminAuth(next)(w, r)
	}
}

func dbFileSize(path string) int64 {
	if path == "" {
		return 0
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

// handleMetrics is GET /metrics: the control plane's own Prometheus page.
func (a *API) handleMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hosts, err := a.store.ListHosts(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	sandboxes, err := a.store.ListSandboxes(ctx, "", "", "", "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	keys, err := a.store.ListApiKeys(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	committed, err := a.store.CommittedByHost(ctx) // v5
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	now := time.Now().UTC()
	g := metrics.Gauges{
		Sandboxes: map[metrics.SandboxKey]int{}, ApiKeySandboxes: map[string]int{},
		HostCaps: map[string]events.HostCaps{}, HostCommitted: map[string]events.HostCommitted{},
	}
	for _, h := range hosts {
		if registry.HostState(h, now) == "live" {
			g.HostsLive++
		} else {
			g.HostsStale++
		}
		g.HostCaps[h.ID] = h.Caps
		g.HostCommitted[h.ID] = committed[h.ID]
	}
	for _, sb := range sandboxes {
		tier := sb.Isolation
		if tier == "" {
			tier = "unknown"
		}
		g.Sandboxes[metrics.SandboxKey{HostID: sb.HostID, Tier: tier, State: sb.State}]++
	}
	for _, k := range keys {
		if k.LiveSandboxes > 0 {
			g.ApiKeySandboxes[k.Name] += k.LiveSandboxes
		}
	}
	g.DBBytes = dbFileSize(a.store.DBPath())
	g.SSEDropped = a.hub.Dropped.Load()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(a.metrics.Render(g, metrics.BuildVersion())))
}

// handleHostMetrics is GET /api/hosts/{id}/metrics: fetches the host's own /metrics page
// with the pinned-TLS client and streams it back verbatim.
func (a *API) handleHostMetrics(w http.ResponseWriter, r *http.Request) {
	host, err := a.store.GetHost(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if host == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	status, body, err := registry.FetchMetrics(r.Context(), host, a.tokenSecret)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// sdTarget is one Prometheus HTTP service-discovery entry.
type sdTarget struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// handlePrometheusTargets is GET /api/prometheus/targets: one entry per live host plus the
// control plane itself.
func (a *API) handlePrometheusTargets(w http.ResponseWriter, r *http.Request) {
	hosts, err := a.store.ListHosts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	now := time.Now().UTC()
	out := make([]sdTarget, 0, len(hosts)+1)
	for _, h := range hosts {
		if registry.HostState(h, now) != "live" {
			continue
		}
		out = append(out, sdTarget{
			Targets: []string{r.Host},
			Labels: map[string]string{
				"__metrics_path__": "/api/hosts/" + h.ID + "/metrics",
				"host_id":          h.ID,
				"backend":          h.Backend,
				"tiers":            strings.Join(h.Tiers, ","),
			},
		})
	}
	out = append(out, sdTarget{
		Targets: []string{r.Host},
		Labels:  map[string]string{"__metrics_path__": "/metrics", "job": "controlplane"},
	})
	writeJSON(w, http.StatusOK, out)
}

// handlePprof is GET /debug/pprof/ and GET /debug/pprof/{profile}, wrapped in adminAuth.
// Delegates to net/http/pprof's own handlers rather than importing the package for its
// DefaultServeMux side effect.
func (a *API) handlePprof(w http.ResponseWriter, r *http.Request) {
	switch name := strings.TrimPrefix(r.URL.Path, "/debug/pprof/"); name {
	case "", "index":
		pprof.Index(w, r)
	case "cmdline":
		pprof.Cmdline(w, r)
	case "profile":
		pprof.Profile(w, r)
	case "symbol":
		pprof.Symbol(w, r)
	case "trace":
		pprof.Trace(w, r)
	default:
		pprof.Handler(name).ServeHTTP(w, r)
	}
}
