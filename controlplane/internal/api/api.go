// Package api implements every route in docs/protocol.md §4 (the control plane HTTP API).
package api

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/metrics"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/otlp"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/registry"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/store"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/trace"
)

// snapshotHostTimeout bounds how long GET /api/snapshots[/name] waits on any one host;
// reused by placement's own template check (registry.SnapshotHostTimeout).
const snapshotHostTimeout = registry.SnapshotHostTimeout

type API struct {
	store       *store.Store
	hub         *events.Hub
	adminToken  string
	hostToken   string
	tokenSecret string
	log         *slog.Logger
	metrics     *metrics.Collector
	// v4: wired via SetPusher after construction (main.go creates the pusher with a
	// settingsFn closure over the same store) so GET /api/settings/observability can
	// report its health counters. nil is fine (e.g. in tests that don't exercise it):
	// health is just omitted.
	pusher *otlp.Pusher
	// v5 (docs/protocol.md §3a "v5 sizes and limits"): wired via SetSizes; New sets the
	// compiled defaults and 1.0 overcommit so tests that never call SetSizes still work.
	sizes         map[string]events.SandboxLimits
	overcommitCPU float64
	overcommitMem float64
}

func New(s *store.Store, hub *events.Hub, adminToken, hostToken, tokenSecret string, log *slog.Logger) *API {
	if log == nil {
		log = slog.Default()
	}
	return &API{
		store: s, hub: hub, adminToken: adminToken, hostToken: hostToken, tokenSecret: tokenSecret, log: log, metrics: metrics.New(),
		sizes: events.DefaultSizes(), overcommitCPU: 1.0, overcommitMem: 1.0,
	}
}

// SetPusher wires the OTLP pusher (docs/protocol.md §4 v4). See the API.pusher field doc.
func (a *API) SetPusher(p *otlp.Pusher) { a.pusher = p }

// SetSizes wires the v5 size table and placement overcommit factors (config.go SBX_SIZES/
// SBX_OVERCOMMIT_CPU/SBX_OVERCOMMIT_MEM).
func (a *API) SetSizes(table map[string]events.SandboxLimits, overcommitCPU, overcommitMem float64) {
	a.sizes, a.overcommitCPU, a.overcommitMem = table, overcommitCPU, overcommitMem
}

// Routes registers every API route (including /healthz) onto mux.
func (a *API) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", a.handleHealthz)

	mux.HandleFunc("POST /api/hosts/register", a.hostAuth(a.handleHostRegister))
	mux.HandleFunc("PUT /api/hosts/{id}/heartbeat", a.hostAuth(a.handleHeartbeat))
	mux.HandleFunc("POST /api/events", a.hostAuth(a.handleIngestEvents))

	mux.HandleFunc("POST /api/sandboxes", a.sandboxesAuth(a.handleCreateSandbox))
	mux.HandleFunc("GET /api/hosts", a.adminAuth(a.handleListHosts))
	mux.HandleFunc("GET /api/sandboxes", a.sandboxesAuth(a.handleListSandboxes))
	mux.HandleFunc("GET /api/sandboxes/{id}", a.sandboxesAuth(a.handleGetSandbox))
	mux.HandleFunc("GET /api/sandboxes/{id}/events", a.adminAuth(a.handleSandboxEvents))
	mux.HandleFunc("GET /api/sandboxes/{id}/processes", a.adminAuth(a.handleSandboxProcesses))
	mux.HandleFunc("DELETE /api/sandboxes/{id}", a.sandboxesAuth(a.handleDestroySandbox))
	mux.HandleFunc("GET /api/events", a.adminAuth(a.handleListEvents))
	mux.HandleFunc("GET /api/egress", a.adminAuth(a.handleEgress))
	mux.HandleFunc("GET /api/events/stream", a.handleEventStream) // auth via query token, see sse.go

	// v2
	mux.HandleFunc("GET /api/sessions", a.adminAuth(a.handleListSessions))
	mux.HandleFunc("GET /api/sessions/{id}", a.adminAuth(a.handleGetSession))
	mux.HandleFunc("GET /api/sessions/{id}/events", a.adminAuth(a.handleSessionEvents))
	mux.HandleFunc("GET /api/sessions/{id}/trace", a.adminAuth(a.handleSessionTrace))
	mux.HandleFunc("GET /api/sessions/{id}/processes", a.adminAuth(a.handleSessionProcesses))
	mux.HandleFunc("GET /api/alerts", a.adminAuth(a.handleAlerts))
	mux.HandleFunc("GET /api/stats", a.adminAuth(a.handleStats))
	mux.HandleFunc("GET /api/search", a.adminAuth(a.handleSearch))

	// v3: lifecycle, preview, snapshots (docs/protocol.md §4a). Reachable by a
	// "sandboxes"-scope key too, restricted to sandboxes it created (§4b); ownership is
	// checked in resolveSandboxHost.
	mux.HandleFunc("POST /api/sandboxes/{id}/stop", a.sandboxesAuth(a.handleLifecycle("stop")))
	mux.HandleFunc("POST /api/sandboxes/{id}/start", a.sandboxesAuth(a.handleLifecycle("start")))
	mux.HandleFunc("POST /api/sandboxes/{id}/pause", a.sandboxesAuth(a.handleLifecycle("pause")))
	mux.HandleFunc("POST /api/sandboxes/{id}/resume", a.sandboxesAuth(a.handleLifecycle("resume")))
	mux.HandleFunc("POST /api/sandboxes/{id}/archive", a.sandboxesAuth(a.handleLifecycle("archive")))
	mux.HandleFunc("POST /api/sandboxes/{id}/exec", a.sandboxesAuth(a.handleExec))
	mux.HandleFunc("GET /api/sandboxes/{id}/exec/ws", a.sandboxesAuth(a.handleExecWS))
	mux.HandleFunc("POST /api/sandboxes/{id}/preview", a.sandboxesAuth(a.handleCreatePreview))
	// No admin auth: the preview token in the request (query/header/cookie) is the auth,
	// verified by the host.
	mux.HandleFunc("/preview/{id}/{port}/{rest...}", a.handlePreviewProxy)

	mux.HandleFunc("POST /api/snapshots", a.adminAuth(a.handleCreateSnapshot))
	mux.HandleFunc("GET /api/snapshots", a.sandboxesAuth(a.handleListSnapshots))
	mux.HandleFunc("GET /api/snapshots/{name}", a.adminAuth(a.handleGetSnapshot))
	mux.HandleFunc("DELETE /api/snapshots/{name}", a.adminAuth(a.handleDeleteSnapshot))
	mux.HandleFunc("PUT /api/snapshots/{name}", a.adminAuth(a.handleUpdateSnapshot))
	mux.HandleFunc("POST /api/snapshots/{name}/scan", a.adminAuth(a.handleScanSnapshot)) // v5.2

	// v3: API keys (docs/protocol.md §4b)
	a.keysRoutes(mux)

	// v4: metrics, service discovery, pprof, observability settings (docs/protocol.md §4 v4).
	a.metricsRoutes(mux)
}

// ---- auth

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimPrefix(h, prefix)
}

func (a *API) hostAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.hostToken == "" || !events.TokenEqual(bearerToken(r), a.hostToken) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// adminAuth and sandboxesAuth are defined in keys.go alongside the rest of the v3 API
// key principal-resolving logic (docs/protocol.md §4b).

// ---- handlers

func (a *API) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *API) handleHostRegister(w http.ResponseWriter, r *http.Request) {
	var req events.HostRegister
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := a.store.UpsertHost(r.Context(), req); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var hb events.Heartbeat
	if !decodeJSON(w, r, &hb) {
		return
	}
	if err := a.store.Heartbeat(r.Context(), id, hb); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleIngestEvents(w http.ResponseWriter, r *http.Request) {
	var evs []events.Event
	if !decodeJSON(w, r, &evs) {
		return
	}
	if err := a.store.InsertEvents(r.Context(), evs); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	for _, e := range evs {
		a.hub.Publish(e)
		a.metrics.ObserveEvent(e) // v4: sbxcp_events_total/sbxcp_alerts_total
	}
	// v2: generate security.alert{rule:"egress.deny_burst"} ourselves when the daemon
	// didn't (idempotent — see store.CheckDenyBurst).
	alerts, err := a.store.CheckDenyBurst(r.Context(), evs)
	if err != nil {
		a.log.Warn("deny-burst check failed", "err", err)
	}
	for _, al := range alerts {
		a.hub.Publish(al)
		a.metrics.ObserveEvent(al)
	}
	w.WriteHeader(http.StatusNoContent)
}

// nameRe is the sandbox-name grammar (docs/protocol.md §4 v4), reused for the snapshot
// `template` name (no separate grammar is specified for it).
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// validateCreate validates req and, on success, normalises isolation/trust in place to
// their canonical wire values (aliases accepted; docs/protocol.md §4 v4) so every
// downstream consumer — placement, the stored row, the daemon — sees the resolved form.
// Timers are *uint64, so a negative value is already a 400 from decodeJSON's own
// json.Unmarshal error; nothing else to check there.
func validateCreate(req *events.CreateSandboxReq) error {
	isolation, ok := events.NormalizeIsolation(req.Isolation)
	if !ok {
		return fmt.Errorf("unknown isolation %q", req.Isolation)
	}
	trust, ok := events.NormalizeTrust(req.Trust)
	if !ok {
		return fmt.Errorf("unknown trust %q", req.Trust)
	}
	if req.Name != nil && *req.Name != "" && !nameRe.MatchString(*req.Name) {
		return fmt.Errorf("invalid name %q", *req.Name)
	}
	if req.Template != "" && req.Template != "base" && !nameRe.MatchString(req.Template) {
		return fmt.Errorf("invalid template %q", req.Template)
	}
	req.Isolation, req.Trust = isolation, trust
	return nil
}

func (a *API) handleCreateSandbox(w http.ResponseWriter, r *http.Request) {
	var req events.CreateSandboxReq
	if !decodeJSON(w, r, &req) {
		return
	}
	// docs/protocol.md §7: headers carry correlation, so a request that leaves
	// pi_session out of the body still gets attributed via X-Pi-Session.
	if req.PiSession == "" {
		req.PiSession = r.Header.Get(events.HdrPiSession)
	}
	if err := validateCreate(&req); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	ctx := r.Context()

	p := principalFrom(ctx)
	var apiKeyID string
	var allowedTiers []string
	var keyLimits *events.ApiKeyLimits
	if !p.isAdmin() { // a "sandboxes"-scope key: apply its Limits (docs/protocol.md §4b)
		ak, err := a.store.GetApiKey(ctx, p.keyID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if ak == nil { // the key was revoked/deleted between auth and here
			unauthorized(w)
			return
		}
		keyLimits = &ak.Limits
		apiKeyID = p.keyID
		allowedTiers = ak.Limits.AllowedTiers // v4: constrains placement, not rejected up front
	}

	// v5 (docs/protocol.md §4b): a bare request (neither size nor limits) from a
	// restricted key defaults to medium if the key may use it, else the smallest size
	// its limits admit — not unconditionally medium — so the default never lands the
	// caller a 403 a different default would have avoided. An explicit size/limits is
	// unaffected: it either fits the key's bounds or is rejected below.
	if keyLimits != nil && req.Size == "" && req.Limits == nil {
		name, ok := defaultSizeForKey(a.sizes, *keyLimits)
		if !ok {
			sizeErr(w, "this key's limits admit no size")
			return
		}
		req.Size = name
	}

	// v5 (docs/protocol.md §3a "v5 sizes and limits"): resolve once here so every
	// downstream consumer (key limits, placement, the stored row) sees the concrete
	// size name and Limits rather than the caller's possibly-absent request fields.
	sizeName, limits, err := events.ResolveSize(req.Size, req.Limits, a.sizes)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	req.Size, req.Limits = sizeName, &limits

	if keyLimits != nil {
		if !a.enforceApiKeyLimits(w, r, p.keyID, *keyLimits, &req) {
			return
		}
	}

	host, tier, err := registry.PickHostForRequest(ctx, a.store, req, allowedTiers, a.tokenSecret, limits, a.overcommitCPU, a.overcommitMem)
	if err != nil {
		var pe *registry.PlacementError
		if errors.As(err, &pe) {
			writeErr(w, pe.Status, pe)
			return
		}
		writeErr(w, http.StatusServiceUnavailable, err)
		return
	}
	req.Isolation = tier // forward the concrete tier, not "auto" (docs/protocol.md §4 v4)
	resp, err := registry.Acquire(ctx, host, a.tokenSecret, r.Header.Get("X-Sbx-Client"), req)
	if err != nil {
		var ue *registry.UpstreamError
		if errors.As(err, &ue) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ue.Status)
			_, _ = w.Write(ue.Body)
			return
		}
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	sb := sandboxInfoFromCreate(resp, req, host.ID, apiKeyID, sizeName, limits)
	if err := a.store.CreateSandbox(ctx, sb, host.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

// sandboxInfoFromCreate builds the row CreateSandbox stores from the daemon's 201.
// v5.1 (docs/protocol.md §3a): when the daemon echoes Info (its own record right after
// create), it is authoritative for name/labels/timers/enforcement/size/limits. A pre-v5.1
// daemon carries none of that on CreateSandboxResp, so those fields fall back to the
// request the daemon just echoed back, with "name defaults to the id" applied the same way
// qafas applies it, and size/limits fall back to what was resolved and forwarded.
func sandboxInfoFromCreate(resp *events.CreateSandboxResp, req events.CreateSandboxReq, hostID, apiKeyID, sizeName string, limits events.SandboxLimits) events.SandboxInfo {
	sb := events.SandboxInfo{
		ID: resp.ID, Backend: resp.Backend, Template: req.Template, State: "creating",
		WorkspacePath: resp.WorkspacePath, PiSession: req.PiSession,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Endpoint:  resp.Endpoint, HostID: hostID, Isolation: resp.Isolation,
		ApiKeyID: apiKeyID,
	}
	if info := resp.Info; info != nil {
		sb.Name = nameOrDefault(&info.Name, resp.ID)
		sb.Labels = info.Labels
		sb.AutoStopSecs = info.AutoStopSecs
		sb.AutoArchiveSecs = info.AutoArchiveSecs
		sb.AutoDeleteSecs = info.AutoDeleteSecs
		sb.MaxAgeSecs = info.MaxAgeSecs
		sb.Enforcement = info.Enforcement
		sb.Size = cmp.Or(info.Size, sizeName)
		sb.Limits = cmp.Or(info.Limits, &limits)
		return sb
	}
	sb.Name = nameOrDefault(req.Name, resp.ID)
	sb.Labels = req.Labels
	sb.AutoStopSecs = req.AutoStopSecs
	sb.AutoArchiveSecs = req.AutoArchiveSecs
	sb.AutoDeleteSecs = req.AutoDeleteSecs
	sb.MaxAgeSecs = req.MaxAgeSecs
	sb.Size = cmp.Or(resp.Size, sizeName)
	sb.Limits = cmp.Or(resp.Limits, &limits)
	return sb
}

func nameOrDefault(name *string, fallback string) string {
	if name != nil && *name != "" {
		return *name
	}
	return fallback
}

func (a *API) handleSandboxProcesses(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, host, ok := a.resolveSandboxHost(w, r, id)
	if !ok {
		return
	}
	status, body, err := registry.ProxyProcesses(r.Context(), host, a.tokenSecret, id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (a *API) handleListHosts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hosts, err := a.store.ListHosts(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	committed, err := a.store.CommittedByHost(ctx) // v5: docs/protocol.md §4 Host.committed
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	for i := range hosts {
		hosts[i].Committed = committed[hosts[i].ID]
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (a *API) handleListSandboxes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	apiKeyID := q.Get("api_key")
	// A "sandboxes"-scope key only ever sees its own rows, whatever ?api_key= says
	// (docs/protocol.md §4b: "GET /api/sandboxes (filtered to its own)").
	if p := principalFrom(r.Context()); !p.isAdmin() {
		apiKeyID = p.keyID
	}
	list, err := a.store.ListSandboxes(r.Context(), q.Get("state"), q.Get("label"), q.Get("name"), apiKeyID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) handleGetSandbox(w http.ResponseWriter, r *http.Request) {
	sb, err := a.store.GetSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if sb == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	if !a.authorizeSandboxOwner(w, r, sb) {
		return
	}
	writeJSON(w, http.StatusOK, sb)
}

func (a *API) handleListEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var types []string
	if ts := q.Get("types"); ts != "" {
		types = strings.Split(ts, ",")
	}
	list, err := a.store.ListEvents(r.Context(), types, q.Get("pi_session"), q.Get("sandbox_id"), q.Get("after"), parseIntDefault(q.Get("limit"), 500))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) handleDestroySandbox(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sb, err := a.store.GetSandbox(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if sb == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	if !a.authorizeSandboxOwner(w, r, sb) {
		return
	}
	if host, _ := a.store.GetHost(r.Context(), sb.HostID); host != nil {
		if err := registry.Destroy(r.Context(), host, a.tokenSecret, id); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
	}
	if err := a.store.MarkDestroyed(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleSandboxEvents(w http.ResponseWriter, r *http.Request) {
	after := r.URL.Query().Get("after")
	limit := parseIntDefault(r.URL.Query().Get("limit"), 500)
	list, err := a.store.ListEventsForSandbox(r.Context(), r.PathValue("id"), after, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) handleEgress(w http.ResponseWriter, r *http.Request) {
	limit := parseIntDefault(r.URL.Query().Get("limit"), 500)
	q := r.URL.Query()
	list, err := a.store.ListEgressEvents(r.Context(), limit, q.Get("pi_session"), q.Get("sandbox_id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// ---- v2: sessions, alerts, stats, search

func (a *API) handleListSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := parseIntDefault(q.Get("limit"), 100)
	list, err := a.store.ListSessions(r.Context(), limit, q.Get("q"), q.Get("sandbox_id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) handleGetSession(w http.ResponseWriter, r *http.Request) {
	sess, err := a.store.GetSession(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if sess == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

func (a *API) handleSessionEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var types []string
	if ts := q.Get("types"); ts != "" {
		types = strings.Split(ts, ",")
	}
	limit := parseIntDefault(q.Get("limit"), 500)
	list, err := a.store.ListSessionEvents(r.Context(), r.PathValue("id"), q.Get("after"), types, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) handleSessionTrace(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	evs, err := a.store.ListAllSessionEvents(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, trace.Build(id, evs))
}

func (a *API) handleSessionProcesses(w http.ResponseWriter, r *http.Request) {
	nodes, err := a.store.ListProcessesForSession(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (a *API) handleAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	list, err := a.store.ListAlerts(r.Context(), q.Get("severity"), q.Get("pi_session"), q.Get("sandbox_id"), q.Get("since"), parseIntDefault(q.Get("limit"), 500))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) handleStats(w http.ResponseWriter, r *http.Request) {
	st, err := a.store.Stats(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (a *API) handleSearch(w http.ResponseWriter, r *http.Request) {
	limit := parseIntDefault(r.URL.Query().Get("limit"), 200)
	list, err := a.store.Search(r.Context(), r.URL.Query().Get("q"), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// ---- v3: lifecycle, preview, snapshots

// resolveSandboxHost looks up the sandbox and its owning host, writing the appropriate
// error response (404/502) and returning ok=false when either is missing.
func (a *API) resolveSandboxHost(w http.ResponseWriter, r *http.Request, id string) (*events.SandboxInfo, *events.Host, bool) {
	sb, err := a.store.GetSandbox(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return nil, nil, false
	}
	if sb == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return nil, nil, false
	}
	if !a.authorizeSandboxOwner(w, r, sb) {
		return nil, nil, false
	}
	host, err := a.store.GetHost(r.Context(), sb.HostID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return nil, nil, false
	}
	if host == nil {
		writeErr(w, http.StatusBadGateway, fmt.Errorf("host %q not found", sb.HostID))
		return nil, nil, false
	}
	return sb, host, true
}

// lifecycleState maps a lifecycle verb to the state applied on a successful (2xx,
// bodyless) reply. "start" is handled separately: it replies 200 SandboxInfo, whose own
// State field is applied instead.
var lifecycleState = map[string]string{"stop": "stopped", "pause": "paused", "resume": "ready", "archive": "archived"}

// handleLifecycle forwards POST /api/sandboxes/{id}/{verb} to the owning host and updates
// the row's state from the reply (protocol.md §4a/§3a). Relays the daemon's status code
// and body verbatim in every case, success or error.
func (a *API) handleLifecycle(verb string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		_, host, ok := a.resolveSandboxHost(w, r, id)
		if !ok {
			return
		}
		status, body, err := registry.ForwardLifecycle(r.Context(), host, a.tokenSecret, id, verb)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		if status < 300 {
			if verb == "start" {
				var info events.SandboxInfo
				if json.Unmarshal(body, &info) == nil && info.State != "" {
					if err := a.store.SetSandboxState(r.Context(), id, info.State); err != nil {
						a.log.Warn("lifecycle state update failed", "id", id, "verb", verb, "err", err)
					}
				}
			} else if state, ok := lifecycleState[verb]; ok {
				if err := a.store.SetSandboxState(r.Context(), id, state); err != nil {
					a.log.Warn("lifecycle state update failed", "id", id, "verb", verb, "err", err)
				}
			}
		}
		if len(body) > 0 {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}
}

// handleExec is POST /api/sandboxes/{id}/exec (docs/protocol.md §4a): forwards
// {cmd,cwd?,env?,timeout_ms?} to the owning host's guest-agent (via qafas's
// /sandboxes/{id}/agent/exec proxy), carrying the caller's own X-Pi-Session/
// X-Tool-Call-Id (§7) rather than minting new ones, and relays the daemon's status and
// body unchanged.
func (a *API) handleExec(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, host, ok := a.resolveSandboxHost(w, r, id)
	if !ok {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	status, respBody, err := registry.ForwardExec(r.Context(), host, a.tokenSecret, id, body, r.Header.Get(events.HdrPiSession), r.Header.Get(events.HdrToolCallID))
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	if len(respBody) > 0 {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	_, _ = w.Write(respBody)
}

// handleExecWS is GET /api/sandboxes/{id}/exec/ws: the streaming/PTY exec (docs/protocol.md
// §2.1), proxied as a WebSocket upgrade to the owning host's /sandboxes/{id}/agent/exec/ws
// with the host bearer. `sbx shell <id>` joins a sandbox with only the caller's own
// credential; the per-sandbox token never leaves the create reply.
func (a *API) handleExecWS(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, host, ok := a.resolveSandboxHost(w, r, id)
	if !ok {
		return
	}
	target, err := url.Parse(host.URL)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	bearer := "Bearer " + a.tokenSecret
	proxy := &httputil.ReverseProxy{
		Transport: registry.TransportFor(host),
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = "/sandboxes/" + id + "/agent/exec/ws"
			req.URL.RawQuery = ""
			req.Host = target.Host
			req.Header.Set("Authorization", bearer)
		},
	}
	proxy.ServeHTTP(w, r)
}

// publicBaseURL is the base a preview URL is rewritten onto: SBX_PUBLIC_URL when set,
// else scheme+host inferred from the request (protocol.md §3a/§4a).
func publicBaseURL(r *http.Request) string {
	if v := os.Getenv("SBX_PUBLIC_URL"); v != "" {
		return strings.TrimSuffix(v, "/")
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (a *API) handleCreatePreview(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req events.CreatePreviewReq
	if !decodeJSON(w, r, &req) {
		return
	}
	_, host, ok := a.resolveSandboxHost(w, r, id)
	if !ok {
		return
	}
	status, body, err := registry.ForwardPreview(r.Context(), host, a.tokenSecret, id, req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	if status != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}
	var info events.PreviewInfo
	if err := json.Unmarshal(body, &info); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	info.URL = publicBaseURL(r) + "/preview/" + id + "/" + strconv.Itoa(int(info.Port)) + "/"
	writeJSON(w, http.StatusOK, info)
}

// rewriteSetCookiePath narrows a preview cookie's Path to the control plane's own
// /preview/{id}/{port}/ mount, in case the host set one scoped to its own base path.
func rewriteSetCookiePath(resp *http.Response, id, port string) {
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return
	}
	resp.Header.Del("Set-Cookie")
	base := "/preview/" + id + "/" + port + "/"
	for _, c := range cookies {
		if c.Path != "" {
			c.Path = base
		}
		resp.Header.Add("Set-Cookie", c.String())
	}
}

// handlePreviewProxy is ANY /preview/{id}/{port}/{*rest}: no admin auth, the preview
// token in the query/header/cookie is the auth and the host verifies it. Reverse-proxies
// HTTP and WebSocket upgrades to the owning host's identical /preview/{id}/{port}/{rest}.
func (a *API) handlePreviewProxy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	port := r.PathValue("port")
	rest := r.PathValue("rest")

	sb, err := a.store.GetSandbox(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if sb == nil {
		http.NotFound(w, r)
		return
	}
	host, err := a.store.GetHost(r.Context(), sb.HostID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if host == nil {
		http.Error(w, `{"error":"host unreachable"}`, http.StatusBadGateway)
		return
	}
	target, err := url.Parse(host.URL)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	targetPath := "/preview/" + id + "/" + port + "/" + rest

	proxy := &httputil.ReverseProxy{
		Transport: registry.TransportFor(host),
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = targetPath
			req.Host = target.Host
		},
		ModifyResponse: func(resp *http.Response) error {
			rewriteSetCookiePath(resp, id, port)
			return nil
		},
	}
	proxy.ServeHTTP(w, r)
}

// resolveSnapshotRuntime normalises CreateSnapshotReq.Runtime (docs/protocol.md §3a
// v4c). "" (absent) defaults to the fleet default: remote if any registered host
// advertises it, else vm. Anything else goes through NormalizeIsolation (aliases
// accepted); native, explicit "auto", and unknown values are all rejected — a
// snapshot always has one concrete runtime.
func resolveSnapshotRuntime(raw string, hosts []events.Host) (string, error) {
	if raw == "" {
		if len(registry.FilterByTier(hosts, events.IsolationRemote)) > 0 {
			return events.IsolationRemote, nil
		}
		return events.IsolationVm, nil
	}
	runtime, ok := events.NormalizeIsolation(raw)
	if !ok || runtime == events.IsolationNative || runtime == events.IsolationAuto {
		return "", fmt.Errorf("unknown runtime %q", raw)
	}
	return runtime, nil
}

func (a *API) handleCreateSnapshot(w http.ResponseWriter, r *http.Request) {
	var req events.CreateSnapshotReq
	if !decodeJSON(w, r, &req) {
		return
	}

	// v4c: a sandbox_id source is a checkpoint of one live sandbox — build only on the
	// host that owns it, at that sandbox's own runtime (docs/decisions.md D26 "2.
	// Template"; the bug this fixes: fanning out a checkpoint request to every vm/remote
	// host made every host but the owner answer 404).
	if req.Source.SandboxID != "" {
		sb, host, ok := a.resolveSandboxHost(w, r, req.Source.SandboxID)
		if !ok {
			return
		}
		req.Runtime = sb.Isolation
		info, err := registry.CreateSnapshotOnHost(r.Context(), host, a.tokenSecret, req)
		if err != nil {
			a.log.Warn("snapshot create failed", "host", host.ID, "err", err)
			writeJSON(w, http.StatusAccepted, []events.SnapshotInfo{{Name: req.Name, HostID: host.ID, State: "error", Error: err.Error()}})
			return
		}
		writeJSON(w, http.StatusAccepted, []events.SnapshotInfo{*info})
		return
	}

	hosts, err := a.store.ListHosts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	runtime, err := resolveSnapshotRuntime(req.Runtime, hosts)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	req.Runtime = runtime
	targets := registry.FilterByTier(hosts, runtime)
	if len(targets) == 0 {
		writeErr(w, http.StatusConflict, fmt.Errorf("no host serves the %s runtime", runtime))
		return
	}
	out := fanout(targets, func(h events.Host) events.SnapshotInfo {
		info, err := registry.CreateSnapshotOnHost(r.Context(), &h, a.tokenSecret, req)
		if err != nil {
			a.log.Warn("snapshot create failed", "host", h.ID, "err", err)
			return events.SnapshotInfo{Name: req.Name, HostID: h.ID, State: "error", Error: err.Error()}
		}
		return *info
	})
	writeJSON(w, http.StatusAccepted, out)
}

func (a *API) handleListSnapshots(w http.ResponseWriter, r *http.Request) {
	hosts, err := a.store.ListHosts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	lists := fanout(hosts, func(h events.Host) []events.SnapshotInfo {
		list, err := registry.ListSnapshotsOnHost(r.Context(), &h, a.tokenSecret, snapshotHostTimeout)
		if err != nil {
			a.log.Warn("list snapshots failed", "host", h.ID, "err", err)
			return nil
		}
		return list
	})
	out := make([]events.SnapshotInfo, 0)
	for _, list := range lists {
		out = append(out, list...)
	}
	// v4c: GET /api/snapshots?runtime= filters the merged rows (docs/protocol.md §3a).
	if runtime := r.URL.Query().Get("runtime"); runtime != "" {
		filtered := out[:0]
		for _, si := range out {
			if si.Runtime == runtime {
				filtered = append(filtered, si)
			}
		}
		out = filtered
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleGetSnapshot(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	hosts, err := a.store.ListHosts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	results := fanout(hosts, func(h events.Host) *events.SnapshotInfo {
		info, err := registry.GetSnapshotOnHost(r.Context(), &h, a.tokenSecret, name, snapshotHostTimeout)
		if err != nil {
			return &events.SnapshotInfo{Name: name, State: "error", Error: "host unreachable", HostID: h.ID}
		}
		return info // nil when the host simply doesn't have it
	})
	out := make([]events.SnapshotInfo, 0)
	for _, info := range results {
		if info != nil {
			out = append(out, *info)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDeleteSnapshot fans DELETE /snapshots/{name} out to every host. When every
// failure is an upstream response (the daemon answering, e.g. 409 "in use by sbx_…"),
// that status and body are relayed verbatim rather than wrapped as 502 (a host that never
// had the snapshot, or that's simply down, doesn't count as a failure here — see
// DeleteSnapshotOnHost). 502 "some hosts failed" is kept only for a genuine transport
// failure (a host unreachable while some other host's delete needs relaying).
func (a *API) handleDeleteSnapshot(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	hosts, err := a.store.ListHosts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	results := fanout(hosts, func(h events.Host) error {
		return registry.DeleteSnapshotOnHost(r.Context(), &h, a.tokenSecret, name)
	})
	errs := map[string]string{}
	var upstream *registry.UpstreamError
	var transportFailed bool
	for i, err := range results {
		if err == nil {
			continue
		}
		errs[hosts[i].ID] = err.Error()
		var ue *registry.UpstreamError
		if errors.As(err, &ue) {
			upstream = ue
		} else {
			transportFailed = true
		}
	}
	if len(errs) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !transportFailed && upstream != nil {
		// Every failing host answered with its own status (409 when the snapshot is
		// still in use) — relay the daemon's exact status and body.
		if len(upstream.Body) > 0 {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(upstream.Status)
		_, _ = w.Write(upstream.Body)
		return
	}
	writeJSON(w, http.StatusBadGateway, map[string]any{"error": "some hosts failed", "hosts": errs})
}

// handleUpdateSnapshot fans PUT /snapshots/{name} out to every host that reports the
// snapshot (checked with the same GetSnapshotOnHost a GET-by-name uses), one row per
// host that has it — mirroring handleCreateSnapshot's per-host result rows.
func (a *API) handleUpdateSnapshot(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req events.UpdateSnapshotReq
	if !decodeJSON(w, r, &req) {
		return
	}
	hosts, err := a.store.ListHosts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	results := fanout(hosts, func(h events.Host) *events.SnapshotInfo {
		if info, err := registry.GetSnapshotOnHost(r.Context(), &h, a.tokenSecret, name, snapshotHostTimeout); err != nil || info == nil {
			return nil // host doesn't have this snapshot (or is unreachable): no row, no PUT
		}
		info, err := registry.UpdateSnapshotOnHost(r.Context(), &h, a.tokenSecret, name, req)
		if err != nil {
			a.log.Warn("snapshot update failed", "host", h.ID, "err", err)
			return &events.SnapshotInfo{Name: name, HostID: h.ID, State: "error", Error: err.Error()}
		}
		return info
	})
	out := make([]events.SnapshotInfo, 0)
	for _, info := range results {
		if info != nil {
			out = append(out, *info)
		}
	}
	if len(out) == 0 {
		writeErr(w, http.StatusNotFound, fmt.Errorf("unknown snapshot %q", name))
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleScanSnapshot starts the template security scan (v5.2) on every host that has the
// template. 202 with each host's row as it stands; the grades land on the rows when done.
func (a *API) handleScanSnapshot(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	hosts, err := a.store.ListHosts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	results := fanout(hosts, func(h events.Host) *events.SnapshotInfo {
		if info, err := registry.GetSnapshotOnHost(r.Context(), &h, a.tokenSecret, name, snapshotHostTimeout); err != nil || info == nil {
			return nil // host doesn't have this template (or is unreachable)
		}
		info, err := registry.ScanSnapshotOnHost(r.Context(), &h, a.tokenSecret, name)
		if err != nil {
			a.log.Warn("snapshot scan failed", "host", h.ID, "err", err)
			return &events.SnapshotInfo{Name: name, HostID: h.ID, State: "error", Error: err.Error()}
		}
		return info
	})
	out := make([]events.SnapshotInfo, 0)
	for _, info := range results {
		if info != nil {
			out = append(out, *info)
		}
	}
	if len(out) == 0 {
		writeErr(w, http.StatusNotFound, fmt.Errorf("unknown snapshot %q", name))
		return
	}
	writeJSON(w, http.StatusAccepted, out)
}

// ---- helpers

// fanout runs fn concurrently for every host and returns the results in the same order as
// hosts (each goroutine writes only its own slot, so no mutex is needed) — the shape shared
// by every snapshot handler's per-host fan-out above.
func fanout[T any](hosts []events.Host, fn func(h events.Host) T) []T {
	out := make([]T, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h events.Host) {
			defer wg.Done()
			out[i] = fn(h)
		}(i, h)
	}
	wg.Wait()
	return out
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, `{"error":"bad request: `+err.Error()+`"}`, http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
