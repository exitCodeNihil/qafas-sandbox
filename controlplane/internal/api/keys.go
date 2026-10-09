// keys.go: v3 API keys (docs/protocol.md §4b) — the principal-resolving auth middleware,
// the /api/keys routes, and the sandbox-creation limits check.
package api

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
)

// ---- principal

// principal is who's calling: the admin token, or a resolved API key. An "admin" scope
// key is equal to the admin token everywhere (docs/protocol.md §4b).
type principal struct {
	admin  bool
	keyID  string
	scopes []string
}

func (p *principal) isAdmin() bool {
	return p != nil && (p.admin || slices.Contains(p.scopes, "admin"))
}
func (p *principal) hasScope(scope string) bool {
	return p != nil && (p.isAdmin() || slices.Contains(p.scopes, scope))
}

type principalCtxKey struct{}

func principalFrom(ctx context.Context) *principal {
	p, _ := ctx.Value(principalCtxKey{}).(*principal)
	if p == nil {
		return &principal{} // defensive default: no admin, no scopes, no access
	}
	return p
}

func withPrincipal(r *http.Request, p *principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), principalCtxKey{}, p))
}

func unauthorized(w http.ResponseWriter) {
	http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
}
func forbidden(w http.ResponseWriter) { http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden) }

// resolvePrincipal is the auth middleware every route goes through: bearer ==
// SBX_ADMIN_TOKEN resolves to the admin principal; else a key lookup by secret resolves
// to {key id, scopes} (401 if revoked or unknown); else 401. The principal is stashed in
// the request context for handlers/other middleware to read via principalFrom.
func (a *API) resolvePrincipal(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			unauthorized(w)
			return
		}
		if a.adminToken != "" && events.TokenEqual(token, a.adminToken) {
			next(w, withPrincipal(r, &principal{admin: true}))
			return
		}
		key, err := a.store.LookupApiKeyBySecret(r.Context(), token)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if key == nil || key.RevokedAt != nil {
			unauthorized(w)
			return
		}
		if err := a.store.TouchApiKeyLastUsed(r.Context(), key.ID); err != nil {
			a.log.Warn("touch api key last_used_at failed", "id", key.ID, "err", err)
		}
		next(w, withPrincipal(r, &principal{keyID: key.ID, scopes: key.Scopes}))
	}
}

// adminAuth resolves the principal and requires it to be admin (the admin token, or a
// key with the "admin" scope). Every route not explicitly opened to "sandboxes" scope
// below stays admin-only — docs/protocol.md §4b: "everything else 403".
func (a *API) adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return a.resolvePrincipal(func(w http.ResponseWriter, r *http.Request) {
		if !principalFrom(r.Context()).isAdmin() {
			forbidden(w)
			return
		}
		next(w, r)
	})
}

// sandboxesAuth allows the admin principal or a key with the "sandboxes" scope; per-
// sandbox/per-key ownership is still checked by the handler (docs/protocol.md §4b).
func (a *API) sandboxesAuth(next http.HandlerFunc) http.HandlerFunc {
	return a.resolvePrincipal(func(w http.ResponseWriter, r *http.Request) {
		if !principalFrom(r.Context()).hasScope("sandboxes") {
			forbidden(w)
			return
		}
		next(w, r)
	})
}

// authorizeSandboxOwner reports whether the request's principal may act on sb: admin
// (or an admin-scope key) always, a "sandboxes"-scope key only if it created sb. Writes
// 403 and returns false otherwise.
func (a *API) authorizeSandboxOwner(w http.ResponseWriter, r *http.Request, sb *events.SandboxInfo) bool {
	p := principalFrom(r.Context())
	if p.isAdmin() || (p.keyID != "" && p.keyID == sb.ApiKeyID) {
		return true
	}
	forbidden(w)
	return false
}

// ---- routes

func (a *API) keysRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/keys", a.adminAuth(a.handleCreateApiKey))
	mux.HandleFunc("GET /api/keys", a.adminAuth(a.handleListApiKeys))
	mux.HandleFunc("GET /api/keys/self", a.resolvePrincipal(a.handleGetSelfApiKey))
	mux.HandleFunc("GET /api/keys/{id}", a.resolvePrincipal(a.handleGetApiKey))
	mux.HandleFunc("DELETE /api/keys/{id}", a.adminAuth(a.handleRevokeApiKey))
	mux.HandleFunc("GET /api/keys/{id}/usage", a.resolvePrincipal(a.handleApiKeyUsage))
}

// adminOrSelf reports whether the principal may see key id: admin, or the key itself.
func adminOrSelf(p *principal, id string) bool {
	return p.isAdmin() || (p.keyID != "" && p.keyID == id)
}

func (a *API) handleCreateApiKey(w http.ResponseWriter, r *http.Request) {
	var req events.CreateApiKeyReq
	if !decodeJSON(w, r, &req) {
		return
	}
	created, err := a.store.CreateApiKey(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (a *API) handleListApiKeys(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListApiKeys(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) handleGetApiKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !adminOrSelf(principalFrom(r.Context()), id) {
		forbidden(w)
		return
	}
	ak, err := a.store.GetApiKey(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if ak == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, ak)
}

// handleGetSelfApiKey is GET /api/keys/self: the caller's own ApiKey, or {"id":"admin"}
// for the admin token (docs/protocol.md §4b).
func (a *API) handleGetSelfApiKey(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p.admin {
		writeJSON(w, http.StatusOK, map[string]string{"id": "admin"})
		return
	}
	ak, err := a.store.GetApiKey(r.Context(), p.keyID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if ak == nil { // the key backing this principal was deleted mid-request; treat as gone
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, ak)
}

// handleRevokeApiKey is DELETE /api/keys/{id}: revokes a live key (soft, so its sandboxes
// and usage history stay attributed); a key that's already revoked is hard-deleted
// instead, so repeated DELETEs don't leave revoked rows accumulating forever.
func (a *API) handleRevokeApiKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ak, err := a.store.GetApiKey(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if ak == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	if ak.RevokedAt != nil {
		if _, err := a.store.DeleteApiKey(r.Context(), id); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if _, err := a.store.RevokeApiKey(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseSince parses ?since= as RFC 3339 or a duration ("30m", "24h", or a "<n>d" day
// count Go's time.ParseDuration doesn't support), defaulting to 24h ago when empty.
func parseSince(s string) (time.Time, error) {
	if s == "" {
		return time.Now().UTC().Add(-24 * time.Hour), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil {
			return time.Now().UTC().Add(-time.Duration(n) * 24 * time.Hour), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().UTC().Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("bad since %q: want RFC3339 or a duration like 24h or 7d", s)
}

func (a *API) handleApiKeyUsage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !adminOrSelf(principalFrom(r.Context()), id) {
		forbidden(w)
		return
	}
	ak, err := a.store.GetApiKey(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if ak == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	since, err := parseSince(r.URL.Query().Get("since"))
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	usage, err := a.store.ApiKeyUsage(r.Context(), id, since.Format(time.RFC3339))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, usage)
}

// ---- limits (POST /api/sandboxes for a "sandboxes"-scope key)

// limitErr is the exact 429 body shape docs/protocol.md §4b specifies:
// {"error":"max_concurrent 5 reached"}.
func limitErr(w http.ResponseWriter, limit string, n uint32) {
	writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": fmt.Sprintf("%s %d reached", limit, n)})
}

// sizeErr is the v5 403 body shape docs/protocol.md §4b specifies: {"error":"this key may
// use at most 1024 MiB"}.
func sizeErr(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusForbidden, map[string]string{"error": msg})
}

// defaultSizeForKey picks what POST /api/sandboxes resolves to when a "sandboxes"-scope
// key's request names neither size nor limits (docs/protocol.md §4b): medium if the key
// may use it, else the smallest size (by mem_mib) its limits admit at all — its
// AllowedSizes when set, else every named size, filtered to what fits MaxCpus/MaxMemMiB/
// MaxDiskMiB. ok is false when the key's limits admit no size, ever.
func defaultSizeForKey(table map[string]events.SandboxLimits, limits events.ApiKeyLimits) (name string, ok bool) {
	if l, exists := table[events.DefaultSize]; exists && keyMayUseSize(limits, events.DefaultSize, l) {
		return events.DefaultSize, true
	}
	candidates := limits.AllowedSizes
	if len(candidates) == 0 {
		for n := range table {
			candidates = append(candidates, n)
		}
	}
	var bestMem uint64
	for _, n := range candidates {
		l, exists := table[n]
		if !exists || !keyMayUseSize(limits, n, l) {
			continue
		}
		if !ok || l.MemMiB < bestMem {
			name, bestMem, ok = n, l.MemMiB, true
		}
	}
	return name, ok
}

// keyMayUseSize reports whether limits lets a "sandboxes"-scope key request the named
// size: present in AllowedSizes when set, and within MaxCpus/MaxMemMiB/MaxDiskMiB.
func keyMayUseSize(limits events.ApiKeyLimits, name string, l events.SandboxLimits) bool {
	if len(limits.AllowedSizes) > 0 && !slices.Contains(limits.AllowedSizes, name) {
		return false
	}
	if limits.MaxCpus != nil && l.Cpus > *limits.MaxCpus {
		return false
	}
	if limits.MaxMemMiB != nil && l.MemMiB > *limits.MaxMemMiB {
		return false
	}
	if limits.MaxDiskMiB != nil && l.DiskMiB > *limits.MaxDiskMiB {
		return false
	}
	return true
}

// enforceApiKeyLimits applies ApiKeyLimits to a POST /api/sandboxes request from a
// "sandboxes"-scope key principal (docs/protocol.md §4b). Returns ok=false after writing
// the 403/429 response when a hard limit is violated; ttl caps are clamped onto req in
// place rather than rejected.
func (a *API) enforceApiKeyLimits(w http.ResponseWriter, r *http.Request, keyID string, limits events.ApiKeyLimits, req *events.CreateSandboxReq) (ok bool) {
	// v4: allowed_tiers no longer rejects here — it flows into registry.PickHostForRequest,
	// which restricts placement candidates to it (auto resolves within the list; an
	// explicit tier outside it is a 403 there, docs/protocol.md §4b).
	if len(limits.AllowedEgress) > 0 {
		for _, g := range req.EgressAllow {
			if !slices.Contains(limits.AllowedEgress, g) {
				forbidden(w)
				return false
			}
		}
	}
	// v5 (docs/protocol.md §4b): by the time this runs, req.Size/req.Limits are the
	// resolved values the caller ends up with — a bare request already got its
	// key-aware default from defaultSizeForKey (handleCreateSandbox), so this only ever
	// rejects an explicit size/limits outside the key's bounds. Refuse, never clamp.
	if len(limits.AllowedSizes) > 0 && req.Size != events.CustomSize && !slices.Contains(limits.AllowedSizes, req.Size) {
		sizeErr(w, fmt.Sprintf("this key may use sizes %v", limits.AllowedSizes))
		return false
	}
	if req.Limits != nil {
		if limits.MaxCpus != nil && req.Limits.Cpus > *limits.MaxCpus {
			sizeErr(w, fmt.Sprintf("this key may use at most %v cpus", *limits.MaxCpus))
			return false
		}
		if limits.MaxMemMiB != nil && req.Limits.MemMiB > *limits.MaxMemMiB {
			sizeErr(w, fmt.Sprintf("this key may use at most %d MiB", *limits.MaxMemMiB))
			return false
		}
		if limits.MaxDiskMiB != nil && req.Limits.DiskMiB > *limits.MaxDiskMiB {
			sizeErr(w, fmt.Sprintf("this key may use at most %d MiB disk", *limits.MaxDiskMiB))
			return false
		}
	}
	if limits.MaxTTLSecs != nil {
		clamp := func(v *uint64) *uint64 {
			if v == nil || *v <= *limits.MaxTTLSecs {
				return v
			}
			return limits.MaxTTLSecs
		}
		req.TTLSecs = clamp(req.TTLSecs)
		req.AutoStopSecs = clamp(req.AutoStopSecs)
		req.MaxAgeSecs = clamp(req.MaxAgeSecs)
	}

	live, createdLastHour, err := a.store.ApiKeyLimitCounts(r.Context(), keyID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return false
	}
	if limits.MaxConcurrent != nil && uint32(live) >= *limits.MaxConcurrent {
		limitErr(w, "max_concurrent", *limits.MaxConcurrent)
		return false
	}
	if limits.MaxPerHour != nil && uint32(createdLastHour) >= *limits.MaxPerHour {
		limitErr(w, "max_per_hour", *limits.MaxPerHour)
		return false
	}
	return true
}
