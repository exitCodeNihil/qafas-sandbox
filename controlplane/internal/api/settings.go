// settings.go: v4 GET/PUT /api/settings/observability and its /test endpoint
// (docs/protocol.md §4 v4, docs/decisions.md D24). Routes are registered in metrics.go's
// metricsRoutes alongside the rest of the v4 surface.
package api

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/otlp"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/store"
)

// observabilityResp is GET/PUT's response shape (docs/protocol.md §4 v4): the secret is
// never returned, only whether one is set. Health is otlp.Health directly — its JSON shape
// is already the wire shape, no separate mirror type needed.
type observabilityResp struct {
	Enabled      bool              `json:"enabled"`
	Provider     string            `json:"provider"`
	Host         string            `json:"host,omitempty"`
	PublicKey    string            `json:"public_key,omitempty"`
	SecretKeySet bool              `json:"secret_key_set"`
	OTLPURL      string            `json:"otlp_url,omitempty"`
	OTLPHeaders  map[string]string `json:"otlp_headers,omitempty"`
	Capture      string            `json:"capture,omitempty"`
	Health       *otlp.Health      `json:"health,omitempty"`
}

func toObservabilityResp(s store.ObservabilitySettings, h *otlp.Health) observabilityResp {
	return observabilityResp{
		Enabled: s.Enabled, Provider: s.Provider, Host: s.Host, PublicKey: s.PublicKey,
		SecretKeySet: s.SecretKey != "", OTLPURL: s.OTLPURL, OTLPHeaders: s.OTLPHeaders, Capture: s.Capture,
		Health: h,
	}
}

// pusherHealth returns the wired pusher's health, or nil if none is wired (tests that
// don't call SetPusher) — GET just omits `health` in that case.
func (a *API) pusherHealth() *otlp.Health {
	if a.pusher == nil {
		return nil
	}
	h := a.pusher.Health()
	return &h
}

func (a *API) handleGetObservabilitySettings(w http.ResponseWriter, r *http.Request) {
	settings, err := a.store.GetObservabilitySettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, toObservabilityResp(settings, a.pusherHealth()))
}

// handlePutObservabilitySettings is PUT /api/settings/observability: an absent/empty
// secret_key in the request keeps the one already stored (docs/protocol.md §4 v4).
func (a *API) handlePutObservabilitySettings(w http.ResponseWriter, r *http.Request) {
	var req store.ObservabilitySettings
	if !decodeJSON(w, r, &req) {
		return
	}
	existing, err := a.store.GetObservabilitySettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if req.SecretKey == "" {
		req.SecretKey = existing.SecretKey
	}
	// The watermark survives edits while enabled and moves when export turns on.
	req.EnabledAt = existing.EnabledAt
	if req.Enabled && (!existing.Enabled || existing.EnabledAt == "") {
		req.EnabledAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if err := a.store.SetObservabilitySettings(r.Context(), req); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	// "same shape minus health" (docs/protocol.md §4 v4): no pusher health on the PUT reply.
	writeJSON(w, http.StatusOK, toObservabilityResp(req, nil))
}

// handleTestObservabilitySettings is POST /api/settings/observability/test: body as PUT,
// but any field omitted from the request JSON falls back to the stored value (rather than
// PUT's "empty means keep" rule, this is plain json.Unmarshal-onto-a-copy: only keys
// actually present in the body override `existing`). Never touches the live pusher.
func (a *API) handleTestObservabilitySettings(w http.ResponseWriter, r *http.Request) {
	existing, err := a.store.GetObservabilitySettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	merged := existing
	if r.Body != nil {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&merged); err != nil && err != io.EOF {
			http.Error(w, `{"error":"bad request: `+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
	}
	ok, detail := otlp.Test(r.Context(), merged)
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "detail": detail})
}
