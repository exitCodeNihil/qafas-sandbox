package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
)

// handleEventStream serves GET /api/events/stream?sandbox_id=&token=&pi_session=&types=a,b.
// Auth is via the query string (EventSource cannot set headers) rather than the
// Authorization header. pi_session and types are v2 filters, combinable with sandbox_id.
func (a *API) handleEventStream(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if a.adminToken == "" || !events.TokenEqual(token, a.adminToken) {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, `{"error":"streaming unsupported"}`, http.StatusInternalServerError)
		return
	}

	filter := events.Filter{
		SandboxID: r.URL.Query().Get("sandbox_id"),
		PiSession: r.URL.Query().Get("pi_session"),
	}
	if ts := r.URL.Query().Get("types"); ts != "" {
		filter.Types = map[string]bool{}
		for _, t := range strings.Split(ts, ",") {
			if t = strings.TrimSpace(t); t != "" {
				filter.Types[t] = true
			}
		}
	}
	ch, cancel := a.hub.Subscribe(filter)
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case e, open := <-ch:
			if !open {
				return
			}
			data, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}
