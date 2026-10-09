package api

import (
	"bufio"
	"net"
	"net/http"
	"time"
)

// statusRecorder captures the status code a handler wrote, for HTTPMiddleware's
// sbxcp_http_requests_total{code}. It forwards Flush (SSE, sse.go) and Hijack (websocket
// upgrades, e.g. the preview proxy in api.go) to the underlying ResponseWriter, so wrapping
// the mux for metrics doesn't break either.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.status = http.StatusOK
		r.wroteHeader = true
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return r.ResponseWriter.(http.Hijacker).Hijack()
}

// longLivedRoutes are timed as sbxcp_connection_seconds instead of
// sbxcp_http_request_duration_ms (a connection open for minutes would otherwise blow out
// the request-duration histogram's sub-second buckets).
var longLivedRoutes = map[string]bool{
	"GET /api/events/stream":          true,
	"GET /api/sandboxes/{id}/exec/ws": true,
	"/preview/{id}/{port}/{rest...}":  true,
}

// HTTPMiddleware wraps mux — the same *http.ServeMux Routes registered on — to record
// sbxcp_http_requests_total{route,code}, sbxcp_http_request_duration_ms and (for
// longLivedRoutes) sbxcp_connection_seconds (docs/protocol.md §4 v4). mux.Handler(r)
// reports the matched mux pattern (e.g. "GET /api/sandboxes/{id}") as the route label
// rather than the raw path, so cardinality stays bounded to the fixed set of registered
// routes instead of growing with every sandbox/session id ever seen.
func (a *API) HTTPMiddleware(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		route := pattern
		if route == "" {
			route = "unmatched"
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		mux.ServeHTTP(rec, r)
		dur := time.Since(start)
		if longLivedRoutes[route] {
			a.metrics.ObserveConnection(dur)
			return
		}
		a.metrics.ObserveHTTP(route, rec.status, dur)
	})
}
