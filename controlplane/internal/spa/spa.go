// Package spa serves the embedded React build with an index.html fallback for
// client-side routes, and a JSON 404 for unmatched /api/ paths (so the fallback
// never masks a missing API route as HTML).
package spa

import (
	"io/fs"
	"net/http"
	"strings"
)

// Handler serves files from dist (typically web.Dist, //go:embed all:dist) with SPA
// fallback to index.html for any path that isn't a real file and doesn't start with /api/.
func Handler(dist fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"not found"}`))
			return
		}
		// Client-side routes (and index.html itself) get the bytes directly:
		// http.FileServer would 301 "/index.html" to "/" and loop on the fallback.
		if st, err := fs.Stat(dist, path); err != nil || st.IsDir() || path == "index.html" {
			body, err := fs.ReadFile(dist, "index.html")
			if err != nil {
				http.Error(w, "index.html missing from build", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			w.Write(body)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
