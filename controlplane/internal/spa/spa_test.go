package spa

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestFallbackNeverRedirects(t *testing.T) {
	dist := fstest.MapFS{"index.html": {Data: []byte("<html>app</html>")}, "assets/a.js": {Data: []byte("js")}}
	h := Handler(dist)
	for _, p := range []string{"/", "/index.html", "/sessions", "/sessions/abc?tab=trace", "/sessions/"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "<html>app</html>" {
			t.Fatalf("%s: want 200 index, got %d %q", p, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/assets/a.js", nil))
	if rec.Body.String() != "js" {
		t.Fatalf("real file must be served: %q", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/api/ must 404 as JSON, got %d", rec.Code)
	}
}
