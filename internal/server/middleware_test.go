package server

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// gzipMiddleware must compress text/json, pass image bytes through untouched, and
// not compress for clients that don't advertise gzip.
func TestGzipMiddlewareJSONRoundTrip(t *testing.T) {
	h := gzipMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hello":"world","n":12345}`))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	body, _ := io.ReadAll(zr)
	if string(body) != `{"hello":"world","n":12345}` {
		t.Fatalf("decompressed body = %q", body)
	}
}

func TestGzipMiddlewareSkipsImageAndNoAccept(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\nrest-of-bytes")
	mk := func() http.Handler {
		return gzipMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(png)
		}))
	}
	// image/png: gzip-capable client, but content is not compressible -> passthrough.
	req := httptest.NewRequest(http.MethodGet, "/api/qr", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	mk().ServeHTTP(rec, req)
	if rec.Header().Get("Content-Encoding") == "gzip" {
		t.Fatal("image/png must not be gzipped")
	}
	if string(rec.Body.Bytes()) != string(png) {
		t.Fatal("png body altered")
	}
	// No Accept-Encoding: never gzip, even for JSON.
	h := gzipMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"a":1}`))
	}))
	req2 := httptest.NewRequest(http.MethodGet, "/api/y", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Header().Get("Content-Encoding") == "gzip" {
		t.Fatal("must not gzip without Accept-Encoding: gzip")
	}
	if rec2.Body.String() != `{"a":1}` {
		t.Fatalf("plain body = %q", rec2.Body.String())
	}
}

// staticHandler must serve assets with a stable ETag and answer If-None-Match
// with 304 (no body) so repeat loads don't re-download the bundle.
func TestStaticHandlerETag304(t *testing.T) {
	s := &Server{ui: fstest.MapFS{
		"index.html": {Data: []byte("<html>hi</html>")},
		"app.js":     {Data: []byte(strings.Repeat("console.log(1);\n", 200))},
		"styles.css": {Data: []byte("body{}")},
	}}
	h := s.staticHandler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app.js", nil))
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag set on static response")
	}
	if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
		t.Fatalf("first load: code=%d len=%d, want 200 with body", rec.Code, rec.Body.Len())
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Fatalf("plain 200 Vary = %q, want Accept-Encoding", got)
	}

	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	req.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match match: code=%d, want 304", rec2.Code)
	}
	if rec2.Body.Len() != 0 {
		t.Fatal("304 must have no body")
	}
	if got := rec2.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Fatalf("plain 304 Vary = %q, want Accept-Encoding", got)
	}

	// A gzip representation varies by Accept-Encoding. RFC 9110 requires a 304 to repeat the Vary
	// metadata its 200 would carry; otherwise revalidation can collapse encoded and plain cache keys.
	gzipReq := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	gzipReq.Header.Set("Accept-Encoding", "gzip")
	gzipReq.Header.Set("If-None-Match", etag)
	gzipRec := httptest.NewRecorder()
	h.ServeHTTP(gzipRec, gzipReq)
	if gzipRec.Code != http.StatusNotModified {
		t.Fatalf("gzip If-None-Match: code=%d, want 304", gzipRec.Code)
	}
	if got := gzipRec.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Fatalf("gzip 304 Vary = %q, want Accept-Encoding", got)
	}
	if gzipRec.Body.Len() != 0 {
		t.Fatal("gzip 304 must have no body")
	}
}

// Small text/SVG assets skip the pre-compressed static cache, but the outer gzip middleware still
// compresses their 200 response. Their early conditional 304 therefore has to advertise the same
// Vary metadata even though staticGzipCache has no body entry for them.
func TestStaticHandlerSmallCompressible304KeepsVary(t *testing.T) {
	s := &Server{ui: fstest.MapFS{
		"index.html":  {Data: []byte("<html>hi</html>")},
		"tiny.js":     {Data: []byte("let x=1")},
		"favicon.svg": {Data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)},
	}}
	h := gzipMiddleware(s.staticHandler())

	for _, asset := range []string{"/tiny.js", "/favicon.svg"} {
		t.Run(asset, func(t *testing.T) {
			firstReq := httptest.NewRequest(http.MethodGet, asset, nil)
			firstReq.Header.Set("Accept-Encoding", "gzip")
			first := httptest.NewRecorder()
			h.ServeHTTP(first, firstReq)
			if first.Code != http.StatusOK || first.Header().Get("Content-Encoding") != "gzip" {
				t.Fatalf("gzip 200 = %d encoding %q, want 200 gzip", first.Code, first.Header().Get("Content-Encoding"))
			}
			etag := first.Header().Get("ETag")
			if etag == "" {
				t.Fatal("gzip 200 has no ETag")
			}

			conditionalReq := httptest.NewRequest(http.MethodGet, asset, nil)
			conditionalReq.Header.Set("Accept-Encoding", "gzip")
			conditionalReq.Header.Set("If-None-Match", etag)
			conditional := httptest.NewRecorder()
			h.ServeHTTP(conditional, conditionalReq)
			if conditional.Code != http.StatusNotModified || conditional.Body.Len() != 0 {
				t.Fatalf("conditional response = %d/%d bytes, want 304/0", conditional.Code, conditional.Body.Len())
			}
			if got := conditional.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
				t.Fatalf("gzip 304 Vary = %q, want Accept-Encoding", got)
			}
		})
	}
}

func TestStaticHandlerRejectsNonRetrievalMethods(t *testing.T) {
	s := &Server{ui: fstest.MapFS{
		"index.html": {Data: []byte("<html>hi</html>")},
	}}
	h := s.staticHandler()

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodTrace} {
		t.Run(method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(method, "/", nil))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405", rec.Code)
			}
			if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
				t.Fatalf("Allow = %q, want GET, HEAD", got)
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", got)
			}
			if strings.Contains(rec.Body.String(), "<html") {
				t.Fatal("unsupported method received the SPA document")
			}
		})
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(method, "/", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
		})
	}
}
