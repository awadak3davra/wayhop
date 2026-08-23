package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// bigJS is large enough to clear gzipMinBytes and compressible enough to be worth caching.
var bigJS = []byte(strings.Repeat("console.log('wayhop ui bundle');\n", 200))

func testUIFS() fstest.MapFS {
	return fstest.MapFS{
		"app.js":     {Data: bigJS},
		"index.html": {Data: []byte("<!doctype html><html><body>" + strings.Repeat("x", 2000) + "</body></html>")},
		"tiny.js":    {Data: []byte("var a=1;")}, // below gzipMinBytes
		"logo.png":   {Data: bytes.Repeat([]byte{0x89, 0x50, 0x4e, 0x47}, 500)},
	}
}

// The whole point: a gzip-capable client gets a gzipped body, and the SECOND request is served from
// cache rather than re-compressing (which is what cost ~1.15 s per page load on a router CPU).
func TestStaticGzipCache_ServesAndCaches(t *testing.T) {
	c := newStaticGzipCache(testUIFS())

	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	if !c.serve(w, req) {
		t.Fatal("a large compressible asset should be served from the cache")
	}
	if got := w.Header().Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", got)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "javascript") {
		t.Errorf("Content-Type = %q, want a javascript type", w.Header().Get("Content-Type"))
	}
	if w.Header().Get("Vary") == "" {
		t.Error("Vary: Accept-Encoding is required or a shared cache may serve gzip to a client that cannot read it")
	}

	// The body must actually be valid gzip that decodes to the original.
	zr, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		t.Fatalf("body is not valid gzip: %v", err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gzip body did not decode: %v", err)
	}
	if !bytes.Equal(got, bigJS) {
		t.Error("decoded body does not match the source asset")
	}
	if len(w.Body.Bytes()) >= len(bigJS) {
		t.Errorf("compression did not shrink the asset: %d >= %d", len(w.Body.Bytes()), len(bigJS))
	}

	// Second request: identical bytes, served from the cached entry.
	w2 := httptest.NewRecorder()
	if !c.serve(w2, req) {
		t.Fatal("second request should also be served")
	}
	if !bytes.Equal(w.Body.Bytes(), w2.Body.Bytes()) {
		t.Error("cached response differs between requests")
	}
	if len(c.m) == 0 {
		t.Error("nothing was cached")
	}
}

// A client that cannot accept gzip must fall through to normal file serving — never receive a
// gzipped body it cannot decode.
func TestStaticGzipCache_SkipsWithoutAcceptEncoding(t *testing.T) {
	c := newStaticGzipCache(testUIFS())
	req := httptest.NewRequest(http.MethodGet, "/app.js", nil) // no Accept-Encoding
	w := httptest.NewRecorder()
	if c.serve(w, req) {
		t.Error("must not serve gzip to a client that did not ask for it")
	}
}

func TestStaticGzipCache_SkipsSmallAndIncompressible(t *testing.T) {
	c := newStaticGzipCache(testUIFS())
	for _, p := range []string{"/tiny.js", "/logo.png", "/does-not-exist.js"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		if c.serve(httptest.NewRecorder(), req) {
			t.Errorf("%s should fall through to normal serving", p)
		}
	}
	// The negative answers are memoised so repeat requests do not re-read the file each time.
	if len(c.m) == 0 {
		t.Error("negative lookups should be remembered")
	}
}

// "/" maps to index.html, matching http.FileServer.
func TestStaticGzipCache_RootIsIndex(t *testing.T) {
	c := newStaticGzipCache(testUIFS())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	if !c.serve(w, req) {
		t.Fatal("/ should serve index.html from the cache")
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "html") {
		t.Errorf("Content-Type = %q, want html", w.Header().Get("Content-Type"))
	}
}

// A HEAD must carry the headers but no body.
func TestStaticGzipCache_HeadHasNoBody(t *testing.T) {
	c := newStaticGzipCache(testUIFS())
	req := httptest.NewRequest(http.MethodHead, "/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	if !c.serve(w, req) {
		t.Fatal("HEAD should be handled")
	}
	if w.Body.Len() != 0 {
		t.Errorf("HEAD must not write a body, got %d bytes", w.Body.Len())
	}
	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Error("HEAD should still advertise the encoding")
	}
}

// Path traversal must not escape the asset FS.
func TestStaticGzipCache_NoTraversal(t *testing.T) {
	c := newStaticGzipCache(testUIFS())
	req := httptest.NewRequest(http.MethodGet, "/../../etc/passwd", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	if c.serve(httptest.NewRecorder(), req) {
		t.Error("traversal outside the embedded FS must not be served")
	}
}

// The double-compression guard: a response that already declares an encoding must be passed through
// by gzipResponseWriter untouched, or the browser receives a doubly-gzipped body.
func TestGzipResponseWriter_SkipsAlreadyEncoded(t *testing.T) {
	rec := httptest.NewRecorder()
	gw := &gzipResponseWriter{ResponseWriter: rec, gz: gzip.NewWriter(io.Discard)}
	gw.Header().Set("Content-Type", "application/javascript")
	gw.Header().Set("Content-Encoding", "gzip") // already encoded by the static cache
	gw.decide()
	if gw.use != usePlain {
		t.Fatal("an already-encoded response must be passed through, not compressed again")
	}
}
