package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/web"
)

// The panel provokes /favicon.ico on every cold load, so a 404 there is not a browser quirk to
// except in the gates — it is the panel failing to answer its own request. These tests are the
// precondition for removing that exception: the exception may only go once the route is proven.
//
// Driven through staticHandler directly rather than Handler(): the mux registers it as the catch-all
// at "/", so for a path with no API route these are the same handler, and building a whole Server
// would test the route table rather than the icon.

func faviconGet(t *testing.T, s *Server, path, ifNoneMatch string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Host = "127.0.0.1:8088"
	if ifNoneMatch != "" {
		r.Header.Set("If-None-Match", ifNoneMatch)
	}
	w := httptest.NewRecorder()
	s.staticHandler().ServeHTTP(w, r)
	return w
}

func TestFavicon_BothPathsAreServed(t *testing.T) {
	s := &Server{ui: web.FS()}
	for _, path := range []string{"/favicon.svg", "/favicon.ico"} {
		t.Run(path, func(t *testing.T) {
			w := faviconGet(t, s, path, "")
			if w.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200", path, w.Code)
			}
			if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "image/svg+xml") {
				t.Errorf("Content-Type = %q, want image/svg+xml", ct)
			}
			if !strings.Contains(w.Body.String(), "<svg") {
				t.Errorf("body is not the icon: %.60q", w.Body.String())
			}
			if w.Header().Get("ETag") == "" {
				t.Error("no ETag, so every cold load re-sends the icon")
			}
			if cc := w.Header().Get("Cache-Control"); cc == "" {
				t.Error("no Cache-Control")
			}
		})
	}
}

// The .ico alias must be the same asset, not a second copy that can drift.
func TestFavicon_IcoIsTheSameAssetAsSvg(t *testing.T) {
	s := &Server{ui: web.FS()}
	ico := faviconGet(t, s, "/favicon.ico", "")
	svg := faviconGet(t, s, "/favicon.svg", "")
	if ico.Body.String() != svg.Body.String() {
		t.Error("/favicon.ico and /favicon.svg returned different bytes")
	}
	if ico.Header().Get("ETag") != svg.Header().Get("ETag") {
		t.Error("the two paths carry different ETags, so a browser caches the icon twice")
	}
}

// A revalidating browser must get a 304, or the icon is re-sent on every navigation.
func TestFavicon_RevalidatesTo304(t *testing.T) {
	s := &Server{ui: web.FS()}
	etag := faviconGet(t, s, "/favicon.ico", "").Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag to revalidate with")
	}
	if w := faviconGet(t, s, "/favicon.ico", etag); w.Code != http.StatusNotModified {
		t.Errorf("revalidation returned %d, want 304", w.Code)
	}
}

// The rewrite must not turn every unknown path into the icon: a missing asset still has to 404, or
// a typo'd chunk name would silently render a picture instead of failing.
func TestFavicon_RewriteIsExactlyOnePath(t *testing.T) {
	s := &Server{ui: web.FS()}
	for _, path := range []string{"/favicon.png", "/favicon.ico.map", "/nope.ico"} {
		if w := faviconGet(t, s, path, ""); w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 — the rewrite is too broad", path, w.Code)
		}
	}
}
