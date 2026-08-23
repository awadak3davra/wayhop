package server

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/web"
)

// TestDeferredFeatureRoutesNotMounted prevents the optional Plugins catalog or
// IPTV module from leaking back into the active daemon while their source is
// intentionally preserved for a later product iteration.
// localReq builds a request the Host allow-list accepts, so these assertions measure the ROUTE
// table and not the DNS-rebinding guard that now sits in front of it.
func localReq(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Host = "127.0.0.1:8088"
	return r
}

func TestDeferredFeatureRoutesNotMounted(t *testing.T) {
	_, h := routing_newServer(t)
	for _, path := range []string{
		"/api/features",
		"/api/features/iptv/settings",
		"/api/iptv/catalog",
		"/api/iptv/deadbeefdeadbeef/tv.m3u",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, localReq(http.MethodGet, path))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 while feature is deferred", path, rec.Code)
		}
	}

	// Engine plugins are a separate, load-bearing connection subsystem.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, localReq(http.MethodGet, "/api/plugins"))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /api/plugins = %d, want 200 for active engine plugins", rec.Code)
	}
}

// TestDeferredFeatureAssetsNotEmbedded keeps the inactive pages out of the
// router binary while their exact source remains under deferred/features.
func TestDeferredFeatureAssetsNotEmbedded(t *testing.T) {
	ui := web.FS()
	if _, err := fs.Stat(ui, "iptv-i18n.js"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("iptv-i18n.js must not be embedded while IPTV is deferred; stat err = %v", err)
	}

	checks := map[string][]string{
		"index.html": {`data-page="plugins"`},
		"app.js": {
			"renderPlugins",
			"renderIptv",
			"refreshPluginNav",
			`api.get("/api/features")`,
			`api.get("/api/iptv/`,
		},
	}
	for name, forbidden := range checks {
		body, err := fs.ReadFile(ui, name)
		if err != nil {
			t.Fatalf("read embedded %s: %v", name, err)
		}
		for _, marker := range forbidden {
			if strings.Contains(string(body), marker) {
				t.Errorf("embedded %s still contains deferred marker %q", name, marker)
			}
		}
	}
}
