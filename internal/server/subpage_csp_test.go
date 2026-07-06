package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/web"
)

// TestSubLandingPage_NoInlineScript: the subscription landing page must carry NO inline <script>
// (the panel's CSP is script-src 'self', which blocks inline — the old per-token injected copy
// handler rendered a dead Copy button). The copy logic lives in the STATIC same-origin
// /subcopy.js, and the URL it copies is read from the visible <code id="u"> element.
func TestSubLandingPage_NoInlineScript(t *testing.T) {
	s, _ := sharehandlers_server(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://192.168.1.1:8088/sub/deadbeefdeadbeefdeadbeef", nil)
	s.serveSubLandingPage(rec, req, nil)
	page := rec.Body.String()

	if strings.Contains(page, "<script>") {
		t.Error("landing page still contains an inline <script> — blocked by CSP script-src 'self'")
	}
	if !strings.Contains(page, `<script src="/subcopy.js" defer>`) {
		t.Error("landing page must reference the static /subcopy.js copy handler")
	}
	if !strings.Contains(page, `id="u"`) {
		t.Error(`landing page must keep <code id="u"> — subcopy.js reads the URL from it`)
	}
	if !strings.Contains(page, "http://192.168.1.1:8088/sub/deadbeefdeadbeefdeadbeef") {
		t.Error("the subscription URL must still be visible in the page body")
	}
}

// TestSubCopyJS_ServedStatic: /subcopy.js is embedded in the web FS and served same-origin by the
// static handler (CSP 'self' allows it), with a JS content type.
func TestSubCopyJS_ServedStatic(t *testing.T) {
	s := &Server{ui: web.FS()}
	rec := httptest.NewRecorder()
	s.staticHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/subcopy.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /subcopy.js = %d, want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), `getElementById("u")`) {
		t.Error("subcopy.js must read the URL from the #u element")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type = %q, want javascript", ct)
	}
}
