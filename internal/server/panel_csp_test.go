package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/web"
)

// The panel uses a strict script-src 'self' policy. Any executable inline
// bootstrap would be blocked in production even though direct file previews
// and syntax checks appear healthy.
func TestPanelLanguageBootstrapRespectsCSP(t *testing.T) {
	s := &Server{ui: web.FS()}
	h := securityHeaders(s.staticHandler())

	indexRec := httptest.NewRecorder()
	h.ServeHTTP(indexRec, httptest.NewRequest(http.MethodGet, "/", nil))
	if indexRec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", indexRec.Code)
	}
	page := indexRec.Body.String()
	if strings.Contains(page, "<script>") {
		t.Fatal("index.html contains an inline script blocked by script-src 'self'")
	}
	if !strings.Contains(page, `<script src="i18n-loader.js"></script>`) {
		t.Fatal("index.html must load the same-origin language bootstrap")
	}

	loaderRec := httptest.NewRecorder()
	h.ServeHTTP(loaderRec, httptest.NewRequest(http.MethodGet, "/i18n-loader.js", nil))
	if loaderRec.Code != http.StatusOK {
		t.Fatalf("GET /i18n-loader.js = %d, want 200", loaderRec.Code)
	}
	body, err := io.ReadAll(loaderRec.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `localStorage.getItem("wr-lang")`) {
		t.Fatal("i18n-loader.js does not contain the language selection bootstrap")
	}
	if ct := loaderRec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Fatalf("Content-Type = %q, want javascript", ct)
	}
}
