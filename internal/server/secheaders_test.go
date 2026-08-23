package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSecurityHeaders pins the defensive response headers. The clickjacking
// defenses (X-Frame-Options + CSP frame-ancestors) are the load-bearing ones —
// the same-origin/CSRF guard does NOT stop a same-origin click inside a framed
// panel, so a regression that drops these re-opens the one-click Apply/Rollback
// controls to frame-and-trick attacks.
func TestSecurityHeaders(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "http://192.168.2.1:8088/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	want := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}

	csp := rec.Header().Get("Content-Security-Policy")
	for _, must := range []string{"script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "object-src 'none'"} {
		if !strings.Contains(csp, must) {
			t.Errorf("CSP %q missing %q", csp, must)
		}
	}
	// The CSP must NOT add style-src/default-src: the UI uses inline style
	// attributes, so a style policy would need 'unsafe-inline' and an over-broad
	// default-src could silently break styles/images/fetches. Keeping them unset
	// is the deliberate low-risk design (only scripts are restricted) — guard it.
	for _, mustNot := range []string{"style-src", "default-src"} {
		if strings.Contains(csp, mustNot) {
			t.Errorf("CSP %q unexpectedly contains %q — risks breaking the inline-style UI", csp, mustNot)
		}
	}
}

// TestSecurityHeadersOnError confirms the headers are present even on a
// non-2xx reply (defense must apply to every response, not just successes).
func TestSecurityHeadersOnError(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://192.168.2.1:8088/api/apply", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("X-Frame-Options missing on a 403 response")
	}
}
