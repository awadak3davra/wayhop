package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandlerChain_SecurityMiddlewareWired is an integration guard for the middleware
// CHAIN composed in server.go Handler(). The per-middleware unit tests (csrf_guard,
// secheaders, limitbody, hostallow) all keep passing even if a middleware is dropped
// from the Handler() chain by a refactor — which would silently disable that defense
// in production. This drives the real composed handler (via httptest) and asserts the
// always-on security middleware are actually in the path. (hostAllowGuard is a no-op
// under the default empty allow-list, so it's covered by its own unit test instead.)
func TestHandlerChain_SecurityMiddlewareWired(t *testing.T) {
	_, h := routing_newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	client := ts.Client()

	// securityHeaders: every reply must carry the defensive headers + strict CSP.
	resp, err := client.Get(ts.URL + "/api/health")
	if err != nil {
		t.Fatalf("GET /api/health: %v", err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("securityHeaders not wired into Handler(): X-Frame-Options = %q, want DENY", got)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("securityHeaders not wired into Handler(): CSP = %q, want it to contain script-src 'self'", csp)
	}

	// sameOriginGuard: a cross-origin mutating request must be rejected (403).
	xreq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/generate", strings.NewReader("{}"))
	xreq.Header.Set("Origin", "http://evil.example.com")
	xreq.Header.Set("Content-Type", "text/plain")
	xr, err := client.Do(xreq)
	if err != nil {
		t.Fatalf("cross-origin POST: %v", err)
	}
	xr.Body.Close()
	if xr.StatusCode != http.StatusForbidden {
		t.Errorf("sameOriginGuard not wired into Handler(): cross-origin POST = %d, want 403", xr.StatusCode)
	}
	if got := xr.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("sameOriginGuard refusal Cache-Control = %q, want no-store", got)
	}

	// ...and a same-origin mutating request must NOT be blocked by the guard
	// (any non-403 proves it reached past the guard to the handler).
	sreq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/generate", strings.NewReader("{}"))
	sreq.Header.Set("Origin", ts.URL) // the httptest server's own origin
	sreq.Header.Set("Content-Type", "application/json")
	sr, err := client.Do(sreq)
	if err != nil {
		t.Fatalf("same-origin POST: %v", err)
	}
	sr.Body.Close()
	if sr.StatusCode == http.StatusForbidden {
		t.Error("sameOriginGuard wrongly blocked a same-origin POST through Handler() (got 403)")
	}
}

func TestHandlerChain_HostRejectionStillCarriesSecurityPolicy(t *testing.T) {
	_, h := routing_newServer(t)
	req := httptest.NewRequest(http.MethodGet, "http://evil.example/api/health", nil)
	req.Host = "evil.example"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q, want DENY", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q, want no-referrer", got)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("Content-Security-Policy = %q, want frame-ancestors", csp)
	}
	if got := rec.Body.String(); got != "host not allowed\n" {
		t.Fatalf("body = %q, want fixed non-reflecting error", got)
	}
}
