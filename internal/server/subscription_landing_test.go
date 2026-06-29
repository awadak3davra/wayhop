package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// These tests reuse sharehandlers_server / sharehandlers_vless from share_test.go
// (same package) and exercise the additive HTML subscription landing page. The
// hard requirement is ADDITIVE behavior: every existing client path must stay
// unchanged, so the regression guards below assert that VPN clients still get
// their machine config and never the HTML page.

// browserHeaders sets the Accept + User-Agent a real browser sends so wantsHTML
// matches. Anything that doesn't look like Mozilla + text/html must NOT match.
func subland_browserReq(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/sub/"+token, nil)
	req.SetPathValue("token", token)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	return req
}

// TestSubLanding_BrowserGetsHTMLPage: a browser request returns the on-brand HTML
// install page (200, text/html), shows the subscription URL, and — critically —
// leaks no per-endpoint secrets (no vless:// share link in the body).
func TestSubLanding_BrowserGetsHTMLPage(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertEndpoint(sharehandlers_vless("v1", "Reality")); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	tok := s.subToken()

	req := subland_browserReq(tok)
	w := httptest.NewRecorder()
	s.handleSubServe(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("browser request: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Velinx subscription") {
		t.Errorf("page is missing the heading: %q", body)
	}
	// The (token-gated) subscription URL must be shown for the QR / copy helpers.
	if !strings.Contains(body, "/api/sub/"+tok) {
		t.Errorf("page does not contain the subscription URL path")
	}
	// SECURITY: the per-endpoint share link / UUID must never appear in the page.
	if strings.Contains(body, "vless://") {
		t.Errorf("share-link scheme leaked into the HTML page: %q", body)
	}
	if strings.Contains(body, "11111111-2222-3333-4444-555555555555") {
		t.Errorf("endpoint UUID leaked into the HTML page")
	}
}

// TestSubLanding_VPNClientUnaffected: a v2ray-family client (non-browser UA,
// Accept: */*) still gets the base64 share-link blob, NOT the HTML page. This is
// the core regression guard that existing clients are untouched.
func TestSubLanding_VPNClientUnaffected(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertEndpoint(sharehandlers_vless("v1", "Reality")); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	tok := s.subToken()

	req := httptest.NewRequest(http.MethodGet, "/api/sub/"+tok, nil)
	req.SetPathValue("token", tok)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "v2rayN/6.42")
	w := httptest.NewRecorder()
	s.handleSubServe(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("v2ray client: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain (client must get the blob, not HTML)", ct)
	}
	if strings.Contains(w.Body.String(), "Velinx subscription") {
		t.Errorf("client wrongly received the HTML landing page")
	}
}

// TestSubLanding_ExplicitFlagWinsOverBrowser: a browser request carrying an
// explicit ?flag=clash gets clash YAML, not HTML — an explicit client-format
// request always means "give me a config".
func TestSubLanding_ExplicitFlagWinsOverBrowser(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertEndpoint(sharehandlers_vless("v1", "Reality")); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	tok := s.subToken()

	req := httptest.NewRequest(http.MethodGet, "/api/sub/"+tok+"?flag=clash", nil)
	req.SetPathValue("token", tok)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0)")
	w := httptest.NewRecorder()
	s.handleSubServe(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("flag=clash browser: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/yaml") {
		t.Fatalf("Content-Type = %q, want text/yaml (explicit flag must win)", ct)
	}
	if strings.Contains(w.Body.String(), "Velinx subscription") {
		t.Errorf("flag=clash browser wrongly received the HTML landing page")
	}
}

// TestSubLanding_WebQueryForcesHTML: an explicit ?web=1 forces the HTML page even
// for a non-browser UA (deliberate "view in browser").
func TestSubLanding_WebQueryForcesHTML(t *testing.T) {
	s, _ := sharehandlers_server(t)
	tok := s.subToken()

	req := httptest.NewRequest(http.MethodGet, "/api/sub/"+tok+"?web=1", nil)
	req.SetPathValue("token", tok)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "curl/8.0")
	w := httptest.NewRecorder()
	s.handleSubServe(w, req)

	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("?web=1: Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(w.Body.String(), "Velinx subscription") {
		t.Errorf("?web=1 did not render the HTML page")
	}
}

// TestSubLanding_InvalidTokenStill403: the token gate still rejects a wrong token
// before any content-negotiation, even for a browser request.
func TestSubLanding_InvalidTokenStill403(t *testing.T) {
	s, _ := sharehandlers_server(t)
	_ = s.subToken()

	req := subland_browserReq("not-the-token")
	w := httptest.NewRecorder()
	s.handleSubServe(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("invalid token: got %d, want 403", w.Code)
	}
	if strings.Contains(w.Body.String(), "Velinx subscription") {
		t.Errorf("forbidden response wrongly rendered the HTML page")
	}
}

// TestWantsHTML_UnitMatrix locks down the wantsHTML decision table directly so a
// future tweak can't silently start matching a VPN client.
func TestWantsHTML_UnitMatrix(t *testing.T) {
	cases := []struct {
		name   string
		target string
		accept string
		ua     string
		want   bool
	}{
		{"browser", "/api/sub/t", "text/html,*/*", "Mozilla/5.0", true},
		{"web=1 non-browser", "/api/sub/t?web=1", "*/*", "curl/8", true},
		{"web=true non-browser", "/api/sub/t?web=true", "*/*", "curl/8", true},
		{"flag set, browser", "/api/sub/t?flag=clash", "text/html", "Mozilla/5.0", false},
		{"format set, browser", "/api/sub/t?format=clash", "text/html", "Mozilla/5.0", false},
		{"v2ray client", "/api/sub/t", "*/*", "v2rayN/6.42", false},
		{"sing-box client", "/api/sub/t", "*/*", "sing-box", false},
		{"clash client", "/api/sub/t", "*/*", "clash-verge/1", false},
		{"no headers", "/api/sub/t", "", "", false},
		{"html accept but no mozilla UA", "/api/sub/t", "text/html", "Hiddify/1.0", false},
		{"mozilla UA but no html accept", "/api/sub/t", "*/*", "Mozilla/5.0", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, c.target, nil)
			if c.accept != "" {
				req.Header.Set("Accept", c.accept)
			}
			if c.ua != "" {
				req.Header.Set("User-Agent", c.ua)
			}
			if got := wantsHTML(req); got != c.want {
				t.Errorf("wantsHTML(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}
