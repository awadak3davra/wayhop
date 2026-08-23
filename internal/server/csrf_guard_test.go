package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSameOriginGuard pins the CSRF guard's contract: state-changing requests
// (POST/PUT/PATCH/DELETE) carrying a cross-origin Origin/Referer are rejected
// with 403, while same-origin requests, header-less requests (curl/scripts), and
// all safe methods pass through. A regression here re-opens the router admin
// panel to drive-by CSRF from any LAN browser.
func TestSameOriginGuard(t *testing.T) {
	const host = "192.168.2.1:8088"

	var reached bool
	guarded := sameOriginGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	type hdr struct{ k, v string }
	cases := []struct {
		name       string
		method     string
		headers    []hdr
		wantStatus int
		wantReach  bool
	}{
		// --- mutating methods ---
		{"same-origin POST allowed", "POST", []hdr{{"Origin", "http://192.168.2.1:8088"}}, http.StatusOK, true},
		{"same-origin POST via referer allowed", "POST", []hdr{{"Referer", "http://192.168.2.1:8088/"}}, http.StatusOK, true},
		{"no headers (curl/script) allowed", "POST", nil, http.StatusOK, true},
		{"cross-origin Origin blocked", "POST", []hdr{{"Origin", "https://evil.example.com"}}, http.StatusForbidden, false},
		{"cross-origin host:port mismatch blocked", "POST", []hdr{{"Origin", "http://192.168.2.1:9090"}}, http.StatusForbidden, false},
		{"cross-origin via referer blocked", "POST", []hdr{{"Referer", "http://evil.example.com/x"}}, http.StatusForbidden, false},
		{"origin wins over matching referer (blocked)", "POST", []hdr{{"Origin", "http://evil.example.com"}, {"Referer", "http://192.168.2.1:8088/"}}, http.StatusForbidden, false},
		{"malformed origin fails closed", "POST", []hdr{{"Origin", "::not a url::"}}, http.StatusForbidden, false},
		{"PUT cross-origin blocked", "PUT", []hdr{{"Origin", "http://attacker"}}, http.StatusForbidden, false},
		{"DELETE cross-origin blocked", "DELETE", []hdr{{"Origin", "http://attacker"}}, http.StatusForbidden, false},
		{"PUT same-origin allowed", "PUT", []hdr{{"Origin", "http://192.168.2.1:8088"}}, http.StatusOK, true},
		// --- safe methods are never guarded, even cross-origin ---
		{"GET cross-origin allowed", "GET", []hdr{{"Origin", "http://evil.example.com"}}, http.StatusOK, true},
		{"HEAD cross-origin allowed", "HEAD", []hdr{{"Origin", "http://evil.example.com"}}, http.StatusOK, true},
		{"OPTIONS cross-origin allowed", "OPTIONS", []hdr{{"Origin", "http://evil.example.com"}}, http.StatusOK, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reached = false
			req := httptest.NewRequest(c.method, "http://"+host+"/api/apply", nil)
			req.Host = host
			for _, h := range c.headers {
				req.Header.Set(h.k, h.v)
			}
			rec := httptest.NewRecorder()
			guarded.ServeHTTP(rec, req)

			if rec.Code != c.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, c.wantStatus)
			}
			if reached != c.wantReach {
				t.Errorf("handler reached = %v, want %v", reached, c.wantReach)
			}
			if !c.wantReach && c.wantStatus == http.StatusForbidden {
				if got := rec.Header().Get("Cache-Control"); got != "no-store" {
					t.Errorf("Cache-Control = %q, want no-store on refusal", got)
				}
			}
		})
	}
}

// TestOriginMatchesHost checks the authority comparison directly, including the
// fail-closed branch for unparseable input.
func TestOriginMatchesHost(t *testing.T) {
	cases := []struct {
		origin, host string
		want         bool
	}{
		{"http://192.168.2.1:8088", "192.168.2.1:8088", true},
		{"https://192.168.2.1:8088", "192.168.2.1:8088", true}, // scheme ignored, host:port matches
		{"http://192.168.2.1:8088/some/path", "192.168.2.1:8088", true},
		{"http://192.168.2.1:9090", "192.168.2.1:8088", false},
		{"http://evil.example.com", "192.168.2.1:8088", false},
		{"http://router.lan:8088", "router.lan:8088", true},
		{"", "192.168.2.1:8088", false},          // empty fails closed
		{"not-a-url", "192.168.2.1:8088", false}, // no host fails closed
	}
	for _, c := range cases {
		if got := originMatchesHost(c.origin, c.host); got != c.want {
			t.Errorf("originMatchesHost(%q, %q) = %v, want %v", c.origin, c.host, got, c.want)
		}
	}
}
