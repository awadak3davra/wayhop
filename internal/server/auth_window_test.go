package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// authRequestFrom is authRequest with a chosen peer address, for the decisions that depend on who is
// asking: the setup window's loopback exception and the per-source login buckets.
func authRequestFrom(t *testing.T, handler http.Handler, remote, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Host = "localhost"
	request.RemoteAddr = remote
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

// pinAuthClock fixes the auth clock and puts the daemon start `elapsed` before it.
func pinAuthClock(s *Server, elapsed time.Duration) *time.Time {
	now := time.Unix(1_700_000_000, 0)
	s.auth.started = now.Add(-elapsed)
	s.auth.now = func() time.Time { return now }
	return &now
}

var authSetupBody = `{"username":"` + authTestUser + `","password":"` + authTestPassword + `"}`

// SEC-01: an unconfigured router used to accept setup, including "run without a password", from any
// LAN host for as long as nobody had answered. Past the window both answers are refused, the panel is
// told why, and nothing is written.
func TestAuthSetupWindowClosesThirtyMinutesAfterStart(t *testing.T) {
	s, handler, cfgPath := authTestServer(t)
	pinAuthClock(s, authSetupWindow+time.Minute)

	status := authResponse(t, authRequest(t, handler, http.MethodGet, "/api/auth/status", "", nil, "", false))
	if status["setup_window_open"] != false || status["configured"] != false {
		t.Fatalf("status after the window = %v", status)
	}
	for _, body := range []string{authSetupBody, `{"skip":true}`} {
		response := authRequest(t, handler, http.MethodPost, "/api/auth/setup", body, nil, "", false)
		if response.Code != http.StatusForbidden || authResponse(t, response)["code"] != AuthCodeSetupWindowClosed {
			t.Fatalf("setup %s after the window = %d %s", body, response.Code, response.Body.String())
		}
	}
	if stored := storedAuth(t, cfgPath); stored.Disabled || stored.PasswordHash != "" || stored.Username != "" {
		t.Fatalf("a refused setup wrote the credential: %+v", stored)
	}
	if got := authRequest(t, handler, http.MethodGet, "/api/profile", "", nil, "", false); got.Code != http.StatusForbidden {
		t.Fatalf("protected route after a refused skip = %d, want 403", got.Code)
	}
}

func TestAuthSetupWindowIsOpenRightAfterStart(t *testing.T) {
	s, handler, _ := authTestServer(t)
	pinAuthClock(s, authSetupWindow-time.Minute)
	status := authResponse(t, authRequest(t, handler, http.MethodGet, "/api/auth/status", "", nil, "", false))
	if status["setup_window_open"] != true {
		t.Fatalf("status inside the window = %v", status)
	}
	setupAuth(t, handler, false, nil)
}

// A loopback peer is an SSH tunnel to the router: it proves access, so the window does not apply.
func TestAuthSetupFromLoopbackPeerIgnoresTheWindow(t *testing.T) {
	s, handler, _ := authTestServer(t)
	s.cfgMu.Lock()
	s.cfg.Demo = false // the loopback demo bypass must not be what lets this through
	s.cfgMu.Unlock()
	pinAuthClock(s, 24*time.Hour)
	for _, peer := range []string{"127.0.0.1:50000", "[::1]:50000"} {
		status := authResponse(t, authRequestFrom(t, handler, peer, http.MethodGet, "/api/auth/status", ""))
		if status["setup_window_open"] != true || status["bypass"] != nil {
			t.Fatalf("status from %s = %v", peer, status)
		}
	}
	response := authRequestFrom(t, handler, "127.0.0.1:50000", http.MethodPost, "/api/auth/setup", authSetupBody)
	if response.Code != http.StatusCreated {
		t.Fatalf("setup from loopback after the window = %d %s", response.Code, response.Body.String())
	}
}

// Once "no password" is on record the question is answered: saying it again is refused, and leaving
// passwordless mode is decided like a protected route, so Settings → Account (setPasswordForm, which
// posts the credential with no cookie and no CSRF token) still works long after the window closed.
func TestAuthPasswordlessSetupIsAProtectedActionNotAWindowOne(t *testing.T) {
	s, handler, cfgPath := authTestServer(t)
	now := pinAuthClock(s, 0)
	if skip := authRequest(t, handler, http.MethodPost, "/api/auth/setup", `{"skip":true}`, nil, "", false); skip.Code != http.StatusCreated {
		t.Fatalf("skip inside the window = %d %s", skip.Code, skip.Body.String())
	}
	*now = now.Add(48 * time.Hour)

	again := authRequest(t, handler, http.MethodPost, "/api/auth/setup", `{"skip":true}`, nil, "", false)
	if again.Code != http.StatusForbidden || authResponse(t, again)["code"] != AuthCodeAlreadyConfigured {
		t.Fatalf("second skip = %d %s", again.Code, again.Body.String())
	}
	status := authResponse(t, authRequest(t, handler, http.MethodGet, "/api/auth/status", "", nil, "", false))
	if _, present := status["setup_window_open"]; present || status["passwordless"] != true {
		t.Fatalf("passwordless status = %v", status)
	}

	set := authRequest(t, handler, http.MethodPost, "/api/auth/setup", authSetupBody, nil, "", false)
	if set.Code != http.StatusCreated {
		t.Fatalf("setting a password from passwordless mode after the window = %d %s", set.Code, set.Body.String())
	}
	if csrf, _ := authResponse(t, set)["csrf_token"].(string); csrf == "" || len(set.Result().Cookies()) != 1 {
		t.Fatalf("no session issued: %s", set.Body.String())
	}
	if stored := storedAuth(t, cfgPath); stored.Username != authTestUser || !verifyPasswordRecord(authTestPassword, stored.PasswordHash) {
		t.Fatalf("credential not stored: %+v", stored)
	}
	if got := authRequest(t, handler, http.MethodGet, "/api/profile", "", nil, "", false); got.Code != http.StatusUnauthorized {
		t.Fatalf("protected route after setting a password = %d, want 401", got.Code)
	}
}

// SEC-05: a host that owns an IPv6 /64 must not reset its lockout by changing address.
func TestAuthLockoutKeysIPv6SourcesByPrefix(t *testing.T) {
	s, handler, _ := authTestServer(t)
	pinAuthClock(s, 0)
	setupAuth(t, handler, false, nil)
	bad := `{"username":"` + authTestUser + `","password":"definitely-wrong"}`
	for attempt := 1; attempt <= authMaxFailures; attempt++ {
		peer := fmt.Sprintf("[2001:db8:1:2::%x]:4242", attempt)
		if got := authRequestFrom(t, handler, peer, http.MethodPost, "/api/auth/login", bad); got.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d %s", attempt, got.Code, got.Body.String())
		}
	}
	locked := authRequestFrom(t, handler, "[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:4242", http.MethodPost, "/api/auth/login", bad)
	if locked.Code != http.StatusTooManyRequests {
		t.Fatalf("a fresh address in the same /64 = %d, want 429", locked.Code)
	}
	other := authRequestFrom(t, handler, "[2001:db8:1:3::1]:4242", http.MethodPost, "/api/auth/login", bad)
	if other.Code != http.StatusUnauthorized {
		t.Fatalf("another /64 = %d, want 401", other.Code)
	}
}

// SEC-05: past the global budget every attempt waits first, whichever address it comes from, and the
// operator's correct password still gets in.
func TestAuthGlobalFailureBudgetSlowsEveryAttempt(t *testing.T) {
	s, handler, _ := authTestServer(t)
	now := pinAuthClock(s, 0)
	var waits []time.Duration
	s.auth.pause = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	setupAuth(t, handler, false, nil)
	bad := `{"username":"` + authTestUser + `","password":"definitely-wrong"}`
	for i := 1; i <= authGlobalMaxFailures; i++ {
		peer := fmt.Sprintf("198.51.100.%d:4242", i)
		if got := authRequestFrom(t, handler, peer, http.MethodPost, "/api/auth/login", bad); got.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d = %d %s", i, got.Code, got.Body.String())
		}
	}
	if len(waits) != 0 {
		t.Fatalf("waited before the budget was spent: %v", waits)
	}
	good := authRequestFrom(t, handler, "198.51.100.200:4242", http.MethodPost, "/api/auth/login", authSetupBody)
	if good.Code != http.StatusOK {
		t.Fatalf("operator login past the budget = %d %s", good.Code, good.Body.String())
	}
	if len(waits) != 1 || waits[0] != authGlobalDelay {
		t.Fatalf("waits past the budget = %v, want one of %s", waits, authGlobalDelay)
	}
	*now = now.Add(authFailureWindow + time.Second)
	authRequestFrom(t, handler, "198.51.100.201:4242", http.MethodPost, "/api/auth/login", bad)
	if len(waits) != 1 {
		t.Fatalf("still waiting after the window: %v", waits)
	}
}

// SEC-05: sources whose window and lockout have run out are forgotten.
func TestAuthFailureEntriesArePruned(t *testing.T) {
	manager := newAuthManager(nil)
	now := time.Unix(1_700_000_000, 0)
	manager.now = func() time.Time { return now }
	manager.recordLogin("192.0.2.1", false)
	manager.recordLogin("2001:db8::1", false)
	now = now.Add(authFailureWindow + time.Second)
	manager.recordLogin("192.0.2.2", false)
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.failures) != 1 {
		t.Fatalf("failures after the window = %v, want only the new source", manager.failures)
	}
	if _, ok := manager.failures["192.0.2.2"]; !ok {
		t.Fatalf("the new source is missing: %v", manager.failures)
	}
}
