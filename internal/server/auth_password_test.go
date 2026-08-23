package server

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"wayhop/internal/config"
)

const authNewPassword = "another correct horse battery"

// loginAgain signs in a SECOND time, standing in for the operator's other device: a phone with the
// panel open, or a session left behind on a machine they no longer trust. Changing the password has
// to reach it.
func loginAgain(t *testing.T, handler http.Handler, password string) (*http.Cookie, string) {
	t.Helper()
	body := `{"username":"` + authTestUser + `","password":"` + password + `"}`
	response := authRequest(t, handler, http.MethodPost, "/api/auth/login", body, nil, "", false)
	if response.Code != http.StatusOK {
		t.Fatalf("login = %d: %s", response.Code, response.Body.String())
	}
	csrf, _ := authResponse(t, response)["csrf_token"].(string)
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == authSessionCookie && cookie.Value != "" {
			return cookie, csrf
		}
	}
	t.Fatal("login returned no session cookie")
	return nil, ""
}

func storedAuth(t *testing.T, cfgPath string) config.Auth {
	t.Helper()
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk struct {
		Auth config.Auth `json:"auth"`
	}
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("config is not JSON: %v", err)
	}
	return onDisk.Auth
}

// Changing the password must end every session that was minted under the old one — that is what the
// operator means when they change it because someone else might be in — while leaving the tab they
// are using signed in, under a NEW token (rotating on credential change is the answer to session
// fixation).
func TestAuthPasswordChangeEndsEverySessionAndRotatesTheCallers(t *testing.T) {
	server, handler, cfgPath := authTestServer(t)
	_ = server
	first, firstCSRF := setupAuth(t, handler, false, nil)
	other, _ := loginAgain(t, handler, authTestPassword)

	body := `{"current_password":"` + authTestPassword + `","new_password":"` + authNewPassword + `"}`
	response := authRequest(t, handler, http.MethodPost, "/api/auth/password", body, first, firstCSRF, false)
	if response.Code != http.StatusOK {
		t.Fatalf("password change = %d: %s", response.Code, response.Body.String())
	}
	decoded := authResponse(t, response)
	if decoded["authenticated"] != true || decoded["principal"] != authTestUser {
		t.Fatalf("unexpected body: %v", decoded)
	}
	var rotated *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == authSessionCookie && cookie.Value != "" {
			rotated = cookie
		}
	}
	if rotated == nil {
		t.Fatal("the caller was not given a fresh session")
	}
	if rotated.Value == first.Value {
		t.Fatal("the session token was not rotated")
	}

	// The other device is out.
	if got := authRequest(t, handler, http.MethodGet, "/api/profile", "", other, "", false); got.Code != http.StatusUnauthorized {
		t.Fatalf("the other session survived the password change: %d", got.Code)
	}
	// The old token of the caller is out too.
	if got := authRequest(t, handler, http.MethodGet, "/api/profile", "", first, "", false); got.Code != http.StatusUnauthorized {
		t.Fatalf("the pre-change token still works: %d", got.Code)
	}
	// The rotated one works.
	if got := authRequest(t, handler, http.MethodGet, "/api/profile", "", rotated, "", false); got.Code != http.StatusOK {
		t.Fatalf("the rotated session does not work: %d", got.Code)
	}

	// The credential itself changed, on disk.
	stored := storedAuth(t, cfgPath)
	if stored.Username != authTestUser || stored.PasswordHash == "" {
		t.Fatalf("stored credential looks wrong: %+v", stored)
	}
	if verifyPasswordRecord(authTestPassword, stored.PasswordHash) {
		t.Fatal("the OLD password still verifies against the stored record")
	}
	if !verifyPasswordRecord(authNewPassword, stored.PasswordHash) {
		t.Fatal("the new password does not verify against the stored record")
	}
	// And through the front door.
	old := authRequest(t, handler, http.MethodPost, "/api/auth/login",
		`{"username":"`+authTestUser+`","password":"`+authTestPassword+`"}`, nil, "", false)
	if old.Code != http.StatusUnauthorized {
		t.Fatalf("the old password still logs in: %d", old.Code)
	}
}

// A session is a bearer token. One that leaked must not be a lever for taking the account over, so
// the current password is required — and a wrong answer counts on the same per-IP lockout the login
// uses, or this endpoint becomes an oracle for guessing it from inside a stolen tab.
func TestAuthPasswordChangeRequiresTheCurrentPasswordAndIsRateLimited(t *testing.T) {
	_, handler, cfgPath := authTestServer(t)
	cookie, csrf := setupAuth(t, handler, false, nil)

	body := `{"current_password":"not the password","new_password":"` + authNewPassword + `"}`
	for attempt := 1; attempt <= authMaxFailures; attempt++ {
		response := authRequest(t, handler, http.MethodPost, "/api/auth/password", body, cookie, csrf, false)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401: %s", attempt, response.Code, response.Body.String())
		}
	}
	// The next one is refused before the password is even looked at.
	locked := authRequest(t, handler, http.MethodPost, "/api/auth/password", body, cookie, csrf, false)
	if locked.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d failures the endpoint is not rate limited: %d", authMaxFailures, locked.Code)
	}
	if code, _ := authResponse(t, locked)["code"].(string); code != AuthCodeRateLimited {
		t.Fatalf("unexpected code: %s", code)
	}
	// Nothing was written.
	if !verifyPasswordRecord(authTestPassword, storedAuth(t, cfgPath).PasswordHash) {
		t.Fatal("a failed change altered the stored credential")
	}
}

// The new password faces the same policy as first-run setup. A weaker rule here would mean the only
// way to get a weak password onto the router is to change it, which is the wrong way round.
func TestAuthPasswordChangeEnforcesTheSetupPolicy(t *testing.T) {
	_, handler, cfgPath := authTestServer(t)
	cookie, csrf := setupAuth(t, handler, false, nil)

	for _, weak := range []string{"short", strings.Repeat("x", authPasswordMinBytes-1), "  padded password  "} {
		body := `{"current_password":"` + authTestPassword + `","new_password":"` + weak + `"}`
		response := authRequest(t, handler, http.MethodPost, "/api/auth/password", body, cookie, csrf, false)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("password %q was accepted (%d)", weak, response.Code)
		}
	}
	if !verifyPasswordRecord(authTestPassword, storedAuth(t, cfgPath).PasswordHash) {
		t.Fatal("a rejected change altered the stored credential")
	}
}

// Declining a password is a DECISION and is recorded as one: the panel then serves without a login,
// which is exactly what the operator asked for, and says so through /api/auth/status.
func TestAuthSetupSkipRunsThePanelWithoutAPassword(t *testing.T) {
	_, handler, cfgPath := authTestServer(t)

	response := authRequest(t, handler, http.MethodPost, "/api/auth/setup", `{"skip":true}`, nil, "", false)
	if response.Code != http.StatusCreated {
		t.Fatalf("skip = %d: %s", response.Code, response.Body.String())
	}
	decoded := authResponse(t, response)
	if decoded["passwordless"] != true || decoded["configured"] != false {
		t.Fatalf("unexpected body: %v", decoded)
	}

	status := authResponse(t, authRequest(t, handler, http.MethodGet, "/api/auth/status", "", nil, "", false))
	if status["passwordless"] != true || status["authenticated"] != true || status["configured"] != false {
		t.Fatalf("status does not report the passwordless state: %v", status)
	}

	// A protected route serves with no cookie at all.
	if got := authRequest(t, handler, http.MethodGet, "/api/profile", "", nil, "", false); got.Code != http.StatusOK {
		t.Fatalf("protected route = %d with no password configured", got.Code)
	}
	// And the decision survives a restart, because it is on disk.
	if stored := storedAuth(t, cfgPath); !stored.Disabled || stored.PasswordHash != "" {
		t.Fatalf("the decision was not persisted: %+v", stored)
	}
}

// Skipping is only reachable while no password exists. Setup already refuses once one does, so an
// unauthenticated request can never turn authentication OFF on a panel that has it.
func TestAuthSkipCannotDisableAConfiguredPanel(t *testing.T) {
	_, handler, cfgPath := authTestServer(t)
	setupAuth(t, handler, false, nil)

	response := authRequest(t, handler, http.MethodPost, "/api/auth/setup", `{"skip":true}`, nil, "", false)
	if response.Code != http.StatusForbidden {
		t.Fatalf("skip on a configured panel = %d, want 403: %s", response.Code, response.Body.String())
	}
	if code, _ := authResponse(t, response)["code"].(string); code != AuthCodeAlreadyConfigured {
		t.Fatalf("unexpected code: %s", code)
	}
	if !verifyPasswordRecord(authTestPassword, storedAuth(t, cfgPath).PasswordHash) {
		t.Fatal("a refused skip altered the stored credential")
	}
	// Still gated.
	if got := authRequest(t, handler, http.MethodGet, "/api/profile", "", nil, "", false); got.Code != http.StatusUnauthorized {
		t.Fatalf("protected route = %d, want 401", got.Code)
	}
}

// A stored password always wins over the flag. Otherwise a hand-edited config — or a flag left over
// from before a password was set — would silently open a panel that has one.
func TestStalePasswordlessFlagCannotOpenAConfiguredPanel(t *testing.T) {
	server, handler, _ := authTestServer(t)
	setupAuth(t, handler, false, nil)

	server.cfgMu.Lock()
	auth := server.cfg.Auth
	auth.Disabled = true
	server.cfg.Auth = auth
	server.cfgMu.Unlock()

	if server.auth.passwordless() {
		t.Fatal("a configured panel reported itself as passwordless")
	}
	if got := authRequest(t, handler, http.MethodGet, "/api/profile", "", nil, "", false); got.Code != http.StatusUnauthorized {
		t.Fatalf("protected route = %d with a password configured, want 401", got.Code)
	}
}
