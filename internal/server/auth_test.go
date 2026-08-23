package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"wayhop/internal/clash"
	"wayhop/internal/config"
	"wayhop/internal/core"
	"wayhop/internal/health"
	"wayhop/internal/serverstore"
	"wayhop/internal/store"
	"wayhop/internal/traffic"
	"wayhop/web"
)

const (
	authTestUser     = "operator"
	authTestPassword = "correct horse battery staple"
)

func authTestServer(t *testing.T) (*Server, http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Demo = true
	cfg.SingBox.Bin = filepath.Join(dir, "missing-sing-box")
	cfg.SingBox.Config = filepath.Join(dir, "singbox.json")
	hub := traffic.NewHub(10)
	cl, err := clash.New(cfg.Clash.Controller, cfg.Clash.Secret)
	if err != nil {
		t.Fatal(err)
	}
	sb := core.New(cfg.SingBox.Bin, cfg.SingBox.Config)
	profile, err := store.Open(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	servers, err := serverstore.Open(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	monitor := health.NewMonitor(cl, profile, sb, true)
	s := New(cfg, hub, cl, sb, profile, monitor, servers, web.FS())
	return s, s.Handler(), cfgPath
}

func authRequest(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	body string,
	cookie *http.Cookie,
	csrf string,
	tlsEnabled bool,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Host = "localhost"
	request.RemoteAddr = "192.0.2.10:4242"
	if tlsEnabled {
		request.TLS = &tls.ConnectionState{}
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if csrf != "" {
		request.Header.Set(authCSRFHeader, csrf)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func authResponse(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("response %d is not JSON: %v: %s", response.Code, err, response.Body.String())
	}
	return decoded
}

func setupAuth(t *testing.T, handler http.Handler, tlsEnabled bool, fixation *http.Cookie) (*http.Cookie, string) {
	t.Helper()
	body := `{"username":"` + authTestUser + `","password":"` + authTestPassword + `"}`
	response := authRequest(t, handler, http.MethodPost, "/api/auth/setup", body, fixation, "", tlsEnabled)
	if response.Code != http.StatusCreated {
		t.Fatalf("setup = %d: %s", response.Code, response.Body.String())
	}
	decoded := authResponse(t, response)
	csrf, _ := decoded["csrf_token"].(string)
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != authSessionCookie || csrf == "" {
		t.Fatalf("setup session = cookies:%+v body:%v", cookies, decoded)
	}
	return cookies[0], csrf
}

func TestAuthFirstRunBlocksAuthorityAndPersistsOnlyArgon2Record(t *testing.T) {
	s, handler, cfgPath := authTestServer(t)
	blocked := authRequest(t, handler, http.MethodPost, "/api/generate", `{}`, nil, "", false)
	if blocked.Code != http.StatusForbidden || authResponse(t, blocked)["code"] != AuthCodeSetupRequired {
		t.Fatalf("first-run protected route = %d %s", blocked.Code, blocked.Body.String())
	}
	status := authRequest(t, handler, http.MethodGet, "/api/auth/status", "", nil, "", false)
	if got := authResponse(t, status); got["configured"] != false || got["authenticated"] != false {
		t.Fatalf("first-run status = %v", got)
	}
	cookie, _ := setupAuth(t, handler, false, nil)
	stored := s.config().Auth
	if stored.Username != authTestUser || !strings.HasPrefix(stored.PasswordHash, "$argon2id$") ||
		strings.Contains(stored.PasswordHash, authTestPassword) ||
		!verifyPasswordRecord(authTestPassword, stored.PasswordHash) {
		t.Fatalf("stored credential is not a valid password-only record: %+v", stored)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(authTestPassword)) || !bytes.Contains(data, []byte("$argon2id$")) {
		t.Fatalf("credential file contains plaintext or no KDF record: %s", data)
	}
	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// Windows exposes synthetic FileMode bits; the router file-permission contract is Unix.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v", info.Mode().Perm())
	}
	getConfig := authRequest(t, handler, http.MethodGet, "/api/config", "", cookie, "", false)
	if getConfig.Code != http.StatusOK || !strings.Contains(getConfig.Body.String(), `"password_hash":"***"`) ||
		strings.Contains(getConfig.Body.String(), stored.PasswordHash) {
		t.Fatalf("config API exposed credential record: %d %s", getConfig.Code, getConfig.Body.String())
	}
	bundle, err := json.Marshal(s.buildSupportBundle())
	if err != nil || bytes.Contains(bundle, []byte(stored.PasswordHash)) || bytes.Contains(bundle, []byte(authTestPassword)) {
		t.Fatalf("support bundle exposed credentials: error=%v body=%s", err, bundle)
	}
}

func TestAuthSessionFixationAndCookieSecurity(t *testing.T) {
	_, handler, _ := authTestServer(t)
	fixation := &http.Cookie{Name: authSessionCookie, Value: "attacker-selected-session"}
	setupCookie, _ := setupAuth(t, handler, false, fixation)
	if setupCookie.Value == fixation.Value || !setupCookie.HttpOnly || setupCookie.SameSite != http.SameSiteStrictMode || setupCookie.Secure {
		t.Fatalf("HTTP setup cookie = %+v", setupCookie)
	}
	body := `{"username":"` + authTestUser + `","password":"` + authTestPassword + `"}`
	login := authRequest(t, handler, http.MethodPost, "/api/auth/login", body, setupCookie, "", true)
	if login.Code != http.StatusOK {
		t.Fatalf("TLS login = %d: %s", login.Code, login.Body.String())
	}
	loginCookies := login.Result().Cookies()
	if len(loginCookies) != 1 || loginCookies[0].Value == setupCookie.Value ||
		!loginCookies[0].HttpOnly || !loginCookies[0].Secure || loginCookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("rotated TLS cookie = %+v", loginCookies)
	}
	oldStatus := authRequest(t, handler, http.MethodGet, "/api/auth/status", "", setupCookie, "", false)
	newStatus := authRequest(t, handler, http.MethodGet, "/api/auth/status", "", loginCookies[0], "", true)
	if authResponse(t, oldStatus)["authenticated"] != false || authResponse(t, newStatus)["authenticated"] != true {
		t.Fatalf("session fixation survived: old=%s new=%s", oldStatus.Body.String(), newStatus.Body.String())
	}
}

func TestAuthRequiresBothSessionAndCSRF(t *testing.T) {
	_, handler, _ := authTestServer(t)
	cookie, csrf := setupAuth(t, handler, false, nil)
	csrfOnly := authRequest(t, handler, http.MethodPost, "/api/generate", `{}`, nil, csrf, false)
	if csrfOnly.Code != http.StatusUnauthorized || authResponse(t, csrfOnly)["code"] != AuthCodeRequired {
		t.Fatalf("CSRF-only = %d %s", csrfOnly.Code, csrfOnly.Body.String())
	}
	sessionOnly := authRequest(t, handler, http.MethodPost, "/api/generate", `{}`, cookie, "", false)
	if sessionOnly.Code != http.StatusForbidden || authResponse(t, sessionOnly)["code"] != AuthCodeCSRFRequired {
		t.Fatalf("session-only = %d %s", sessionOnly.Code, sessionOnly.Body.String())
	}
	both := authRequest(t, handler, http.MethodPost, "/api/generate", `{}`, cookie, csrf, false)
	if both.Code == http.StatusUnauthorized || both.Code == http.StatusForbidden {
		t.Fatalf("valid session+CSRF did not reach protected handler: %d %s", both.Code, both.Body.String())
	}
}

func TestAuthSessionsExpireOnIdleAndAbsoluteDeadlines(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		s, handler, _ := authTestServer(t)
		now := time.Unix(1_700_000_000, 0)
		s.auth.now = func() time.Time { return now }
		cookie, _ := setupAuth(t, handler, false, nil)
		now = now.Add(authSessionIdle + time.Second)
		status := authRequest(t, handler, http.MethodGet, "/api/auth/status", "", cookie, "", false)
		if authResponse(t, status)["authenticated"] != false {
			t.Fatalf("idle-expired session survived: %s", status.Body.String())
		}
	})
	t.Run("absolute", func(t *testing.T) {
		s, handler, _ := authTestServer(t)
		now := time.Unix(1_700_000_000, 0)
		s.auth.now = func() time.Time { return now }
		cookie, _ := setupAuth(t, handler, false, nil)
		for elapsed := 20 * time.Minute; elapsed < authSessionAbsolute; elapsed += 20 * time.Minute {
			now = now.Add(20 * time.Minute)
			status := authRequest(t, handler, http.MethodGet, "/api/auth/status", "", cookie, "", false)
			if authResponse(t, status)["authenticated"] != true {
				t.Fatalf("session expired before absolute deadline at %s", elapsed)
			}
		}
		now = now.Add(20 * time.Minute)
		status := authRequest(t, handler, http.MethodGet, "/api/auth/status", "", cookie, "", false)
		if authResponse(t, status)["authenticated"] != false {
			t.Fatalf("absolute-expired session survived: %s", status.Body.String())
		}
	})
}

func TestAuthRateLimitTripsAndReleases(t *testing.T) {
	s, handler, _ := authTestServer(t)
	now := time.Unix(1_700_000_000, 0)
	s.auth.now = func() time.Time { return now }
	setupAuth(t, handler, false, nil)
	bad := `{"username":"` + authTestUser + `","password":"definitely-wrong"}`
	for attempt := 0; attempt < authMaxFailures; attempt++ {
		response := authRequest(t, handler, http.MethodPost, "/api/auth/login", bad, nil, "", false)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("bad login %d = %d %s", attempt, response.Code, response.Body.String())
		}
	}
	locked := authRequest(t, handler, http.MethodPost, "/api/auth/login", bad, nil, "", false)
	if locked.Code != http.StatusTooManyRequests || authResponse(t, locked)["code"] != AuthCodeRateLimited {
		t.Fatalf("lockout = %d %s", locked.Code, locked.Body.String())
	}
	now = now.Add(authLockout + time.Second)
	good := `{"username":"` + authTestUser + `","password":"` + authTestPassword + `"}`
	released := authRequest(t, handler, http.MethodPost, "/api/auth/login", good, nil, "", false)
	if released.Code != http.StatusOK {
		t.Fatalf("released login = %d %s", released.Code, released.Body.String())
	}
}

func TestAuthRouteClassificationFailsClosed(t *testing.T) {
	s, _, _ := authTestServer(t)
	mux := http.NewServeMux()
	defer func() {
		if recover() == nil {
			t.Fatal("unclassified route registration did not fail closed")
		}
	}()
	s.route(mux, authRouteClass("forgotten"), "POST /api/new-authority", func(http.ResponseWriter, *http.Request) {})
}
