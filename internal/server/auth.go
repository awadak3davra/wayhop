package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"wayhop/internal/config"
)

const (
	authSessionCookie         = "wayhop_session"
	authCSRFHeader            = "X-WayHop-CSRF"
	authLocalDemoPrincipal    = "local-demo"
	authPasswordlessPrincipal = "no-password"
	authLocalDemoCSRF         = "local-demo"
	authSessionIdle           = 30 * time.Minute
	authSessionAbsolute       = 12 * time.Hour
	authFailureWindow         = 10 * time.Minute
	authLockout               = 5 * time.Minute
	authMaxFailures           = 5
	authTokenBytes            = 32
	authSaltBytes             = 16
	authHashBytes             = 32
	authArgonMemoryKiB        = 16 * 1024
	authArgonIterations       = 2
	authArgonParallelism      = 1
	authPasswordMinBytes      = 12
	authPasswordMaxBytes      = 256
	authCredentialMaxBytes    = 8 << 10
)

const (
	AuthCodeSetupRequired     = "AUTH_SETUP_REQUIRED"
	AuthCodeAlreadyConfigured = "AUTH_ALREADY_CONFIGURED"
	AuthCodeRequired          = "AUTH_REQUIRED"
	AuthCodeCSRFRequired      = "AUTH_CSRF_REQUIRED"
	AuthCodeInvalidCredential = "AUTH_INVALID_CREDENTIALS"
	AuthCodeRateLimited       = "AUTH_RATE_LIMITED"
	AuthCodeInvalidRequest    = "AUTH_INVALID_REQUEST"
	AuthCodeUnavailable       = "AUTH_UNAVAILABLE"
)

var authUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type authRouteClass string

const (
	authRoutePublic    authRouteClass = "public"
	authRouteProtected authRouteClass = "protected"
)

type authSession struct {
	Principal string
	CSRF      string
	CreatedAt time.Time
	LastSeen  time.Time
}

type authFailure struct {
	Count       int
	WindowStart time.Time
	LockedUntil time.Time
}

type authManager struct {
	mu      sync.Mutex
	loginMu sync.Mutex
	now     func() time.Time
	random  io.Reader

	credentials func() config.Auth
	save        func(config.Auth) error
	sessions    map[[sha256.Size]byte]authSession
	failures    map[string]authFailure
}

type authPrincipalContextKey struct{}

func newAuthManager(s *Server) *authManager {
	manager := &authManager{
		now: time.Now, random: rand.Reader,
		sessions: make(map[[sha256.Size]byte]authSession),
		failures: make(map[string]authFailure),
	}
	if s != nil {
		manager.credentials = s.authCredentials
		manager.save = s.saveAuthCredentials
	}
	return manager
}

func (s *Server) authCredentials() config.Auth {
	if s == nil {
		return config.Auth{}
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	return s.cfg.Auth
}

func (s *Server) saveAuthCredentials(auth config.Auth) error {
	if s == nil || s.cfg == nil {
		return errors.New("auth config unavailable")
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	previous := s.cfg.Auth
	s.cfg.Auth = auth
	if err := s.cfg.Save(); err != nil {
		s.cfg.Auth = previous
		return err
	}
	return nil
}

func (manager *authManager) configured() bool {
	if manager == nil || manager.credentials == nil {
		return false
	}
	auth := manager.credentials()
	return auth.Username != "" && auth.PasswordHash != "" && auth.PasswordHash != config.RedactedMark
}

// passwordless reports the state where the operator was asked for a password and said no. It is
// deliberately NOT the same test as "no password stored": an unanswered first run must keep blocking
// on setup, because a panel holding every tunnel's private key must not open itself just because
// nobody has answered yet. A stored password always wins — Disabled is ignored while one exists, so
// a stale flag in a hand-edited config cannot turn authentication off under a configured panel.
func (manager *authManager) passwordless() bool {
	if manager == nil || manager.credentials == nil {
		return false
	}
	if manager.configured() {
		return false
	}
	return manager.credentials().Disabled
}

func (s *Server) route(
	mux *http.ServeMux,
	class authRouteClass,
	pattern string,
	handler http.HandlerFunc,
) {
	if mux == nil || handler == nil {
		panic("invalid route registration")
	}
	switch class {
	case authRoutePublic:
		mux.HandleFunc(pattern, handler)
	case authRouteProtected:
		mux.HandleFunc(pattern, s.requireSession(handler))
	default:
		panic("unclassified route: " + pattern)
	}
}

// SetDevNoAuth disables the panel's authentication for development.
//
// It exists so the API can be driven while the product is being built, and it is deliberately
// awkward to enable by accident: only the --dev-no-auth process flag reaches it, nothing in
// config.json does, so it cannot survive a restart that did not ask for it. The daemon announces it
// on every start. This is a scaffold, not a feature — the panel binds all interfaces, so a router
// left running with it is an unauthenticated control plane on the LAN.
func (s *Server) SetDevNoAuth(enabled bool) {
	if s != nil {
		s.devNoAuth = enabled
	}
}

// authBypass is the single question both the middleware and the status endpoint ask, so the two can
// never disagree about whether this request is authenticated.
func (s *Server) authBypass(r *http.Request) bool {
	return s != nil && (s.devNoAuth || s.localDemoAuthBypass(r))
}

func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authBypass(r) {
			ctx := context.WithValue(r.Context(), authPrincipalContextKey{}, authLocalDemoPrincipal)
			next(w, r.WithContext(ctx))
			return
		}
		// The operator declined a password. Requests pass, and the principal SAYS so rather than
		// borrowing a name that implies someone signed in — it lands in audit lines and in the panel.
		if s != nil && s.auth != nil && s.auth.passwordless() {
			ctx := context.WithValue(r.Context(), authPrincipalContextKey{}, authPasswordlessPrincipal)
			next(w, r.WithContext(ctx))
			return
		}
		if s == nil || s.auth == nil || !s.auth.configured() {
			writeAuthError(w, http.StatusForbidden, AuthCodeSetupRequired, "operator setup is required")
			return
		}
		session, ok := s.auth.sessionForRequest(r, true)
		if !ok {
			writeAuthError(w, http.StatusUnauthorized, AuthCodeRequired, "authentication is required")
			return
		}
		if requestMutates(r.Method) && !constantTextEqual(r.Header.Get(authCSRFHeader), session.CSRF) {
			writeAuthError(w, http.StatusForbidden, AuthCodeCSRFRequired, "a valid session CSRF token is required")
			return
		}
		ctx := context.WithValue(r.Context(), authPrincipalContextKey{}, session.Principal)
		next(w, r.WithContext(ctx))
	}
}

// localDemoAuthBypass keeps the isolated browser/fault harness usable without shipping a password.
// It is impossible on a LAN listener: Demo must be explicit and both the configured bind address
// and request peer must be loopback. Host and same-origin guards remain active around this handler.
func (s *Server) localDemoAuthBypass(r *http.Request) bool {
	if s == nil || r == nil {
		return false
	}
	cfg := s.config()
	if !cfg.Demo {
		return false
	}
	bindHost, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil || bindHost == "" {
		return false
	}
	bindIP := net.ParseIP(strings.Trim(bindHost, "[]"))
	peerIP := net.ParseIP(authClientIP(r))
	return bindIP != nil && bindIP.IsLoopback() && peerIP != nil && peerIP.IsLoopback()
}

func requestMutates(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func (manager *authManager) sessionForRequest(r *http.Request, touch bool) (authSession, bool) {
	if manager == nil || r == nil {
		return authSession{}, false
	}
	cookie, err := r.Cookie(authSessionCookie)
	if err != nil || cookie.Value == "" {
		return authSession{}, false
	}
	digest := sha256.Sum256([]byte(cookie.Value))
	now := manager.now()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	session, ok := manager.sessions[digest]
	if !ok {
		return authSession{}, false
	}
	if now.Sub(session.LastSeen) >= authSessionIdle || now.Sub(session.CreatedAt) >= authSessionAbsolute {
		delete(manager.sessions, digest)
		return authSession{}, false
	}
	if touch {
		session.LastSeen = now
		manager.sessions[digest] = session
	}
	return session, true
}

func (manager *authManager) newSession(w http.ResponseWriter, r *http.Request, principal string) (authSession, error) {
	if manager == nil || w == nil || r == nil || principal == "" {
		return authSession{}, errors.New("session unavailable")
	}
	manager.revokeRequestSession(r)
	token, err := manager.randomToken()
	if err != nil {
		return authSession{}, err
	}
	csrf, err := manager.randomToken()
	if err != nil {
		return authSession{}, err
	}
	now := manager.now()
	session := authSession{Principal: principal, CSRF: csrf, CreatedAt: now, LastSeen: now}
	digest := sha256.Sum256([]byte(token))
	manager.mu.Lock()
	manager.sessions[digest] = session
	manager.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: authSessionCookie, Value: token, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
		MaxAge: int(authSessionAbsolute.Seconds()),
	})
	return session, nil
}

func (manager *authManager) randomToken() (string, error) {
	raw := make([]byte, authTokenBytes)
	if _, err := io.ReadFull(manager.random, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// revokeAllSessions drops every live session. Used when the credential itself changes: a session
// minted under the old password must not outlive it, wherever it is held.
func (manager *authManager) revokeAllSessions() {
	if manager == nil {
		return
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.sessions = map[[sha256.Size]byte]authSession{}
}

func (manager *authManager) revokeRequestSession(r *http.Request) {
	if manager == nil || r == nil {
		return
	}
	if cookie, err := r.Cookie(authSessionCookie); err == nil && cookie.Value != "" {
		digest := sha256.Sum256([]byte(cookie.Value))
		manager.mu.Lock()
		delete(manager.sessions, digest)
		manager.mu.Unlock()
	}
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: authSessionCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: r != nil && r.TLS != nil, SameSite: http.SameSiteStrictMode,
		MaxAge: -1,
	})
}

func (manager *authManager) hashPassword(password string) (string, error) {
	salt := make([]byte, authSaltBytes)
	if _, err := io.ReadFull(manager.random, salt); err != nil {
		return "", err
	}
	return encodePasswordRecord(password, salt), nil
}

func encodePasswordRecord(password string, salt []byte) string {
	digest := argon2.IDKey([]byte(password), salt, authArgonIterations, authArgonMemoryKiB,
		authArgonParallelism, authHashBytes)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		authArgonMemoryKiB, authArgonIterations, authArgonParallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(digest))
}

func verifyPasswordRecord(password, record string) bool {
	parts := strings.Split(record, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	var memory uint32
	var iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil ||
		memory < 8*1024 || memory > 64*1024 || iterations < 1 || iterations > 4 ||
		parallelism < 1 || parallelism > 4 ||
		parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", memory, iterations, parallelism) {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != authSaltBytes {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) != authHashBytes {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

var (
	dummyPasswordOnce sync.Once
	dummyPasswordHash string
)

func dummyPasswordRecord() string {
	dummyPasswordOnce.Do(func() {
		dummyPasswordHash = encodePasswordRecord("not-a-real-password", []byte("wayhop-dummy-v1!"))
	})
	return dummyPasswordHash
}

func constantTextEqual(left, right string) bool {
	leftHash := sha256.Sum256([]byte(left))
	rightHash := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftHash[:], rightHash[:]) == 1
}

func authClientIP(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if ip := net.ParseIP(r.RemoteAddr); ip != nil {
		return ip.String()
	}
	return "unknown"
}

func (manager *authManager) locked(ip string) bool {
	now := manager.now()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	failure := manager.failures[ip]
	if failure.LockedUntil.After(now) {
		return true
	}
	if !failure.LockedUntil.IsZero() || now.Sub(failure.WindowStart) > authFailureWindow {
		delete(manager.failures, ip)
	}
	return false
}

func (manager *authManager) recordLogin(ip string, success bool) {
	now := manager.now()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if success {
		delete(manager.failures, ip)
		return
	}
	failure := manager.failures[ip]
	if failure.WindowStart.IsZero() || now.Sub(failure.WindowStart) > authFailureWindow {
		failure = authFailure{WindowStart: now}
	}
	failure.Count++
	if failure.Count >= authMaxFailures {
		failure.LockedUntil = now.Add(authLockout)
	}
	manager.failures[ip] = failure
}

type authCredentialRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// Skip is the setup form's "run without a password" answer. Only handleAuthSetup reads it; login
	// ignores it, and the decoder rejects unknown fields, so it cannot be smuggled anywhere else.
	Skip bool `json:"skip,omitempty"`
}

func decodeAuthCredential(r *http.Request) (authCredentialRequest, error) {
	if r == nil || r.Body == nil {
		return authCredentialRequest{}, errors.New("missing body")
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, authCredentialMaxBytes+1))
	decoder.DisallowUnknownFields()
	var request authCredentialRequest
	if err := decoder.Decode(&request); err != nil {
		return authCredentialRequest{}, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return authCredentialRequest{}, errors.New("trailing JSON")
	}
	return request, nil
}

func validNewCredential(request authCredentialRequest) bool {
	return authUsernamePattern.MatchString(request.Username) &&
		len(request.Password) >= authPasswordMinBytes && len(request.Password) <= authPasswordMaxBytes &&
		strings.TrimSpace(request.Password) == request.Password &&
		!strings.ContainsAny(request.Password, "\x00\r\n")
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.authBypass(r) {
		// configured/authenticated stay true so the panel opens, which is the point of the bypass —
		// but "bypass" says WHY, because the panel offers account controls that cannot work here:
		// there is no stored credential to change, and handleAuthPassword would refuse. A card that
		// offered a password form on a --dev-no-auth process would be advertising a dead control.
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": true, "authenticated": true, "bypass": true,
			"principal": authLocalDemoPrincipal, "csrf_token": authLocalDemoCSRF,
		})
		return
	}
	configured := s != nil && s.auth != nil && s.auth.configured()
	// passwordless is reported separately from configured, because the panel has to tell three states
	// apart: nobody has set up yet (show the setup form), a password exists (show the login form), and
	// the operator declined one (show the panel — and say, in Settings, that it is open).
	passwordless := s != nil && s.auth != nil && s.auth.passwordless()
	response := map[string]any{"configured": configured, "authenticated": passwordless, "passwordless": passwordless}
	if passwordless {
		response["principal"] = authPasswordlessPrincipal
	}
	if configured {
		if session, ok := s.auth.sessionForRequest(r, true); ok {
			response["authenticated"] = true
			response["principal"] = session.Principal
			response["csrf_token"] = session.CSRF
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s == nil || s.auth == nil || s.auth.save == nil {
		writeAuthError(w, http.StatusServiceUnavailable, AuthCodeUnavailable, "authentication is unavailable")
		return
	}
	s.auth.loginMu.Lock()
	defer s.auth.loginMu.Unlock()
	if s.auth.configured() {
		writeAuthError(w, http.StatusForbidden, AuthCodeAlreadyConfigured, "operator credentials are already configured")
		return
	}
	request, err := decodeAuthCredential(r)
	// "skip": the operator was asked and declined. Recorded as a decision (config.Auth.Disabled) so it
	// survives a restart and can be read back and shown; it is NOT the same as leaving setup unfinished,
	// which keeps blocking. Reachable only while no password exists — this handler already refused
	// above if one does, so an unauthenticated request can never turn authentication OFF.
	if err == nil && request.Skip {
		if saveErr := s.auth.save(config.Auth{Disabled: true}); saveErr != nil {
			writeAuthError(w, http.StatusServiceUnavailable, AuthCodeUnavailable, "the choice could not be persisted")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"configured": false, "authenticated": true, "passwordless": true,
			"principal": authPasswordlessPrincipal,
		})
		return
	}
	if err != nil || !validNewCredential(request) {
		writeAuthError(w, http.StatusBadRequest, AuthCodeInvalidRequest, "username or password does not meet the setup policy")
		return
	}
	record, err := s.auth.hashPassword(request.Password)
	if err != nil || !verifyPasswordRecord(request.Password, record) {
		writeAuthError(w, http.StatusServiceUnavailable, AuthCodeUnavailable, "authentication is unavailable")
		return
	}
	if err := s.auth.save(config.Auth{Username: request.Username, PasswordHash: record}); err != nil {
		writeAuthError(w, http.StatusServiceUnavailable, AuthCodeUnavailable, "credentials could not be persisted")
		return
	}
	session, err := s.auth.newSession(w, r, request.Username)
	if err != nil {
		writeAuthError(w, http.StatusServiceUnavailable, AuthCodeUnavailable, "session could not be created")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"configured": true, "authenticated": true,
		"principal": session.Principal, "csrf_token": session.CSRF,
	})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s == nil || s.auth == nil {
		writeAuthError(w, http.StatusUnauthorized, AuthCodeInvalidCredential, "invalid credentials")
		return
	}
	s.auth.loginMu.Lock()
	defer s.auth.loginMu.Unlock()
	ip := authClientIP(r)
	if s.auth.locked(ip) {
		writeAuthError(w, http.StatusTooManyRequests, AuthCodeRateLimited, "too many login attempts; try again later")
		return
	}
	request, decodeErr := decodeAuthCredential(r)
	credentials := s.auth.credentials()
	record := credentials.PasswordHash
	if record == "" || record == config.RedactedMark {
		record = dummyPasswordRecord()
	}
	passwordOK := verifyPasswordRecord(request.Password, record)
	usernameOK := constantTextEqual(request.Username, credentials.Username)
	success := decodeErr == nil && passwordOK && usernameOK && s.auth.configured()
	s.auth.recordLogin(ip, success)
	if !success {
		writeAuthError(w, http.StatusUnauthorized, AuthCodeInvalidCredential, "invalid credentials")
		return
	}
	session, err := s.auth.newSession(w, r, credentials.Username)
	if err != nil {
		writeAuthError(w, http.StatusServiceUnavailable, AuthCodeUnavailable, "session could not be created")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true, "principal": session.Principal, "csrf_token": session.CSRF,
	})
}

// authPasswordChangeRequest changes the operator's password, and optionally the username with it.
//
// The current password is required even though the caller already holds a session: a session is a
// bearer token, and one that leaked must not be a lever for taking the account over. It is also why
// the failure path counts toward the SAME per-IP lockout the login uses — otherwise this endpoint
// becomes an oracle for guessing the current password from inside a stolen tab.
type authPasswordChangeRequest struct {
	Username        string `json:"username,omitempty"`
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// handleAuthPassword changes the stored credential. POST /api/auth/password (protected).
//
// Until now the only way to change it was editing config.json over SSH: handleAuthSetup refuses once
// credentials exist (AUTH_ALREADY_CONFIGURED) and nothing else wrote the field. A panel that can be
// logged into but whose password cannot be rotated is a panel whose password never changes after the
// day it is chosen.
//
// Every session dies here, including this one, and a fresh session is issued to the caller. Two
// reasons, both load-bearing: a credential change must not leave a session minted under the old
// password alive somewhere else (that is what "change the password" means to the operator who
// suspects someone else is in), and rotating the caller's own token is the standard answer to
// session fixation. The operator keeps working in the tab they are in; everyone else is out.
func (s *Server) handleAuthPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s == nil || s.auth == nil || s.auth.save == nil {
		writeAuthError(w, http.StatusServiceUnavailable, AuthCodeUnavailable, "authentication is unavailable")
		return
	}
	s.auth.loginMu.Lock()
	defer s.auth.loginMu.Unlock()
	if !s.auth.configured() {
		writeAuthError(w, http.StatusForbidden, AuthCodeSetupRequired, "no operator credentials are configured yet")
		return
	}
	ip := authClientIP(r)
	if s.auth.locked(ip) {
		writeAuthError(w, http.StatusTooManyRequests, AuthCodeRateLimited, "too many attempts; try again later")
		return
	}
	var request authPasswordChangeRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, authCredentialMaxBytes+1))
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(&request)
	if decodeErr == nil && decoder.Decode(&struct{}{}) != io.EOF {
		decodeErr = errors.New("trailing JSON")
	}
	credentials := s.auth.credentials()
	// An empty username means "keep the one I have"; the panel sends it only when it changes.
	principal := request.Username
	if principal == "" {
		principal = credentials.Username
	}
	// The new credential faces the same policy as first-run setup — length, no surrounding space, no
	// control characters, a username shaped like a username. A weaker rule here would mean the only
	// way to get a weak password onto the router is to change it, which is the wrong way round.
	if decodeErr != nil || !validNewCredential(authCredentialRequest{Username: principal, Password: request.NewPassword}) {
		writeAuthError(w, http.StatusBadRequest, AuthCodeInvalidRequest, "username or password does not meet the policy")
		return
	}
	record := credentials.PasswordHash
	if record == "" || record == config.RedactedMark {
		record = dummyPasswordRecord()
	}
	// Verified against the stored record with the same constant-time comparison the login uses, and
	// the outcome is recorded on the same per-IP counter.
	ok := verifyPasswordRecord(request.CurrentPassword, record) && s.auth.configured()
	s.auth.recordLogin(ip, ok)
	if !ok {
		writeAuthError(w, http.StatusUnauthorized, AuthCodeInvalidCredential, "the current password is not correct")
		return
	}
	next, err := s.auth.hashPassword(request.NewPassword)
	if err != nil || !verifyPasswordRecord(request.NewPassword, next) {
		writeAuthError(w, http.StatusServiceUnavailable, AuthCodeUnavailable, "authentication is unavailable")
		return
	}
	if err := s.auth.save(config.Auth{Username: principal, PasswordHash: next}); err != nil {
		writeAuthError(w, http.StatusServiceUnavailable, AuthCodeUnavailable, "credentials could not be persisted")
		return
	}
	s.auth.revokeAllSessions()
	session, err := s.auth.newSession(w, r, principal)
	if err != nil {
		// The credential IS changed; only the new session failed. Say so rather than reporting a
		// failure that would send the operator to change it again.
		clearSessionCookie(w, r)
		writeAuthError(w, http.StatusServiceUnavailable, AuthCodeUnavailable, "the password was changed; sign in again")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": true, "authenticated": true,
		"principal": session.Principal, "csrf_token": session.CSRF,
	})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if s != nil && s.auth != nil {
		s.auth.revokeRequestSession(r)
	}
	clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
}

func writeAuthError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]any{"code": code, "error": message})
}
