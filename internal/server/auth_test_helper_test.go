package server

import (
	"crypto/sha256"
	"net/http"
	"testing"
	"time"

	"wayhop/internal/config"
)

const (
	authTestPrincipal = "test-operator"
	authTestToken     = "test-session-token"
	authTestCSRF      = "test-csrf-token"
)

// authenticatedTestHandler keeps endpoint tests focused on their own contract while the dedicated
// auth tests exercise setup, login, expiry, CSRF and lockout through the unwrapped production chain.
func authenticatedTestHandler(t *testing.T, server *Server) http.Handler {
	t.Helper()
	if server == nil {
		t.Fatal("authenticated test handler needs a server")
	}
	server.cfgMu.Lock()
	server.cfg.Auth = config.Auth{Username: authTestPrincipal, PasswordHash: "configured-test-record"}
	server.cfgMu.Unlock()
	if server.auth == nil {
		server.auth = newAuthManager(server)
	}
	digest := sha256.Sum256([]byte(authTestToken))
	server.auth.mu.Lock()
	server.auth.sessions[digest] = authSession{
		Principal: authTestPrincipal,
		CSRF:      authTestCSRF,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	server.auth.mu.Unlock()
	production := server.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		clone := request.Clone(request.Context())
		clone.Header = request.Header.Clone()
		clone.AddCookie(&http.Cookie{Name: authSessionCookie, Value: authTestToken})
		if requestMutates(clone.Method) {
			clone.Header.Set(authCSRFHeader, authTestCSRF)
		}
		production.ServeHTTP(w, clone)
	})
}
