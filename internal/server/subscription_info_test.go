package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/config"
)

func TestRedactSubscriptionSourceDropsEveryCredentialLocation(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"userinfo", "https://alice:password@provider.example/sub", "https://provider.example/…"},
		{"secret query", "https://provider.example/sub?token=query-secret&user=alice", "https://provider.example/…"},
		{"bearer path", "https://provider.example/v1/subscriptions/BearerPathSecret", "https://provider.example/…"},
		{"explicit port", "https://provider.example:8443/sub/secret", "https://provider.example:8443/…"},
		{"ipv6", "https://[2001:db8::1]/sub/secret", "https://[2001:db8::1]/…"},
		{"empty", "", ""},
		{"malformed", "not a URL with private-token", hiddenSubscriptionSource},
		{"wrong scheme", "file:///private/subscription-token", hiddenSubscriptionSource},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redactSubscriptionSource(tt.raw); got != tt.want {
				t.Fatalf("redactSubscriptionSource(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestRedactSubscriptionErrorDropsProviderAndEndpointCredentials(t *testing.T) {
	raw := "fetch https://alice:user-secret@provider.example/private/path-secret?token=query-secret failed; " +
		"first invalid line: vless://11111111-2222-3333-4444-555555555555@example.invalid:443"
	got := redactSubscriptionError(raw)
	for _, secret := range []string{"alice", "user-secret", "path-secret", "query-secret", "11111111-2222-3333-4444-555555555555"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted error leaked %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "https://provider.example/…") || !strings.Contains(got, "vless://…") {
		t.Fatalf("redacted error lost its safe source context: %s", got)
	}
}

func TestSubscriptionInfoPublicDTONeverLeaksProviderURL(t *testing.T) {
	const raw = "https://alice:userinfo-secret@provider.example/v1/subscriptions/path-secret?token=query-secret"
	s, _ := sharehandlers_server(t)
	s.cfg.Subscription.URL = raw
	s.cfg.Subscription.RefreshHours = 24
	s.subStatus.record(0, errors.New("fetch "+raw+": connection refused"))

	w := httptest.NewRecorder()
	s.handleSubInfo(w, httptest.NewRequest(http.MethodGet, "/api/subscription/info", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET subscription info = %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	for _, secret := range []string{"userinfo-secret", "path-secret", "query-secret", "alice"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("public subscription DTO leaked %q: %s", secret, w.Body.String())
		}
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, exists := got["url"]; exists {
		t.Fatalf("public DTO must not carry a url field: %s", w.Body.String())
	}
	if got["configured"] != true || got["source"] != "https://provider.example/…" {
		t.Fatalf("public identity = configured:%v source:%v", got["configured"], got["source"])
	}
	if s.config().Subscription.URL != raw {
		t.Fatal("rendering subscription info changed the private URL used for refresh")
	}
}

func TestSubscriptionMutationResponseDoesNotEchoProviderURL(t *testing.T) {
	const raw = "https://provider.example/private/bearer-token?token=query-secret"
	s, _ := sharehandlers_server(t)
	s.cfg.Subscription.URL = raw
	w := profilehandlers_post(s.handleSubAutoRefresh, `{"hours":24}`)
	if w.Code != http.StatusOK {
		t.Fatalf("set auto-refresh = %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "bearer-token") || strings.Contains(w.Body.String(), "query-secret") {
		t.Fatalf("auto-refresh response leaked the provider URL: %s", w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, exists := got["url"]; exists {
		t.Fatalf("mutation response must not carry a url field: %s", w.Body.String())
	}
	if got["configured"] != true || got["source"] != "https://provider.example/…" {
		t.Fatalf("public identity = configured:%v source:%v", got["configured"], got["source"])
	}
	if s.config().Subscription.URL != raw {
		t.Fatal("changing the refresh interval changed the private provider URL")
	}
}

func TestGetConfigMasksSubscriptionProviderURL(t *testing.T) {
	const raw = "https://provider.example/path/bearer-secret?token=query-secret"
	s, _ := sharehandlers_server(t)
	s.cfg.Subscription.URL = raw
	w := httptest.NewRecorder()
	s.handleGetConfig(w, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET config = %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "bearer-secret") || strings.Contains(w.Body.String(), "query-secret") {
		t.Fatalf("config DTO leaked subscription credentials: %s", w.Body.String())
	}
	var got config.Config
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Subscription.URL != config.RedactedMark {
		t.Fatalf("subscription URL = %q, want redaction mark", got.Subscription.URL)
	}
	// This is the exact Settings flow: GET the public DTO, then PUT it back with unrelated
	// edits. The redaction sentinel must never replace the private URL used by refresh.
	body, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	put := httptest.NewRecorder()
	s.handlePutConfig(put, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(string(body))))
	if put.Code != http.StatusOK {
		t.Fatalf("round-trip redacted config = %d: %s", put.Code, put.Body.String())
	}
	if s.config().Subscription.URL != raw {
		t.Fatal("Settings round-trip changed the private URL used for refresh")
	}
}
