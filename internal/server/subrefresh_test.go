package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/config"
)

// subrefresh_link1 / subrefresh_link2 / subrefresh_link3 are three distinct,
// importer-parseable share links used to build base64 subscription bodies.
const (
	subrefresh_link1 = "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443" +
		"?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision#S1"
	subrefresh_link2 = "trojan://secretpass@example.com:443?security=tls&sni=example.com#S2"
	subrefresh_link3 = "vless://99999999-8888-7777-6666-555555555555@203.0.113.9:8443" +
		"?type=tcp&security=reality&sni=www.apple.com&fp=chrome&pbk=PUBKEY2&sid=cd34&flow=xtls-rprx-vision#S3"
)

// subrefresh_sub returns a base64-encoded v2ray subscription body for the links.
func subrefresh_sub(links ...string) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
}

// subrefresh_server builds a *Server with the SSRF guard disabled (so it can fetch
// a loopback httptest server) and the given subscription URL pre-set in config.
func subrefresh_server(t *testing.T, url string) *Server {
	t.Helper()
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	s.cfg.Subscription.URL = url
	return s
}

func TestSubrefresh_AddsNewThenDedupes(t *testing.T) {
	// A mutable body so we can change what the "provider" serves between refreshes.
	body := subrefresh_sub(subrefresh_link1, subrefresh_link2)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()

	s := subrefresh_server(t, ts.URL)

	// First refresh: both links are new.
	added, err := s.refreshSubscriptionOnce(context.Background())
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if added != 2 {
		t.Fatalf("first refresh added %d, want 2", added)
	}
	if got := len(s.store.Profile().Endpoints); got != 2 {
		t.Fatalf("profile has %d endpoints after first refresh, want 2", got)
	}

	// Second refresh of the SAME content: DedupeNew should add nothing.
	added, err = s.refreshSubscriptionOnce(context.Background())
	if err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if added != 0 {
		t.Fatalf("second refresh added %d, want 0 (dedupe)", added)
	}
	if got := len(s.store.Profile().Endpoints); got != 2 {
		t.Fatalf("profile has %d endpoints after dedup refresh, want 2", got)
	}

	// Provider rotates in one NEW server: only the new one is added.
	body = subrefresh_sub(subrefresh_link1, subrefresh_link2, subrefresh_link3)
	added, err = s.refreshSubscriptionOnce(context.Background())
	if err != nil {
		t.Fatalf("third refresh: %v", err)
	}
	if added != 1 {
		t.Fatalf("third refresh added %d, want 1", added)
	}
	if got := len(s.store.Profile().Endpoints); got != 3 {
		t.Fatalf("profile has %d endpoints after rotation refresh, want 3", got)
	}
}

func TestSubrefresh_StatusRecorded(t *testing.T) {
	body := subrefresh_sub(subrefresh_link1, subrefresh_link2)
	code := http.StatusOK
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()
	s := subrefresh_server(t, ts.URL)

	// Before any attempt: never refreshed.
	if last, added, errStr := s.subStatus.snapshot(); !last.IsZero() || added != 0 || errStr != "" {
		t.Fatalf("initial status = (%v,%d,%q), want (zero,0,empty)", last, added, errStr)
	}

	// A successful refresh records the time + added count and clears the error.
	if _, err := s.refreshSubscriptionOnce(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	last, added, errStr := s.subStatus.snapshot()
	if last.IsZero() || added != 2 || errStr != "" {
		t.Fatalf("after success: zero=%v added=%d err=%q, want (set,2,empty)", last.IsZero(), added, errStr)
	}

	// A failing refresh records the error.
	code = http.StatusInternalServerError
	if _, err := s.refreshSubscriptionOnce(context.Background()); err == nil {
		t.Fatal("expected an error on HTTP 500")
	}
	if _, _, errStr := s.subStatus.snapshot(); errStr == "" {
		t.Fatal("after a failed refresh the status error must be set")
	}

	// An empty-URL refresh is a no-op and must NOT overwrite the recorded status.
	s.cfg.Subscription.URL = ""
	before, _, _ := s.subStatus.snapshot()
	if _, err := s.refreshSubscriptionOnce(context.Background()); err != nil {
		t.Fatalf("empty-url refresh: %v", err)
	}
	if after, _, _ := s.subStatus.snapshot(); !after.Equal(before) {
		t.Fatal("empty-url no-op must not touch the status timestamp")
	}
}

func TestSubrefresh_EmptyURLNoOp(t *testing.T) {
	s, _ := sharehandlers_server(t) // no URL set
	added, err := s.refreshSubscriptionOnce(context.Background())
	if err != nil {
		t.Fatalf("empty-url refresh: %v", err)
	}
	if added != 0 {
		t.Fatalf("empty-url refresh added %d, want 0", added)
	}
}

func TestSubrefresh_NonOKStatusErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer ts.Close()
	s := subrefresh_server(t, ts.URL)
	if _, err := s.refreshSubscriptionOnce(context.Background()); err == nil {
		t.Fatal("expected error on non-200 subscription, got nil")
	}
}

// TestSubrefresh_SSRFGuardRefusesLoopback verifies the SSRF dial guard refuses a
// loopback URL when the guard is enabled (the production default).
func TestSubrefresh_SSRFGuardRefusesLoopback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(subrefresh_sub(subrefresh_link1)))
	}))
	defer ts.Close()

	s, _ := sharehandlers_server(t)
	// allowInternalFetch stays false (guard ON), so the loopback dial must be refused.
	s.cfg.Subscription.URL = ts.URL
	if _, err := s.refreshSubscriptionOnce(context.Background()); err == nil {
		t.Fatal("SSRF guard should refuse a loopback subscription URL, got nil error")
	}
}

// TestSubrefresh_RefreshNowConfigErrorIs400 verifies handleSubRefreshNow maps a
// config/validation failure (bad scheme / unparseable stored URL) to 400, not 502:
// the upstream was never contacted, so it is a client/config error.
func TestSubrefresh_RefreshNowConfigErrorIs400(t *testing.T) {
	for _, badURL := range []string{
		"ftp://example.com/sub", // unsupported scheme
		"://noscheme",           // unparseable
		"http://[::1",           // malformed (url.Parse error)
	} {
		s, _ := sharehandlers_server(t)
		s.allowInternalFetch = true
		s.cfg.Subscription.URL = badURL
		w := profilehandlers_post(s.handleSubRefreshNow, `{}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("stored URL %q: got %d, want 400 (%s)", badURL, w.Code, w.Body.String())
		}
	}
}

// TestSubrefresh_RefreshNowFetchFailureIs502 verifies an actual upstream failure
// (a non-200 status from the provider) is mapped to 502, not 400.
func TestSubrefresh_RefreshNowFetchFailureIs502(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer ts.Close()
	s := subrefresh_server(t, ts.URL)
	w := profilehandlers_post(s.handleSubRefreshNow, `{}`)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("upstream non-200: got %d, want 502 (%s)", w.Code, w.Body.String())
	}
}

func TestSubrefresh_AutoRefreshSetsHours(t *testing.T) {
	s, cfgPath := sharehandlers_server(t)

	w := profilehandlers_post(s.handleSubAutoRefresh, `{"hours":24}`)
	if w.Code != http.StatusOK {
		t.Fatalf("set hours: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		RefreshHours int    `json:"refresh_hours"`
		URL          string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if resp.RefreshHours != 24 {
		t.Fatalf("refresh_hours = %d, want 24", resp.RefreshHours)
	}
	if s.cfg.Subscription.RefreshHours != 24 {
		t.Fatalf("in-memory RefreshHours = %d, want 24", s.cfg.Subscription.RefreshHours)
	}
	// Persisted to disk.
	if reloaded, err := config.Load(cfgPath); err != nil {
		t.Fatalf("reload config: %v", err)
	} else if reloaded.Subscription.RefreshHours != 24 {
		t.Fatalf("persisted RefreshHours = %d, want 24", reloaded.Subscription.RefreshHours)
	}
}

func TestSubrefresh_AutoRefreshRejectsOutOfRange(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if w := profilehandlers_post(s.handleSubAutoRefresh, `{"hours":-1}`); w.Code != http.StatusBadRequest {
		t.Fatalf("negative hours: got %d, want 400", w.Code)
	}
	if w := profilehandlers_post(s.handleSubAutoRefresh, `{"hours":169}`); w.Code != http.StatusBadRequest {
		t.Fatalf("too-large hours: got %d, want 400", w.Code)
	}
	if w := profilehandlers_post(s.handleSubAutoRefresh, `???`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad json: got %d, want 400", w.Code)
	}
}

func TestSubrefresh_RefreshNowHandler(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(subrefresh_sub(subrefresh_link1, subrefresh_link2)))
	}))
	defer ts.Close()
	s := subrefresh_server(t, ts.URL)

	w := profilehandlers_post(s.handleSubRefreshNow, `{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("refresh now: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Added int `json:"added"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if resp.Added != 2 {
		t.Fatalf("added = %d, want 2", resp.Added)
	}
}
