package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/config"
)

func TestValidatePorts(t *testing.T) {
	ok := config.Ports{UI: 8088, Clash: 9090, DNS: 5353, Mixed: 7890}
	if err := validatePorts(ok); err != nil {
		t.Fatalf("valid ports rejected: %v", err)
	}
	bad := []config.Ports{
		{UI: 0, Clash: 9090, DNS: 5353, Mixed: 7890},     // out of range (low)
		{UI: 70000, Clash: 9090, DNS: 5353, Mixed: 7890}, // out of range (high)
		{UI: 8088, Clash: 8088, DNS: 5353, Mixed: 7890},  // duplicate ui/clash
		{UI: 8088, Clash: 9090, DNS: 5353, Mixed: 5353},  // duplicate dns/mixed
	}
	for i, p := range bad {
		if err := validatePorts(p); err == nil {
			t.Errorf("case %d: invalid ports %+v were accepted", i, p)
		}
	}
}

func putConfig(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handlePutConfig(w, req)
	return w
}

// TestHandlePutConfig_ListenFollowsUIPort: editing the UI port in Settings must move the actual
// bind (Listen) — the documented escape from the lighttpd :8088 conflict — not silently no-op.
// Listen's host/interface is preserved, and a malformed Listen is rejected at save, not at restart.
func TestHandlePutConfig_ListenFollowsUIPort(t *testing.T) {
	cfg, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: cfg}

	w := putConfig(t, s, `{"listen":":8088","ports":{"ui":8089,"clash":9090,"dns":5353,"mixed":7890}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if s.cfg.Listen != ":8089" {
		t.Errorf("Listen must follow Ports.UI: got %q, want :8089", s.cfg.Listen)
	}

	w = putConfig(t, s, `{"listen":"192.168.1.1:8088","ports":{"ui":8090,"clash":9090,"dns":5353,"mixed":7890}}`)
	if w.Code != http.StatusOK || s.cfg.Listen != "192.168.1.1:8090" {
		t.Errorf("host preserved + port from UI: got %q (code %d), want 192.168.1.1:8090", s.cfg.Listen, w.Code)
	}

	if w := putConfig(t, s, `{"listen":"8088","ports":{"ui":8089,"clash":9090,"dns":5353,"mixed":7890}}`); w.Code != http.StatusBadRequest {
		t.Errorf("malformed listen (no port) must be rejected at save: got %d, want 400", w.Code)
	}
}

func TestHandlePutConfig(t *testing.T) {
	cfg, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: cfg}

	// Missing listen -> 400.
	if w := putConfig(t, s, `{"ports":{"ui":8088,"clash":9090,"dns":5353,"mixed":7890}}`); w.Code != http.StatusBadRequest {
		t.Fatalf("missing listen: got %d, want 400", w.Code)
	}
	// Duplicate ports -> 400.
	if w := putConfig(t, s, `{"listen":":8088","ports":{"ui":8088,"clash":8088,"dns":5353,"mixed":7890}}`); w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate ports: got %d, want 400", w.Code)
	}
	// Valid PUT -> 200, and failsafe/watchdog persisted to the live config.
	good := `{"listen":":8088","demo":true,"ports":{"ui":8088,"clash":9090,"dns":5353,"mixed":7890},` +
		`"failsafe":{"target":"9.9.9.9","auto_reboot":true},"watchdog":{"notify_url":"https://hook.test/x"}}`
	w := putConfig(t, s, good)
	if w.Code != http.StatusOK {
		t.Fatalf("valid PUT: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["saved"] != true || resp["restart_needed"] != true {
		t.Fatalf("unexpected PUT response: %v", resp)
	}
	if s.cfg.FailSafe.Target != "9.9.9.9" || !s.cfg.FailSafe.AutoReboot {
		t.Errorf("failsafe not applied: %+v", s.cfg.FailSafe)
	}
	if s.cfg.Watchdog.NotifyURL != "https://hook.test/x" {
		t.Errorf("watchdog notify_url not applied: %q", s.cfg.Watchdog.NotifyURL)
	}
	if !s.cfg.Demo {
		t.Errorf("demo flag not applied")
	}
}
