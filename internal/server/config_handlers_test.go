package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"velinx/internal/config"
)

// TestPutConfig_RoundTripsGateway guards the cutover toggle: PUT /api/config must
// persist the gateway flag (a regression once dropped it silently), and it must
// flow through genOptions into TunEnabled.
func TestPutConfig_RoundTripsGateway(t *testing.T) {
	s := opshandlers_server(t)
	// Give the live config a file path so Save() works (Default() has none).
	path := filepath.Join(t.TempDir(), "config.json")
	data, _ := json.Marshal(s.cfg)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s.cfg = loaded

	cfg := s.config()
	cfg.Gateway = true
	body, _ := json.Marshal(cfg)
	w := opshandlers_post(s.handlePutConfig, "/api/config", string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /api/config = %d: %s", w.Code, w.Body.String())
	}
	if !s.config().Gateway {
		t.Fatal("handlePutConfig dropped the gateway flag")
	}
	gp := s.store.Profile()
	if !s.genOptions(&gp).TunEnabled {
		t.Fatal("gateway=true did not set genOptions().TunEnabled")
	}
}

// TestPutConfig_RoundTripsAllowedHosts guards the Host allow-list (DNS-rebinding)
// setting against the same field-silently-dropped regression the gateway flag once
// hit: handlePutConfig applies the decoded config field-by-field, so a new field is
// easy to omit. PUT /api/config must persist allowed_hosts both in the live config
// and to disk (the guard reads it from the saved config on the next restart).
func TestPutConfig_RoundTripsAllowedHosts(t *testing.T) {
	s := opshandlers_server(t)
	path := filepath.Join(t.TempDir(), "config.json")
	data, _ := json.Marshal(s.cfg)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s.cfg = loaded

	want := []string{"192.168.2.1", "router.lan"}
	cfg := s.config()
	cfg.AllowedHosts = want
	body, _ := json.Marshal(cfg)
	w := opshandlers_post(s.handlePutConfig, "/api/config", string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /api/config = %d: %s", w.Code, w.Body.String())
	}

	got := s.config().AllowedHosts
	if len(got) != len(want) || (len(got) > 0 && (got[0] != want[0] || got[1] != want[1])) {
		t.Fatalf("handlePutConfig dropped allowed_hosts: got %v, want %v", got, want)
	}
	// Must also be persisted to disk, not just live memory (the guard reloads it).
	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.AllowedHosts) != len(want) {
		t.Fatalf("allowed_hosts not persisted to disk: got %v, want %v", reloaded.AllowedHosts, want)
	}
}
