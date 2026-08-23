package server

import "testing"

// TestAllowedHosts_CopyAndEmpty: allowedHosts() returns nil when unset (the cheap disabled-default
// path the hostAllowGuard relies on) and an INDEPENDENT copy when set — a caller mutating the result
// must not corrupt the live config.
func TestAllowedHosts_CopyAndEmpty(t *testing.T) {
	s, _ := sharehandlers_server(t)

	if got := s.allowedHosts(); got != nil {
		t.Errorf("unset allowedHosts = %v, want nil (disabled default)", got)
	}

	s.cfg.AllowedHosts = []string{"router.lan", "10.0.0.1:8088"}
	got := s.allowedHosts()
	if len(got) != 2 || got[0] != "router.lan" || got[1] != "10.0.0.1:8088" {
		t.Fatalf("allowedHosts = %v, want the 2 configured hosts", got)
	}
	got[0] = "evil.example" // mutate the returned copy
	if s.cfg.AllowedHosts[0] != "router.lan" {
		t.Errorf("allowedHosts returned an aliased slice — a caller mutated the live config: %v", s.cfg.AllowedHosts)
	}
}
