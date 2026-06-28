package kb

import "testing"

// TestLocalPortAndFdEntries: the two router-failure entries match their representative log lines
// (WakeRoute's own :7890/:9090 binding, and fd exhaustion) and carry a cause + fix, while NOT
// firing on the provisioned-inbound port conflict (which has its own dedicated entry).
func TestLocalPortAndFdEntries(t *testing.T) {
	matches := []struct{ line, wantID string }{
		{`FATAL[0000] start service: initialize inbound/mixed[mixed-in]: listen tcp 127.0.0.1:7890: bind: address already in use`, "local-port-in-use"},
		{`FATAL[0000] start service: create clash api server: listen tcp 127.0.0.1:9090: bind: address already in use`, "local-port-in-use"},
		{`ERROR dial tcp 1.2.3.4:443: socket: too many open files`, "gen-too-many-files"},
	}
	for _, c := range matches {
		if !hasID(c.line, c.wantID) {
			t.Errorf("line %q did not match %q (got %v)", c.line, c.wantID, gotIDs(c.line))
		}
		if e := entryByID(c.wantID); e == nil || e.Title == "" || e.Fix == "" {
			t.Errorf("entry %q missing title/fix", c.wantID)
		}
	}

	// The provisioned-inbound (8443) conflict must NOT trigger the local-port entry — that case is
	// covered by inbound-port-in-use, and the two must stay disjoint.
	provisioned := `start inbound/vmess[in]: listen tcp 0.0.0.0:8443: bind: address already in use`
	if hasID(provisioned, "local-port-in-use") {
		t.Errorf("provisioned :8443 conflict wrongly matched local-port-in-use (got %v)", gotIDs(provisioned))
	}
	if !hasID(provisioned, "inbound-port-in-use") {
		t.Errorf("provisioned :8443 conflict should match inbound-port-in-use (got %v)", gotIDs(provisioned))
	}
}
