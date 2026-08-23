package kb

import "testing"

// TestKB_UrltestTargetUnreachable covers the failover-tier-down diagnostic: the real
// sing-box urltest timeout log (observed live) must map to the failover-specific entry,
// while a plain (non-urltest) io-timeout must NOT (no false positive).
func TestKB_UrltestTargetUnreachable(t *testing.T) {
	line := "outbound/urltest[group-failover]: (dial tcp 77.88.44.242:443: i/o timeout | dial tcp 5.255.255.242:443: i/o timeout)"
	ids := map[string]bool{}
	for _, e := range Match(line) {
		ids[e.ID] = true
	}
	if !ids["urltest-target-unreachable"] {
		t.Errorf("urltest timeout line did not match the failover-specific entry; matched: %v", ids)
	}

	plain := "dial tcp 1.2.3.4:443: i/o timeout"
	for _, e := range Match(plain) {
		if e.ID == "urltest-target-unreachable" {
			t.Errorf("plain io-timeout wrongly matched the failover-specific entry")
		}
	}
}
