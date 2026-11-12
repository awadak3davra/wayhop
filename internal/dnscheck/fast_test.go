package dnscheck

import (
	"net/netip"
	"testing"
)

func TestFastCatalogValidation(t *testing.T) {
	// Acceptance test 12:
	// The catalog: unique ids, every IP parses and is public, every entry has DoH or DoT, every Filter known.
	if len(FastCatalog) == 0 {
		t.Fatal("FastCatalog is empty")
	}

	knownFilters := map[string]bool{
		"none":    true,
		"malware": true,
		"ads":     true,
		"family":  true,
	}

	ids := make(map[string]bool, len(FastCatalog))
	for _, e := range FastCatalog {
		if e.ID == "" {
			t.Errorf("entry with empty ID: %+v", e)
		}
		if ids[e.ID] {
			t.Errorf("duplicate catalog ID: %q", e.ID)
		}
		ids[e.ID] = true

		ip, err := netip.ParseAddr(e.IP)
		if err != nil {
			t.Errorf("entry %q: IP %q does not parse: %v", e.ID, e.IP, err)
		} else {
			if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				t.Errorf("entry %q: IP %q is not a public address", e.ID, e.IP)
			}
		}

		if e.DoHPath == "" && !e.DoT {
			t.Errorf("entry %q has neither DoH nor DoT", e.ID)
		}

		if !knownFilters[e.Filter] {
			t.Errorf("entry %q: unknown filter %q", e.ID, e.Filter)
		}
	}
}
