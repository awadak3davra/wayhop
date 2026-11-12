package dnscheck

import (
	"strings"
	"testing"
)

func TestFastCatalogLeavesOutStateOperators(t *testing.T) {
	addresses := []string{"77.88.", "223.5.5.", "223.6.6.", "1.12.12.", "120.53.", "119.29.", "86.54.11.", "86.54.1.", "178.22.122.", "185.51.200."}
	names := []string{"yandex", "alidns", "dot.pub", "dnspod", "joindns4", "dns4eu", "shecan"}
	for _, e := range FastCatalog {
		for _, a := range addresses {
			if strings.HasPrefix(e.IP, a) {
				t.Errorf("%s: %s belongs to an operator a state owns, funds or reads", e.ID, e.IP)
			}
		}
		for _, n := range names {
			if strings.Contains(strings.ToLower(e.ID+" "+e.Name+" "+e.Host), n) {
				t.Errorf("%s: %q names an operator a state owns, funds or reads", e.ID, n)
			}
		}
	}
}
