package server

import (
	"strings"
	"testing"
)

func TestDNSPresetsLeaveOutStateOperators(t *testing.T) {
	addresses := []string{"77.88.", "223.5.5.", "223.6.6.", "1.12.12.", "120.53.", "119.29.", "86.54.11.", "86.54.1.", "178.22.122.", "185.51.200."}
	names := []string{"yandex", "alidns", "dnspod", "dns4eu", "shecan"}
	for _, p := range dnsPresets {
		for _, a := range addresses {
			if strings.HasPrefix(p.Server, a) {
				t.Errorf("%s: %s belongs to an operator a state owns, funds or reads", p.Name, p.Server)
			}
		}
		for _, n := range names {
			if strings.Contains(strings.ToLower(p.Name), n) {
				t.Errorf("preset %q names an operator a state owns, funds or reads", p.Name)
			}
		}
	}
}
