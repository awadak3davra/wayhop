package config

import "testing"

// The probe port follows the mixed port, never lands on another of the daemon's ports or in the
// engine plugins' SOCKS block, and gives up rather than guess.
func TestPortsProbe(t *testing.T) {
	for _, tc := range []struct {
		p    Ports
		want int
	}{
		{Ports{UI: 8088, Clash: 9090, DNS: 5353, Mixed: 7890}, 17890},
		{Ports{UI: 17890, Clash: 9090, DNS: 5353, Mixed: 7890}, 17891},
		{Ports{UI: 8088, Clash: 9090, DNS: 5353, Mixed: 7905}, 0}, // 17905-17914: all in the plugin block
		{Ports{UI: 8088, Clash: 9090, DNS: 5353, Mixed: 7895}, 17895},
		{Ports{UI: 8088, Clash: 9090, DNS: 5353, Mixed: 60000}, 50000},
	} {
		if got := tc.p.Probe(); got != tc.want {
			t.Errorf("Probe(%+v) = %d, want %d", tc.p, got, tc.want)
		}
	}
}
