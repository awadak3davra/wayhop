package server

import (
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// A router that never turned this on must keep its saved revision through an update, or the panel
// raises unapplied changes nobody made.
func TestDesiredInputsCountTheDNSPortOnlyWhenItIsServed(t *testing.T) {
	cfg := config.Config{}
	cfg.Ports.DNS = 5353
	for _, tc := range []struct {
		name string
		dns  *model.DNSSettings
		want int
	}{
		{"no DNS plane", nil, 0},
		{"plane without the switch", &model.DNSSettings{Enabled: true}, 0},
		{"switch on a disabled plane", &model.DNSSettings{ServeClients: true}, 0},
		{"served", &model.DNSSettings{Enabled: true, ServeClients: true}, 5353},
	} {
		if got := desiredInputsV1(cfg, model.Profile{DNS: tc.dns}).DNSPort; got != tc.want {
			t.Errorf("%s: DNSPort = %d, want %d", tc.name, got, tc.want)
		}
	}
}
