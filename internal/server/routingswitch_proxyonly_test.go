package server

import (
	"testing"

	"wayhop/internal/platform"
)

func TestRoutingSwitchViewSaysWhenDevicesAreNotRouted(t *testing.T) {
	s := bindTestServer(t, feedProfile(), "")
	cases := []struct {
		name    string
		plat    platform.Platform
		mode    string
		gateway bool
		demo    bool
		want    bool
	}{
		{"OpenWrt, auto without the gateway setting is mixed", platform.OpenWrt, "", false, false, true},
		{"OpenWrt, mixed chosen", platform.OpenWrt, "mixed", false, false, true},
		{"OpenWrt, auto with the gateway setting is tun", platform.OpenWrt, "", true, false, false},
		{"OpenWrt, hybrid", platform.OpenWrt, "hybrid", false, false, false},
		{"KeeneticOS mixed is the router's own routing", platform.Keenetic, "mixed", false, false, false},
		{"the demo has no devices", platform.OpenWrt, "mixed", false, true, false},
	}
	for _, c := range cases {
		plat := c.plat
		s.platformOf = func() platform.Platform { return plat }
		s.cfg.RoutingMode, s.cfg.Gateway, s.cfg.Demo = c.mode, c.gateway, c.demo
		if got := s.routingSwitchView().ProxyOnly; got != c.want {
			t.Errorf("%s: proxy_only = %v, want %v", c.name, got, c.want)
		}
	}
}
