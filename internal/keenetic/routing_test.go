package keenetic

import (
	"strings"
	"testing"
)

func TestRouteCommands(t *testing.T) {
	routes := []Route{
		{CIDR: "0.0.0.0/0", Target: RouteTarget{Iface: "Wireguard5"}},                         // default via native AWG
		{CIDR: "10.0.0.0/24", Target: RouteTarget{Iface: "Wireguard5"}},                       // selective list → VPN
		{CIDR: "203.0.113.10/32", Target: RouteTarget{Iface: "ISP"}, Comment: "vpn endpoint"}, // anti-loop exception
		{CIDR: "109.254.0.0/16", Target: RouteTarget{Iface: "ISP"}, Auto: true, Comment: "RU direct"},
		{CIDR: "10.10.0.0/16", Target: RouteTarget{Reject: true}},         // blackhole
		{CIDR: "2001:db8::/32", Target: RouteTarget{Iface: "Wireguard5"}}, // v6
	}
	cmds, err := RouteCommands(routes)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip route 0.0.0.0 0.0.0.0 Wireguard5",
		"ip route 10.0.0.0 255.255.255.0 Wireguard5",
		"ip route 203.0.113.10 255.255.255.255 ISP !vpn_endpoint",
		"ip route 109.254.0.0 255.255.0.0 ISP auto !RU_direct",
		"ip route 10.10.0.0 255.255.0.0 reject",
		"ipv6 route 2001:db8::/32 Wireguard5",
	}
	got := strings.Join(cmds, "\n")
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("missing route %q\n--- got ---\n%s", w, got)
		}
	}
	if len(cmds) != len(routes) {
		t.Errorf("got %d cmds, want %d", len(cmds), len(routes))
	}
}

func TestRouteCommands_Errors(t *testing.T) {
	if _, err := RouteCommands([]Route{{CIDR: "10.0.0.0/8" /* no iface, not reject */}}); err == nil {
		t.Error("route with no iface and no reject must error")
	}
	if _, err := RouteCommands([]Route{{CIDR: "not-an-ip", Target: RouteTarget{Iface: "ISP"}}}); err == nil {
		t.Error("bad CIDR must error")
	}
}

func TestSanitizeComment(t *testing.T) {
	if got := sanitizeComment("RU direct! (banks)"); got != "RU_direct_banks" {
		t.Errorf("sanitizeComment = %q", got)
	}
}
