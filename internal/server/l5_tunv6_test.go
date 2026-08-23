package server

import "testing"

// TestTUNIPv6DroppedWhenAutoRouteOff (L5): an address that cannot do its job must not do damage.
//
// The generator puts fdfe:dcba:9876::1/126 on the TUN so auto_route ALSO installs the IPv6 defaults,
// without which a dual-stack client's v6 leaks past a v4-only TUN. The Keenetic binding turns
// auto_route OFF - NDM installs the route into wrtun0 instead - so on that platform the address can
// never buy what it was added for.
//
// It still costs: the kernel gets "fdfe:dcba:9876::/126 dev wrtun0", NDM cannot map wrtun0 to an
// interface it manages, and it answers every IPv6 route enumeration with a ~24-frame backtrace.
// Measured on a live router: 165 of 165 "unable to resolve" records named wrtun0, ~4000 log
// lines in 9.5 minutes, cutting the bounded native log to under ten minutes - the same log S99wayhop
// routes this daemon's own output into, so WayHop's own lines were evicted before anyone read them.
func TestTUNIPv6DroppedWhenAutoRouteOff(t *testing.T) {
	cfg := map[string]any{"inbounds": []map[string]any{
		{"type": "mixed", "tag": "mixed-in"},
		{"type": "tun", "tag": "tun-in", "address": []string{"172.31.3.1/30", "fdfe:dcba:9876::1/126"}},
	}}
	if err := bindKeeneticCompatibilityTUN(cfg); err != nil {
		t.Fatalf("bind: %v", err)
	}
	tun := cfg["inbounds"].([]map[string]any)[1]
	addrs, ok := tun["address"].([]string)
	if !ok {
		t.Fatalf("address is not a string list: %T", tun["address"])
	}
	if len(addrs) != 1 || addrs[0] != "172.31.3.1/30" {
		t.Errorf("the v4 host net stays and the v6 ULA goes, got %v", addrs)
	}
	// The binding is what makes the address pointless, so the two must not drift apart.
	if auto, _ := tun["auto_route"].(bool); auto {
		t.Error("this binding is only correct because auto_route is off")
	}

	// The reverse case is the one that must never regress: with auto_route ON the address is the
	// only thing standing between a dual-stack client and a plaintext v6 leak.
	keep := map[string]any{"auto_route": true,
		"address": []any{"172.31.3.1/30", "fdfe:dcba:9876::1/126"}}
	dropTUNIPv6WithoutAutoRoute(keep)
	if got := keep["address"].([]any); len(got) != 2 {
		t.Errorf("with auto_route on the v6 address must be left alone, got %v", got)
	}
}
