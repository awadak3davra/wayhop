package server

import "testing"

// TestParseDefaultRouteDev covers the `ip -o route show default` shapes the offload probe
// must handle, including the real on-device line (double space before src), a PPPoE WAN,
// a no-dev line, and multiple defaults (first wins).
func TestParseDefaultRouteDev(t *testing.T) {
	cases := []struct{ in, want string }{
		{"default via 192.168.1.254 dev wan  src 192.168.1.70", "wan"}, // real device output
		{"default via 10.0.0.1 dev eth1 proto static metric 1", "eth1"},
		{"default dev pppoe-wan scope link", "pppoe-wan"},
		{"", ""},
		{"blackhole default", ""}, // no dev token
		{"default via 1.2.3.4 dev wan\ndefault via 5.6.7.8 dev wwan metric 20", "wan"}, // first wins
		{"dev", ""}, // trailing dev with no name must not panic
	}
	for _, c := range cases {
		if got := parseDefaultRouteDev(c.in); got != c.want {
			t.Errorf("parseDefaultRouteDev(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAppendUniqueStr(t *testing.T) {
	got := appendUniqueStr(appendUniqueStr([]string{"wan"}, "br-lan"), "wan")
	if len(got) != 2 || got[0] != "wan" || got[1] != "br-lan" {
		t.Errorf("appendUniqueStr dedup failed: %v", got)
	}
}

// TestParseBridgeLinks: the offload probe enumerates REAL bridges (OpenWrt br-lan, Keenetic br0,
// multi-bridge) from `ip -o link show type bridge`, stripping any @parent suffix.
func TestParseBridgeLinks(t *testing.T) {
	out := "3: br-lan: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT\n" +
		"5: br0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state UP\n" +
		"7: br-guest@eth0: <BROADCAST> mtu 1500\n"
	got := parseBridgeLinks(out)
	want := []string{"br-lan", "br0", "br-guest"}
	if len(got) != len(want) {
		t.Fatalf("parseBridgeLinks = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if len(parseBridgeLinks("")) != 0 {
		t.Errorf("empty input must yield no bridges")
	}
}

// TestPbrCompileOptions_OffloadGate: flow-offload is compiled ONLY where the kernel supports the
// nft flowtable. Demo poses as a capable OpenWrt box (offload honored); a Keenetic-PPE host has it
// forced off so preview/apply/reconcile agree and the best-effort transaction never runs.
func TestPbrCompileOptions_OffloadGate(t *testing.T) {
	s := opshandlers_server(t)
	s.cfg.Demo = true
	s.cfg.RoutingMode = "fast"
	s.cfg.Offload = "hw"
	s.cfg.OffloadDevices = []string{"br-lan"}
	if opts := s.pbrCompileOptions(s.config()); opts.Offload != "hw" {
		t.Errorf("demo (flowtable-capable): Offload = %q, want hw", opts.Offload)
	}

	s2 := opshandlers_server(t)
	s2.accelOnce.Do(func() { s2.accelKindCached = "ppe" }) // seed deterministically — no host probe
	s2.cfg.RoutingMode = "fast"
	s2.cfg.Offload = "hw"
	s2.cfg.OffloadDevices = []string{"br-lan"}
	if opts := s2.pbrCompileOptions(s2.config()); opts.Offload != "" {
		t.Errorf("ppe host: Offload = %q, want empty (gated off)", opts.Offload)
	}
}
