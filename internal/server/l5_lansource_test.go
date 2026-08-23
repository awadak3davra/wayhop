package server

import (
	"net/netip"
	"testing"
)

// TestOnlyLANDevicesAreCalledDevices (L5): the card is headed "per device on your network", so what
// it lists has to be devices on that network.
//
// The aggregation filtered destinations only. Every conntrack row with a public destination became a
// "device" keyed by its source, and rows whose source is the far side of a tunnel came in with the
// rest. Measured on a live Keenetic: 30 listed, 23 on the LAN (192.168.0.0/24, the br0
// subnet), and seven from tunnel networks — 10.0.1.x, 10.50.1.x, 10.50.2.x, 10.50.3.x,
// 10.50.4.x, 172.31.1.x, 172.31.2.x. Nearly a quarter of a list someone reads to find which of
// THEIR devices is leaking.
// The host octets are deliberately .20/.30/.2 and never .1x: the publish scrub rewrites the literal
// "192.168.50.1" to "192.168.50.1" (it hides the operator's own LAN), and that is a SUBSTRING rule —
// it turns "192.168.50.10" into "192.168.50.10" while leaving the "192.168.0.0/24" prefix alone, so
// every address here fell outside the LAN and this test failed in the published tree only. Found by
// the scrub-output gate, whose whole purpose is that divergence.
func TestOnlyLANDevicesAreCalledDevices(t *testing.T) {
	lan := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")}
	conns := []Conn{
		{Src: "192.168.0.20", Dst: "203.0.113.5", Mark: 0, UpBytes: 1, DownBytes: 2},
		{Src: "192.168.0.30", Dst: "203.0.113.6", Mark: 0, UpBytes: 1, DownBytes: 2},
		{Src: "10.0.1.2", Dst: "203.0.113.7", Mark: 0, UpBytes: 1, DownBytes: 2},  // socks peer
		{Src: "10.50.2.9", Dst: "203.0.113.8", Mark: 0, UpBytes: 1, DownBytes: 2}, // tunnel network
	}
	out := aggregateClientDests(conns, map[string]string{}, func(uint32) string { return "direct" }, nil, 50, lan, nil)
	if len(out) != 2 {
		t.Fatalf("only the two LAN sources are devices, got %d: %+v", len(out), out)
	}
	for _, c := range out {
		if c.IP != "192.168.0.20" && c.IP != "192.168.0.30" {
			t.Errorf("a tunnel-side address is not a device on this network: %q", c.IP)
		}
	}

	// No opinion must mean "show everything", not "show nothing": a host whose interfaces cannot be
	// read would otherwise get an empty card, which is a worse answer than a few rows too many.
	if all := aggregateClientDests(conns, map[string]string{}, func(uint32) string { return "direct" }, nil, 50, nil, nil); len(all) != 4 {
		t.Errorf("with no LAN prefixes every source is still listed, got %d", len(all))
	}

	// The router is not a device on its own network. Its ppp0 address was listed as one: a
	// point-to-point interface masks to /32, so the prefix contains exactly the router.
	self := map[string]bool{"192.168.0.2": true}
	if isLANSource("192.168.0.2", lan, self) {
		t.Error("the router itself must not be listed among the devices on its network")
	}
	if !isLANSource("192.168.0.20", lan, self) {
		t.Error("and an ordinary LAN device must still be listed")
	}

	// A source that is not an address at all is not a device either.
	if isLANSource("not-an-ip", lan, nil) {
		t.Error("an unparseable source must not count as a LAN device")
	}
}
