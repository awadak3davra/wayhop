package netvpn

import (
	"strings"
	"testing"
)

// liveUCIShow is `uci show network` from the AX3000T (OpenWrt 25.12.2), keys redacted, trimmed to
// the parts that matter. Both peer forms are present on purpose: awg0's peer is ANONYMOUS and
// awg1's is NAMED, which is exactly the pair a reader has to survive. The allowed_ips line carries
// four values on one line, which is how uci prints a list.
const liveUCIShow = `network.loopback=interface
network.loopback.proto='static'
network.wan=interface
network.wan.proto='dhcp'
network.awg0=interface
network.awg0.proto='amneziawg'
network.awg0.private_key='REDACTED0'
network.awg0.addresses='10.0.0.30/32'
network.awg0.mtu='1280'
network.awg0.awg_jc='5'
network.awg0.awg_s3='25'
network.awg0.awg_i1='0x11111111111111111111111111111111'
network.@amneziawg_awg0[0]=amneziawg_awg0
network.@amneziawg_awg0[0].description='WG_A_v2'
network.@amneziawg_awg0[0].public_key='PUB0'
network.@amneziawg_awg0[0].endpoint_host='203.0.113.10'
network.@amneziawg_awg0[0].endpoint_port='8443'
network.@amneziawg_awg0[0].persistent_keepalive='21'
network.@amneziawg_awg0[0].route_allowed_ips='0'
network.@amneziawg_awg0[0].allowed_ips='10.0.0.0/24' '10.0.1.0/28' '192.168.0.0/24' '0.0.0.0/0'
network.awg1=interface
network.awg1.proto='amneziawg'
network.awg1.private_key='REDACTED1'
network.awg1.addresses='10.20.0.10/32'
network.awg1.mtu='1320'
network.awg1_peer=amneziawg_awg1
network.awg1_peer.public_key='PUB1'
network.awg1_peer.endpoint_host='198.51.100.20'
network.awg1_peer.endpoint_port='8443'
network.awg1_peer.route_allowed_ips='0'
network.awg1_peer.allowed_ips='0.0.0.0/0'
`

func TestParseUCIShow_ReadsBothPeerFormsFromTheLiveRouter(t *testing.T) {
	got := ParseUCIShow(liveUCIShow)

	if len(got) != 2 {
		t.Fatalf("expected the two amneziawg interfaces, got %d: %v", len(got), keysOf(got))
	}
	// The plain interfaces must NOT come back: reading them as tunnels would put lan/wan in scope of
	// a writer that is only allowed to touch AmneziaWG.
	for _, notATunnel := range []string{"loopback", "wan"} {
		if _, ok := got[notATunnel]; ok {
			t.Errorf("%s was parsed as an AmneziaWG tunnel", notATunnel)
		}
	}

	a0 := got["awg0"]
	if a0.MTU != 1280 || first(a0.Addresses) != "10.0.0.30/32" {
		t.Errorf("awg0 scalars wrong: mtu=%d addresses=%v", a0.MTU, a0.Addresses)
	}
	if a0.Obfuscation["jc"] != "5" || a0.Obfuscation["s3"] != "25" ||
		a0.Obfuscation["i1"] != "0x11111111111111111111111111111111" {
		t.Errorf("the awg_ prefix was not stripped or a 3.x param was dropped: %v", a0.Obfuscation)
	}
	// The anonymous peer has to be attached by its section TYPE, which is the only link there is.
	if len(a0.Peers) != 1 {
		t.Fatalf("awg0: expected 1 peer from the anonymous section, got %d", len(a0.Peers))
	}
	if p := a0.Peers[0]; p.EndpointHost != "203.0.113.10" || p.EndpointPort != 8443 ||
		p.PersistentKeepalive != 21 || p.Description != "WG_A_v2" {
		t.Errorf("awg0 peer wrong: %+v", p)
	}
	// A list is several quoted tokens on ONE line — splitting naively yields one value or four
	// fragments, and either would make the before/after comparison disagree with itself forever.
	if len(a0.Peers[0].AllowedIPs) != 4 || a0.Peers[0].AllowedIPs[3] != "0.0.0.0/0" {
		t.Errorf("allowed_ips list not split into 4 values: %v", a0.Peers[0].AllowedIPs)
	}

	a1 := got["awg1"]
	if len(a1.Peers) != 1 || a1.Peers[0].EndpointHost != "198.51.100.20" {
		t.Errorf("awg1: the NAMED peer section was not attached: %+v", a1.Peers)
	}
}

// The write path exists to be checked against the read path. If a rendered plan cannot be read back
// into the same value, every before/after comparison is comparing two different notions of the same
// tunnel and would report drift that is not there.
func TestRenderThenParse_RoundTrips(t *testing.T) {
	want := liveShapedIface()

	// Turn the plan back into what `uci show` would print. Only the two forms the renderer emits
	// need handling, which keeps this a test of the round trip rather than a second uci.
	var lines []string
	for _, c := range RenderUCI(want) {
		switch {
		case strings.HasPrefix(c, "uci set "):
			lines = append(lines, strings.TrimPrefix(c, "uci set "))
		case strings.HasPrefix(c, "uci add_list "):
			kv := strings.TrimPrefix(c, "uci add_list ")
			i := strings.Index(kv, "=")
			key, val := kv[:i], kv[i+1:]
			// uci prints a list as one line with the values space-separated; append to any existing.
			found := false
			for j, ln := range lines {
				if strings.HasPrefix(ln, key+"=") {
					lines[j] = ln + " " + val
					found = true
				}
			}
			if !found {
				lines = append(lines, key+"="+val)
			}
		}
	}
	got := ParseUCIShow(strings.Join(lines, "\n"))["awg0"]

	if got.MTU != want.MTU || got.PrivateKey != want.PrivateKey {
		t.Errorf("scalars lost: got mtu=%d key=%q", got.MTU, got.PrivateKey)
	}
	if len(got.Obfuscation) != len(want.Obfuscation) {
		t.Errorf("obfuscation params lost: wrote %d, read %d back", len(want.Obfuscation), len(got.Obfuscation))
	}
	for k, v := range want.Obfuscation {
		if got.Obfuscation[k] != v {
			t.Errorf("awg_%s: wrote %q, read %q", k, v, got.Obfuscation[k])
		}
	}
	if len(got.Peers) != 1 {
		t.Fatalf("peer lost in the round trip: %+v", got.Peers)
	}
	if len(got.Peers[0].AllowedIPs) != len(want.Peers[0].AllowedIPs) {
		t.Errorf("allowed_ips: wrote %v, read %v", want.Peers[0].AllowedIPs, got.Peers[0].AllowedIPs)
	}
}

// A value carrying a quote has to survive the whole loop — render escapes it, the reader must
// un-escape it — or the comparison reports drift on a tunnel nobody touched.
func TestRenderThenParse_SurvivesAQuoteInAValue(t *testing.T) {
	const desc = "peer 'one'"
	iface := liveShapedIface()
	iface.Peers[0].Description = desc

	var lines []string
	for _, c := range RenderUCI(iface) {
		if strings.HasPrefix(c, "uci set ") {
			lines = append(lines, strings.TrimPrefix(c, "uci set "))
		}
	}
	got := ParseUCIShow(strings.Join(lines, "\n"))["awg0"]
	if len(got.Peers) != 1 || got.Peers[0].Description != desc {
		t.Fatalf("description did not survive: wrote %q, read %q", desc, first([]string{got.Peers[0].Description}))
	}
}

// The check that protects the route table. It must find an enabled flag wherever it is, and must not
// cry wolf on the normal case — a false alarm here blocks a legitimate write.
func TestRoutesOwnedByNetifd(t *testing.T) {
	if bad := RoutesOwnedByNetifd(liveUCIShow); len(bad) != 0 {
		t.Errorf("the live config has route_allowed_ips=0 everywhere, but got: %v", bad)
	}
	altered := strings.Replace(liveUCIShow,
		"network.awg1_peer.route_allowed_ips='0'",
		"network.awg1_peer.route_allowed_ips='1'", 1)
	bad := RoutesOwnedByNetifd(altered)
	if len(bad) != 1 || bad[0] != "awg1_peer" {
		t.Fatalf("an enabled route_allowed_ips was not reported by section: %v", bad)
	}
}

func keysOf(m map[string]AWGInterface) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
