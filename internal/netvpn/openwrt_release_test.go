package netvpn

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// openwrt_release_test.go closes the loop the writer's other tests leave open: they check what
// RenderUCI EMITS, against expectations written in the same file by the same hand. This checks what
// a real uci gives BACK after being fed that output — on four OpenWrt releases spanning 19.07.10 to
// snapshot.
//
// The commands are the easy half. The half that can break in silence is reading: ParseUCIShow has
// to understand whatever `uci show` prints, and the list formatting it relies on ("one line,
// space-separated single-quoted values") had only been measured on 25.12. An older uci printing
// lists one-per-line would make the parser see a single value, and the post-write verification
// would then compare the wrong thing and report a match.
//
// The fixtures were captured by running RenderUCI's output through each release's own uci in an
// openwrt/rootfs container and saving `uci show network`. Every command succeeded on every release
// (counted per command, not by the script's exit status, which is only its last line's).

// releases are the fixtures that must exist. A missing file is a failure, never a skip: this test's
// whole value is covering releases the developer is not running, and quietly covering fewer of them
// than the name promises is the failure mode it exists to prevent.
var releases = []string{"19.07.10", "21.02.7", "24.10.4", "snapshot"}

// sampleForFixtures must match cmd/wrgen's sample, which produced the fixtures. It is duplicated
// rather than shared because wrgen is a throwaway; the assertions below are what keeps the two
// honest — a fixture generated from anything else fails them.
func sampleForFixtures() AWGInterface {
	return AWGInterface{
		Name:       "awgtest",
		PrivateKey: "cHJpdmF0ZWtleWZvcnRlc3Rpbmdvbmx5MTIzNA==",
		Addresses:  []string{"10.0.0.30/32", "fd00:9:1::30/128"},
		MTU:        1320,
		Obfuscation: map[string]string{
			"jc": "5", "jmin": "49", "jmax": "998",
			"s1": "0", "s2": "0", "s3": "25", "s4": "40",
			"h1": "500000000-900000000", "h2": "1000000000-1400000000",
			"h3": "1500000000-1900000000", "h4": "2000000000-2400000000",
			"i1": "0x11111111111111111111111111111111",
			"i2": "0x22222222222222222222222222222222",
			"i3": "0x33333333333333333333333333333333",
			"i4": "0x44444444444444444444444444444444",
			"i5": "0x55555555555555555555555555555555",
		},
		Peers: []AWGPeer{
			{
				Description:         "primary",
				PublicKey:           "cHVibGlja2V5b25lZm9ydGVzdGluZzEyMzQ1Njc4OTA=",
				EndpointHost:        "203.0.113.7",
				EndpointPort:        8443,
				AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
				PersistentKeepalive: 21,
			},
			{
				Description:  "roaming, no endpoint",
				PublicKey:    "cHVibGlja2V5dHdvZm9ydGVzdGluZzEyMzQ1Njc4OTA=",
				PresharedKey: "cHJlc2hhcmVka2V5Zm9ydGVzdGluZzEyMzQ1Njc4OTA=",
				AllowedIPs:   []string{"10.9.2.0/24"},
				Disabled:     true,
			},
		},
	}
}

func fixture(t *testing.T, release string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "uci-show-"+release+".txt"))
	if err != nil {
		t.Fatalf("fixture for OpenWrt %s is missing, so that release is not covered: %v", release, err)
	}
	if len(b) == 0 {
		t.Fatalf("fixture for OpenWrt %s is empty; an empty capture parses to nothing and passes every "+
			"per-field check by having no fields", release)
	}
	return string(b)
}

// What a real uci printed, read back through our parser, must be what we asked it to store — on
// every release, not just the one in front of us.
func TestParseUCIShow_RoundTripsThroughEveryRelease(t *testing.T) {
	want := sampleForFixtures()

	for _, rel := range releases {
		t.Run(rel, func(t *testing.T) {
			got, ok := ParseUCIShow(fixture(t, rel))[want.Name]
			if !ok {
				t.Fatalf("the interface is not in what uci gave back")
			}

			if len(got.Addresses) != 2 || got.Addresses[0] != want.Addresses[0] || got.Addresses[1] != want.Addresses[1] {
				t.Errorf("addresses read back as %v, want %v — this is the multi-value list line, and "+
					"reading only its first value is the failure this fixture exists to catch", got.Addresses, want.Addresses)
			}
			if got.MTU != want.MTU {
				t.Errorf("mtu %d, want %d", got.MTU, want.MTU)
			}
			if len(got.Obfuscation) != len(want.Obfuscation) {
				t.Errorf("read back %d obfuscation params, want %d", len(got.Obfuscation), len(want.Obfuscation))
			}
			for k, v := range want.Obfuscation {
				if got.Obfuscation[k] != v {
					t.Errorf("awg_%s read back as %q, want %q", k, got.Obfuscation[k], v)
				}
			}

			if len(got.Peers) != 2 {
				t.Fatalf("read back %d peers, want 2", len(got.Peers))
			}
			p0, p1 := got.Peers[0], got.Peers[1]
			if p0.PublicKey != want.Peers[0].PublicKey || p0.EndpointHost != "203.0.113.7" || p0.EndpointPort != 8443 {
				t.Errorf("peer 1 read back as %s:%d key=%q", p0.EndpointHost, p0.EndpointPort, p0.PublicKey)
			}
			if len(p0.AllowedIPs) != 2 {
				t.Errorf("peer 1 allowed_ips read back as %v, want both entries", p0.AllowedIPs)
			}
			if p0.PersistentKeepalive != 21 {
				t.Errorf("peer 1 keepalive %d, want 21", p0.PersistentKeepalive)
			}
			if p0.Disabled {
				t.Error("peer 1 came back disabled; it was written enabled")
			}

			// The roaming peer: no endpoint at all, and switched off. Disabled is the option that
			// exists in luci-proto-amneziawg and not in the WireGuard schema it was forked from, so
			// it is the one most easily lost.
			if p1.EndpointHost != "" || p1.EndpointPort != 0 {
				t.Errorf("the roaming peer came back with an endpoint %s:%d", p1.EndpointHost, p1.EndpointPort)
			}
			if !p1.Disabled {
				t.Error("peer 2 came back enabled; it was written disabled, and a tunnel that is off " +
					"reading as on is the difference between routing and not")
			}
			if p1.PresharedKey != want.Peers[1].PresharedKey {
				t.Errorf("peer 2 preshared key did not survive")
			}
		})
	}
}

// route_allowed_ips='0' is what keeps netifd out of the route table. Checking the rendered command
// proves we asked; checking what uci gave back proves it was stored.
func TestUCIRoundTrip_RouteAllowedIPsStaysOffOnEveryRelease(t *testing.T) {
	for _, rel := range releases {
		text := fixture(t, rel)
		for _, want := range []string{
			"network.awgtest_peer1.route_allowed_ips='0'",
			"network.awgtest_peer2.route_allowed_ips='0'",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: %q is not in what uci stored; netifd would install routes and our PBR "+
					"would no longer own the route table", rel, want)
			}
		}
	}
}

// Six years of releases print `uci show` the same way. Asserting it keeps that a measured fact: if a
// future release changes the format, this fails naming the release rather than the parser quietly
// reading one value where there were two.
func TestUCIShowFormat_IsIdenticalAcrossReleases(t *testing.T) {
	first := sum(fixture(t, releases[0]))
	for _, rel := range releases[1:] {
		if got := sum(fixture(t, rel)); got != first {
			t.Errorf("OpenWrt %s prints `uci show` differently from %s (%s vs %s); ParseUCIShow was "+
				"only ever measured against the shared format", rel, releases[0], got, first)
		}
	}
	// And the format itself, stated rather than implied: a multi-value list is ONE line with
	// space-separated single-quoted values.
	if !strings.Contains(fixture(t, releases[0]), "network.awgtest.addresses='10.0.0.30/32' 'fd00:9:1::30/128'") {
		t.Error("the multi-value list is no longer on one line; the parser's central assumption is gone")
	}
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}
