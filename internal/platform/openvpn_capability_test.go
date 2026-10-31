package platform

import (
	"strings"
	"testing"
)

// The Components page names the core a protocol needs from this map; it must reach the API (QA-017).
func TestCapabilities_ExposeSingboxMinMinor(t *testing.T) {
	for _, c := range []Capabilities{DetectCapabilities(), DemoCapabilities()} {
		for _, proto := range []string{"openvpn", "snell", "openconnect"} {
			if c.SingboxMinMinor[proto] != 14 {
				t.Errorf("%s: singbox_min_minor[%s] = %d, want 14", c.Platform, proto, c.SingboxMinMinor[proto])
			}
		}
		if _, ok := c.SingboxMinMinor["vless"]; ok {
			t.Errorf("%s: vless needs no newer core than WayHop's oldest", c.Platform)
		}
	}
}

// A core built without a protocol's tag cannot load that protocol, whatever its version: OpenWrt's
// package can switch each one off (SINGBOX_WITH_*). The gate reads the Tags line of the version
// output; with no Tags line it knows nothing and leaves the decision to the version gate.
func TestEvaluate_BuildTagsGateProtocols(t *testing.T) {
	caps := DemoCapabilities()
	release := "sing-box version 1.14.4\n\nEnvironment: go1.26.10 linux/arm64\nTags: with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_naive_outbound,with_openvpn,with_openconnect\n"
	trimmed := "sing-box version 1.14.4\n\nEnvironment: go1.26.10 linux/arm64\nTags: with_gvisor,with_utls\n"
	for _, tc := range []struct {
		name, version string
		usable        bool
	}{
		{"release build", release, true},
		{"no Tags line", "sing-box version 1.14.4", true},
		{"built without them", trimmed, false},
	} {
		rt := readyRuntime()
		rt.SingboxVersion = tc.version
		set := Evaluate(caps, rt)
		for proto, tag := range map[string]string{"openvpn": "with_openvpn", "openconnect": "with_openconnect", "hysteria2": "with_quic", "tuic": "with_quic"} {
			got := set.Get(CapProtocolPrefix + proto)
			if got.State.Usable() != tc.usable {
				t.Errorf("%s: %s usable = %v, want %v (%+v)", tc.name, proto, got.State.Usable(), tc.usable, got)
			}
			if !tc.usable && (got.Reason != ReasonBinaryLacksFeature || !strings.Contains(got.Remedy, tag)) {
				t.Errorf("%s: %s reason %q remedy %q, want BINARY_LACKS_FEATURE naming %s", tc.name, proto, got.Reason, got.Remedy, tag)
			}
		}
		if !set.Get(CapProtocolPrefix + "vless").State.Usable() {
			t.Errorf("%s: vless needs no tag and must stay usable", tc.name)
		}
	}
}

// OpenVPN rides sing-box's openvpn-client endpoint, which arrived in 1.14. A usable older core
// (the OpenWrt feeds ship 1.13.x) must not make the protocol look available: the review would then
// accept a connection the core cannot load.
func TestEvaluate_OpenVPNNeedsSingbox114(t *testing.T) {
	caps := DemoCapabilities()
	for _, tc := range []struct {
		version string
		usable  bool
	}{
		{"1.13.21", false},
		{"sing-box version 1.12.17\n\nEnvironment: go1.24.4 linux/arm64", false},
		{"1.14.4", true},
		{"sing-box version 1.15.0-alpha.13", true},
		{"", false},
	} {
		rt := readyRuntime()
		rt.SingboxVersion = tc.version
		// Snell and OpenConnect arrived in the same release and share the gate.
		for _, proto := range []string{"openvpn", "snell", "openconnect"} {
			got := Evaluate(caps, rt).Get(CapProtocolPrefix + proto)
			if got.State.Usable() != tc.usable {
				t.Errorf("sing-box %q: %s usable = %v, want %v (%+v)", tc.version, proto, got.State.Usable(), tc.usable, got)
			}
			if !tc.usable && (got.Reason != ReasonBinaryTooOld || !strings.Contains(got.Remedy, "1.14")) {
				t.Errorf("sing-box %q: %s reason %q remedy %q, want BINARY_TOO_OLD naming 1.14", tc.version, proto, got.Reason, got.Remedy)
			}
		}
		// The gate is OpenVPN's alone: the older core still carries every other proxy protocol.
		if !Evaluate(caps, rt).Get(CapProtocolPrefix + "vless").State.Usable() {
			t.Errorf("sing-box %q: vless must stay usable", tc.version)
		}
	}
}
