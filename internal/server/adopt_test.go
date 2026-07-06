package server

import (
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/netvpn"
)

// TestEndpointFromDiscovered locks the EngineExternal adoption mapping: an OS-owned
// native tunnel becomes a DISABLED external endpoint with the iface, the anti-loop
// endpoint_ip (peer host, port stripped), the public key, and the discovered marker.
// Synthetic data only.
func TestEndpointFromDiscovered(t *testing.T) {
	d := netvpn.DiscoveredVPN{
		Iface:     "awg0",
		Type:      "amneziawg",
		PublicKey: "iface-pub-key-aaaa",
		Peers: []netvpn.Peer{
			{PublicKey: "peer-pub-1", Endpoint: "203.0.113.7:51820", AllowedIPs: []string{"0.0.0.0/0"}},
		},
	}
	got := endpointFromDiscovered(d)

	if got.Engine != model.EngineExternal {
		t.Errorf("Engine = %q, want %q", got.Engine, model.EngineExternal)
	}
	if got.Enabled {
		t.Error("Enabled = true, want false (adoption must not auto-enable)")
	}
	if got.ID != "external-awg0" {
		t.Errorf("ID = %q, want stable %q", got.ID, "external-awg0")
	}
	if got.Name != "awg0 (native)" {
		t.Errorf("Name = %q, want %q", got.Name, "awg0 (native)")
	}
	if got.Server != "" || got.Port != 0 {
		t.Errorf("external endpoint must have no Server/Port, got server=%q port=%d", got.Server, got.Port)
	}
	if got.Protocol != model.Protocol("amneziawg") {
		t.Errorf("Protocol = %q, want descriptive %q", got.Protocol, "amneziawg")
	}
	if iface, _ := got.Params["interface"].(string); iface != "awg0" {
		t.Errorf("params[interface] = %q, want %q", iface, "awg0")
	}
	if ip, _ := got.Params["endpoint_ip"].(string); ip != "203.0.113.7" {
		t.Errorf("params[endpoint_ip] = %q, want host-only %q (anti-loop bypass)", ip, "203.0.113.7")
	}
	if pk, _ := got.Params["public_key"].(string); pk != "iface-pub-key-aaaa" {
		t.Errorf("params[public_key] = %q, want %q", pk, "iface-pub-key-aaaa")
	}
	if disc, _ := got.Params["discovered"].(bool); !disc {
		t.Error("params[discovered] = false, want true")
	}
	// The adopted endpoint must pass model validation (external needs only interface).
	prof := model.Profile{Endpoints: []model.Endpoint{got}}
	if err := prof.Validate(); err != nil {
		t.Errorf("adopted endpoint fails Validate: %v", err)
	}
}

// TestEndpointFromDiscovered_NoPeerEndpoint covers a roaming/peerless tunnel: no
// endpoint_ip is set (nothing to bypass) and the rest of the mapping still holds.
func TestEndpointFromDiscovered_NoPeerEndpoint(t *testing.T) {
	d := netvpn.DiscoveredVPN{
		Iface:     "wg1",
		Type:      "wireguard",
		PublicKey: "iface-pub-key-bbbb",
		Peers:     []netvpn.Peer{{PublicKey: "peer-roaming"}}, // no Endpoint
	}
	got := endpointFromDiscovered(d)

	if _, ok := got.Params["endpoint_ip"]; ok {
		t.Errorf("params[endpoint_ip] should be absent when no peer endpoint, got %v", got.Params["endpoint_ip"])
	}
	if got.ID != "external-wg1" {
		t.Errorf("ID = %q, want %q", got.ID, "external-wg1")
	}
	if got.Engine != model.EngineExternal || got.Enabled {
		t.Errorf("Engine/Enabled = %q/%v, want external/false", got.Engine, got.Enabled)
	}
}

// TestEndpointFromDiscovered_NamedTunnel covers an NDM-discovered tunnel that carries
// a human description: the name is used, the iface still drives the stable ID.
func TestEndpointFromDiscovered_NamedTunnel(t *testing.T) {
	d := netvpn.DiscoveredVPN{
		Iface: "nwg1",
		Type:  "wireguard",
		Name:  "Office",
		Peers: []netvpn.Peer{{Endpoint: "198.51.100.4:443"}},
	}
	got := endpointFromDiscovered(d)
	if got.Name != "Office (native)" {
		t.Errorf("Name = %q, want %q", got.Name, "Office (native)")
	}
	if got.ID != "external-nwg1" {
		t.Errorf("ID = %q, want %q", got.ID, "external-nwg1")
	}
	if ip, _ := got.Params["endpoint_ip"].(string); ip != "198.51.100.4" {
		t.Errorf("params[endpoint_ip] = %q, want %q", ip, "198.51.100.4")
	}
}

// TestEndpointFromDiscovered_NDMName locks the native-toggle mapping capture: an
// NDM-discovered tunnel carries its raw NDM name into params["ndm_name"] (so the managed
// toggle targets the right interface without guessing), while a wg/awg-dump tunnel with no
// NDM name gets no such key.
func TestEndpointFromDiscovered_NDMName(t *testing.T) {
	ndm := netvpn.DiscoveredVPN{Iface: "nwg5", NDMName: "Wireguard5", Type: "amneziawg", Name: "ND_NL"}
	got := endpointFromDiscovered(ndm)
	if n, _ := got.Params["ndm_name"].(string); n != "Wireguard5" {
		t.Errorf("params[ndm_name] = %q, want %q", n, "Wireguard5")
	}

	// wg/awg dump (OpenWrt) has no NDM name ⇒ no ndm_name param at all.
	dump := netvpn.DiscoveredVPN{Iface: "awg0", Type: "amneziawg", PublicKey: "pk"}
	got2 := endpointFromDiscovered(dump)
	if _, ok := got2.Params["ndm_name"]; ok {
		t.Errorf("params[ndm_name] should be absent for a dump-discovered tunnel, got %v", got2.Params["ndm_name"])
	}
}

// TestPeerEndpointHost checks host extraction across IPv4, IPv6, and missing-port forms.
func TestPeerEndpointHost(t *testing.T) {
	cases := []struct {
		name  string
		peers []netvpn.Peer
		want  string
	}{
		{"ipv4 host:port", []netvpn.Peer{{Endpoint: "203.0.113.7:51820"}}, "203.0.113.7"},
		{"ipv6 bracketed host:port", []netvpn.Peer{{Endpoint: "[2001:db8::1]:51820"}}, "2001:db8::1"},
		{"ipv6 bracketed no port", []netvpn.Peer{{Endpoint: "[2001:db8::1]"}}, "2001:db8::1"},
		{"host no port", []netvpn.Peer{{Endpoint: "vpn.example.test"}}, "vpn.example.test"},
		{"skips empty, takes first with endpoint", []netvpn.Peer{{Endpoint: ""}, {Endpoint: "192.0.2.9:1234"}}, "192.0.2.9"},
		{"none", []netvpn.Peer{{Endpoint: ""}}, ""},
		{"no peers", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := peerEndpointHost(tc.peers); got != tc.want {
				t.Errorf("peerEndpointHost = %q, want %q", got, tc.want)
			}
		})
	}
}
