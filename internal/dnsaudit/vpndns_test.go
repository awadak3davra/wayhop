package dnsaudit

import (
	"testing"

	"wayhop/internal/model"
)

// vpnProf sends a routing list's traffic to listOutbound and its lookups to the resolvers the
// OpenVPN connection "ovpn" pushes.
func vpnProf(listOutbound string) model.Profile {
	return model.Profile{
		RoutingLists: []model.RoutingList{{ID: "corp", Name: "Office", Outbound: listOutbound, Enabled: true}},
		DNS: &model.DNSSettings{
			Enabled: true,
			Servers: []model.DNSServer{
				{Tag: "doh", Type: "https", Server: "192.0.2.53", Enabled: true},
				{Tag: "office-dns", Type: "openvpn", Endpoint: "ovpn", Enabled: true},
			},
			Rules: []model.DNSRule{{ID: "r", RuleSets: []string{"corp"}, Server: "office-dns"}},
			Final: "doh",
		},
	}
}

// A VPN's pushed resolvers are reached through that connection's tunnel, so the connection is the exit
// of the lookup: a list whose traffic takes the same connection is coherent. Read as a server with no
// detour, it was "direct" - a plaintext lookup bypassing the tunnel - which it never is.
func TestDetectAsymmetric_VPNResolverThroughItsTunnel(t *testing.T) {
	if got := DetectAsymmetric(vpnProf("ovpn"), Plane{}); len(got) != 0 {
		t.Fatalf("lookups and traffic both through ovpn: %+v", got)
	}
}

// Traffic that leaves elsewhere is a mismatch, and never an exposure: the lookup only ever leaves
// through the tunnel. Nor is it counted as encrypted - past the VPN server it is usually plain DNS.
func TestDetectAsymmetric_VPNResolverOtherExit(t *testing.T) {
	for _, out := range []string{"direct", "vpn-nl"} {
		got := DetectAsymmetric(vpnProf(out), Plane{})
		if len(got) != 1 {
			t.Fatalf("%s: want one finding, got %+v", out, got)
		}
		a := got[0]
		if a.Exposed || a.Encrypted || a.DNSVia != "ovpn" || a.DNSServerTag != "office-dns" || a.TrafficVia != out {
			t.Errorf("%s: %+v", out, a)
		}
	}
}
