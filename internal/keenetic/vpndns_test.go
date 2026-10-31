package keenetic

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// A resolver that asks a VPN connection's pushed resolvers has no address and no detour, which read as
// a plain resolver going direct - one dnsmasq could carry. Only the core can reach those resolvers, and
// the reason says which connection.
func TestDNSPlaneNeedsCoreForVPNResolvers(t *testing.T) {
	p := &model.Profile{DNS: &model.DNSSettings{Enabled: true, Servers: []model.DNSServer{
		{Tag: "isp", Type: "udp", Server: "192.0.2.53", Enabled: true},
		{Tag: "office-dns", Type: "openvpn", Endpoint: "ovpn", Enabled: true},
	}}}
	reasons := dnsPlaneCoreReasons(p)
	if len(reasons) != 1 || !strings.Contains(reasons[0], `"office-dns"`) || !strings.Contains(reasons[0], `"ovpn"`) {
		t.Fatalf("reasons = %q", reasons)
	}
	p.DNS.Servers[1].Enabled = false
	if dnsPlaneNeedsCore(p) {
		t.Fatal("a switched-off VPN resolver must not require the core")
	}
}
