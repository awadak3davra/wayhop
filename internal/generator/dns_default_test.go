package generator

import (
	"testing"

	"wayhop/internal/model"
)

// model.DNSSettings.DefaultServer is what the leak checks judge as the resolver for unmatched
// queries (QA-105). It mirrors this generator: the emitted `final`, else the first emitted server,
// which sing-box makes the default when `final` is absent. If the emission rules here change (order,
// which servers are dropped), the checks must change with them, so the two are compared directly.
func TestDNSDefaultServerMatchesTheEmittedDefault(t *testing.T) {
	local := model.DNSServer{Tag: "dns_local", Type: "local", Enabled: true}
	doh := model.DNSServer{Tag: "cf", Type: "https", Server: "192.0.2.53", Path: "/dns-query", Detour: "nl", Enabled: true}
	fake := model.DNSServer{Tag: "fake", Type: "fakeip", Inet4Range: "198.18.0.0/15", Enabled: true}
	off := model.DNSServer{Tag: "off", Type: "local", Enabled: false}
	cases := []struct {
		name    string
		final   string
		servers []model.DNSServer
	}{
		{"no final, local first", "", []model.DNSServer{local, doh}},
		{"no final, encrypted first", "", []model.DNSServer{doh, local}},
		{"no final, fakeip first", "", []model.DNSServer{fake, local, doh}},
		{"no final, disabled first", "", []model.DNSServer{off, doh, local}},
		{"named final", "dns_local", []model.DNSServer{doh, local}},
		{"fakeip final", "fake", []model.DNSServer{fake, doh, local}},
	}
	for _, c := range cases {
		for _, tun := range []bool{false, true} {
			p := &model.Profile{
				Endpoints: []model.Endpoint{{ID: "nl", Engine: model.EngineExternal, Params: map[string]any{"interface": "awg0"}, Enabled: true}},
				DNS: &model.DNSSettings{Enabled: true, FakeIP: true, IndependentCache: true,
					Servers: c.servers, Final: c.final},
			}
			res, err := Generate(p, Options{MixedPort: 1080, TunEnabled: tun})
			if err != nil {
				t.Fatalf("%s tun=%v: %v", c.name, tun, err)
			}
			dns, _ := res.Config["dns"].(map[string]any)
			emitted, _ := dns["final"].(string)
			if emitted == "" {
				servers, _ := dns["servers"].([]map[string]any)
				if len(servers) > 0 {
					emitted, _ = servers[0]["tag"].(string)
				}
			}
			got := ""
			if s := p.DNS.DefaultServer(tun); s != nil {
				got = s.Tag
			}
			if got != emitted {
				t.Errorf("%s tun=%v: DefaultServer=%q, the generated core answers with %q", c.name, tun, got, emitted)
			}
		}
	}
}
