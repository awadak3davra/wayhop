package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// vpnDNSStore holds two OpenVPN connections and an OpenConnect one; a DNS server asks the first one's
// pushed resolvers and a rule sends the office domain there.
func vpnDNSStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	ovpn := func(id string) model.Endpoint {
		return model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoOpenVPN,
			Server: "192.0.2.10", Port: 1194, Params: map[string]any{"ca": "test-ca"}}
	}
	oc := model.Endpoint{ID: "oc", Name: "oc", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoOpenConnect,
		Server: "192.0.2.11", Port: 443}
	p := model.Profile{
		Endpoints: []model.Endpoint{ovpn("ovpn"), ovpn("ovpn2"), oc},
		DNS: &model.DNSSettings{Enabled: true, Final: "doh", Servers: []model.DNSServer{
			{Tag: "doh", Type: "https", Server: "192.0.2.53", Enabled: true},
			{Tag: "office-dns", Type: "openvpn", Endpoint: "ovpn", Enabled: true},
		}, Rules: []model.DNSRule{{ID: "office", DomainSuffix: []string{"corp.example"}, Server: "office-dns"}}},
	}
	if err := s.Replace(p); err != nil {
		t.Fatal(err)
	}
	return s
}

func hasDependent(ds []EndpointDependent, kind, id string) bool {
	for _, d := range ds {
		if d.Kind == kind && d.ID == id {
			return true
		}
	}
	return false
}

// A connection whose pushed resolvers a DNS server asks cannot be deleted from under it: that server
// would name a connection that is gone, which `sing-box check` lets through and the core dies on. The
// refusal names the way out that works: switching the server off alone is refused while a rule
// targets it, so it names detach (which parks both) and replace_with.
func TestVPNResolverBlocksDelete(t *testing.T) {
	s := vpnDNSStore(t)
	if !hasDependent(s.EndpointDependents("ovpn"), "dns_server", "office-dns") {
		t.Fatalf("dependents = %+v", s.EndpointDependents("ovpn"))
	}
	err := s.DeleteEndpoint("ovpn")
	if err == nil || !strings.Contains(err.Error(), "office-dns") || !strings.Contains(err.Error(), "?detach=1") ||
		!strings.Contains(err.Error(), "?replace_with=") || strings.Contains(err.Error(), "switch that resolver off first") {
		t.Fatalf("delete: err = %v", err)
	}
	if len(s.EndpointDependents("ovpn2")) != 0 {
		t.Errorf("ovpn2 has dependents: %+v", s.EndpointDependents("ovpn2"))
	}
}

// Deleting it anyway parks the resolver and its rule - switched off, kept - and the profile stays
// appliable.
func TestVPNResolverParkedOnDetach(t *testing.T) {
	s := vpnDNSStore(t)
	if err := s.DetachEndpointDependents("ovpn"); err != nil {
		t.Fatal(err)
	}
	p := s.Profile()
	if p.DNS.Servers[1].Enabled || !p.DNS.Rules[0].Disabled || p.DNS.Servers[1].Endpoint != "ovpn" {
		t.Errorf("not parked: %+v %+v", p.DNS.Servers[1], p.DNS.Rules[0])
	}
	if err := p.Validate(); err != nil {
		t.Errorf("parked profile: %v", err)
	}
}

// Moving the dependents to another OpenVPN connection moves the resolver; to anything without pushed
// resolvers (direct, an OpenConnect connection) it is parked instead.
func TestVPNResolverMovedOrParkedOnReplace(t *testing.T) {
	s := vpnDNSStore(t)
	if err := s.DeleteEndpointReplacing("ovpn", "ovpn2"); err != nil {
		t.Fatal(err)
	}
	p := s.Profile()
	if !p.DNS.Servers[1].Enabled || p.DNS.Servers[1].Endpoint != "ovpn2" || p.DNS.Rules[0].Disabled {
		t.Errorf("not moved: %+v %+v", p.DNS.Servers[1], p.DNS.Rules[0])
	}
	if err := p.Validate(); err != nil {
		t.Errorf("moved: %v", err)
	}
	for _, repl := range []string{model.OutboundDirect, "oc"} {
		s := vpnDNSStore(t)
		if err := s.DeleteEndpointReplacing("ovpn", repl); err != nil {
			t.Fatalf("%s: %v", repl, err)
		}
		p := s.Profile()
		if p.DNS.Servers[1].Enabled || !p.DNS.Rules[0].Disabled {
			t.Errorf("%s: not parked: %+v %+v", repl, p.DNS.Servers[1], p.DNS.Rules[0])
		}
		if err := p.Validate(); err != nil {
			t.Errorf("%s: %v", repl, err)
		}
	}
}

// Switching the connection off underneath an enabled resolver is refused (it would fail every later
// Apply), with the resolver among the blockers; switching it off with its dependents parks it.
func TestVPNResolverBlocksDisable(t *testing.T) {
	s := vpnDNSStore(t)
	off := s.Profile().Endpoints[0]
	off.Enabled = false
	if err := s.UpsertEndpoint(off); err == nil || !strings.Contains(err.Error(), "office-dns") {
		t.Fatalf("disable: err = %v", err)
	}
	if !hasDependent(s.EndpointDisableBlockers("ovpn"), "dns_server", "office-dns") {
		t.Fatalf("blockers = %+v", s.EndpointDisableBlockers("ovpn"))
	}
	if err := s.SetEndpointDisabledDetaching(off); err != nil {
		t.Fatal(err)
	}
	p := s.Profile()
	if p.Endpoints[0].Enabled || p.DNS.Servers[1].Enabled || !p.DNS.Rules[0].Disabled {
		t.Errorf("not parked: %+v %+v", p.DNS.Servers[1], p.DNS.Rules[0])
	}
	if err := p.Validate(); err != nil {
		t.Errorf("parked: %v", err)
	}
}

// Changing the connection's protocol or engine saved before: the edit itself is valid, only the DNS
// server it strands is not, and the guard above it refuses just the switched-off class. Every later
// Apply then failed, and the DNS page could not switch the server off while its rule targeted it. The
// write is refused, naming the server, and nothing is stored.
func TestVPNResolverStrandingEditRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(e *model.Endpoint)
		why  string
	}{
		{"protocol", func(e *model.Endpoint) { e.Protocol = model.ProtoOpenConnect }, "would be openconnect, not openvpn"},
		{"engine", func(e *model.Endpoint) { e.Engine = model.EngineOpenVPN }, "would not be run by the proxy core"},
	} {
		s := vpnDNSStore(t)
		e := s.Profile().Endpoints[0]
		c.edit(&e)
		err := s.UpsertEndpoint(e)
		var stranded *StrandedResolverError
		if !errors.As(err, &stranded) || !strings.Contains(err.Error(), `DNS server "office-dns"`) || !strings.Contains(err.Error(), c.why) {
			t.Fatalf("%s: err = %v", c.name, err)
		}
		p := s.Profile()
		if got := p.Endpoints[0]; got.Protocol != model.ProtoOpenVPN || got.Engine != model.EngineSingBox {
			t.Errorf("%s: stored anyway: %+v", c.name, got)
		}
		if _, err := s.UpsertEndpoints([]model.Endpoint{e}); !errors.As(err, &stranded) {
			t.Errorf("%s: bulk upsert: err = %v", c.name, err)
		}
	}
}

// The guard does not lean on the profile having validated before: one already invalid for an unrelated
// reason (a rule aimed at a connection that is gone) still refuses the stranding edit.
func TestVPNResolverStrandingRefusedOnInvalidProfile(t *testing.T) {
	s := vpnDNSStore(t)
	if err := s.UpsertRule(model.Rule{ID: "ghost", Domain: []string{"a.example"}, Outbound: "gone"}); err != nil {
		t.Fatal(err)
	}
	p := s.Profile()
	if p.Validate() == nil {
		t.Fatal("setup: the profile should be invalid")
	}
	e := p.Endpoints[0]
	e.Protocol = model.ProtoOpenConnect
	var stranded *StrandedResolverError
	if err := s.UpsertEndpoint(e); !errors.As(err, &stranded) {
		t.Fatalf("err = %v", err)
	}
}

// A server stranded before this write (a profile restored from disk that way) does not block writes
// that repair something else, or every edit would be refused until it is fixed.
func TestVPNResolverAlreadyStrandedDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	p := model.Profile{
		Endpoints: []model.Endpoint{{ID: "ovpn", Name: "ovpn", Enabled: true, Engine: model.EngineSingBox,
			Protocol: model.ProtoOpenConnect, Server: "192.0.2.10", Port: 443}},
		DNS: &model.DNSSettings{Enabled: true, Final: "doh", Servers: []model.DNSServer{
			{Tag: "doh", Type: "https", Server: "192.0.2.53", Enabled: true},
			{Tag: "office-dns", Type: "openvpn", Endpoint: "ovpn", Enabled: true},
		}},
	}
	data, _ := json.Marshal(p)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.StrandedVPNResolvers(&p)) != 1 {
		t.Fatalf("setup: %+v", model.StrandedVPNResolvers(&p))
	}
	if err := s.UpsertRule(model.Rule{ID: "r", Domain: []string{"a.example"}, Outbound: "ovpn"}); err != nil {
		t.Fatalf("an unrelated write was refused: %v", err)
	}
}
