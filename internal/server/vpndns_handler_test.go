package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// vpnDNSSeed adds an OpenVPN connection, a DNS server asking its pushed resolvers and a rule to it.
func vpnDNSSeed(t *testing.T) (*Server, model.Endpoint) {
	t.Helper()
	s := dnsSeed(t)
	ovpn := model.Endpoint{ID: "ovpn", Name: "Office", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoOpenVPN,
		Server: "192.0.2.10", Port: 1194, Params: map[string]any{"ca": "test-ca"}}
	if err := s.store.UpsertEndpoint(ovpn); err != nil {
		t.Fatal(err)
	}
	dns := &model.DNSSettings{Enabled: true, Final: "doh", Servers: []model.DNSServer{
		{Tag: "doh", Type: "https", Server: "192.0.2.53", Enabled: true},
		{Tag: "office-dns", Type: "openvpn", Endpoint: "ovpn", Enabled: true},
	}, Rules: []model.DNSRule{{ID: "office", DomainSuffix: []string{"corp.example"}, Server: "office-dns"}}}
	if _, err := s.store.SetDNSIfGen(dns, s.store.Gen()); err != nil {
		t.Fatal(err)
	}
	return s, ovpn
}

// Changing the connection's protocol in its form used to save, leaving the DNS server asking a
// connection of the wrong kind: every Apply then failed, and the DNS page could not switch the server
// off in one step while its rule targeted it. It is refused at the save, naming the server.
func TestVPNResolverHandler_ProtocolChangeRefused(t *testing.T) {
	s, ovpn := vpnDNSSeed(t)
	ovpn.Protocol = model.ProtoOpenConnect
	ovpn.Params = map[string]any{"username": "u", "password": "p"}
	body, _ := json.Marshal(ovpn)
	w := profilehandlers_post(s.handleUpsertEndpoint, string(body))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "office-dns") {
		t.Fatalf("got %d (%s), want 409 naming office-dns", w.Code, w.Body.String())
	}
	p := s.store.Profile()
	if e := p.EndpointByID("ovpn"); e == nil || e.Protocol != model.ProtoOpenVPN {
		t.Fatalf("the connection changed despite the refusal: %+v", e)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("profile left invalid: %v", err)
	}
	// A bulk import (or a subscription refresh) bringing another protocol or engine under the same id
	// is stored as a new connection (importer.DedupeNew keys content on both), so it strands nothing.
	orig := p.Endpoints[1]
	orig.Engine = model.EngineOpenVPN
	eng, _ := json.Marshal(orig)
	for _, b := range [][]byte{body, eng} {
		w = profilehandlers_post(s.handleBulkEndpoints, `{"endpoints":[`+string(b)+`]}`)
		p = s.store.Profile()
		e := p.EndpointByID("ovpn")
		if w.Code != http.StatusOK || e == nil || e.Protocol != model.ProtoOpenVPN || e.Engine != model.EngineSingBox || p.Validate() != nil {
			t.Fatalf("bulk: %d (%s), ovpn = %+v", w.Code, w.Body.String(), e)
		}
	}
}
