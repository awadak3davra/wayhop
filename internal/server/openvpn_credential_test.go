package server

import (
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// An OpenVPN profile that signs in with a user name and password, saved without them, is reported in
// the review as that one exit not coming up - not refused by the generator, which would fail every
// connection's shared config. A certificate profile needs neither.
func TestEndpointFindings_OpenVPNCredentials(t *testing.T) {
	s, _ := sharehandlers_server(t)
	ep := func(params map[string]any) model.Endpoint {
		params["ca"] = "PEM"
		return model.Endpoint{ID: "ovpn", Name: "Provider", Enabled: true, Engine: model.EngineSingBox,
			Protocol: model.ProtoOpenVPN, Server: "vpn.example.com", Port: 1194, Params: params}
	}
	credential := func(e model.Endpoint) string {
		for _, f := range s.endpointFindings(model.Profile{Endpoints: []model.Endpoint{e}}, platform.CapabilitySet{}) {
			if f.ID == "endpoint.credential" {
				return f.Detail
			}
		}
		return ""
	}
	if d := credential(ep(map[string]any{"auth_user_pass": true})); d == "" {
		t.Error("auth-user-pass with no user name raised no credential finding")
	}
	if d := credential(ep(map[string]any{"auth_user_pass": true, "username": "u"})); d == "" {
		t.Error("auth-user-pass with no password raised no credential finding")
	}
	if d := credential(ep(map[string]any{"auth_user_pass": true, "username": "u", "password": "p"})); d != "" {
		t.Errorf("complete credentials raised %q", d)
	}
	if d := credential(ep(map[string]any{"cert": "PEM", "key": "PEM"})); d != "" {
		t.Errorf("a certificate profile raised %q", d)
	}
}
