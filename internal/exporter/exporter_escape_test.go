package exporter

import (
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// TestShareLinkEscapesSpecialCredsAndName guards the userinfo + fragment encoding fixes:
// a password containing ':' / '@' / '/' / '?' must survive a round-trip (a bare ':' would
// be read as the user:pass separator and truncate the password on every client), and a name
// containing '+' must not become a space on import.
func TestShareLinkEscapesSpecialCredsAndName(t *testing.T) {
	cases := []struct {
		name string
		e    model.Endpoint
		pw   string
	}{
		{"trojan", model.Endpoint{
			Name: "My+VPS #1", Engine: model.EngineSingBox, Protocol: model.ProtoTrojan,
			Server: "1.2.3.4", Port: 443, Params: map[string]any{"password": "p:s@s/w?x"},
			TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "h"},
		}, "p:s@s/w?x"},
		{"hysteria2", model.Endpoint{
			Name: "Hop+Node", Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
			Server: "5.6.7.8", Port: 8443, Params: map[string]any{"password": "a:b@c"},
			TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "h"},
		}, "a:b@c"},
		{"tuic", model.Endpoint{
			Name: "T+1", Engine: model.EngineSingBox, Protocol: model.ProtoTUIC,
			Server: "9.9.9.9", Port: 443,
			Params: map[string]any{"uuid": "11111111-2222-3333-4444-555555555555", "password": "x:y@z"},
			TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "h"},
		}, "x:y@z"},
		{"shadowsocks", model.Endpoint{
			Name: "SS+Box", Engine: model.EngineSingBox, Protocol: model.ProtoShadowsocks,
			Server: "8.8.8.8", Port: 8388, Params: map[string]any{"method": "aes-256-gcm", "password": "p:w@d"},
		}, "p:w@d"},
	}
	for _, c := range cases {
		link, ok := ShareLink(c.e)
		if !ok {
			t.Fatalf("%s: ShareLink not ok", c.name)
		}
		got, err := importer.Parse(link)
		if err != nil {
			t.Fatalf("%s: re-import failed: %v\nlink=%s", c.name, err, link)
		}
		if pw, _ := got.Params["password"].(string); pw != c.pw {
			t.Errorf("%s: password = %q, want %q (colon-truncation regression)\nlink=%s", c.name, pw, c.pw, link)
		}
		if got.Name != c.e.Name {
			t.Errorf("%s: name = %q, want %q ('+' must not become a space)\nlink=%s", c.name, got.Name, c.e.Name, link)
		}
	}
}
