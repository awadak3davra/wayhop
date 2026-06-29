package exporter

import (
	"strings"
	"testing"

	"velinx/internal/importer"
	"velinx/internal/model"
)

// TestAnyTLSRoundTrip: an AnyTLS endpoint exports to an anytls:// link that re-imports to the same
// core fields (password, server, port, TLS) — covering both anytlsLink and the importer's parseAnyTLS.
func TestAnyTLSRoundTrip(t *testing.T) {
	e := model.Endpoint{
		Protocol: model.ProtoAnyTLS, Server: "1.2.3.4", Port: 8443, Name: "NL",
		Params: map[string]any{"password": "mypass"},
		TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "example.com", Insecure: true, Fingerprint: "chrome"},
	}
	link, ok := ShareLink(e)
	if !ok || !strings.HasPrefix(link, "anytls://") {
		t.Fatalf("ShareLink = %q (ok=%v), want an anytls:// link", link, ok)
	}

	got, err := importer.Parse(link)
	if err != nil {
		t.Fatalf("re-import %q: %v", link, err)
	}
	if got.Protocol != model.ProtoAnyTLS || got.Server != "1.2.3.4" || got.Port != 8443 {
		t.Errorf("core: protocol=%v server=%s port=%d", got.Protocol, got.Server, got.Port)
	}
	if got.Params["password"] != "mypass" {
		t.Errorf("password=%v, want mypass", got.Params["password"])
	}
	if got.TLS == nil || got.TLS.SNI != "example.com" || !got.TLS.Insecure {
		t.Errorf("TLS round-trip: %+v", got.TLS)
	}
	if got.Transport != nil {
		t.Errorf("AnyTLS must have no transport, got %+v", got.Transport)
	}
}
