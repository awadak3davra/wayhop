package generator

import (
	"testing"

	"wayhop/internal/model"
)

// TestAnyTLSOutbound: an AnyTLS endpoint generates a `type: anytls` outbound carrying its password
// and (since AnyTLS is tlsCapable) a tls block — mirroring Trojan.
func TestAnyTLSOutbound(t *testing.T) {
	e := generator_singBoxEndpoint("a", model.ProtoAnyTLS, map[string]any{"password": "pw"})
	e.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: "x.com", Insecure: true}
	ob, err := outboundFor(&e)
	if err != nil {
		t.Fatalf("outboundFor: %v", err)
	}
	if ob["type"] != "anytls" {
		t.Errorf("type=%v, want anytls", ob["type"])
	}
	if ob["password"] != "pw" {
		t.Errorf("password=%v, want pw", ob["password"])
	}
	if _, ok := ob["tls"].(map[string]any); !ok {
		t.Errorf("AnyTLS must carry a tls block (it is tlsCapable), got %v", ob["tls"])
	}
}
