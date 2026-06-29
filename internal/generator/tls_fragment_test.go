package generator

import (
	"encoding/base64"
	"testing"

	"velinx/internal/model"
)

// TestTLSFragment: the opt-in TLS-fragmentation flags emit on a plain-TLS outbound, are absent by
// default, and are NOT emitted alongside a Reality block (Reality has its own evasion; fragmenting
// its ClientHello would disturb the fingerprint mimicry).
func TestTLSFragment(t *testing.T) {
	out := tlsJSON(&model.TLS{Enabled: true, Type: "tls", SNI: "x.com", Fragment: true, RecordFragment: true})
	if out["fragment"] != true || out["record_fragment"] != true {
		t.Errorf("plain TLS: fragment=%v record_fragment=%v, want true/true", out["fragment"], out["record_fragment"])
	}

	base := tlsJSON(&model.TLS{Enabled: true, Type: "tls", SNI: "x.com"})
	if _, ok := base["fragment"]; ok {
		t.Error("fragment must be absent by default (byte-identical for existing profiles)")
	}

	pub := base64.StdEncoding.EncodeToString(make([]byte, 32)) // valid 32-byte reality key
	rty := tlsJSON(&model.TLS{Enabled: true, Type: "reality", SNI: "x.com", PublicKey: pub, Fragment: true, RecordFragment: true})
	if _, ok := rty["reality"]; !ok {
		t.Fatal("reality block should be present for this case")
	}
	if _, ok := rty["fragment"]; ok {
		t.Error("fragment must NOT be emitted alongside a reality block")
	}
}
