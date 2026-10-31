package changeset

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// A pin added or replaced is a TLS review row of its own, each pin named by its first 8 hex digits.
func TestDescribeTLSNamesPins(t *testing.T) {
	a := strings.Repeat("a0fe70f9", 8)
	b := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab, 0xcd, 0xef, 0x12}, 8))
	tl := &model.TLS{Enabled: true, Type: "tls", SNI: "example.com", PinCertSHA256: []string{a}, PinPubKeySHA256: []string{b}}
	if got, want := describeTLS(tl), "tls, SNI example.com, certificate pin a0fe70f9, public-key pin abcdef12"; got != want {
		t.Errorf("describeTLS = %q, want %q", got, want)
	}
	ep := func(pins ...string) model.Profile {
		return model.Profile{Endpoints: []model.Endpoint{{ID: "a", Name: "A", Engine: model.EngineSingBox, Protocol: model.ProtoTrojan,
			Server: "192.0.2.1", Port: 443, Enabled: true, TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "example.com", PinCertSHA256: pins}}}}
	}
	cs := Diff("", "", ep(), ep(a), config.Config{}, config.Config{})
	var row *Change
	for i := range cs.Changes {
		if cs.Changes[i].Field == "TLS settings" {
			row = &cs.Changes[i]
		}
	}
	if row == nil || strings.Contains(row.Before, "pin") || !strings.Contains(row.After, "certificate pin a0fe70f9") {
		t.Fatalf("pin row = %+v (all %+v)", row, cs.Changes)
	}
}
