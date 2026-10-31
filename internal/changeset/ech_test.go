package changeset

import (
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

func TestDescribeTLSNamesECH(t *testing.T) {
	base := func(e *model.ECH) *model.TLS {
		return &model.TLS{Enabled: true, Type: "tls", SNI: "example.com", ECH: e}
	}
	for want, tl := range map[string]*model.TLS{
		"tls, SNI example.com":                                    base(nil),
		"tls, SNI example.com, ECH (config bbdebf38)":             base(&model.ECH{Enabled: true, Config: "AEb+DQ"}),
		"tls, SNI example.com, ECH (DNS)":                         base(&model.ECH{Enabled: true}),
		"tls, SNI example.com, ECH (DNS, example.net)":            base(&model.ECH{Enabled: true, QueryServerName: "example.net"}),
		"reality, SNI example.com":                                {Enabled: true, Type: "reality", SNI: "example.com", ECH: &model.ECH{Config: "AEb+DQ"}},
		"tls, SNI example.com, fragmented, ECH (config 2d711642)": {Enabled: true, Type: "tls", SNI: "example.com", Fragment: true, ECH: &model.ECH{Enabled: true, Config: "x"}},
	} {
		if got := describeTLS(tl); got != want {
			t.Errorf("describeTLS = %q, want %q", got, want)
		}
	}
	// Switching ECH on is a review row on its own, with the before and after it changed.
	ep := func(e *model.ECH) model.Profile {
		return model.Profile{Endpoints: []model.Endpoint{{ID: "a", Name: "A", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
			Server: "192.0.2.1", Port: 443, Enabled: true, TLS: base(e)}}}
	}
	tlsRow := func(cs *ChangeSet) *Change {
		for i := range cs.Changes {
			if cs.Changes[i].Field == "TLS settings" {
				return &cs.Changes[i]
			}
		}
		return nil
	}
	cs := Diff("", "", ep(nil), ep(&model.ECH{Enabled: true, Config: "AEb+DQ"}), config.Config{}, config.Config{})
	row := tlsRow(&cs)
	if row == nil || !strings.Contains(row.After, "ECH (config bbdebf38)") || strings.Contains(row.Before, "ECH") || strings.Contains(row.After, "AEb+DQ") {
		t.Fatalf("ECH change row = %+v (all %+v)", row, cs.Changes)
	}
	// A server's new config in place of the old one reads as a change, not as the same row twice.
	cs = Diff("", "", ep(&model.ECH{Enabled: true, Config: "AEb+DQ"}), ep(&model.ECH{Enabled: true, Config: "AEb+DR"}), config.Config{}, config.Config{})
	if row = tlsRow(&cs); row == nil || row.Before == row.After || !strings.Contains(row.After, "ECH (config d81b15c9)") {
		t.Fatalf("config swap row = %+v (all %+v)", row, cs.Changes)
	}
}
