package model

import (
	"strings"
	"testing"
)

// SEC-07: a manual entry is written into dnsmasq's configuration on KeeneticOS, so a line break
// inside one would add a configuration line (an upstream resolver, say) nobody reviewed.
func TestValidateRefusesControlCharactersInManualEntries(t *testing.T) {
	list := func(entries ...string) Profile {
		return Profile{RoutingLists: []RoutingList{{ID: "l", Name: "L", Manual: entries, Outbound: "direct", Enabled: true}}}
	}
	for _, bad := range []string{
		"b.b\nserver=203.0.113.9",
		"b.b\rresolv-file=x.y",
		"example.com\x00",
		"example.com\x1b[0m",
		"x\u0085.example.com", // NEL, a C1 control (inside: at an end TrimSpace takes it as space)
	} {
		p := list("a.a", bad)
		err := p.Validate()
		if err == nil || !strings.Contains(err.Error(), "control character") {
			t.Errorf("manual entry %q: Validate = %v, want a control-character refusal", bad, err)
		}
	}
	// Surrounding whitespace is trimmed by every consumer and has always worked.
	for _, ok := range []string{"example.net", " example.net\r", "\t example.net\n", "10.0.0.0/8", "*.example.org"} {
		p := list(ok)
		if err := p.Validate(); err != nil {
			t.Errorf("manual entry %q: Validate = %v, want nil", ok, err)
		}
	}
}

// An external connection has no protocol settings of its own; discovery records "amneziawg" for
// display, and the save path asked for its private key, so such a connection could not be edited.
func TestEndpointParamProblemSkipsExternal(t *testing.T) {
	e := Endpoint{ID: "ru", Engine: EngineExternal, Protocol: "amneziawg", Enabled: true,
		Params: map[string]any{"interface": "awg1"}}
	if p := EndpointParamProblem(&e); p != "" {
		t.Fatalf("EndpointParamProblem = %q, want none", p)
	}
}
