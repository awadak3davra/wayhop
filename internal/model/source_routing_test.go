package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRuleSourceFieldsOmitWhenUnset: an unset Rule must serialize no source/disabled key, so
// adding the fields is byte-identical for existing profiles.
func TestRuleSourceFieldsOmitWhenUnset(t *testing.T) {
	r := Rule{ID: "r", IPCIDR: []string{"10.0.0.0/8"}, Outbound: "direct"}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(b)
	for _, key := range []string{"source_ip_cidr", "source_mac", "source_iface", "source_port", "disabled"} {
		if strings.Contains(js, key) {
			t.Errorf("unset rule must omit %q, got: %s", key, js)
		}
	}
}

// TestRuleSourceJSONTags pins the exact source-matcher JSON keys — the shared-spec names the
// UI/importer/generator align on; a rename here silently breaks round-trips.
func TestRuleSourceJSONTags(t *testing.T) {
	r := Rule{
		ID: "r", Outbound: "direct",
		SourceIPCIDR: []string{"192.168.1.50/32"}, SourceMAC: []string{"aa:bb:cc:dd:ee:ff"},
		SourceIface: []string{"br-guest"}, SourcePort: []int{51820}, Disabled: true,
	}
	b, _ := json.Marshal(r)
	js := string(b)
	for _, want := range []string{
		`"source_ip_cidr":["192.168.1.50/32"]`, `"source_mac":["aa:bb:cc:dd:ee:ff"]`,
		`"source_iface":["br-guest"]`, `"source_port":[51820]`, `"disabled":true`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("expected %s in %s", want, js)
		}
	}
}

func TestValidateSourceRules(t *testing.T) {
	valid := func(r Rule) error { return (&Profile{Rules: []Rule{r}}).Validate() }

	// A source-only rule is valid (ruleHasNoMatcher counts source fields).
	if err := valid(Rule{ID: "src-only", SourceIface: []string{"br-guest"}, Outbound: "block"}); err != nil {
		t.Errorf("source-only rule should be valid: %v", err)
	}
	// Combined source + dest with every source dimension.
	if err := valid(Rule{ID: "ok", IPCIDR: []string{"1.2.3.0/24"}, SourceIPCIDR: []string{"10.0.0.5"},
		SourcePort: []int{443}, SourceMAC: []string{"aa:bb:cc:dd:ee:ff"}, SourceIface: []string{"br-lan.10"}, Outbound: "direct"}); err != nil {
		t.Errorf("valid source rule rejected: %v", err)
	}
	// A trailing-* iface wildcard is accepted.
	if err := valid(Rule{ID: "wild", SourceIface: []string{"br-lan*"}, Outbound: "direct"}); err != nil {
		t.Errorf("trailing-* iface should be valid: %v", err)
	}

	bad := []struct {
		name string
		r    Rule
	}{
		{"bad-source-cidr", Rule{ID: "b1", SourceIPCIDR: []string{"not-an-ip"}, Outbound: "direct"}},
		{"bad-source-port", Rule{ID: "b2", SourceIPCIDR: []string{"10.0.0.1"}, SourcePort: []int{70000}, Outbound: "direct"}},
		{"bad-source-mac", Rule{ID: "b3", SourceMAC: []string{"zz:zz"}, Outbound: "direct"}},
		{"iface-too-long", Rule{ID: "b4", SourceIface: []string{"a-very-long-iface-name"}, Outbound: "direct"}},
		{"iface-whitespace", Rule{ID: "b5", SourceIface: []string{"br lan"}, Outbound: "direct"}},
		{"iface-bare-star", Rule{ID: "b6", SourceIface: []string{"*"}, Outbound: "direct"}},
		{"iface-injection", Rule{ID: "b7", SourceIface: []string{"a;reboot"}, Outbound: "direct"}},
		{"all-blank-source-only", Rule{ID: "b8", SourceIPCIDR: []string{"  "}, SourceIface: []string{" "}, Outbound: "direct"}},
	}
	for _, c := range bad {
		if err := valid(c.r); err == nil {
			t.Errorf("%s: expected a validation error, got nil", c.name)
		}
	}
}

// TestDisabledRuleExemption pins §3.5 + the inverted-toggle safety: a DISABLED rule pointing
// at a disabled/absent endpoint passes Validate (inert no-op); the same rule ENABLED fails.
func TestDisabledRuleExemption(t *testing.T) {
	mk := func(disabled bool) *Profile {
		return &Profile{
			Endpoints: []Endpoint{{ID: "ep", Name: "ep", Engine: EngineSingBox, Protocol: ProtoVLESS, Server: "1.1.1.1", Port: 443, Enabled: false}},
			Rules:     []Rule{{ID: "r", IPCIDR: []string{"1.2.3.0/24"}, Outbound: "ep", Disabled: disabled}},
		}
	}
	if err := mk(true).Validate(); err != nil {
		t.Errorf("disabled rule targeting a disabled endpoint should pass Validate: %v", err)
	}
	if err := mk(false).Validate(); err == nil {
		t.Error("enabled rule targeting a disabled endpoint must fail Validate")
	}
}

// TestRuleBackwardCompat: a pre-feature rule JSON (no source_*/disabled keys) decodes
// Disabled=false (the whole point of the inverted toggle) and re-marshals byte-identically.
func TestRuleBackwardCompat(t *testing.T) {
	const pre = `{"id":"r","ip_cidr":["10.0.0.0/8"],"outbound":"direct"}`
	var r Rule
	if err := json.Unmarshal([]byte(pre), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.Disabled {
		t.Error("a keyless pre-feature rule must decode Disabled=false (else the inverted toggle silently disables it)")
	}
	b, _ := json.Marshal(r)
	if string(b) != pre {
		t.Errorf("pre-feature rule not byte-identical:\n got %s\nwant %s", b, pre)
	}
}
