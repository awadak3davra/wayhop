package model

import "testing"

// #1: a rule or group that targets a DISABLED endpoint must fail Validate —
// otherwise it passes validation but the generator (which skips disabled
// endpoints) emits a dangling outbound tag that sing-box rejects.
func TestValidateRejectsDisabledTarget(t *testing.T) {
	ep := func(en bool) Endpoint {
		return Endpoint{ID: "e", Name: "E", Engine: EngineSingBox, Protocol: ProtoVLESS, Server: "s", Port: 443, Enabled: en}
	}

	ruleToDisabled := &Profile{
		Endpoints: []Endpoint{ep(false)},
		Rules:     []Rule{{ID: "d", Default: true, Outbound: "e"}},
	}
	if err := ruleToDisabled.Validate(); err == nil {
		t.Fatal("rule targeting a disabled endpoint should fail Validate")
	}

	groupWithDisabled := &Profile{
		Endpoints: []Endpoint{ep(false)},
		Groups:    []Group{{ID: "g", Name: "G", Type: GroupURLTest, Members: []string{"e"}}},
	}
	if err := groupWithDisabled.Validate(); err == nil {
		t.Fatal("group with a disabled member should fail Validate")
	}

	// Enabling the endpoint makes the rule profile valid.
	ok := &Profile{Endpoints: []Endpoint{ep(true)}, Rules: []Rule{{ID: "d", Default: true, Outbound: "e"}}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("rule targeting an enabled endpoint should validate: %v", err)
	}
}

// #9: a non-default rule with no match condition is invalid (sing-box rejects a
// condition-less rule); Validate must catch it.
func TestValidateRejectsConditionlessRule(t *testing.T) {
	p := &Profile{
		Endpoints: []Endpoint{{ID: "e", Engine: EngineSingBox, Protocol: ProtoVLESS, Server: "s", Port: 443, Enabled: true}},
		Rules: []Rule{
			{ID: "bad", Outbound: "e"}, // non-default, NO matcher
			{ID: "d", Default: true, Outbound: "e"},
		},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("a non-default rule with no match condition should fail Validate")
	}
	// Giving it a matcher makes it valid.
	p.Rules[0].Domain = []string{"example.com"}
	if err := p.Validate(); err != nil {
		t.Fatalf("rule with a matcher should validate: %v", err)
	}
	// A bare default rule (no matcher) is fine — it's the catch-all.
	def := &Profile{
		Endpoints: []Endpoint{{ID: "e", Engine: EngineSingBox, Protocol: ProtoVLESS, Server: "s", Port: 443, Enabled: true}},
		Rules:     []Rule{{ID: "d", Default: true, Outbound: "e"}},
	}
	if err := def.Validate(); err != nil {
		t.Fatalf("a default rule needs no matcher: %v", err)
	}
}

// TestValidateRejectsBlankMatcherRule: a non-default rule whose matcher slices
// hold only blank strings (geosite:[""], domain_suffix:[" "]) is NOT a real
// matcher — the generator trims blanks away, leaving a condition-less rule that
// matches ALL traffic and shadows every later rule + the block-default (a routing
// leak). It must be rejected at Validate. A mixed real+blank matcher stays valid
// (it has a real condition; the generator drops the blank so it can't go match-all).
func TestValidateRejectsBlankMatcherRule(t *testing.T) {
	mk := func(r Rule) *Profile {
		return &Profile{
			Endpoints: []Endpoint{{ID: "e", Engine: EngineSingBox, Protocol: ProtoVLESS, Server: "s", Port: 443, Enabled: true}},
			Rules:     []Rule{r, {ID: "d", Default: true, Outbound: "e"}},
		}
	}
	for _, r := range []Rule{
		{ID: "g", GeoSite: []string{""}, Outbound: "e"},
		{ID: "ds", DomainSuffix: []string{" ", "\t"}, Outbound: "e"},
		{ID: "ip", IPCIDR: []string{""}, Outbound: "e"},
	} {
		if err := mk(r).Validate(); err == nil {
			t.Errorf("rule %q with an all-blank matcher must fail Validate", r.ID)
		}
	}
	if err := mk(Rule{ID: "mix", DomainSuffix: []string{"real.com", ""}, Outbound: "e"}).Validate(); err != nil {
		t.Fatalf("mixed real+blank matcher should validate, got %v", err)
	}
}

// TestValidateRejectsMalformedIPCIDR: a malformed ip_cidr matcher (e.g. "garbage")
// FATALs sing-box at config-load (netip.ParsePrefix: no '/'), bricking the shared
// singbox.json on apply. Validate must reject it with a precise error. sing-box
// accepts BOTH a bare IP and a CIDR (verified on the live router, cycle 72), so
// those stay valid; a blank entry is ignored (handled by ruleHasNoMatcher).
func TestValidateRejectsMalformedIPCIDR(t *testing.T) {
	mk := func(cidrs []string) *Profile {
		return &Profile{
			Endpoints: []Endpoint{{ID: "e", Engine: EngineSingBox, Protocol: ProtoVLESS, Server: "s", Port: 443, Enabled: true}},
			Rules:     []Rule{{ID: "r", IPCIDR: cidrs, Outbound: "e"}, {ID: "d", Default: true, Outbound: "e"}},
		}
	}
	for _, bad := range [][]string{
		{"garbage"},
		{"1.2.3.4/24", "not-a-cidr"}, // a real+malformed mix is still rejected (precise feedback)
		{"999.999.999.999"},
	} {
		if err := mk(bad).Validate(); err == nil {
			t.Errorf("ip_cidr %v with a malformed entry must fail Validate", bad)
		}
	}
	for _, ok := range [][]string{
		{"1.2.3.4"},        // bare IPv4 — sing-box accepts
		{"10.0.0.0/8"},     // IPv4 CIDR
		{"2001:db8::1"},    // bare IPv6
		{"2001:db8::/32"},  // IPv6 CIDR
		{"1.2.3.4/24", ""}, // trailing blank is ignored
	} {
		if err := mk(ok).Validate(); err != nil {
			t.Errorf("ip_cidr %v should validate, got %v", ok, err)
		}
	}
}

// TestValidateRejectsBadRulePort: a route-rule port outside 0-65535 FATALs
// sing-box at decode ("cannot unmarshal number 70000 into uint16"), bricking the
// shared config on apply (verified live, cycle 72). Validate must reject it; the
// in-range ports (incl. 0, which sing-box accepts) stay valid.
func TestValidateRejectsBadRulePort(t *testing.T) {
	mk := func(ports []int) *Profile {
		return &Profile{
			Endpoints: []Endpoint{{ID: "e", Engine: EngineSingBox, Protocol: ProtoVLESS, Server: "s", Port: 443, Enabled: true}},
			Rules:     []Rule{{ID: "r", Port: ports, Outbound: "e"}, {ID: "d", Default: true, Outbound: "e"}},
		}
	}
	for _, bad := range [][]int{{70000}, {-1}, {443, 99999}} {
		if err := mk(bad).Validate(); err == nil {
			t.Errorf("rule port %v out of range must fail Validate", bad)
		}
	}
	for _, ok := range [][]int{{0}, {443}, {65535}, {80, 443}} {
		if err := mk(ok).Validate(); err != nil {
			t.Errorf("rule port %v should validate, got %v", ok, err)
		}
	}
}

// A routing list whose download_via points at a DISABLED endpoint must fail
// Validate — the generator skips disabled endpoints, so the emitted
// download_detour would reference a missing outbound tag that sing-box rejects.
func TestValidateRejectsRoutingListDownloadViaDisabled(t *testing.T) {
	mk := func(en bool) Endpoint {
		return Endpoint{ID: "dl", Name: "DL", Engine: EngineSingBox, Protocol: ProtoVLESS, Server: "s", Port: 443, Enabled: en}
	}
	bad := &Profile{
		Endpoints: []Endpoint{mk(false)},
		RoutingLists: []RoutingList{{
			ID: "l", Name: "L", Source: "https://example.com/x.srs",
			Outbound: OutboundDirect, DownloadVia: "dl", Enabled: true,
		}},
	}
	if err := bad.Validate(); err == nil {
		t.Fatal("download_via targeting a disabled endpoint should fail Validate")
	}
	// Enabling the download endpoint makes it valid.
	bad.Endpoints[0].Enabled = true
	if err := bad.Validate(); err != nil {
		t.Fatalf("download_via to an enabled endpoint should validate: %v", err)
	}
}
