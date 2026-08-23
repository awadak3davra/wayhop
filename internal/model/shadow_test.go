package model

import "testing"

func TestShadowedRules_IdenticalMatchIsDead(t *testing.T) {
	rules := []Rule{
		{ID: "a", DomainSuffix: []string{".ru"}, Outbound: "direct"},
		{ID: "b", DomainSuffix: []string{".ru"}, Outbound: "grp"}, // can never fire
	}
	got := ShadowedRules(rules)
	if len(got) != 1 {
		t.Fatalf("expected the second rule to be reported dead, got %d findings: %+v", len(got), got)
	}
	if got[0].ID != "b" || got[0].ByID != "a" || got[0].Index != 1 || got[0].ShadowedBy != 0 {
		t.Errorf("wrong rule pair: %+v", got[0])
	}
}

// Order within a matcher is irrelevant to what it matches, so it must not hide a duplicate.
func TestShadowedRules_MatcherOrderAndDuplicatesDoNotMatter(t *testing.T) {
	rules := []Rule{
		{ID: "a", DomainSuffix: []string{".ru", ".su"}, Outbound: "direct"},
		{ID: "b", DomainSuffix: []string{".su", ".ru", ".ru"}, Outbound: "block"},
	}
	if got := ShadowedRules(rules); len(got) != 1 {
		t.Fatalf("reordered/duplicated entries describe the same set; expected 1 finding, got %+v", got)
	}
}

// Different matchers are not shadowing, and the analysis must not guess at containment.
func TestShadowedRules_DifferentMatchIsNotReported(t *testing.T) {
	rules := []Rule{
		{ID: "a", DomainSuffix: []string{".ru"}, Outbound: "direct"},
		{ID: "b", DomainSuffix: []string{".com"}, Outbound: "grp"},
		// A genuine subset of rule "a" — deliberately NOT reported: proving containment across
		// domains, CIDRs and remote rule-sets is not possible here, and an unreliable warning is
		// worse than none.
		{ID: "c", Domain: []string{"mail.example.ru"}, Outbound: "grp"},
		// Same matcher NAME, different matcher kind.
		{ID: "d", GeoSite: []string{"ru"}, Outbound: "direct"},
	}
	if got := ShadowedRules(rules); len(got) != 0 {
		t.Fatalf("expected no findings, got %+v", got)
	}
}

// A rule differing only in a source matcher matches different traffic and is not dead.
func TestShadowedRules_SourceMatchersDistinguish(t *testing.T) {
	rules := []Rule{
		{ID: "a", DomainSuffix: []string{".ru"}, Outbound: "direct"},
		{ID: "b", DomainSuffix: []string{".ru"}, SourceIPCIDR: []string{"10.0.0.0/24"}, Outbound: "grp"},
	}
	if got := ShadowedRules(rules); len(got) != 0 {
		t.Fatalf("a source matcher narrows the rule; it is not shadowed: %+v", got)
	}
}

func TestShadowedRules_DisabledNeitherShadowsNorIsReported(t *testing.T) {
	rules := []Rule{
		{ID: "a", DomainSuffix: []string{".ru"}, Outbound: "direct", Disabled: true},
		{ID: "b", DomainSuffix: []string{".ru"}, Outbound: "grp"},
	}
	if got := ShadowedRules(rules); len(got) != 0 {
		t.Fatalf("a disabled rule is not emitted, so it cannot shadow: %+v", got)
	}
	rules = []Rule{
		{ID: "a", DomainSuffix: []string{".ru"}, Outbound: "direct"},
		{ID: "b", DomainSuffix: []string{".ru"}, Outbound: "grp", Disabled: true},
	}
	if got := ShadowedRules(rules); len(got) != 0 {
		t.Fatalf("a disabled rule is already inert; reporting it as dead is noise: %+v", got)
	}
}

// The catch-all is meant to match everything last; it is not a shadowing finding.
func TestShadowedRules_DefaultRuleExcluded(t *testing.T) {
	rules := []Rule{
		{ID: "d1", Default: true, Outbound: "grp"},
		{ID: "d2", Default: true, Outbound: "direct"},
	}
	if got := ShadowedRules(rules); len(got) != 0 {
		t.Fatalf("default rules are excluded by design: %+v", got)
	}
}

// Three identical rules: both later ones are dead, and each is attributed to the FIRST.
func TestShadowedRules_ChainAttributesToTheFirst(t *testing.T) {
	rules := []Rule{
		{ID: "a", GeoIP: []string{"ru"}, Outbound: "direct"},
		{ID: "b", GeoIP: []string{"ru"}, Outbound: "grp"},
		{ID: "c", GeoIP: []string{"ru"}, Outbound: "block"},
	}
	got := ShadowedRules(rules)
	if len(got) != 2 {
		t.Fatalf("expected both later rules reported, got %+v", got)
	}
	for _, f := range got {
		if f.ByID != "a" {
			t.Errorf("%s should be attributed to the first matching rule, got %q", f.ID, f.ByID)
		}
	}
}

func TestShadowedDNSRules(t *testing.T) {
	rules := []DNSRule{
		{ID: "1", RuleSets: []string{"rl-ru"}, Server: "plain"},
		{ID: "2", RuleSets: []string{"rl-ru"}, Server: "doh"}, // dead
		{ID: "3", RuleSets: []string{"rl-ads"}, Server: "reject"},
		// Query type narrows the match, so this is live.
		{ID: "4", RuleSets: []string{"rl-ru"}, QueryType: []string{"AAAA"}, Server: "doh"},
	}
	got := ShadowedDNSRules(rules)
	if len(got) != 1 {
		t.Fatalf("expected exactly one dead DNS rule, got %+v", got)
	}
	if got[0].ID != "2" || got[0].ByID != "1" {
		t.Errorf("wrong pair: %+v", got[0])
	}
}

// A rule with no match criteria at all is not analysed: it is a catch-all by another name and
// reporting a pair of them as "shadowed" would be noise rather than a defect.
func TestShadowedRules_EmptyMatchIgnored(t *testing.T) {
	rules := []Rule{{ID: "a", Outbound: "direct"}, {ID: "b", Outbound: "grp"}}
	if got := ShadowedRules(rules); len(got) != 0 {
		t.Fatalf("expected no findings for matcher-less rules, got %+v", got)
	}
}
