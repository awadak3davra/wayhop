package model

import "testing"

// TestValidate_RejectsCyclicGroups guards the nested-group cycle fix: g1→g2→g1 (each a
// valid urltest group) would emit mutually-referencing sing-box outbounds that FATAL the
// config at load. The pre-fix self-only check missed the indirect cycle.
func TestValidate_RejectsCyclicGroups(t *testing.T) {
	p := Profile{
		Groups: []Group{
			{ID: "g1", Name: "G1", Type: GroupURLTest, Members: []string{"g2"}},
			{ID: "g2", Name: "G2", Type: GroupURLTest, Members: []string{"g1"}},
		},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected a cycle error for g1<->g2, got nil")
	}
}

// TestValidate_AcceptsAcyclicNestedGroups ensures the cycle check doesn't reject a valid
// nested chain (g_outer → g_inner → direct).
func TestValidate_AcceptsAcyclicNestedGroups(t *testing.T) {
	p := Profile{
		Groups: []Group{
			{ID: "g_inner", Name: "inner", Type: GroupURLTest, Members: []string{OutboundDirect}},
			{ID: "g_outer", Name: "outer", Type: GroupURLTest, Members: []string{"g_inner"}},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("acyclic nested groups should validate, got: %v", err)
	}
}

// TestValidate_RejectsDuplicateAndEmptyRuleID guards the rule-id fix: a duplicate or empty
// rule id (which corrupts Upsert/Delete-by-id) must be rejected like the other entities.
func TestValidate_RejectsDuplicateAndEmptyRuleID(t *testing.T) {
	dup := Profile{
		Rules: []Rule{
			{ID: "r1", DomainSuffix: []string{"a.com"}, Outbound: OutboundDirect},
			{ID: "r1", DomainSuffix: []string{"b.com"}, Outbound: OutboundDirect},
		},
	}
	if err := dup.Validate(); err == nil {
		t.Fatal("expected a duplicate rule-id error")
	}
	empty := Profile{Rules: []Rule{{ID: "", DomainSuffix: []string{"a.com"}, Outbound: OutboundDirect}}}
	if err := empty.Validate(); err == nil {
		t.Fatal("expected an empty rule-id error")
	}
}
