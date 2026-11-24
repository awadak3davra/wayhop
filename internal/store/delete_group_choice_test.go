package store

import (
	"testing"

	"wayhop/internal/model"
)

func groupChoiceStore(t *testing.T) *Store {
	t.Helper()
	s, _ := storemodelconfig_newStore(t)
	storemodelconfig_seedEndpoint(t, s, "e1")
	storemodelconfig_seedEndpoint(t, s, "e2")
	if err := s.UpsertGroup(model.Group{ID: "g1", Name: "G1", Type: model.GroupURLTest, Members: []string{"e1"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertRule(model.Rule{ID: "r1", Default: true, Outbound: "g1"}); err != nil {
		t.Fatal(err)
	}
	return s
}

// Deleting a group something points at is three choices, not a refusal: straight to the WAN, to
// another exit, or parked without a failover.
func TestDeleteGroupReplacing_ToDirectToAnotherExitOrParked(t *testing.T) {
	cases := []struct {
		name        string
		replacement string
		detach      bool
		outbound    string
		disabled    bool
	}{
		{"wan", model.OutboundDirect, false, model.OutboundDirect, false},
		{"exit", "e2", false, "e2", false},
		{"parked", "", true, model.OutboundDirect, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := groupChoiceStore(t)
			if err := s.DeleteGroup("g1"); err == nil {
				t.Fatal("the plain delete should still refuse")
			}
			if err := s.DeleteGroupReplacing("g1", c.replacement, c.detach); err != nil {
				t.Fatal(err)
			}
			p := s.Profile()
			if p.GroupByID("g1") != nil {
				t.Fatal("group still there")
			}
			var rule *model.Rule
			for i := range p.Rules {
				if p.Rules[i].ID == "r1" {
					rule = &p.Rules[i]
				}
			}
			if rule == nil || rule.Outbound != c.outbound || rule.Disabled != c.disabled {
				t.Fatalf("rule after delete: %+v", rule)
			}
			if err := p.Validate(); err != nil {
				t.Fatalf("profile no longer validates: %v", err)
			}
		})
	}
}

func TestDeleteGroupReplacing_RefusesWhatWouldLeaveAGroupEmpty(t *testing.T) {
	s := groupChoiceStore(t)
	if err := s.UpsertGroup(model.Group{ID: "outer", Name: "Outer", Type: model.GroupSelector, Members: []string{"g1"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroupReplacing("g1", model.OutboundDirect, false); err == nil {
		t.Fatal("a group left with no member was accepted")
	}
	if err := s.DeleteGroupReplacing("g1", "e2", false); err != nil {
		t.Fatalf("replacing by a connection: %v", err)
	}
	if got := func() []string { p := s.Profile(); return p.GroupByID("outer").Members }(); len(got) != 1 || got[0] != "e2" {
		t.Fatalf("outer members = %v", got)
	}
}

func TestDeleteRoutingListDetaching_TakesTheListOutOfDNSRules(t *testing.T) {
	s, _ := storemodelconfig_newStore(t)
	storemodelconfig_seedEndpoint(t, s, "e1")
	if err := s.UpsertRoutingList(model.RoutingList{ID: "l1", Name: "L1", Outbound: "e1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	dns := &model.DNSSettings{Rules: []model.DNSRule{
		{ID: "only", RuleSets: []string{"l1"}, Server: "reject"},
		{ID: "mixed", RuleSets: []string{"l1"}, Domain: []string{"a.example"}, Server: "reject"},
	}}
	if err := s.SetDNS(dns); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRoutingList("l1"); err == nil {
		t.Fatal("plain delete should refuse while a DNS rule uses the list")
	}
	if got := s.RoutingListDNSRules("l1"); len(got) != 2 {
		t.Fatalf("dependents = %v", got)
	}
	if err := s.DeleteRoutingListDetaching("l1"); err != nil {
		t.Fatal(err)
	}
	rules := s.Profile().DNS.Rules
	if len(rules) != 1 || rules[0].ID != "mixed" || len(rules[0].RuleSets) != 0 {
		t.Fatalf("rules after: %+v", rules)
	}
}

// Replacing a group by one that already contains its parent would close a loop between the two.
func TestDeleteGroupReplacing_RefusesALoop(t *testing.T) {
	s := groupChoiceStore(t)
	if err := s.UpsertGroup(model.Group{ID: "p", Name: "P", Type: model.GroupSelector, Members: []string{"g1", "e1"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertGroup(model.Group{ID: "r", Name: "R", Type: model.GroupSelector, Members: []string{"p", "e2"}}); err != nil {
		t.Fatal(err)
	}
	err := s.DeleteGroupReplacing("g1", "r", false)
	p := s.Profile()
	if err == nil && p.Validate() != nil {
		t.Fatalf("a loop was published: %v", p.Validate())
	}
	if err == nil {
		g := p.GroupByID("p")
		if containsString(g.Members, "r") {
			t.Fatalf("p now holds r, which holds p: %v", g.Members)
		}
	}
}

// block is a fine exit for a list's traffic but not for a DNS detour or a download: moving those
// there must not publish a profile that fails Validate.
func TestDeleteGroupReplacing_BlockDoesNotBreakDetourOrDownload(t *testing.T) {
	s := groupChoiceStore(t)
	if err := s.UpsertRoutingList(model.RoutingList{ID: "l1", Name: "L1", Outbound: "e1", DownloadVia: "g1", Enabled: true, Manual: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDNS(&model.DNSSettings{Servers: []model.DNSServer{
		{Tag: "d1", Type: "udp", Server: "1.1.1.1", Detour: "g1"}}}); err != nil {
		t.Skipf("dns fixture: %v", err)
	}
	if err := s.DeleteGroupReplacing("g1", model.OutboundBlock, false); err == nil {
		p := s.Profile()
		if verr := p.Validate(); verr != nil {
			t.Fatalf("published an invalid profile: %v", verr)
		}
	}
}
