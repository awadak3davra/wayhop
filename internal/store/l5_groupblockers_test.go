package store

import (
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestGroupDeleteBlockersMatchTheRefusal (L5): the list the panel is shown must be the list the store
// actually refuses on.
//
// DeleteGroup answered with a sentence and nothing else, so the panel could only print it raw —
// measured on the demo: with the default route pointed at a group, Delete produced the toast
// `group "grp-order-probe" is used by rule "default"; repoint it first`, with nothing to act on.
// GroupDeleteBlockers is what replaces that, and its whole value depends on agreeing with the
// refusal: a blocker list that is shorter promises a delete the store rejects, and one that is
// longer refuses a delete the store would allow.
func TestGroupDeleteBlockersMatchTheRefusal(t *testing.T) {
	open := func(t *testing.T, p model.Profile) *Store {
		t.Helper()
		st, err := Open(filepath.Join(t.TempDir(), "profile.json"))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if err := st.Replace(p); err != nil {
			t.Fatalf("seed: %v", err)
		}
		return st
	}
	ep := model.Endpoint{ID: "ep", Enabled: true, Engine: model.EngineSingBox,
		Protocol: model.ProtoTrojan, Server: "198.51.100.7", Port: 443,
		Params: map[string]any{"password": "x"}}

	// (1) A rule pointing at the group: refused, and named.
	byRule := open(t, model.Profile{
		Endpoints: []model.Endpoint{ep},
		Groups:    []model.Group{{ID: "g", Type: "fallback", Members: []string{"ep"}}},
		Rules:     []model.Rule{{ID: "default", Default: true, Outbound: "g"}},
	})
	err := byRule.DeleteGroup("g")
	blockers := byRule.GroupDeleteBlockers("g")
	if err == nil {
		t.Fatal("a group a rule points at must not be deletable")
	}
	if len(blockers) != 1 || blockers[0].Kind != "rule" || blockers[0].ID != "default" {
		t.Errorf("the refusal names rule \"default\"; the blockers must too: %+v", blockers)
	}
	if !strings.Contains(err.Error(), "default") {
		t.Errorf("refusal and blockers must be about the same object: %v", err)
	}

	// (2) Sole member of another group: refused, and named.
	byParent := open(t, model.Profile{
		Endpoints: []model.Endpoint{ep},
		Groups: []model.Group{
			{ID: "g", Type: "fallback", Members: []string{"ep"}},
			{ID: "parent", Name: "Parent", Type: "fallback", Members: []string{"g"}},
		},
		Rules: []model.Rule{{ID: "default", Default: true, Outbound: "direct"}},
	})
	if err := byParent.DeleteGroup("g"); err == nil {
		t.Fatal("a group that is another group's only member must not be deletable")
	}
	pb := byParent.GroupDeleteBlockers("g")
	if len(pb) != 1 || pb[0].Kind != "sole_member_of" || pb[0].ID != "parent" {
		t.Errorf("the parent group must be named: %+v", pb)
	}

	// (3) A routing list routing through it, and (4) a DNS server detouring through it. Both refuse,
	// and both were MISSING from the first cut of GroupDeleteBlockers — a live DELETE on the demo
	// answered `group "auto" is used by DNS server "dns_secure_bk" (detour)` while the blockers came
	// back empty. The cases below exist so the list cannot fall short of the refusal again.
	byList := open(t, model.Profile{
		Endpoints:    []model.Endpoint{ep},
		Groups:       []model.Group{{ID: "g", Type: "fallback", Members: []string{"ep"}}},
		RoutingLists: []model.RoutingList{{ID: "rl", Name: "List", Enabled: true, Outbound: "g", Manual: []string{"203.0.113.0/24"}}},
		Rules:        []model.Rule{{ID: "default", Default: true, Outbound: "direct"}},
	})
	if err := byList.DeleteGroup("g"); err == nil {
		t.Fatal("a group a routing list routes through must not be deletable")
	}
	if b := byList.GroupDeleteBlockers("g"); len(b) != 1 || b[0].Kind != "routing_list" || b[0].ID != "rl" {
		t.Errorf("the routing list must be named: %+v", b)
	}

	byDNS := open(t, model.Profile{
		Endpoints: []model.Endpoint{ep},
		Groups:    []model.Group{{ID: "g", Type: "fallback", Members: []string{"ep"}}},
		Rules:     []model.Rule{{ID: "default", Default: true, Outbound: "direct"}},
		DNS:       &model.DNSSettings{Servers: []model.DNSServer{{Tag: "doh", Type: "https", Server: "203.0.113.53", Detour: "g"}}},
	})
	if err := byDNS.DeleteGroup("g"); err == nil {
		t.Fatal("a group a DNS server detours through must not be deletable")
	}
	if b := byDNS.GroupDeleteBlockers("g"); len(b) != 1 || b[0].Kind != "dns_detour" || b[0].ID != "doh" {
		t.Errorf("the DNS server must be named: %+v", b)
	}

	// (5) Nothing points at it: deletable, and the blocker list is empty. Without this the two
	// assertions above would pass on a function that returns everything it can find.
	// The second group here is the negative control, and it has to be a group that does NOT depend on
	// the subject — it holds two members of its own. Without it the profile has nothing else to
	// over-report, and a version of GroupDeleteBlockers that named every other group passed this test.
	ep2 := ep
	ep2.ID = "ep2"
	free := open(t, model.Profile{
		Endpoints: []model.Endpoint{ep, ep2},
		Groups: []model.Group{
			{ID: "g", Type: "fallback", Members: []string{"ep"}},
			{ID: "unrelated", Name: "Unrelated", Type: "fallback", Members: []string{"ep", "ep2"}},
		},
		Rules: []model.Rule{{ID: "default", Default: true, Outbound: "direct"}},
	})
	if b := free.GroupDeleteBlockers("g"); len(b) != 0 {
		t.Errorf("an unreferenced group has no blockers: %+v", b)
	}
	if err := free.DeleteGroup("g"); err != nil {
		t.Errorf("and must delete: %v", err)
	}
}
