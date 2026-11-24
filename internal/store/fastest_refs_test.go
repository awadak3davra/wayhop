package store

import (
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// fastestRefsStore holds a fastest list over e1, e2 and the group g (e3, e4), pinned to e4 with e2
// excluded: every path that removes or replaces an exit must leave it Validate-clean (review F1).
func fastestRefsStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"e1", "e2", "e3", "e4", "e5"} {
		if err := s.UpsertEndpoint(model.Endpoint{ID: id, Name: strings.ToUpper(id), Server: "1.1.1.1", Port: 443, Protocol: model.ProtoVLESS, Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertGroup(model.Group{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"e3", "e4"}}); err != nil {
		t.Fatal(err)
	}
	rl := model.RoutingList{ID: "l", Name: "L", Enabled: true, Outbound: "e1", Candidates: []string{"e1", "e2", "g"},
		Manual:  []string{"1.2.3.0/24"},
		Fastest: &model.FastestPolicy{Enabled: true, Pinned: "e4", Excluded: []string{"e2"}}}
	if err := s.UpsertRoutingList(rl); err != nil {
		t.Fatal(err)
	}
	mustValid(t, s, "seed")
	return s
}

func listL(t *testing.T, s *Store) model.RoutingList {
	t.Helper()
	p := s.Profile()
	for _, rl := range p.RoutingLists {
		if rl.ID == "l" {
			return rl
		}
	}
	t.Fatal("list l missing")
	return model.RoutingList{}
}

func mustValid(t *testing.T, s *Store, what string) {
	t.Helper()
	p := s.Profile()
	if err := p.Validate(); err != nil {
		t.Fatalf("%s left the profile invalid: %v", what, err)
	}
}

func TestFastestRefsDeleteSecondCandidate(t *testing.T) {
	s := fastestRefsStore(t)
	if err := s.DeleteEndpoint("e2"); err != nil {
		t.Fatal(err)
	}
	mustValid(t, s, "DeleteEndpoint(e2)")
	rl := listL(t, s)
	if strings.Join(rl.Candidates, ",") != "e1,g" || len(rl.Fastest.Excluded) != 0 {
		t.Fatalf("candidates %v excluded %v", rl.Candidates, rl.Fastest.Excluded)
	}
}

func TestFastestRefsDeleteFirstCandidateMovesOn(t *testing.T) {
	s := fastestRefsStore(t)
	if err := s.DeleteEndpoint("e1"); err != nil {
		t.Fatalf("a list with other tunnels must not block the delete: %v", err)
	}
	mustValid(t, s, "DeleteEndpoint(e1)")
	if rl := listL(t, s); rl.Outbound != "e2" || strings.Join(rl.Candidates, ",") != "e2,g" {
		t.Fatalf("outbound %s candidates %v", rl.Outbound, rl.Candidates)
	}
	if b := s.EndpointDependents("e2"); len(b) != 0 {
		t.Fatalf("e2 is not the list's only tunnel, yet listed as a dependent: %+v", b)
	}
}

func TestFastestRefsDeleteReplacing(t *testing.T) {
	s := fastestRefsStore(t)
	if err := s.DeleteEndpointReplacing("e1", "e5"); err != nil {
		t.Fatal(err)
	}
	mustValid(t, s, "DeleteEndpointReplacing(e1, e5)")
	if rl := listL(t, s); rl.Outbound != "e5" || strings.Join(rl.Candidates, ",") != "e5,e2,g" {
		t.Fatalf("outbound %s candidates %v", rl.Outbound, rl.Candidates)
	}
	// Replaced by a builtin: the list keeps its other tunnels.
	if err := s.DeleteEndpointReplacing("e5", model.OutboundDirect); err != nil {
		t.Fatal(err)
	}
	mustValid(t, s, "DeleteEndpointReplacing(e5, direct)")
	if rl := listL(t, s); rl.Outbound != "e2" {
		t.Fatalf("outbound %s", rl.Outbound)
	}
}

func TestFastestRefsPinnedMemberLeavesGroup(t *testing.T) {
	s := fastestRefsStore(t)
	if err := s.DeleteEndpoint("e4"); err != nil {
		t.Fatal(err)
	}
	mustValid(t, s, "DeleteEndpoint(e4) (pinned group member)")
	if rl := listL(t, s); rl.Fastest.Pinned != "" {
		t.Fatalf("pin on a deleted tunnel kept: %q", rl.Fastest.Pinned)
	}
	// A group edit that drops the excluded member's sibling: exclusions follow too.
	s2 := fastestRefsStore(t)
	if err := s2.UpsertGroup(model.Group{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"e3"}}); err != nil {
		t.Fatal(err)
	}
	mustValid(t, s2, "group member removed")
}

func TestFastestRefsParkAndDetach(t *testing.T) {
	s := fastestRefsStore(t)
	if err := s.DetachEndpointDependents("e1"); err != nil {
		t.Fatal(err)
	}
	mustValid(t, s, "DetachEndpointDependents(e1)")
	if rl := listL(t, s); !rl.Enabled || rl.Outbound != "e2" {
		t.Fatalf("a list with other tunnels was parked: enabled %v outbound %s", rl.Enabled, rl.Outbound)
	}
	p := s.Profile()
	off := *p.EndpointByID("e2")
	off.Enabled = false
	if err := s.SetEndpointDisabledDetaching(off); err != nil {
		t.Fatal(err)
	}
	mustValid(t, s, "SetEndpointDisabledDetaching(e2)")
}

func TestFastestRefsDeleteGroupCandidate(t *testing.T) {
	s := fastestRefsStore(t)
	if b := s.GroupDeleteBlockers("g"); len(b) != 0 {
		t.Fatalf("blockers %+v", b)
	}
	if err := s.DeleteGroup("g"); err != nil {
		t.Fatal(err)
	}
	mustValid(t, s, "DeleteGroup(g)")
	if rl := listL(t, s); rl.Fastest.Pinned != "" || strings.Join(rl.Candidates, ",") != "e1,e2" {
		t.Fatalf("candidates %v pin %q", rl.Candidates, rl.Fastest.Pinned)
	}
}

func TestFastestRefsOnlyTunnelStillRefuses(t *testing.T) {
	s := fastestRefsStore(t)
	rl := listL(t, s)
	rl.Candidates, rl.Fastest = []string{"e1"}, nil
	if err := s.UpsertRoutingList(rl); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteEndpoint("e1"); err == nil {
		t.Fatal("deleting a list's only tunnel must still be refused")
	}
	if b := s.EndpointDependents("e1"); len(b) != 1 || b[0].Kind != "routing_list" {
		t.Fatalf("dependents %+v", b)
	}
}
