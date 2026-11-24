package changeset

import (
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// Review F1: undoing only the "Outbound" row of a list whose tunnels changed too restored Outbound
// alone, leaving "outbound must be the first candidate", which fails every Apply.
func TestUndoOutboundRowKeepsTunnelsConsistent(t *testing.T) {
	eps := []model.Endpoint{ep("a", "A"), ep("b", "B"), ep("c", "C")}
	for i := range eps {
		eps[i].Enabled = true
	}
	base := model.Profile{Endpoints: eps, RoutingLists: []model.RoutingList{{ID: "r", Name: "R", Enabled: true,
		Manual: []string{"example.net"}, Outbound: "a", Candidates: []string{"a", "b"},
		Fastest: &model.FastestPolicy{Enabled: true}}}}
	desired := base
	desired.RoutingLists = []model.RoutingList{base.RoutingLists[0]}
	desired.RoutingLists[0].Outbound = "c"
	desired.RoutingLists[0].Candidates = []string{"c", "b"}
	desired.RoutingLists[0].Fastest = &model.FastestPolicy{Enabled: true, Pinned: "c"}
	if err := desired.Validate(); err != nil {
		t.Fatalf("desired invalid: %v", err)
	}
	got, _, err := Undo(base, desired, config.Config{}, config.Config{},
		UndoRequest{Scope: ScopeField, ID: "r", ObjectType: "routing_list", Field: "Outbound"})
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("undo of the Outbound row left the profile invalid: %v", err)
	}
	if desired.RoutingLists[0].Fastest.Pinned != "c" {
		t.Fatal("undo wrote into the caller's profile")
	}
}

// neutralizeRef must rewrite a dangling candidate that is not Outbound, or the review stops counting.
func TestCollectRefProblemsSeesDanglingCandidate(t *testing.T) {
	eps := []model.Endpoint{ep("a", "A")}
	eps[0].Enabled = true
	p := model.Profile{Endpoints: eps, RoutingLists: []model.RoutingList{
		{ID: "r", Name: "R", Enabled: true, Manual: []string{"example.net"}, Outbound: "a", Candidates: []string{"a", "gone"}},
		{ID: "s", Name: "S", Enabled: true, Manual: []string{"example.org"}, Outbound: "gone2"},
	}}
	probs := model.CollectRefProblems(p)
	if len(probs) != 2 || probs[0].Target != "gone" || probs[1].Target != "gone2" {
		t.Fatalf("problems %+v", probs)
	}
}
