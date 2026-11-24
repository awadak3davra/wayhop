package server

import (
	"context"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// The KeeneticOS fault: the connmark of a flow is the INSTALLED plan's, and a saved edit after the
// Apply renumbers the egresses of a recompile. The label must follow the installed marks, and an
// elected table names the member it holds now.
func TestMarkExitResolverFollowsTheInstalledPlan(t *testing.T) {
	applied := awg31Profile()
	tables := &fakeTables{}
	s, plan := appliedFailoverServer(t, applied, applied, tables)
	keeneticPlane(s)
	groupMark := uint32(0)
	for _, e := range plan.Egresses {
		if e.Tag == "grp-awg31" {
			groupMark = e.Mark
		}
	}
	if groupMark == 0 {
		t.Fatalf("no group egress: %+v", plan.Egresses)
	}
	// After the Apply: a list through an endpoint whose id sorts first ("aaa-cascade") is saved, so a
	// recompile of the saved profile gives that endpoint the group's old mark.
	saved := applied
	saved.Endpoints = append(append([]model.Endpoint(nil), applied.Endpoints...), nativeEndpoint("aaa-cascade", "nwg9"))
	saved.RoutingLists = append(append([]model.RoutingList(nil), applied.RoutingLists...),
		model.RoutingList{ID: "ru", Name: "RU", Outbound: "aaa-cascade", Enabled: true, Manual: []string{"203.0.113.0/24"}})
	if err := s.store.Replace(saved); err != nil {
		t.Fatal(err)
	}
	p := s.store.Profile()
	recompiled, _, _ := pbr.Compile(&p, pbr.Options{})
	for _, e := range recompiled.Egresses {
		if e.Mark == groupMark && e.Tag == "grp-awg31" {
			t.Fatal("fixture does not renumber; the test would prove nothing")
		}
	}
	if got := s.computeMarkExitResolver()(groupMark | 0x250); got != "grp-awg31" {
		t.Fatalf("installed mark %#x labelled %q, want grp-awg31", groupMark, got)
	}
	// With the elector holding the table on nwg5, the label names it.
	table := egressTable(t, plan, "grp-awg31")
	tables.show = map[bool]string{false: "default dev nwg5 table " + itoa(table) + " scope link \n"}
	tables.probes = handshakes("cp.cloudflare.com:80", map[string]int{"awg1": -1, "nwg1": 90, "nwg4": 80, "nwg5": 30})
	s.monitor = healthWith(t, []string{"ca", "nl1", "nl4", "nl5"}, "spare")
	s.listFailoverTick(context.Background())
	if got := s.computeMarkExitResolver()(groupMark); got != "grp-awg31 (nwg5)" {
		t.Fatalf("elected label %q, want grp-awg31 (nwg5)", got)
	}
	if got := s.computeMarkExitResolver()(0); got != "direct" {
		t.Fatalf("unmarked %q", got)
	}
}
