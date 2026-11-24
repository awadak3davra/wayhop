package server

import (
	"net/netip"
	"testing"

	"wayhop/internal/failover"
	"wayhop/internal/model"
)

// A kill-switched list is measured by address targets only. Its automatic pair was picked
// from the whole pool, names included, and filtered at the unit, so the unit measured one target
// while the rotation still held two: it never took the unit's targets for its own, a silent target
// was never replaced, and the unproven-target trial never began. The pool of such a list is
// addresses from the start.
func TestFastestKillSwitchedListRotatesItsAutomaticTargets(t *testing.T) {
	profile := cidrFastest()
	// One prefix and one name: picked from everything, the first pair is an address and the name.
	profile.RoutingLists[0].Manual = []string{"203.0.113.0/24", "example.org"}
	profile.Groups = append(profile.Groups, model.Group{ID: "ks", Name: "KS", Type: model.GroupSelector, Members: []string{"nl1"}, KillSwitch: true})
	profile.RoutingLists[0].Candidates, profile.RoutingLists[0].Outbound = []string{"ks", "nl4", "nl5"}, "ks"
	rl := profile.RoutingLists[0]
	if !model.ListKillSwitch(&profile, rl) {
		t.Fatal("the fixture's list is not kill-switched")
	}
	if any := autoFastestTargetPool(rl); len(any) < 3 || len(addressTargets(any[:2])) == 2 {
		t.Fatalf("the fixture's first pair holds no name: %v", any)
	}

	s, plan := fastestServer(t, profile, &fakeTables{})
	var unit *failover.TableUnit
	units := s.fastestUnits(plan, &profile, kernelIfaceByEndpoint(&profile, s.appliedKernelDevices()), nil, 1)
	for i := range units {
		if units[i].List != nil && units[i].List.List == "corp" {
			unit = &units[i]
		}
	}
	if unit == nil {
		t.Fatalf("no unit for the list: %+v", units)
	}
	held := s.fastest.targets["corp"]
	if len(unit.Targets) != 2 || !sameTargets(held.list, unit.Targets) {
		t.Fatalf("the unit measures %v while the rotation holds %v", unit.Targets, held.list)
	}
	for _, target := range held.pool {
		if _, err := netip.ParseAddrPort(target); err != nil {
			t.Errorf("a kill-switched list's pool holds a name the router would resolve by its own path: %s", target)
		}
	}
	if !unit.List.TargetsOnTrial {
		t.Error("automatic targets that have not answered yet, with others left in the pool, are on trial")
	}

	// A cycle in which the first target answers through no tunnel and the second does: it is replaced.
	state := failover.UnitState{Targets: unit.Targets, List: &failover.ListState{List: "corp", DeadTargets: unit.Targets[:1],
		Matrix: map[string]map[string]failover.ProbeCell{"nl4": {unit.Targets[1]: {OK: true}}}}}
	s.rotateFastestTargets([]failover.UnitState{state})
	now := s.fastest.targets["corp"].list
	if now[0] == unit.Targets[0] || now[1] != unit.Targets[1] || !s.fastest.want["corp"] {
		t.Fatalf("targets %v -> %v (measure next tick: %v): the silent one must be replaced", unit.Targets, now, s.fastest.want["corp"])
	}

	// A list with no kill switch keeps names among its automatic targets.
	plain := cidrFastest()
	plain.RoutingLists[0].Manual = rl.Manual
	if got := (&Server{}).fastestTargetsFor(plain.RoutingLists[0], false, 1); len(addressTargets(got)) == len(got) {
		t.Errorf("targets %v: a list without a kill switch is measured by its names too", got)
	}
}
