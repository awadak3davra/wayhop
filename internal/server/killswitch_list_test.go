package server

import (
	"testing"
	"time"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// killSwitchFastest is fastestProfile with the list's tunnels coming from a kill-switched group and
// the saved on_all_down left at "wan" (the panel's default).
func killSwitchFastest() model.Profile {
	p := fastestProfile()
	p.Groups[0].KillSwitch = true
	p.RoutingLists[0].Candidates = []string{"grp-awg31"}
	p.RoutingLists[0].Outbound = "grp-awg31"
	p.RoutingLists[0].Fastest = &model.FastestPolicy{Enabled: true, OnAllDown: model.OnAllDownWAN}
	return p
}

// Review F3 + kill switch audit: the elector unit runs "block", never "wan", under a kill switch, the
// list's own egress fails closed, and the review says why the saved "wan" is not what runs.
func TestKillSwitchForcesListBlock(t *testing.T) {
	profile := killSwitchFastest()
	s, plan := fastestServer(t, profile, &fakeTables{})
	units := fastestUnitsFrom(plan, &profile, kernelIfaceByEndpoint(&profile, s.appliedKernelDevices()),
		autoFastestTargets, nil, time.Now().UnixMilli())
	if len(units) != 1 || units[0].List.OnAllDown != model.OnAllDownBlock {
		t.Fatalf("units %+v", units)
	}
	var le pbr.Egress
	for _, e := range plan.Egresses {
		if e.Tag == model.ListEgressTag("tg") {
			le = e
		}
	}
	if !le.FailClosed {
		t.Fatalf("list egress lost the group's kill switch: %+v", le)
	}
	found := false
	for _, f := range s.fastestFindings(&profile) {
		if f.ID == "routing_list.fastest_killswitch" && f.Item == "tg" {
			found = true
		}
	}
	if !found {
		t.Fatal("no review note for the forced block")
	}
	// Without the kill switch the saved "wan" runs as saved.
	profile.Groups[0].KillSwitch = false
	units = fastestUnitsFrom(plan, &profile, kernelIfaceByEndpoint(&profile, s.appliedKernelDevices()),
		autoFastestTargets, nil, time.Now().UnixMilli())
	if units[0].List.OnAllDown != model.OnAllDownWAN {
		t.Fatalf("on_all_down %s", units[0].List.OnAllDown)
	}
}
