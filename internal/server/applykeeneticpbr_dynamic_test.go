package server

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"wayhop/internal/ctflush"
	"wayhop/internal/pbr"
)

func TestKeeneticDynamicDomainArtifactRoundTrip(t *testing.T) {
	plan := &pbr.Plan{Mask: 0x00ff0000, Zones: []pbr.Zone{{
		Name: "list_alpha", Domains: []string{"alpha.example"}, Mark: 0x00020000,
	}}}
	io := keeneticPBROptions("eth3")
	io.DynamicDomainSets = true
	artifact, err := buildKeeneticKernelIpsetArtifact(plan, exactKernelOptions(), io, keeneticPBRTestTools())
	if err != nil {
		t.Fatal(err)
	}
	if !artifact.DynamicDomainSets || !slices.Contains(artifact.SetNames, "wd_list_alpha_4") {
		t.Fatalf("dynamic artifact was not recorded: %+v", artifact)
	}
	whole := executionKernelArtifactV1{Plan: plan, Ipset: artifact}
	if !validExactKernelPresentIpsetArtifact(whole) {
		t.Fatal("a rendered dynamic artifact did not re-render exactly")
	}
	changed := *artifact
	changed.DynamicDomainSets = false
	whole.Ipset = &changed
	if validExactKernelPresentIpsetArtifact(whole) {
		t.Fatal("changing the dynamic-set mode passed exact validation")
	}
	if !keeneticKillSwitchOptions(*artifact).DynamicDomainSets {
		t.Fatal("kill-switch options lost the dynamic-set mode")
	}
}

func TestWithDynamicMembersReadsResolverSets(t *testing.T) {
	plan := &pbr.Plan{Zones: []pbr.Zone{
		{Name: "list_alpha", Domains: []string{"alpha.example"}},
		{Name: "list_static", V4: []string{"192.0.2.0/24"}},
	}}
	sets := map[string][]netip.Prefix{
		"wr_list_alpha_4":  {netip.MustParsePrefix("192.0.2.1/32")},
		"wd_list_alpha_4":  {netip.MustParsePrefix("198.51.100.7/32")},
		"wr_list_alpha_6":  {},
		"wr_list_static_4": {netip.MustParsePrefix("192.0.2.0/24")},
	}
	read := func(_ context.Context, set string) ([]netip.Prefix, error) {
		got, ok := sets[set]
		if !ok {
			return nil, errors.New("no such set")
		}
		return got, nil
	}
	ctx := context.Background()
	if got, _ := withDynamicMembers(read, plan, false)(ctx, "wr_list_alpha_4"); len(got) != 1 {
		t.Fatalf("legacy read = %v, want the wr_ set only", got)
	}
	dyn := withDynamicMembers(read, plan, true)
	if got, err := dyn(ctx, "wr_list_alpha_4"); err != nil || len(got) != 2 {
		t.Fatalf("dynamic read = %v %v, want both sets", got, err)
	}
	// HUNT-K #5: a wd_ set that cannot be read makes the zone unknown, not known in part.
	if got, err := dyn(ctx, "wr_list_alpha_6"); err == nil || got != nil {
		t.Fatalf("missing wd_ set: %v %v", got, err)
	}
	if got, err := dyn(ctx, "wr_list_gone_4"); err == nil || got != nil {
		t.Fatalf("a missing wr_ set must stay an error: %v %v", got, err)
	}
	if got, err := dyn(ctx, "wr_list_static_4"); err != nil || len(got) != 1 {
		t.Fatalf("static zone read = %v %v", got, err)
	}
	// The zone's v6 wd_ set is missing: it stays unread and a sweep is owed.
	live, unread := livePlanRead(ctx, plan, dyn)
	if !unread || len(live.Zones[0].Domains) == 0 {
		t.Fatalf("a zone with an unread wd_ set passed for known: %+v", live.Zones[0])
	}
	l := &leakSweeper{open: func() (ctflush.Table, error) { return &countingTable{}, nil }, now: time.Now}
	l.sweep(ctx, plan, dyn, nil, true, "the Apply")
	if !l.pending {
		t.Fatal("a sweep that could not read a zone owes no further sweep")
	}
	sets["wd_list_alpha_6"] = nil
	live, unread = livePlanRead(ctx, plan, dyn)
	if unread || !slices.Contains(live.Zones[0].V4, "198.51.100.7/32") {
		t.Fatalf("the leak sweep does not see resolver-learned members: %+v", live.Zones[0])
	}
}
