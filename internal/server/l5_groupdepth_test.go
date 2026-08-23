package server

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestShallowKernelGroups (L5): a fallback pair that the kernel can only fall to once.
//
// Measured on a live AX3000T: group-failover lists tunnel-a (interface awg1) and proxy-member (a
// sing-box socks outbound), its policy table holds one route and no blackhole, and the group has no
// kill switch. When awg1 dies there is nothing to elect, the fwmark lookup falls through to main, and
// traffic meant for a tunnel leaves through the provider. Every other battery row stays green through
// all of that, which is why this one exists.
func TestShallowKernelGroups(t *testing.T) {
	groups := []model.Group{
		{ID: "mixed", Name: "RU failover", Type: "fallback", Members: []string{"awg1", "socks"}},
		{ID: "allnative", Name: "Both native", Type: "fallback", Members: []string{"a", "b"}},
		{ID: "coreonly", Name: "Core carried", Type: "fallback", Members: []string{"x", "y"}},
	}
	electable := map[string][]string{
		"mixed":     {"awg1"},   // one of two
		"allnative": {"a", "b"}, // as deep as it looks
		// "coreonly" is absent: the kernel routes none of its lists, so it is not this row's business
	}

	shallow := shallowKernelGroups(groups, electable)
	if len(shallow) != 1 {
		t.Fatalf("only the mixed group is shallow: %+v", shallow)
	}
	if shallow[0].ID != "mixed" || shallow[0].Electable != 1 || shallow[0].Members != 2 {
		t.Errorf("the depth must be reported against the membership: %+v", shallow[0])
	}
	// A group the kernel does not route must not be judged at all — reporting it would put a kernel
	// caveat on a group whose traffic the core carries end to end.
	for _, g := range shallow {
		if g.ID == "coreonly" {
			t.Error("a group the kernel does not route is not shallow, it is elsewhere")
		}
	}

	// The two outcomes are opposite in the way that matters, so the sentence must not average them.
	leak := groupDepthConsequence(false)
	drop := groupDepthConsequence(true)
	if !strings.Contains(leak, "leaves through the provider") {
		t.Errorf("without a kill switch the traffic leaks, and the row must say so: %q", leak)
	}
	if !strings.Contains(drop, "dropped") || strings.Contains(drop, "provider") {
		t.Errorf("with a kill switch it is dropped instead: %q", drop)
	}

	// Singular honesty, for the reason countWordLists spells out.
	if got := countWordGroups(1); !strings.HasPrefix(got, "1 group has") {
		t.Errorf("one group is not %q", got)
	}
	if got := countWordGroups(3); !strings.HasPrefix(got, "3 groups have") {
		t.Errorf("three groups are not %q", got)
	}
}
