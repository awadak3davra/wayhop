package pbr

import "testing"

// TestZoneOrderIsNotTheOperatorOrder (L5): pins the precedence the KERNEL plane actually applies, so
// the Routing page's wording and this compiler cannot drift apart again.
//
// The page says "Evaluated top to bottom: the first list that matches wins". That is true of the
// plane that reads a rule list; it is not true here. Compile sorts zones — blocks last, then by zone
// NAME — and each zone emits one non-terminating mark, so an address in two zones takes the LAST
// emitted. Verified on a live Keenetic: the panel lists Telegram, Antifilter, Meta, Twitter,
// Re:filter, TeamViewer, GitHub in that order, while `iptables -t mangle -S WR_PREROUTING` emits
// antifilter, meta, refilter, telegram, twitter, github, teamviewer — alphabetical. It changed
// nothing there only because all seven carry the same mark.
//
// Two properties are pinned: a block always outranks an ordinary zone, and among ordinary zones the
// emitted order is by name and NOT the order they were given in.
func TestZoneOrderIsNotTheOperatorOrder(t *testing.T) {
	zones := []Zone{
		{Name: "zzz_last_by_name", EgressTag: "tunA"},
		{Name: "aaa_first_by_name", EgressTag: "tunB"},
		{Name: "mmm_blocked", EgressTag: "blocker"},
	}
	kinds := map[string]EgressKind{"tunA": EgressInterface, "tunB": EgressInterface, "blocker": EgressBlackhole}

	got := orderZonesForEmit(zones, kinds)
	names := []string{}
	for _, z := range got {
		names = append(names, z.Name)
	}
	if len(names) != 3 {
		t.Fatalf("every zone must survive ordering: %v", names)
	}
	if names[2] != "mmm_blocked" {
		t.Errorf("a block must be emitted last so its mark wins an overlap, got %v", names)
	}
	if names[0] != "aaa_first_by_name" || names[1] != "zzz_last_by_name" {
		t.Errorf("ordinary zones are emitted by NAME, not in the order given: %v", names)
	}
	// The input order was the reverse of the output for the two ordinary zones: that IS the property
	// the Routing page has to disclose rather than promise away.
	if zones[0].Name != "zzz_last_by_name" {
		t.Error("the caller's slice must not be reordered in place under it")
	}
}
