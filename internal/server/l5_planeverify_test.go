package server

import "testing"

// TestUnreferencedSets (L5): a set nothing marks against routes nothing, and the supervision must
// say so instead of reporting the plane verified.
//
// Measured on a live Keenetic: deleting the one MARK rule for wr_list_rl_teamviewer_4 left
// the set in place with every member intact, so the postcheck passed, /api/pbr/status kept saying
// verified:true, and the panel kept saying "The router is verified to be running this
// configuration" — while that list was not policy-routed at all. The rule returned in ~30s from the
// NDM firewall hook re-asserting the plane; nothing in WayHop had noticed.
func TestUnreferencedSets(t *testing.T) {
	sets := []string{"wr_list_a_4", "wr_list_b_4", "wr_list_b_6"}
	v4 := "-A WR_PREROUTING -m set --match-set wr_list_a_4 dst -j MARK --set-xmark 0x20000/0xff0000\n" +
		"-A WR_PREROUTING -m set --match-set wr_list_b_4 dst -j MARK --set-xmark 0x30000/0xff0000"
	v6 := "-A WR_PREROUTING -m set --match-set wr_list_b_6 dst -j MARK --set-xmark 0x30000/0xff0000"

	if got := unreferencedSets(sets, v4, v6, true); len(got) != 0 {
		t.Errorf("a fully wired plane must report nothing, got %v", got)
	}

	// The exact drift that was invisible: the set survives, its rule does not.
	v4NoA := "-A WR_PREROUTING -m set --match-set wr_list_b_4 dst -j MARK --set-xmark 0x30000/0xff0000"
	got := unreferencedSets(sets, v4NoA, v6, true)
	if len(got) != 1 || got[0] != "wr_list_a_4" {
		t.Errorf("a set with no rule must be named, got %v", got)
	}

	// v6 is judged only when ip6tables answered. A router without that tool is a shape, not drift —
	// judging it anyway would reinstall the plane on every supervision tick, forever.
	if got := unreferencedSets(sets, v4, "", false); len(got) != 0 {
		t.Errorf("v6 sets must go unjudged when ip6tables could not be asked, got %v", got)
	}
	if got := unreferencedSets(sets, v4, "", true); len(got) != 1 || got[0] != "wr_list_b_6" {
		t.Errorf("but a readable ip6tables with no rule must be reported, got %v", got)
	}

	// A wholesale flush — the case the reconcile loop already existed for — names the first casualty
	// rather than passing because the loop found nothing to compare.
	if got := unreferencedSets(sets, "", "", true); len(got) != 3 {
		t.Errorf("an empty mangle table must report every owned set, got %v", got)
	}
	if len(sets) != 3 {
		t.Error("the input must not be mutated")
	}
}
