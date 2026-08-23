package server

import (
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// TestListsInForce (L5): a battery that answers every question except the one the operator asked.
//
// Measured on a live OpenWrt: every row passed while eleven of fifteen routing lists matched
// nothing. The rows were each true — tunnels up, DNS answering, "Kernel routing (PBR): active — 4
// zone(s) applied" over the four IP/CIDR lists. The other eleven are domain lists, which only the
// proxy core can match, and "fast" mode builds no TUN, so no LAN packet ever reaches the core. The
// battery compared nothing to nothing and reported health.
func TestListsInForce(t *testing.T) {
	lists := []model.RoutingList{
		{ID: "cidr-telegram", Name: "Telegram", Enabled: true}, // kernel zone below
		{ID: "mig-meta", Name: "Meta", Enabled: true},          // core only
		{ID: "off-list", Name: "Switched off", Enabled: false}, // must be ignored
		{ID: "orphan", Name: "Orphan", Enabled: true},          // neither plane
	}
	zones := map[string]bool{pbr.ListZoneName("cidr-telegram"): true}
	core := map[string]bool{"mig-meta": true}

	// fast mode: the core holds mig-meta but nothing feeds the core.
	in, out, unknown := listsInForce(lists, zones, core, true, false)
	if len(in) != 1 || in[0].ID != "cidr-telegram" {
		t.Errorf("the kernel-carried list is the only one in force: %+v", in)
	}
	if len(unknown) != 0 {
		t.Errorf("nothing is unknown when the core config was read: %+v", unknown)
	}
	if len(out) != 2 {
		t.Fatalf("both the core-only and the orphan list must be reported: %+v", out)
	}
	var metaReason, orphanReason string
	for _, c := range out {
		if c.ID == "mig-meta" {
			metaReason = c.Reason
		}
		if c.ID == "orphan" {
			orphanReason = c.Reason
		}
	}
	if !strings.Contains(metaReason, "no LAN traffic reaches the core") {
		t.Errorf("a core-only list in a coreless-datapath mode must say why: %q", metaReason)
	}
	if !strings.Contains(orphanReason, "neither") {
		t.Errorf("a list no plane carries must say that plainly: %q", orphanReason)
	}
	// The disabled list is a decision, not a fault, in every bucket.
	for _, bucket := range [][]listCarrier{in, out, unknown} {
		for _, c := range bucket {
			if c.ID == "off-list" {
				t.Error("a disabled list must not be judged at all")
			}
		}
	}

	// hybrid/tun: the same core-held list IS in force, because the TUN feeds the core.
	in, out, _ = listsInForce(lists, zones, core, true, true)
	if len(in) != 2 {
		t.Errorf("with a TUN the core-carried list counts as in force: %+v", in)
	}
	if len(out) != 1 || out[0].ID != "orphan" {
		t.Errorf("only the orphan remains: %+v", out)
	}

	// An unreadable core config must not accuse a working list.
	in, out, unknown = listsInForce(lists, zones, nil, false, false)
	if len(out) != 0 {
		t.Errorf("nothing may be called broken when the core config could not be read: %+v", out)
	}
	if len(unknown) != 2 {
		t.Errorf("the two non-kernel lists are unknown, not failing: %+v", unknown)
	}
	if len(in) != 1 {
		t.Errorf("the kernel-carried list is still known to be in force: %+v", in)
	}
}

// TestListCarrierNamesSaysWhatItLeftOut (L5): a truncated list of names must not read as the whole
// set. Six names out of twelve, silently, is a report that under-states the damage.
func TestListCarrierNamesSaysWhatItLeftOut(t *testing.T) {
	entries := make([]listCarrier, 12)
	for i := range entries {
		entries[i] = listCarrier{ID: "l", Name: "list"}
	}
	got := listCarrierNames(entries, 6)
	if len(got) != 7 || !strings.Contains(got[6], "6 more") {
		t.Errorf("the overflow must be counted: %v", got)
	}
	if n := listCarrierNames(entries[:3], 6); len(n) != 3 {
		t.Errorf("a short list is rendered whole: %v", n)
	}
}
