package pbr

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestRenderNft_ConnmarkRestoreFirst (L2): the nft wr_mark chain must RESTORE an established
// connection's saved egress mark BEFORE the per-zone match and the connmark-save, so a long-lived
// flow whose dest later leaves an (expiring) set keeps its tunnel instead of falling to the WAN
// default. nft can't express a masked meta↔ct merge (`| ct mark &` → "RHS of | must be constant",
// the form reverted from 0.3.5), so the restore is per-egress: compare ct mark to each egress's
// CONSTANT mark and re-apply it via the markSet form (preserves fw4 bits), terminating with accept.
func TestRenderNft_ConnmarkRestoreFirst(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20",
			Enabled: true, Params: map[string]any{"interface": "awg1"},
		}},
		RoutingLists: []model.RoutingList{{
			ID: "carrier-carveout", Manual: []string{"198.51.100.0/24"}, Outbound: "ru-awg1", Enabled: true,
		}},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	nft := plan.RenderNft()

	// The tunnel egress (ru-awg1) gets mark 0x00020000; its restore line must be the valid form.
	wantRestore := "ct mark & 0x00ff0000 == 0x00020000 meta mark set meta mark & 0xff00ffff | 0x00020000 accept"
	if !strings.Contains(nft, wantRestore) {
		t.Fatalf("missing valid per-egress connmark-restore line:\nwant: %s\n---\n%s", wantRestore, nft)
	}
	// Must NOT regress to the invalid masked meta↔ct merge nft rejects ("RHS of | must be constant").
	if strings.Contains(nft, "| ct mark &") {
		t.Errorf("restore uses the invalid meta↔ct merge form (real nft rejects it):\n%s", nft)
	}
	// Must preserve fw4's non-owned bits (the markSet `& 0xff00ffff` form), never a bare clobber.
	if strings.Contains(nft, "meta mark set ct mark\n") {
		t.Errorf("restore is an unmasked clobber (meta mark set ct mark) — must preserve non-owned bits")
	}

	// Ordering: restore must precede BOTH the per-zone match and the connmark-save.
	restore := strings.Index(nft, "ct mark & 0x00ff0000 == 0x00020000")
	zone := strings.Index(nft, "@list_")
	save := strings.Index(nft, "ct mark set meta mark")
	if restore < 0 || zone < 0 || save < 0 {
		t.Fatalf("setup: restore=%d zone=%d save=%d\n%s", restore, zone, save, nft)
	}
	if restore > zone {
		t.Errorf("restore-first must precede the per-zone match (restore@%d, zone@%d)", restore, zone)
	}
	if restore > save {
		t.Errorf("restore-first must precede the connmark-save (restore@%d, save@%d)", restore, save)
	}
}

// TestRenderNft_BypassFirstTerminating (#12/#13): the anti-loop bypass must come FIRST and be
// terminating (accept), so a tunnel-peer IP that falls inside a routed CIDR — or an established peer
// flow whose connmark carries a tunnel mark — egresses WAN and short-circuits both the L2 restore and
// the per-zone match (no routing loop / re-pin).
func TestRenderNft_BypassFirstTerminating(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20",
			Enabled: true, Params: map[string]any{"interface": "awg1"},
		}},
		RoutingLists: []model.RoutingList{{
			ID: "carrier-carveout", Manual: []string{"198.51.100.0/24"}, Outbound: "ru-awg1", Enabled: true,
		}},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	nft := plan.RenderNft()

	bypass := strings.Index(nft, "ip daddr @bypass4")
	restore := strings.Index(nft, "ct mark & 0x00ff0000 ==")
	zone := strings.Index(nft, "@list_")
	if bypass < 0 || restore < 0 || zone < 0 {
		t.Fatalf("setup: bypass=%d restore=%d zone=%d\n%s", bypass, restore, zone, nft)
	}
	if bypass > restore {
		t.Errorf("anti-loop bypass must precede the L2 restore (bypass@%d, restore@%d)", bypass, restore)
	}
	if bypass > zone {
		t.Errorf("anti-loop bypass must precede the per-zone match (bypass@%d, zone@%d)", bypass, zone)
	}
	for _, ln := range strings.Split(nft, "\n") {
		if strings.Contains(ln, "ip daddr @bypass4") && !strings.HasSuffix(strings.TrimSpace(ln), "accept") {
			t.Errorf("bypass4 line must be terminating (end with accept): %q", ln)
		}
	}
}
