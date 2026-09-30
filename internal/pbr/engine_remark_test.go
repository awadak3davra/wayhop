package pbr

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// nftChain returns the RULES of one chain (header line dropped) from a rendered ruleset, so a test can assert on the
// rules of a SPECIFIC chain. The classification rules are emitted in two chains (wr_mark and
// wr_mark_late), so a whole-ruleset strings.Count would double every expectation.
func nftChain(t *testing.T, nft, name string) string {
	t.Helper()
	head := "\tchain " + name + " {\n"
	i := strings.Index(nft, head)
	if i < 0 {
		t.Fatalf("chain %s not rendered:\n%s", name, nft)
	}
	body := nft[i+len(head):]
	j := strings.Index(body, "\n\t}\n")
	if j < 0 {
		t.Fatalf("chain %s is not terminated:\n%s", name, nft)
	}
	body = body[:j]
	// Drop the chain's own `type ... hook ...` header line so two chains' RULES compare directly.
	if k := strings.Index(body, "\n"); k >= 0 && strings.Contains(body[:k], "type filter hook") {
		body = body[k+1:]
	}
	return body
}

// TestRenderNft_LateRemarkChain: the classification rules must be emitted a SECOND time, for
// ICMP/UDP only, at a priority that runs AFTER sing-box's auto_redirect chain. That chain
// (`prerouting_udp_icmp`, priority dstnat + 2) ends with an unmasked `meta mark set <exclude mark>`
// which wipes the egress mark wr_mark sets at mangle priority — measured live: TCP to a routed CIDR
// left via the tunnel while ICMP and UDP to the same address left via the WAN. Without this second
// pass every UDP service on a routed list (Telegram voice, games, VoWiFi) silently bypasses its
// tunnel, and a traceroute reports a path the real traffic never takes.
func TestRenderNft_LateRemarkChain(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "tunnel-a", Engine: model.EngineExternal, Server: "198.51.100.20",
			Enabled: true, Params: map[string]any{"interface": "awg1"},
		}},
		RoutingLists: []model.RoutingList{{
			ID: "carrier-carveout", Manual: []string{"198.51.100.0/24"}, Outbound: "tunnel-a", Enabled: true,
		}},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	nft := plan.RenderNft()

	early := strings.Index(nft, "\tchain wr_mark {\n")
	late := strings.Index(nft, "\tchain wr_mark_late {\n")
	if early < 0 || late < 0 {
		t.Fatalf("setup: wr_mark@%d wr_mark_late@%d\n%s", early, late, nft)
	}
	if late < early {
		t.Errorf("wr_mark_late must be emitted after wr_mark (wr_mark@%d, late@%d)", early, late)
	}

	// wr_mark keeps mangle priority: it must classify on the ORIGINAL destination, before the
	// engine's DNAT/redirect rewrites it for the protocols the engine does handle.
	if !strings.Contains(nft, "\tchain wr_mark {\n\t\ttype filter hook prerouting priority mangle; policy accept;\n") {
		t.Errorf("wr_mark lost its mangle-priority header:\n%s", nft)
	}
	// The late chain must sit strictly after dstnat + 2 (the engine's chain) and open with the
	// l4proto guard — anything above that guard would also re-run for TCP, which the engine never
	// clobbers and whose destination it may already have rewritten.
	wantHead := "\tchain wr_mark_late {\n" +
		"\t\ttype filter hook prerouting priority dstnat + 3; policy accept;\n" +
		"\t\tmeta l4proto != { icmp, udp, ipv6-icmp } return\n"
	if !strings.Contains(nft, wantHead) {
		t.Fatalf("late chain header/guard wrong, want:\n%s---\ngot:\n%s", wantHead, nft)
	}

	// Same rules, verbatim, in both chains: the zone match, the terminating anti-loop bypass and
	// the masked connmark save. A divergence here is how the two passes drift apart.
	body, lateBody := nftChain(t, nft, "wr_mark"), nftChain(t, nft, "wr_mark_late")
	guard := "\t\tmeta l4proto != { icmp, udp, ipv6-icmp } return\n"
	if got := strings.TrimPrefix(lateBody, guard); got != body {
		t.Errorf("late chain must repeat wr_mark's rules verbatim:\nwr_mark:\n%s\nlate:\n%s", body, got)
	}
	for _, line := range []string{
		"ip daddr @list_carrier_carveout_4 meta mark set meta mark & 0xff00ffff | 0x00020000",
		"ip daddr @bypass4 meta mark set meta mark & 0xff00ffff | 0x00010000 accept",
		"meta mark & 0x00ff0000 == 0x00020000 ct mark set ct mark & 0xff00ffff | 0x00020000",
	} {
		if !strings.Contains(body, line) || !strings.Contains(lateBody, line) {
			t.Errorf("rule missing from a prerouting chain: %s", line)
		}
	}
}

// TestRenderNft_NoLateChainWithoutRules: a plan that classifies nothing — no bypass, no zone, just
// the connmark bookkeeping every plan carries — must not emit an empty second chain.
func TestRenderNft_NoLateChainWithoutRules(t *testing.T) {
	plan, _, err := Compile(&model.Profile{}, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	nft := plan.RenderNft()
	if strings.Contains(nft, "wr_mark_late") {
		t.Errorf("a plan with nothing to classify must not emit wr_mark_late:\n%s", nft)
	}
}
