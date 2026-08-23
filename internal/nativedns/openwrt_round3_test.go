package nativedns

import (
	"strings"
	"testing"
)

// TestRenderUCI_PortedPlainFallbackNoDoH (bugs #5 + #19): a ported plain fallback resolver on a plane
// with NO DoH proxy must render as a LIVE dnsmasq `server` entry that PRESERVES its #port. Folding it
// into doh_backup_server would (a) drop the port — that option can't round-trip one — and (b) leave
// dnsmasq with no upstream at all (noresolv also blocks ISP DNS), killing resolution. Uses a real
// Read->Render round trip.
func TestRenderUCI_PortedPlainFallbackNoDoH(t *testing.T) {
	dhcp := "dhcp.@dnsmasq[0].noresolv='1'\ndhcp.@dnsmasq[0].server='9.9.9.9#5353'"
	nd := ReadUCI("", dhcp)
	if len(nd.Resolvers) != 1 || nd.Resolvers[0].Kind != KindPlain || nd.Resolvers[0].Port != 5353 || nd.Resolvers[0].Tier != TierFallback {
		t.Fatalf("adopt: got %+v", nd.Resolvers)
	}
	plan := strings.Join(RenderUCI(nd), "\n")
	if !strings.Contains(plan, "[0].server='9.9.9.9#5353'") {
		t.Errorf("ported plain fallback must render as a live dnsmasq server preserving #5353:\n%s", plan)
	}
	if strings.Contains(plan, "doh_backup_server='9.9.9.9'") {
		t.Errorf("must not fold the ported resolver into the portless doh_backup_server tier:\n%s", plan)
	}
}

// TestRenderUCI_PlainFallbackNoDoH_KeepsLiveUpstream (bug #5): unported plain fallback resolvers on a
// plane with no DoH proxy must still become live dnsmasq `server` upstreams (not only
// doh_backup_server, which nothing would consume) — else noresolv leaves resolution dead.
func TestRenderUCI_PlainFallbackNoDoH_KeepsLiveUpstream(t *testing.T) {
	nd := NativeDNS{
		NoResolv: true,
		Resolvers: []NativeResolver{
			{Kind: KindPlain, Address: "9.9.9.9", Tier: TierFallback},
			{Kind: KindPlain, Address: "1.1.1.1", Tier: TierFallback},
		},
	}
	plan := strings.Join(RenderUCI(nd), "\n")
	for _, ip := range []string{"9.9.9.9", "1.1.1.1"} {
		if !strings.Contains(plan, "[0].server='"+ip+"'") {
			t.Errorf("plain fallback %s must be a live dnsmasq server when there is no DoH proxy:\n%s", ip, plan)
		}
	}
}

// TestRenderUCI_FallbackWithDoHStaysBackup: WITH a DoH proxy present, an unported plain fallback still
// goes to the doh_backup_server tier — the existing tiering behavior must be preserved.
func TestRenderUCI_FallbackWithDoHStaysBackup(t *testing.T) {
	nd := NativeDNS{
		NoResolv: true,
		Resolvers: []NativeResolver{
			{Kind: KindDoH, Address: "https://1.1.1.1/dns-query", Tier: TierHidden},
			{Kind: KindPlain, Address: "9.9.9.9", Tier: TierFallback},
		},
	}
	plan := strings.Join(RenderUCI(nd), "\n")
	if !strings.Contains(plan, "doh_backup_server='9.9.9.9'") {
		t.Errorf("with a DoH proxy present, an unported plain fallback should stay in doh_backup_server:\n%s", plan)
	}
	if strings.Contains(plan, "[0].server='9.9.9.9'") {
		t.Errorf("unported fallback should NOT also be a live server when DoH is present:\n%s", plan)
	}
}
