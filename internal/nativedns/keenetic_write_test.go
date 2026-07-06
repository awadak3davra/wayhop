package nativedns

import (
	"strings"
	"testing"
)

// Round-trip on the live Tier-3 chain: adopt → render dnsmasq.d → re-adopt must reproduce the exact
// resolver chain (addresses, tiers, via-tunnel) + strict-order + no-resolv. Proves writer↔reader
// consistency on the real config the manual Tier-3 edit produced.
func TestRenderDnsmasqD_RoundTrip(t *testing.T) {
	orig := ReadDnsmasqD(fixtureKeeneticUpstream, "") // 4 plain: 2 mesh Tier-1 + 2 Yandex Tier-3
	rendered := RenderDnsmasqD(orig)
	back := ReadDnsmasqD(rendered, "")

	if back.StrictOrder != orig.StrictOrder || back.NoResolv != orig.NoResolv {
		t.Fatalf("directives lost: got strict=%v noresolv=%v", back.StrictOrder, back.NoResolv)
	}
	if len(back.Resolvers) != len(orig.Resolvers) {
		t.Fatalf("resolver count changed: %d -> %d", len(orig.Resolvers), len(back.Resolvers))
	}
	for i := range orig.Resolvers {
		if back.Resolvers[i] != orig.Resolvers[i] { // NativeResolver is all-comparable value fields
			t.Errorf("resolver[%d] round-trip: %+v -> %+v", i, orig.Resolvers[i], back.Resolvers[i])
		}
	}
}

func TestRenderDnsmasqD_Content(t *testing.T) {
	nd := ReadDnsmasqD(fixtureKeeneticUpstream, "")
	out := RenderDnsmasqD(nd)
	for _, want := range []string{"strict-order", "no-resolv", "server=10.8.1.0", "server=10.0.0.1", "server=77.88.8.8", "server=77.88.8.1"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered dnsmasq.d missing %q\n---\n%s", want, out)
		}
	}
	// The tunnel primaries must appear BEFORE the geo-fallback (strict-order fallback order).
	if strings.Index(out, "server=10.8.1.0") > strings.Index(out, "server=77.88.8.8") {
		t.Error("tunnel primary must be ordered before the geo-fallback")
	}
}

// A DoH resolver renders as a loopback proxy ref (the proxy side is configured separately).
func TestRenderDnsmasqD_DoHAsLoopback(t *testing.T) {
	nd := NativeDNS{NoResolv: true, Resolvers: []NativeResolver{
		{Kind: KindDoH, Address: "https://1.1.1.1/dns-query", Tier: TierHidden},
		{Kind: KindPlain, Address: "77.88.8.8", Tier: TierFallback},
	}}
	out := RenderDnsmasqD(nd)
	if !strings.Contains(out, "server=127.0.0.1#5053") {
		t.Errorf("DoH should render as a loopback proxy ref; got:\n%s", out)
	}
	if !strings.Contains(out, "server=77.88.8.8") {
		t.Error("plain fallback should render directly")
	}
}

func TestKeeneticApplyCmds_BackupAndRestart(t *testing.T) {
	c := strings.Join(KeeneticApplyCmds("/opt/etc/dnsmasq.d/00-upstream.conf"), "\n")
	if !strings.Contains(c, ".bak-wayhop") || !strings.Contains(c, "S56dnsmasq restart") {
		t.Errorf("apply cmds must back up + restart dnsmasq: %s", c)
	}
}
