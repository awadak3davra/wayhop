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

// TestRenderDnsmasqD_LocalForwardRoundTrips: a `server=127.0.0.1#PORT` loopback forward to a local
// resolver whose DoH-proxy argv wasn't captured is read as KindLocal{Port} — it must SURVIVE a
// Read→Render round-trip, not be silently dropped (which deletes that DNS upstream on an
// adopt→edit→write-back).
func TestRenderDnsmasqD_LocalForwardRoundTrips(t *testing.T) {
	nd := ReadDnsmasqD("no-resolv\nserver=127.0.0.1#5335\nserver=77.88.8.8", "") // no proxy argv → KindLocal{5335}
	rendered := RenderDnsmasqD(nd)
	if !strings.Contains(rendered, "server=127.0.0.1#5335") {
		t.Errorf("loopback forward server=127.0.0.1#5335 was dropped on write-back:\n%s", rendered)
	}
}

func TestRenderDnsmasqD_Content(t *testing.T) {
	nd := ReadDnsmasqD(fixtureKeeneticUpstream, "")
	out := RenderDnsmasqD(nd)
	for _, want := range []string{"strict-order", "no-resolv", "server=10.0.1.0", "server=10.0.0.1", "server=77.88.8.8", "server=77.88.8.1"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered dnsmasq.d missing %q\n---\n%s", want, out)
		}
	}
	// The tunnel primaries must appear BEFORE the geo-fallback (strict-order fallback order).
	if strings.Index(out, "server=10.0.1.0") > strings.Index(out, "server=77.88.8.8") {
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

// TestRenderDnsmasqD_AdoptedDoHPortRoundTrips: a DoH resolver adopted from a proxy on a NON-default
// port must re-emit THAT port on write-back, not a synthetic 5053. Emitting 5053 would point dnsmasq
// at a loopback port where no proxy listens, silently breaking the encrypted tier on adopt→apply.
func TestRenderDnsmasqD_AdoptedDoHPortRoundTrips(t *testing.T) {
	conf := "no-resolv\nserver=127.0.0.1#5054\n"
	ps := "1234 root https-dns-proxy -a 127.0.0.1 -p 5054 -r https://dns.example/dns-query"
	nd := ReadDnsmasqD(conf, ps)
	if len(nd.Resolvers) != 1 || nd.Resolvers[0].Kind != KindDoH || nd.Resolvers[0].Port != 5054 {
		t.Fatalf("adopt must capture a DoH resolver on the real proxy port 5054, got %+v", nd.Resolvers)
	}
	out := RenderDnsmasqD(nd)
	if !strings.Contains(out, "server=127.0.0.1#5054") {
		t.Errorf("adopted DoH must re-emit its real proxy port 5054:\n%s", out)
	}
	if strings.Contains(out, "server=127.0.0.1#5053") {
		t.Errorf("must NOT invent a synthetic 5053 that targets a non-existent proxy:\n%s", out)
	}
}

// TestRenderDnsmasqD_AdoptedAndNewDoHNoCollision: an adopted DoH on 5053 plus a NEW (portless) DoH
// must not both emit 5053 — the new one has to skip the adopted port.
func TestRenderDnsmasqD_AdoptedAndNewDoHNoCollision(t *testing.T) {
	nd := NativeDNS{NoResolv: true, Resolvers: []NativeResolver{
		{Kind: KindDoH, Address: "https://a.example/dns-query", Port: 5053}, // adopted proxy on 5053
		{Kind: KindDoH, Address: "https://b.example/dns-query"},             // new, portless
	}}
	out := RenderDnsmasqD(nd)
	if strings.Count(out, "server=127.0.0.1#5053") != 1 {
		t.Errorf("port 5053 must be emitted exactly once (adopted DoH owns it):\n%s", out)
	}
	if !strings.Contains(out, "server=127.0.0.1#5054") {
		t.Errorf("the new DoH must skip the adopted 5053 and take 5054:\n%s", out)
	}
}

func TestKeeneticApplyCmds_BackupAndRestart(t *testing.T) {
	path := "/opt/etc/dnsmasq.d/00-upstream.conf"
	cmds := KeeneticApplyCmds(path)
	c := strings.Join(cmds, "\n")
	if !strings.Contains(c, ".bak-wayhop") || !strings.Contains(c, "S56dnsmasq restart") {
		t.Errorf("apply cmds must back up + restart dnsmasq: %s", c)
	}
	// The backup must be guarded so a SECOND apply (adopt → edit → re-apply) does not
	// overwrite the pristine .bak-wayhop with the already-WayHop-modified file. An
	// unconditional `cp -p` would clobber the only restore artifact.
	var backup string
	for _, cmd := range cmds {
		if strings.Contains(cmd, ".bak-wayhop") && strings.Contains(cmd, "cp ") {
			backup = cmd
		}
	}
	if backup == "" {
		t.Fatalf("no backup cp command found: %s", c)
	}
	if !strings.Contains(backup, "[ -f "+path+".bak-wayhop ]") || !strings.Contains(backup, "||") {
		t.Errorf("backup cp must be guarded with `[ -f ….bak-wayhop ] ||` so it snapshots the original only once: %q", backup)
	}
}

// TestRenderDnsmasqD_DoHPortSkipsLocalCollision: a DoH resolver's synthetic loopback port must not
// collide with a KindLocal forward's real port. With a KindLocal on 5053 and a DoH resolver, the DoH
// port must advance past 5053 so the two never emit the SAME `server=127.0.0.1#PORT` line — a
// collision would silently forward the encrypted DoH query to the plaintext local resolver.
func TestRenderDnsmasqD_DoHPortSkipsLocalCollision(t *testing.T) {
	check := func(nd NativeDNS) {
		out := RenderDnsmasqD(nd)
		if strings.Count(out, "server=127.0.0.1#5053") != 1 {
			t.Errorf("port 5053 must be emitted exactly once (no DoH/local collision):\n%s", out)
		}
		// The DoH resolver must land on a DISTINCT loopback port (5054), leaving 5053 to the local forward.
		if !strings.Contains(out, "server=127.0.0.1#5054") {
			t.Errorf("DoH must skip the KindLocal-claimed 5053 and use 5054:\n%s", out)
		}
	}
	// KindLocal before DoH.
	check(NativeDNS{Resolvers: []NativeResolver{
		{Kind: KindLocal, Address: "127.0.0.1", Port: 5053},
		{Kind: KindDoH, Address: "https://1.1.1.1/dns-query"},
	}})
	// DoH before KindLocal (either order collides without the pre-collected skip set).
	check(NativeDNS{Resolvers: []NativeResolver{
		{Kind: KindDoH, Address: "https://1.1.1.1/dns-query"},
		{Kind: KindLocal, Address: "127.0.0.1", Port: 5053},
	}})
}
