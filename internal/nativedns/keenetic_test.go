package nativedns

import "testing"

// The live Keenetic upstream chain (00-upstream.conf) after the Tier-3 fix: two VPS-DoT-over-tunnel
// primaries (private mesh IPs) + strict-order/no-resolv + the Yandex geo-fallback last resort.
const fixtureKeeneticUpstream = `# Primary: VPS DNS over healthy AWG tunnel (nwg2)
server=10.8.1.0
# Secondary: same VPS DNS over the alternate AWG tunnel (nwg5)
server=10.0.0.1
strict-order
no-resolv
# Tier-3 last-resort: geo-allowed, non-blocked RU resolvers (Yandex)
server=77.88.8.8
server=77.88.8.1`

func TestReadDnsmasqD_LiveTier3Chain(t *testing.T) {
	nd := ReadDnsmasqD(fixtureKeeneticUpstream, "")
	if nd.Platform != "keenetic" {
		t.Errorf("platform = %q, want keenetic", nd.Platform)
	}
	if !nd.StrictOrder || !nd.NoResolv {
		t.Errorf("strict_order/no_resolv should be adopted, got %v/%v", nd.StrictOrder, nd.NoResolv)
	}
	if len(nd.Resolvers) != 4 {
		t.Fatalf("resolvers = %d, want 4, got %+v", len(nd.Resolvers), nd.Resolvers)
	}
	// Primaries: private mesh IPs → Tier-1, via-tunnel.
	for i, ip := range []string{"10.8.1.0", "10.0.0.1"} {
		r := nd.Resolvers[i]
		if r.Address != ip || r.Kind != KindPlain || r.Tier != TierHidden || !r.ViaTunnel {
			t.Errorf("primary[%d] = %+v, want %s Tier1 via-tunnel", i, r, ip)
		}
	}
	// Fallbacks: public Yandex → Tier-3, NOT via-tunnel.
	for i, ip := range []string{"77.88.8.8", "77.88.8.1"} {
		r := nd.Resolvers[2+i]
		if r.Address != ip || r.Kind != KindPlain || r.Tier != TierFallback || r.ViaTunnel {
			t.Errorf("fallback[%d] = %+v, want %s Tier3 direct", i, r, ip)
		}
	}
}

// A local https-dns-proxy referenced by dnsmasq (127.0.0.1#5053) is adopted as its DoH resolver_url.
func TestReadDnsmasqD_LocalDoHProxyRef(t *testing.T) {
	conf := "no-resolv\nserver=127.0.0.1#5053\nserver=77.88.8.8"
	args := "-d -a 127.0.0.1 -p 5053 -b 1.1.1.1,8.8.8.8 -r https://1.1.1.1/dns-query"
	nd := ReadDnsmasqD(conf, args)
	if len(nd.Resolvers) != 2 {
		t.Fatalf("resolvers = %d, want 2, got %+v", len(nd.Resolvers), nd.Resolvers)
	}
	if r := nd.Resolvers[0]; r.Kind != KindDoH || r.Address != "https://1.1.1.1/dns-query" || r.Tier != TierHidden {
		t.Errorf("resolver[0] = %+v, want DoH https://1.1.1.1/dns-query Tier1", r)
	}
	if r := nd.Resolvers[1]; r.Kind != KindPlain || r.Address != "77.88.8.8" || r.Tier != TierFallback {
		t.Errorf("resolver[1] = %+v, want plain Yandex Tier3", r)
	}
}

func TestReadDnsmasqD_SplitDNSAndCommentsSkipped(t *testing.T) {
	conf := "# comment\nserver=/lampa.mx/10.8.1.0\nserver=/jac.red/10.8.1.0\nserver=10.8.1.0"
	nd := ReadDnsmasqD(conf, "")
	if len(nd.Resolvers) != 1 || nd.Resolvers[0].Address != "10.8.1.0" {
		t.Errorf("split-DNS/comments must be skipped; got %+v", nd.Resolvers)
	}
}

func TestIsPrivateIP(t *testing.T) {
	priv := []string{"10.8.1.0", "192.168.1.1", "172.16.5.5", "127.0.0.1"}
	pub := []string{"77.88.8.8", "1.1.1.1", "8.8.8.8"}
	for _, ip := range priv {
		if !isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%s) = false, want true", ip)
		}
	}
	for _, ip := range pub {
		if isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%s) = true, want false", ip)
		}
	}
}
