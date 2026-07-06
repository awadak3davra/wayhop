package nativedns

import "testing"

// Representative `uci show` output, modelled on the live AX3000T DNS stack: 3 https-dns-proxy DoH
// instances + dnsmasq noresolv, split-DNS blocks, loopback refs to the proxies, and doh_backup_server
// plaintext fallbacks. (Synthetic — no live device specifics committed.)
const fixtureHTTPSDNSProxy = `https-dns-proxy.config=main
https-dns-proxy.config.listen_addr='127.0.0.1'
https-dns-proxy.@https-dns-proxy[0]=https-dns-proxy
https-dns-proxy.@https-dns-proxy[0].bootstrap_dns='1.1.1.1,1.0.0.1'
https-dns-proxy.@https-dns-proxy[0].resolver_url='https://1.1.1.1/dns-query'
https-dns-proxy.@https-dns-proxy[0].listen_addr='127.0.0.1'
https-dns-proxy.@https-dns-proxy[0].listen_port='5053'
https-dns-proxy.@https-dns-proxy[1]=https-dns-proxy
https-dns-proxy.@https-dns-proxy[1].resolver_url='https://9.9.9.9/dns-query'
https-dns-proxy.@https-dns-proxy[1].listen_port='5054'
https-dns-proxy.@https-dns-proxy[2]=https-dns-proxy
https-dns-proxy.@https-dns-proxy[2].resolver_url='https://8.8.8.8/dns-query'
https-dns-proxy.@https-dns-proxy[2].listen_port='5055'`

const fixtureDHCP = `dhcp.@dnsmasq[0]=dnsmasq
dhcp.@dnsmasq[0].noresolv='1'
dhcp.@dnsmasq[0].rebind_protection='1'
dhcp.@dnsmasq[0].server='/mask.icloud.com/' '/use-application-dns.net/' '127.0.0.1#5053' '127.0.0.1#5054' '127.0.0.1#5055'
dhcp.@dnsmasq[0].doh_backup_server='1.1.1.1' '1.0.0.1' '9.9.9.9'
dhcp.lan.dhcpv4='server'`

func TestReadUCI_AdoptsDoHAndFallbacks(t *testing.T) {
	nd := ReadUCI(fixtureHTTPSDNSProxy, fixtureDHCP)
	if nd.Platform != "openwrt" {
		t.Errorf("platform = %q, want openwrt", nd.Platform)
	}
	if !nd.NoResolv {
		t.Error("noresolv should be adopted as true")
	}
	// 3 DoH proxies (Tier-1) + 3 plaintext backups (Tier-3); split-DNS + loopback proxy refs excluded.
	if len(nd.Resolvers) != 6 {
		t.Fatalf("resolvers = %d, want 6 (3 DoH + 3 plain fallback), got %+v", len(nd.Resolvers), nd.Resolvers)
	}
	wantDoH := []string{"https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query", "https://8.8.8.8/dns-query"}
	for i, url := range wantDoH {
		r := nd.Resolvers[i]
		if r.Kind != KindDoH || r.Address != url || r.Tier != TierHidden {
			t.Errorf("resolver[%d] = %+v, want DoH %s Tier1", i, r, url)
		}
	}
	wantPlain := []string{"1.1.1.1", "1.0.0.1", "9.9.9.9"}
	for i, ip := range wantPlain {
		r := nd.Resolvers[3+i]
		if r.Kind != KindPlain || r.Address != ip || r.Tier != TierFallback {
			t.Errorf("fallback[%d] = %+v, want plain %s Tier3", i, r, ip)
		}
	}
	// The split-DNS "/domain/" entries and the 127.0.0.1#5053-5 proxy refs must NOT appear as resolvers.
	for _, r := range nd.Resolvers {
		if r.Address == "127.0.0.1" || r.Address == "" {
			t.Errorf("loopback/empty leaked into resolvers: %+v", r)
		}
	}
}

func TestReadUCI_EmptyIsSafe(t *testing.T) {
	nd := ReadUCI("", "")
	if len(nd.Resolvers) != 0 || nd.NoResolv {
		t.Errorf("empty input must yield an empty plane, got %+v", nd)
	}
	if nd.Platform != "openwrt" {
		t.Errorf("platform = %q, want openwrt", nd.Platform)
	}
}

func TestParseUCILine(t *testing.T) {
	cases := []struct {
		line, key string
		vals      []string
	}{
		{"a.b.c='x'", "a.b.c", []string{"x"}},
		{"a.b.server='v1' 'v2' 'v3'", "a.b.server", []string{"v1", "v2", "v3"}},
		{"a.@dnsmasq[0]=dnsmasq", "a.@dnsmasq[0]", []string{"dnsmasq"}},
		{"# comment", "", nil},
		{"no-equals-here", "", nil},
		{"  a.b.c = '1'  ", "a.b.c", []string{"1"}},
	}
	for _, c := range cases {
		k, v := parseUCILine(c.line)
		if k != c.key {
			t.Errorf("parseUCILine(%q) key = %q, want %q", c.line, k, c.key)
		}
		if len(v) != len(c.vals) {
			t.Errorf("parseUCILine(%q) vals = %v, want %v", c.line, v, c.vals)
			continue
		}
		for i := range v {
			if v[i] != c.vals[i] {
				t.Errorf("parseUCILine(%q) vals[%d] = %q, want %q", c.line, i, v[i], c.vals[i])
			}
		}
	}
}

func TestUCISectionIndex(t *testing.T) {
	idx, field, ok := uciSectionIndex("https-dns-proxy.@https-dns-proxy[2].resolver_url")
	if !ok || idx != 2 || field != "resolver_url" {
		t.Errorf("got idx=%d field=%q ok=%v, want 2/resolver_url/true", idx, field, ok)
	}
	if _, _, ok := uciSectionIndex("dhcp.lan.dhcpv4"); ok {
		t.Error("a non-indexed key must return ok=false")
	}
}
