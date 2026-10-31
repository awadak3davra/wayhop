package generator

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// feedLists are two lists fed only by a fetched feed, the shape every domain preset and every CIDR
// preset in the catalog takes once refreshed: no Manual entry, no Source.
func feedLists(outbound string) []model.RoutingList {
	return []model.RoutingList{
		{ID: "feed-dom", Name: "D", Enabled: true, Outbound: outbound,
			DomainSource: "https://example.net/d.lst", DomainCache: []string{"example.org", "example.com"}},
		{ID: "feed-cidr", Name: "C", Enabled: true, Outbound: outbound,
			CIDRSource: "https://example.net/c.lst", CIDRCache: []string{"198.51.100.0/24"}},
	}
}

func feedSet(res *Result, tag string) map[string]any {
	route, _ := res.Config["route"].(map[string]any)
	sets, _ := route["rule_set"].([]map[string]any)
	for _, s := range sets {
		if s["tag"] == tag {
			return s
		}
	}
	return nil
}

func feedSetHas(set map[string]any, key, want string) bool {
	rules, _ := set["rules"].([]map[string]any)
	for _, r := range rules {
		if v, _ := r[key].([]string); slices.Contains(v, want) {
			return true
		}
	}
	return false
}

// A list fed only by a fetched feed had no rule in the core: the generator read Manual alone, while
// the feeds reached only pbr and KeeneticOS's resolver. On OpenWrt a domain preset (seen live: "RU
// outside", 39 names, enabled for weeks) and any IP feed sent to a proxy routed nothing, with a clean
// review (QA-066).
func TestFetchedFeedsReachTheCore(t *testing.T) {
	p := hybridProfile()
	p.RoutingLists = append(p.RoutingLists, feedLists("p-vless")...)
	res := gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true})
	dom, cidr := feedSet(res, "rsm-feed-dom"), feedSet(res, "rsm-feed-cidr")
	if !feedSetHas(dom, "domain_suffix", "example.org") || !feedSetHas(cidr, "ip_cidr", "198.51.100.0/24") {
		t.Fatalf("fetched feeds missing from the core's rule sets: dom=%v cidr=%v", dom, cidr)
	}
	for _, tag := range []string{"rsm-feed-dom", "rsm-feed-cidr"} {
		routed := false
		for _, r := range gen_routeRules(res) {
			if sets, _ := r["rule_set"].([]string); slices.Contains(sets, tag) && r["outbound"] == "p-vless" {
				routed = true
			}
		}
		if !routed {
			t.Errorf("%s: no route rule sends it to the list's outbound", tag)
		}
	}
	feedSingBoxCheck(t, res)
}

// In hybrid the split must treat a feed exactly as pbr does: a pure IP feed at a kernel egress is
// the kernel's (no set here, no DNS tag), a domain feed stays in the core and keeps the kernel
// outbound it routes to alive, and a DNS rule naming either list gets exactly the tags emitted.
func TestFetchedFeedsFollowTheHybridSplit(t *testing.T) {
	p := hybridProfile()
	p.RoutingLists = append(p.RoutingLists, feedLists("k-ext")...)
	p.RoutingLists[0].Enabled = false // the fixture's own pure-IP list; leave k-ext reached by the feeds alone
	p.Rules = slices.DeleteFunc(p.Rules, func(r model.Rule) bool { return r.Outbound == "k-ext" })
	ex4, ex6 := hybridExclude(t, p)
	if !slices.Contains(ex4, "198.51.100.0/24") {
		t.Fatalf("test setup: pbr should kernel-route the CIDR feed, exclude = %v", ex4)
	}
	res := gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true, Hybrid: true, KernelExcludeV4: ex4, KernelExcludeV6: ex6})
	if feedSet(res, "rsm-feed-cidr") != nil {
		t.Error("a pure IP feed at a kernel egress is pbr's; the core must not carry it too")
	}
	if !feedSetHas(feedSet(res, "rsm-feed-dom"), "domain_suffix", "example.com") {
		t.Error("a domain feed at a kernel egress must stay in the core: pbr cannot route names on OpenWrt")
	}
	if !gen_outboundTags(res)["k-ext"] {
		t.Error("the kernel outbound the domain feed routes to was dropped")
	}
	gen_assertNoDangling(t, res)
	if got := dnsListTags(p, "feed-dom", true); !slices.Equal(got, []string{"rsm-feed-dom"}) {
		t.Errorf("DNS tags for the domain feed = %v", got)
	}
	if got := dnsListTags(p, "feed-cidr", true); len(got) != 0 {
		t.Errorf("DNS tags for the kernel-routed CIDR feed = %v, want none (no such set is emitted)", got)
	}
	feedSingBoxCheck(t, res)
}

// Fast mode may stop the core only when nothing needs it. A domain feed does on OpenWrt, so it
// keeps the core exactly like a typed name; an IP feed at a kernel egress does not.
func TestFetchedDomainFeedKeepsTheCore(t *testing.T) {
	native := func(rl model.RoutingList) *model.Profile {
		return &model.Profile{
			Endpoints: []model.Endpoint{{ID: "k-ext", Name: "EXT", Engine: model.EngineExternal, Enabled: true,
				Params: map[string]any{"interface": "awg1"}}},
			Rules:        []model.Rule{{ID: "def", Default: true, Outbound: model.OutboundDirect}},
			RoutingLists: []model.RoutingList{rl},
		}
	}
	lists := feedLists("k-ext")
	if DatapathNativeOnly(native(lists[0]), "fast") {
		t.Error("a domain feed was judged native: stopping the core would drop it")
	}
	if !DatapathNativeOnly(native(lists[1]), "fast") {
		t.Error("an IP feed at a kernel egress needs no core")
	}
}

func feedSingBoxCheck(t *testing.T, res *Result) {
	t.Helper()
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		return
	}
	data, err := json.MarshalIndent(res.Config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "feeds.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", f).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check rejected the config: %v\n%s", err, strings.TrimSpace(string(out)))
	}
}

// A DNS rule may name only lists that emit a set. A plain-text Source emits none (sing-box cannot load
// it), and naming its rs- tag anyway left the rule pointing at a missing rule_set: check refused.
func TestDNSListTagsSkipAPlainTextSource(t *testing.T) {
	p := genDNSProfile(secureDNS())
	p.RoutingLists[0].Source = "https://example.net/list.lst"
	for _, tag := range dnsListTags(p, "ru-list", false) {
		if tag == "rs-ru-list" {
			t.Fatalf("tags = %v: a plain-text source has no rule_set to name", dnsListTags(p, "ru-list", false))
		}
	}
}

// A DNS rule whose every named list emits nothing would keep only its other matchers and widen:
// {lists, query_type: A} meant "A queries for these names" and became "every A query".
func TestDNSRuleWithNoListLeftIsDropped(t *testing.T) {
	dns := secureDNS()
	dns.Rules = []model.DNSRule{{ID: "a-only", RuleSets: []string{"ru-list"}, QueryType: []string{"A"}, Server: "local"}}
	p := genDNSProfile(dns)
	p.RoutingLists[0].Enabled = false
	res := gen_must(t, p, Options{MixedPort: 1080})
	block, _ := res.Config["dns"].(map[string]any)
	rules, _ := block["rules"].([]map[string]any)
	for _, r := range rules {
		if _, ok := r["query_type"]; ok {
			t.Fatalf("rule widened to every query of its type: %v", r)
		}
	}
	singboxCheckDNS(t, res.Config)
}

// In hybrid a list at a kernel egress stays in the core for its names, but pbr routes its fetched IP
// feed and the TUN excludes those prefixes: the core's copy of the feed would never see a packet.
func TestHybridCoreCarriesNamesNotTheKernelFeed(t *testing.T) {
	p := hybridProfile()
	p.RoutingLists = []model.RoutingList{{ID: "both", Name: "B", Enabled: true, Outbound: "k-ext",
		Manual: []string{"192.0.2.10"}, CIDRSource: "https://example.net/c.lst", CIDRCache: []string{"198.51.100.0/24"},
		DomainSource: "https://example.net/d.lst", DomainCache: []string{"example.org"}}}
	ex4, ex6 := hybridExclude(t, p)
	res := gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true, Hybrid: true, KernelExcludeV4: ex4, KernelExcludeV6: ex6})
	set := feedSet(res, "rsm-both")
	if !feedSetHas(set, "domain_suffix", "example.org") || !feedSetHas(set, "ip_cidr", "192.0.2.10/32") {
		t.Fatalf("the core lost the list's names or its typed IP: %v", set)
	}
	if feedSetHas(set, "ip_cidr", "198.51.100.0/24") {
		t.Error("the core carries the kernel-routed IP feed it never sees a packet for")
	}
	// Without hybrid the core is the only carrier, so the feed must be there.
	if !feedSetHas(feedSet(gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true}), "rsm-both"), "ip_cidr", "198.51.100.0/24") {
		t.Error("tun mode: the IP feed is missing from the only plane that can route it")
	}
}
