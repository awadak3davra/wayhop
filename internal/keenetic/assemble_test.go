package keenetic

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

func TestParseDomainFeed(t *testing.T) {
	body := "# comment\nyoutube.com\n! another\ndomain:googlevideo.com\nfull:exact.example.com\ninclude:google\nregexp:.*ads.*\nkeyword:tracker\n  spaced.com  # inline\n1.2.3.0/24\n"
	got := strings.Join(ParseDomainFeed(body), ",")
	want := "youtube.com,googlevideo.com,exact.example.com,spaced.com,1.2.3.0/24"
	if got != want {
		t.Errorf("ParseDomainFeed = %q, want %q", got, want)
	}
}

func TestInlineDomainSources(t *testing.T) {
	p := &model.Profile{RoutingLists: []model.RoutingList{
		{ID: "yt", Source: "https://feed/youtube.lst", Outbound: "g", Enabled: true},
		{ID: "tg", CIDRSource: "https://feed/ipv4.txt", Outbound: "g", Enabled: true},
	}}
	if err := InlineDomainSources(p, func(url string) ([]string, error) {
		return []string{"youtube.com", "googlevideo.com"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if p.RoutingLists[0].Source != "" || len(p.RoutingLists[0].Manual) != 2 {
		t.Errorf("domain Source not inlined: %+v", p.RoutingLists[0])
	}
	if p.RoutingLists[1].CIDRSource == "" {
		t.Error("a CIDRSource list must be left untouched by InlineDomainSources")
	}
}

// TestInlineCIDRSources: a CIDRSource feed is fetched + inlined into Manual (so it becomes a
// sing-box ip_cidr rule_set), while a domain Source list is left untouched.
func TestInlineCIDRSources(t *testing.T) {
	p := &model.Profile{RoutingLists: []model.RoutingList{
		{ID: "tg", CIDRSource: "https://feed/ipv4.txt", Outbound: "g", Enabled: true},
		{ID: "yt", Source: "https://feed/youtube.lst", Outbound: "g", Enabled: true},
	}}
	if err := InlineCIDRSources(p, func(url string) ([]string, error) {
		return []string{"149.154.160.0/20", "91.108.4.0/22"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if p.RoutingLists[0].CIDRSource != "" {
		t.Error("CIDRSource must be cleared after inlining")
	}
	if len(p.RoutingLists[0].Manual) != 2 || p.RoutingLists[0].Manual[0] != "149.154.160.0/20" {
		t.Errorf("CIDRs not inlined: %v", p.RoutingLists[0].Manual)
	}
	if p.RoutingLists[1].Source == "" || len(p.RoutingLists[1].Manual) != 0 {
		t.Error("a domain Source list must be left untouched")
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func genericAssemblyProfile() *model.Profile {
	return &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "exit-a", Name: "Exit A", Engine: model.EngineExternal,
			Protocol: model.ProtoAmneziaWG, Owner: model.OwnerExternal, Enabled: true,
			Params: map[string]any{"interface": "nwg1", "ndm_name": "Wireguard1"},
		}},
		RoutingLists: []model.RoutingList{
			{ID: "video", Source: "https://example.invalid/video.srs", Format: "binary", Outbound: "exit-a", Enabled: true},
			{ID: "messaging", CIDRSource: "https://example.invalid/ipv4.txt", Outbound: "exit-a", Enabled: true},
		},
	}
}

// TestAssembleSingboxConfig: the assembled config (validated whole on the device's sing-box
// 1.13.3) has the fakeip DNS plane over the DOMAIN sets only, the Keenetic TUN shape, and the
// fakeip cache.
func TestAssembleSingboxConfig(t *testing.T) {
	p := genericAssemblyProfile()
	cfg, err := AssembleSingboxConfig(p, "exit-a")
	if err != nil {
		t.Fatal(err)
	}

	// fakeip dns: censored DOMAIN sets resolve to fakeip; the IP-feed (telegram) is NOT a set.
	dns := cfg["dns"].(map[string]any)
	if dns["final"] != "dns_local" {
		t.Error("dns final must be dns_local")
	}
	rules := dns["rules"].([]map[string]any)
	if len(rules) == 0 {
		t.Fatal("expected a fakeip rule for the censored sets")
	}
	sets := rules[0]["rule_set"].([]string)
	if !containsStr(sets, "rs-video") {
		t.Errorf("video (domain) must be a fakeip censored set; sets=%v", sets)
	}
	if containsStr(sets, "rs-messaging") || containsStr(sets, "rsm-messaging") {
		t.Errorf("messaging (IP feed → kernel) must NOT be a sing-box fakeip set; sets=%v", sets)
	}

	// TUN overridden to the Keenetic shape (NDM routes the fakeip range into it).
	var tun map[string]any
	for _, in := range cfg["inbounds"].([]any) {
		if m, ok := in.(map[string]any); ok && m["tag"] == "tun-in" {
			tun = m
		}
	}
	if tun == nil {
		t.Fatal("no tun-in inbound")
	}
	if tun["auto_route"] != false || tun["interface_name"] != "wr-tun" || tun["stack"] != "gvisor" {
		t.Errorf("tun not overridden to the Keenetic shape: %v", tun)
	}

	// store_fakeip cache so an all-down lookup returns the cached fakeip (no leak).
	exp := cfg["experimental"].(map[string]any)
	if exp["cache_file"].(map[string]any)["store_fakeip"] != true {
		t.Error("experimental.cache_file.store_fakeip must be set")
	}

	// route.default_domain_resolver present.
	if cfg["route"].(map[string]any)["default_domain_resolver"] == nil {
		t.Error("route.default_domain_resolver must be set")
	}
}

// TestAssembleSingboxConfig_DanglingDetourRejected: a DoH detour that is not a live outbound is
// rejected at assembly (pre-flight) rather than emitted as a dangling dns.detour that sing-box
// would reject at startup — which, with no check gate, would black-hole the LAN until rollback.
func TestAssembleSingboxConfig_DanglingDetourRejected(t *testing.T) {
	p := genericAssemblyProfile()
	if _, err := AssembleSingboxConfig(p, "missing-exit"); err == nil {
		t.Error("a DoH detour that is not a live outbound must be rejected")
	}
	if _, err := AssembleSingboxConfig(p, ""); err == nil {
		t.Error("an empty DoH detour must be rejected")
	}
}

func TestCensoredRuleSetTags_DomainsOnly(t *testing.T) {
	p := genericAssemblyProfile()
	tags := strings.Join(censoredRuleSetTags(p), ",")
	if !strings.Contains(tags, "rs-video") {
		t.Errorf("domain list video missing from censored sets: %s", tags)
	}
	if strings.Contains(tags, "messaging") {
		t.Errorf("IP-feed/IP lists must not be censored sets: %s", tags)
	}
}
