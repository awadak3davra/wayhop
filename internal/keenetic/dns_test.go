package keenetic

import "testing"

// TestFakeipDNS: the structure that passed `sing-box check` on the device's sing-box 1.13.3.
func TestFakeipDNS(t *testing.T) {
	d := fakeipDNS(DNSOptions{DoHDetour: "wgtest", CensoredSets: []string{"rkn", "youtube"}})

	servers := d["servers"].([]map[string]any)
	if len(servers) != 3 {
		t.Fatalf("want 3 dns servers, got %d", len(servers))
	}
	// DoH pinned by IP-literal, routed over a tunnel (no plaintext WAN leak, no bootstrap A-lookup).
	if doh := servers[0]; doh["type"] != "https" || doh["server"] != "1.1.1.1" || doh["detour"] != "wgtest" {
		t.Errorf("DoH server wrong: %v", doh)
	}
	if loc := servers[1]; loc["type"] != "local" {
		t.Errorf("local resolver wrong: %v", loc)
	}
	if fi := servers[2]; fi["type"] != "fakeip" || fi["inet4_range"] != "198.18.0.0/15" {
		t.Errorf("fakeip server wrong: %v", fi)
	}

	rules := d["rules"].([]map[string]any)
	if len(rules) != 1 || rules[0]["server"] != "dns_fakeip" {
		t.Errorf("censored sets must resolve to fakeip: %v", rules)
	}
	if got := rules[0]["rule_set"].([]string); len(got) != 2 {
		t.Errorf("rule_set members = %v", got)
	}
	if d["final"] != "dns_local" {
		t.Error("non-censored lookups must use the local resolver (final=dns_local)")
	}
	if d["independent_cache"] != true {
		t.Error("independent_cache must be set for fakeip")
	}
}

func TestFakeipDNS_NoCensoredSets(t *testing.T) {
	if rules := fakeipDNS(DNSOptions{})["rules"].([]map[string]any); len(rules) != 0 {
		t.Errorf("no censored sets → no fakeip rule, got %v", rules)
	}
}

func TestKeeneticTUN(t *testing.T) {
	tun := keeneticTUN("tun-in", "wr-tun", "172.19.8.1/30", 0)
	if tun["auto_route"] != false {
		t.Error("auto_route must be false — NDM owns the routes, not sing-box")
	}
	if tun["stack"] != "gvisor" || tun["interface_name"] != "wr-tun" {
		t.Errorf("tun shape wrong: %v", tun)
	}
	if tun["mtu"] != 1400 {
		t.Errorf("default mtu = %v, want 1400", tun["mtu"])
	}
}
