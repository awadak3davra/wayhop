package generator

import (
	"encoding/json"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// fastDNSProfile: a domain list at a kernel tunnel, a remote rule-set list at the same tunnel, and a
// domain list at a proxy only the core carries.
func fastDNSProfile() *model.Profile {
	p := hybridProfile()
	p.RoutingLists = append(p.RoutingLists,
		model.RoutingList{ID: "rl-dom-ext", Name: "AI", Manual: []string{"openai.com", "1.2.3.0/24"}, Outbound: "k-ext", Enabled: true},
		model.RoutingList{ID: "rl-srs-ext", Name: "SRS", Source: "https://example.test/geo.srs", Outbound: "k-ext", Enabled: true},
		model.RoutingList{ID: "rl-dom-vless", Name: "YT", Manual: []string{"youtube.com"}, Outbound: "p-vless", Enabled: true},
	)
	return p
}

func fastGen(t *testing.T, tun bool) (*Result, string) {
	t.Helper()
	res, err := Generate(fastDNSProfile(), Options{MixedPort: 7890, Hybrid: true, FastDNS: true, TunEnabled: tun,
		KernelExcludeV4: []string{"1.2.3.0/24"}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	raw, _ := json.Marshal(res.Config)
	return res, string(raw)
}

// TestFastDNSKernelListsLeaveTheCore: a list at a kernel egress, names or remote rule-set alike, emits
// nothing into the core; the core-only list keeps its rule.
func TestFastDNSKernelListsLeaveTheCore(t *testing.T) {
	_, raw := fastGen(t, false)
	for _, gone := range []string{"rsm-rl-dom-ext", "rs-rl-srs-ext", "geo.srs", "openai.com"} {
		if strings.Contains(raw, gone) {
			t.Errorf("kernel-egress list content %q reached the core config", gone)
		}
	}
	if !strings.Contains(raw, "rsm-rl-dom-vless") || !strings.Contains(raw, "youtube.com") {
		t.Error("the core-only list lost its rule")
	}
	// Hybrid (no FastDNS) keeps the domain list in the core: the TUN sniffs it there.
	res, err := Generate(fastDNSProfile(), Options{MixedPort: 7890, Hybrid: true, TunEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res.Config)
	if !strings.Contains(string(b), "rsm-rl-dom-ext") {
		t.Error("hybrid dropped a domain list it must sniff")
	}
}

// TestFastDNSTun: with a core-only list the server asks for the TUN (pbr's CorePin), and it is the
// hybrid TUN: auto_route + auto_redirect with the kernel's prefixes excluded. Without, no TUN.
func TestFastDNSTun(t *testing.T) {
	tunOf := func(res *Result) map[string]any {
		ins, _ := res.Config["inbounds"].([]map[string]any)
		for _, in := range ins {
			if in["type"] == "tun" {
				return in
			}
		}
		return nil
	}
	res, _ := fastGen(t, true)
	tun := tunOf(res)
	if tun == nil || tun["auto_route"] != true || tun["auto_redirect"] != true {
		t.Fatalf("fast mode with a core-only list: tun = %v", tun)
	}
	if ex, _ := tun["route_exclude_address"].([]string); len(ex) != 1 || ex[0] != "1.2.3.0/24" {
		t.Errorf("route_exclude_address = %v", tun["route_exclude_address"])
	}
	res, _ = fastGen(t, false)
	if tunOf(res) != nil {
		t.Error("TUN without a core-only list")
	}
}
