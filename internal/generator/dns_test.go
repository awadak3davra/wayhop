package generator

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"wayhop/internal/model"
)

func genDNSProfile(dns *model.DNSSettings) *model.Profile {
	return &model.Profile{
		Endpoints:    []model.Endpoint{{ID: "nl", Engine: model.EngineExternal, Params: map[string]any{"interface": "awg0"}, Enabled: true}},
		Groups:       []model.Group{{ID: "grp", Type: model.GroupURLTest, Members: []string{"nl", "direct"}}},
		RoutingLists: []model.RoutingList{{ID: "ru-list", Manual: []string{"example.ru"}, Outbound: "direct", Enabled: true}},
		DNS:          dns,
	}
}

// secureDNS is the failover-aware secure default: DoH pinned by IP, detour = the failover group,
// local for in-country, leak-proof, ipv4_only.
func secureDNS() *model.DNSSettings {
	return &model.DNSSettings{
		Enabled: true,
		Servers: []model.DNSServer{
			{Tag: "secure", Type: "https", Server: "1.1.1.1", Detour: "grp", Enabled: true},
			{Tag: "secure_bk", Type: "https", Server: "9.9.9.9", Detour: "grp", Enabled: true},
			{Tag: "local", Type: "local", Enabled: true},
		},
		Rules:     []model.DNSRule{{ID: "ru", RuleSets: []string{"ru-list"}, Server: "local"}},
		Final:     "secure",
		Strategy:  "ipv4_only",
		LeakProof: true,
	}
}

// singboxCheckDNS runs a real `sing-box check` on the config when WR_SINGBOX points at a binary (CI);
// otherwise it skips, leaving the structural assertions as the local gate.
func singboxCheckDNS(t *testing.T, cfg map[string]any) {
	t.Helper()
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		return
	}
	f := filepath.Join(t.TempDir(), "dns.json")
	b, _ := json.MarshalIndent(cfg, "", " ")
	if err := os.WriteFile(f, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", f).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check rejected the DNS config: %v\n%s", err, out)
	}
}

// TestGenerateDNSNilByteIdentical: a profile with no DNS plane emits no "dns" key, and the presence
// of DNS never changes anything for such a profile (the backward-compat guarantee).
func TestGenerateDNSNilByteIdentical(t *testing.T) {
	p := genDNSProfile(nil)
	res, err := Generate(p, Options{MixedPort: 1080})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, ok := res.Config["dns"]; ok {
		t.Fatalf("nil DNS must not emit a \"dns\" key")
	}
}

func TestGenerateDNSSecureDefault(t *testing.T) {
	p := genDNSProfile(secureDNS())
	res, err := Generate(p, Options{MixedPort: 1080})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	dns, ok := res.Config["dns"].(map[string]any)
	if !ok {
		t.Fatalf("no dns block emitted")
	}
	servers, _ := dns["servers"].([]map[string]any)
	if len(servers) != 3 {
		t.Fatalf("servers = %d, want 3 (secure, secure_bk, local)", len(servers))
	}
	if servers[0]["tag"] != "secure" || servers[0]["type"] != "https" || servers[0]["server"] != "1.1.1.1" || servers[0]["detour"] != "grp" {
		t.Errorf("secure server = %+v, want IP-pinned DoH detour=grp (failover-aware)", servers[0])
	}
	if dns["final"] != "secure" || dns["strategy"] != "ipv4_only" {
		t.Errorf("final/strategy = %v/%v, want secure/ipv4_only", dns["final"], dns["strategy"])
	}
	rules, _ := dns["rules"].([]map[string]any)
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if ts, _ := rules[0]["rule_set"].([]string); len(ts) != 1 || ts[0] != "rsm-ru-list" {
		t.Errorf("rule rule_set = %v, want [rsm-ru-list] (the manual list's tag)", rules[0]["rule_set"])
	}
	if rules[0]["server"] != "local" {
		t.Errorf("rule server = %v, want local", rules[0]["server"])
	}
	// cache_file must be enabled so the DNS cache survives a reboot.
	exp, _ := res.Config["experimental"].(map[string]any)
	if _, ok := exp["cache_file"]; !ok {
		t.Errorf("cache_file not enabled for a DNS profile")
	}
	singboxCheckDNS(t, res.Config)
}

// TestGenerateDNSDefaultDomainResolver: emitting a DNS plane must add route.default_domain_resolver
// (a WARN on sing-box 1.12.x but a startup FATAL on 1.13.x when absent — the whole config fails to
// load), pointing at a DIRECT-dialing resolver — the `local` server here — so an outbound hostname
// never needs its tunnel already up. A nil DNS plane must NOT add the field (byte-identical).
func TestGenerateDNSDefaultDomainResolver(t *testing.T) {
	res, err := Generate(genDNSProfile(secureDNS()), Options{MixedPort: 1080})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	route, _ := res.Config["route"].(map[string]any)
	ddr, ok := route["default_domain_resolver"].(map[string]any)
	if !ok {
		t.Fatalf("route.default_domain_resolver missing — sing-box 1.13 FATALs without it once a dns plane exists")
	}
	if ddr["server"] != "local" {
		t.Errorf("default_domain_resolver.server = %v, want local (direct-dialing, no bootstrap cycle)", ddr["server"])
	}
	// nil DNS: the field must be absent (no behavioural change for a pre-DNS profile).
	res2, err := Generate(genDNSProfile(nil), Options{MixedPort: 1080})
	if err != nil {
		t.Fatalf("generate nil: %v", err)
	}
	if r2, _ := res2.Config["route"].(map[string]any); r2 != nil {
		if _, ok := r2["default_domain_resolver"]; ok {
			t.Errorf("nil DNS must not add route.default_domain_resolver")
		}
	}
}

func TestGenerateDNSFakeIPDroppedInFast(t *testing.T) {
	dns := secureDNS()
	dns.FakeIP = true
	dns.IndependentCache = true
	dns.Servers = append(dns.Servers, model.DNSServer{Tag: "fake", Type: "fakeip", Inet4Range: "198.18.0.0/15", Enabled: true})
	dns.Rules = append(dns.Rules, model.DNSRule{ID: "cx", RuleSets: []string{"ru-list"}, Server: "fake"})

	// fast/mixed (no TUN): the fakeip server + its rule must be dropped (they'd blackhole in kernel PBR).
	res, err := Generate(genDNSProfile(dns), Options{MixedPort: 1080, TunEnabled: false})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	d := res.Config["dns"].(map[string]any)
	for _, s := range d["servers"].([]map[string]any) {
		if s["type"] == "fakeip" {
			t.Fatalf("fakeip server must be dropped without a TUN plane")
		}
	}
	for _, r := range d["rules"].([]map[string]any) {
		if r["server"] == "fake" {
			t.Fatalf("a rule targeting the dropped fakeip server must be dropped too")
		}
	}
}

func TestGenerateDNSFakeIPKeptInTun(t *testing.T) {
	dns := secureDNS()
	dns.FakeIP = true
	dns.IndependentCache = true
	dns.Servers = append(dns.Servers, model.DNSServer{Tag: "fake", Type: "fakeip", Inet4Range: "198.18.0.0/15", Enabled: true})
	dns.Rules = append([]model.DNSRule{{ID: "cx", RuleSets: []string{"ru-list"}, Server: "fake"}}, dns.Rules...)

	res, err := Generate(genDNSProfile(dns), Options{MixedPort: 1080, TunEnabled: true, TunAddr: "172.19.0.1/30"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	d := res.Config["dns"].(map[string]any)
	foundFake := false
	for _, s := range d["servers"].([]map[string]any) {
		if s["type"] == "fakeip" && s["inet4_range"] == "198.18.0.0/15" {
			foundFake = true
		}
	}
	if !foundFake {
		t.Fatalf("fakeip server must be kept in TUN mode")
	}
	if d["independent_cache"] != true {
		t.Errorf("fakeip requires independent_cache=true in the emitted block")
	}
	singboxCheckDNS(t, res.Config)
}
