package generator

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// TestGenerateDNSDropsUnreferencedDisabledServer: a disabled server that nothing references is a
// valid saved-but-inactive draft — the generator must simply not EMIT it (a disabled resolver in the
// live plane is nonsense), while the rest of the config generates normally.
func TestGenerateDNSDropsUnreferencedDisabledServer(t *testing.T) {
	dns := &model.DNSSettings{
		Enabled: true,
		Servers: []model.DNSServer{
			{Tag: "off", Type: "https", Server: "1.1.1.1", Detour: "grp", Enabled: false}, // disabled, UNREFERENCED
			{Tag: "local", Type: "local", Enabled: true},
		},
		Final: "local", // the ENABLED server
	}
	res, err := Generate(genDNSProfile(dns), Options{MixedPort: 1080})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	d, _ := res.Config["dns"].(map[string]any)
	if d == nil {
		t.Fatal("expected a dns block")
	}
	blob, _ := json.Marshal(d)
	if strings.Contains(string(blob), `"off"`) {
		t.Errorf("disabled server \"off\" was emitted into the live plane:\n%s", blob)
	}
	singboxCheckDNS(t, res.Config)
}

// TestGenerateDNSRejectsReferenceToDisabledServer: a `final` or an enabled rule that names a DISABLED
// server is refused at the generator boundary too (Generate runs Validate) — LOOP-029. Before that
// fix Generate silently dropped the reference, leaving the plane with no default resolver, or the
// rule's queries falling through to `final` instead of where they were aimed.
func TestGenerateDNSRejectsReferenceToDisabledServer(t *testing.T) {
	base := func() []model.DNSServer {
		return []model.DNSServer{
			{Tag: "off", Type: "https", Server: "1.1.1.1", Detour: "grp", Enabled: false},
			{Tag: "local", Type: "local", Enabled: true},
		}
	}
	finalOff := &model.DNSSettings{Enabled: true, Servers: base(), Final: "off"}
	if _, err := Generate(genDNSProfile(finalOff), Options{MixedPort: 1080}); err == nil || !strings.Contains(err.Error(), "targets a disabled server") {
		t.Fatalf("final on a disabled server must be rejected, got %v", err)
	}
	ruleOff := &model.DNSSettings{Enabled: true, Servers: base(), Final: "local",
		Rules: []model.DNSRule{{ID: "r", RuleSets: []string{"ru-list"}, Server: "off"}}}
	if _, err := Generate(genDNSProfile(ruleOff), Options{MixedPort: 1080}); err == nil || !strings.Contains(err.Error(), "disabled resolver") {
		t.Fatalf("an enabled rule on a disabled server must be rejected, got %v", err)
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

// TestGenerateDNSH3Path: a DoH3 (h3) DNS server with a custom path must emit that path, exactly
// like https. Emitting it only for https silently dropped a configured h3 path, so sing-box queried
// the default /dns-query over HTTP/3 and a provider serving DoH at a custom path returned 404.
func TestGenerateDNSH3Path(t *testing.T) {
	dns := &model.DNSSettings{
		Enabled: true,
		Servers: []model.DNSServer{
			{Tag: "doh3", Type: "h3", Server: "1.1.1.1", Path: "/custom-dns", Detour: "grp", Enabled: true},
			{Tag: "local", Type: "local", Enabled: true},
		},
		Final: "doh3",
	}
	res, err := Generate(genDNSProfile(dns), Options{MixedPort: 1080})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	d := res.Config["dns"].(map[string]any)
	var doh3 map[string]any
	for _, s := range d["servers"].([]map[string]any) {
		if s["tag"] == "doh3" {
			doh3 = s
		}
	}
	if doh3 == nil {
		t.Fatal("doh3 server not emitted")
	}
	if doh3["path"] != "/custom-dns" {
		t.Errorf("h3 path = %v, want /custom-dns (a configured DoH3 path must not be dropped)", doh3["path"])
	}
	singboxCheckDNS(t, res.Config)
}

// TestGenerateDNSDirectDetourIsOmitted pins a runtime-only sing-box 1.12.17 failure found on the
// AX3000T. A network resolver with detour="direct" passes `sing-box check`, then `sing-box run`
// aborts with "detour to an empty direct outbound makes no sense". The schema's empty detour already
// means direct, so the generator must omit the field while preserving real group detours (covered by
// TestGenerateDNSSecureDefault below).
func TestGenerateDNSDirectDetourIsOmitted(t *testing.T) {
	for _, detour := range []string{model.OutboundDirect, "DIRECT"} {
		dns := &model.DNSSettings{
			Enabled: true,
			Servers: []model.DNSServer{{
				Tag: "direct-doh", Type: "https", Server: "1.1.1.1",
				Detour: detour, Enabled: true,
			}},
			Final: "direct-doh",
		}
		res, err := Generate(genDNSProfile(dns), Options{MixedPort: 1080})
		if err != nil {
			t.Fatalf("generate detour %q: %v", detour, err)
		}
		block := res.Config["dns"].(map[string]any)
		server := block["servers"].([]map[string]any)[0]
		if got, ok := server["detour"]; ok {
			t.Fatalf("detour %q emitted as %v; direct must be represented by omission", detour, got)
		}
		singboxCheckDNS(t, res.Config)
	}
}

// TestGenerateCacheFileStoreFakeIP: when a DNS plane is present, cache_file must set store_fakeip so
// the FakeIP synthetic-IP↔domain map survives a reboot (cache_file.enabled alone does not persist it).
func TestGenerateCacheFileStoreFakeIP(t *testing.T) {
	res, err := Generate(genDNSProfile(secureDNS()), Options{MixedPort: 1080, CacheFile: "/tmp/c.db"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	exp, _ := res.Config["experimental"].(map[string]any)
	if exp == nil {
		t.Fatal("expected an experimental block")
	}
	cf, _ := exp["cache_file"].(map[string]any)
	if cf == nil {
		t.Fatal("expected cache_file")
	}
	if cf["store_fakeip"] != true {
		t.Errorf("cache_file must set store_fakeip=true when a DNS plane is present, got %v", cf["store_fakeip"])
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

	res, err := Generate(genDNSProfile(dns), Options{MixedPort: 1080, TunEnabled: true, TunAddr: "172.31.3.1/30"})
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

// TestGenerateDNSRuleSetGeoSiteAND: a DNS rule carrying BOTH a routing-list rule_set
// and a geosite must AND them (list-membership AND geosite-membership), not OR. Two
// tags in a single rule_set field are OR'd, so the generator must wrap them in a
// logical(mode=and) rule with separate rule_set sub-rules — mirroring the route plane —
// rather than merging them into one flat rule_set field.
func TestGenerateDNSRuleSetGeoSiteAND(t *testing.T) {
	dns := &model.DNSSettings{
		Enabled: true,
		Servers: []model.DNSServer{{Tag: "local", Type: "local", Enabled: true}},
		Rules:   []model.DNSRule{{ID: "mix", RuleSets: []string{"ru-list"}, GeoSite: []string{"category-ads"}, Server: "local"}},
		Final:   "local",
	}
	res, err := Generate(genDNSProfile(dns), Options{MixedPort: 1080})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	d := res.Config["dns"].(map[string]any)
	rules, _ := d["rules"].([]map[string]any)

	isGeo := func(tag string) bool { return strings.HasPrefix(tag, "geosite-") }

	var logical map[string]any
	for _, r := range rules {
		if r["type"] == "logical" {
			logical = r
		}
		// No flat rule may carry a rule_set that mixes a list tag and a geosite tag —
		// that would OR them (the bug).
		if rs, ok := r["rule_set"].([]string); ok {
			var hasList, hasGeo bool
			for _, tag := range rs {
				if isGeo(tag) {
					hasGeo = true
				} else {
					hasList = true
				}
			}
			if hasList && hasGeo {
				t.Fatalf("list rule_set + geosite merged into one OR'd field: %v", rs)
			}
		}
	}
	if logical == nil {
		t.Fatalf("expected a logical AND DNS rule for RuleSets+GeoSite; rules=%v", rules)
	}
	if logical["mode"] != "and" {
		t.Errorf("logical rule mode = %v, want and", logical["mode"])
	}
	if logical["server"] != "local" {
		t.Errorf("server must sit on the outer logical rule, got %v", logical["server"])
	}
	sub, _ := logical["rules"].([]map[string]any)
	var sawList, sawGeo bool
	for _, s := range sub {
		rs, _ := s["rule_set"].([]string)
		for _, tag := range rs {
			if isGeo(tag) {
				sawGeo = true
			} else {
				sawList = true
			}
		}
	}
	if !sawList || !sawGeo {
		t.Errorf("logical sub-rules must include both a list rule_set and a geosite rule_set: %v", sub)
	}
	singboxCheckDNS(t, res.Config)
}
