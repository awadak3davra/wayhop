package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/ctflush"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

func fastReviewProfile() *model.Profile {
	return &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "awg2", Engine: model.EngineExternal, Enabled: true, Params: map[string]any{"interface": "awg2"}},
			{ID: "vl", Protocol: "vless", Enabled: true, Server: "203.0.113.9"},
		},
		Groups: []model.Group{{ID: "g", Members: []string{"awg2"}}},
		RoutingLists: []model.RoutingList{
			{ID: "ai", Name: "AI", Manual: []string{"openai.com"}, Outbound: "awg2", Enabled: true},
			{ID: "srs", Name: "SRS", Source: "https://example.test/x.srs", Outbound: "awg2", Enabled: true},
		},
		Rules: []model.Rule{
			{ID: "geo", GeoSite: []string{"netflix"}, Outbound: "vl"},
			{ID: "exact", Domain: []string{"chat.example.net"}, Outbound: "awg2"},
		},
	}
}

func findingIDs(fs []PlanFinding) map[string]PlanFinding {
	out := map[string]PlanFinding{}
	for _, f := range fs {
		out[f.ID] = f
	}
	return out
}

func TestFastDNSFindingsBlock(t *testing.T) {
	prof := fastReviewProfile()
	plan, _, err := pbr.Compile(prof, pbr.Options{FastDNS: true, DNSEnforce: true, LANIfaces: []string{"br-lan"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{RoutingMode: "fast"}
	got := findingIDs(fastDNSFindings(cfg, prof, plan, fastReviewFacts{nftset: -1, remoteErr: map[string]string{"srs": "HTTP 404"}}))
	for _, id := range []string{"fast_path.unrepresentable.geo", "fast_path.remote_not_loaded.srs", "fast_path.dnsmasq_nftset"} {
		if f, ok := got[id]; !ok || f.Blocks != platform.BlocksApply {
			t.Errorf("%s: %+v (all: %v)", id, f, got)
		}
	}
	if !strings.Contains(got["fast_path.remote_not_loaded.srs"].Detail, "HTTP 404") {
		t.Error("the fetch error is not shown")
	}
	if f := got["fast_path.domain_widened.exact"]; f.Blocks != platform.BlocksNothing {
		t.Errorf("widened exact name: %+v", f)
	}
	if _, ok := got["fast_path.kill_switch"]; ok {
		t.Error("kill switch finding without a kill switch")
	}
	if _, ok := got["fast_path.caveats"]; !ok {
		t.Error("caveats not shown")
	}

	// A kill switch anywhere with names in fast mode: refused.
	prof.Groups[0].KillSwitch = true
	got = findingIDs(fastDNSFindings(cfg, prof, plan, fastReviewFacts{nftset: 1}))
	if f, ok := got["fast_path.kill_switch"]; !ok || f.Blocks != platform.BlocksApply || !strings.Contains(f.Remedy, "hybrid") {
		t.Errorf("kill switch: %+v", f)
	}
	if _, ok := got["fast_path.dnsmasq_nftset"]; ok {
		t.Error("dnsmasq-full present, still refused")
	}

	// fast_dns_enforce off: a warning, not a block.
	off := false
	cfg.FastDNSEnforce = &off
	got = findingIDs(fastDNSFindings(cfg, prof, plan, fastReviewFacts{nftset: 1}))
	if f := got["fast_path.dns_enforce_off"]; f.Blocks != platform.BlocksNothing || f.ID == "" {
		t.Errorf("enforce off: %+v", f)
	}

	// Not a fast DNS plan: nothing.
	hyb, _, _ := pbr.Compile(prof, pbr.Options{})
	if len(fastDNSFindings(cfg, prof, hyb, fastReviewFacts{nftset: -1})) != 0 {
		t.Error("findings for a plan without the fast DNS plane")
	}
}

func TestFastDNSRemoteKeywordBlocks(t *testing.T) {
	s := &Server{cfg: &config.Config{RoutingMode: "fast"}}
	s.fastDNS.remote = map[string]fastRemoteEntry{"srs": {fetched: time.Now(),
		set: pbr.RemoteSet{Source: "https://example.test/x.srs", Unrepresentable: []string{"domain_keyword"}}}}
	prof := fastReviewProfile()
	got := s.planUnrepresentableRemote(prof)
	if len(got) != 1 || got[0].Scope != "srs" || !strings.Contains(got[0].Msg, "domain_keyword") {
		t.Fatalf("got %+v", got)
	}
	// A direct list may hold what nothing can express: what it does not match goes direct anyway.
	prof.RoutingLists[1].Outbound = model.OutboundDirect
	if got := s.planUnrepresentableRemote(prof); len(got) != 0 {
		t.Errorf("direct list refused: %+v", got)
	}
}

func TestParseRuleSetSource(t *testing.T) {
	src := `{"version":3,"rules":[
		{"domain":"a.example","domain_suffix":[".b.example","c.example"],"ip_cidr":["192.0.2.0/24"]},
		{"domain_keyword":["porn"]},
		{"domain_regex":"^x"},
		{"type":"logical","mode":"and","rules":[]},
		{"domain":["d.example"],"port":[443]}]}`
	set, err := parseRuleSetSource([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(set.Domains, ",") != "a.example,b.example,c.example" || strings.Join(set.CIDRs, ",") != "192.0.2.0/24" {
		t.Errorf("set = %+v", set)
	}
	if strings.Join(set.Unrepresentable, ",") != "domain_keyword,domain_regex,logical rule,port" {
		t.Errorf("unrepresentable = %v", set.Unrepresentable)
	}
	if _, err := parseRuleSetSource([]byte("not json")); err == nil {
		t.Error("garbage accepted")
	}
	if fastRemoteFormat(model.RoutingList{Source: "https://x/y.json?t=1"}) != "source" || fastRemoteFormat(model.RoutingList{Source: "https://x/y.srs"}) != "binary" {
		t.Error("format inference")
	}
}

// fastSyncServer is an OpenWrt server whose dnsmasq (dnsmasq-full) lives in a temp dir.
func fastSyncServer(t *testing.T) (*Server, string, *int) {
	t.Helper()
	dir := t.TempDir()
	confDir := filepath.Join(dir, "dnsmasq.cfg01411c.d")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dnsmasq.conf.cfg01411c"), []byte("conf-dir="+confDir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	restarts := 0
	oldGlob, oldRestart, oldAlive, oldWarm, oldVer := fastDNSConfGlob, fastDNSRestart, fastDNSAlive, fastWarmResolve, fastDNSVersion
	fastDNSConfGlob = filepath.Join(dir, "dnsmasq.conf.*")
	fastDNSRestart = func(context.Context) error { restarts++; return nil }
	fastDNSAlive = func(context.Context, bool) error { return nil }
	fastWarmResolve = func(context.Context, string) {}
	fastDNSVersion = func(context.Context) (string, error) { return "Compile time options: IPv6 nftset auth", nil }
	t.Cleanup(func() {
		fastDNSConfGlob, fastDNSRestart, fastDNSAlive, fastWarmResolve, fastDNSVersion = oldGlob, oldRestart, oldAlive, oldWarm, oldVer
	})
	s := &Server{cfg: &config.Config{RoutingMode: "fast"}, platformOf: func() platform.Platform { return platform.OpenWrt }}
	return s, confDir, &restarts
}

func TestSyncFastDNS(t *testing.T) {
	s, confDir, restarts := fastSyncServer(t)
	plan, _, _ := pbr.Compile(fastReviewProfile(), pbr.Options{FastDNS: true})
	file := filepath.Join(confDir, fastDNSSnippetName)
	if err := s.syncFastDNS(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(file)
	if err != nil || !strings.Contains(string(b), "nftset=/openai.com/4#inet#wayhop_dns#dlist_list_ai_4") || *restarts != 1 {
		t.Fatalf("snippet %q err %v restarts %d", b, err, *restarts)
	}
	// Same content: no restart.
	_ = s.syncFastDNS(context.Background(), plan)
	if *restarts != 1 {
		t.Errorf("restarted for an unchanged snippet (%d)", *restarts)
	}
	// Torn down: the snippet goes, one more restart.
	_ = s.syncFastDNS(context.Background(), nil)
	if _, err := os.Stat(file); !os.IsNotExist(err) || *restarts != 2 {
		t.Errorf("teardown: stat %v restarts %d", err, *restarts)
	}
}

// TestFastDNSOverfullAtRuntime: a remote list refreshed after Review
// that puts a name into more zones than one dnsmasq line holds leaves the name out of the snippet (not
// kept with only some of its zones), and Diagnostics names it.
func TestFastDNSOverfullAtRuntime(t *testing.T) {
	s, confDir, _ := fastSyncServer(t)
	plan := &pbr.Plan{Table: "wayhop_pbr", FastDNS: true}
	for i := 0; i < 12; i++ {
		plan.Zones = append(plan.Zones, pbr.Zone{Name: fmt.Sprintf("list_copy_%02d", i), RemoteList: "srs"})
	}
	plan.Zones = append(plan.Zones, pbr.Zone{Name: "list_own", Domains: []string{"own.example"}})
	s.fastDNS.remote = map[string]fastRemoteEntry{"srs": {fetched: time.Now(), set: pbr.RemoteSet{Source: "u", Domains: []string{"shared.example"}}}}
	s.fastDNS.remoteGen = 1
	if err := s.syncFastDNS(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(confDir, fastDNSSnippetName))
	if strings.Contains(string(b), "shared.example") || !strings.Contains(string(b), "nftset=/own.example/") {
		t.Fatalf("snippet:\n%s", b)
	}
	s.applyState.rec = applyStateRecord{Committed: &appliedRevision{Rev: "r1", At: 1,
		Materialization: executionMaterializationV1{Kernel: executionKernelArtifactV1{Action: ExecutionEnsurePresent, Plan: plan, Renderer: kernelRendererID()}}}}
	s.applyState.loaded = true
	old := listDlistSets
	t.Cleanup(func() { listDlistSets = old })
	listDlistSets = func(context.Context, string, string, []string) (map[string][]pbr.DlistElement, error) {
		return map[string][]pbr.DlistElement{}, nil
	}
	row := s.fastDNSCheck(context.Background())
	if row.Status != "warn" || !strings.Contains(row.Detail, "shared.example") {
		t.Errorf("Diagnostics: %+v", row)
	}
}

// TestSyncFastDNSBrokenDnsmasq: a dnsmasq that does not answer the snippet's canary loses it again
// and the Apply step fails (keen-pbr #142: another resolver in front).
func TestSyncFastDNSBrokenDnsmasq(t *testing.T) {
	s, confDir, restarts := fastSyncServer(t)
	fastDNSAlive = func(_ context.Context, canary bool) error {
		if canary {
			return errors.New("the resolver on 127.0.0.1:53 does not answer the canary")
		}
		return nil
	}
	plan, _, _ := pbr.Compile(fastReviewProfile(), pbr.Options{FastDNS: true})
	err := s.syncFastDNS(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "removed") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(confDir, fastDNSSnippetName)); !os.IsNotExist(err) {
		t.Error("the snippet that broke dnsmasq is still there")
	}
	if *restarts != 2 {
		t.Errorf("restarts = %d, want 2", *restarts)
	}
}

// TestSyncFastDNSRefusesSilentFailures: no nftset, or no conf-dir, fails the step instead of logging.
func TestSyncFastDNSRefusesSilentFailures(t *testing.T) {
	s, _, restarts := fastSyncServer(t)
	plan, _, _ := pbr.Compile(fastReviewProfile(), pbr.Options{FastDNS: true})
	fastDNSVersion = func(context.Context) (string, error) { return "Compile time options: no-nftset", nil }
	if err := s.syncFastDNS(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "dnsmasq-full") {
		t.Errorf("no nftset: %v", err)
	}
	s2, _, _ := fastSyncServer(t)
	fastDNSConfGlob = filepath.Join(t.TempDir(), "none.*")
	old := fastDNSDefaultConfDir
	fastDNSDefaultConfDir = filepath.Join(t.TempDir(), "missing")
	t.Cleanup(func() { fastDNSDefaultConfDir = old })
	if err := s2.syncFastDNS(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "conf-dir") {
		t.Errorf("no conf-dir: %v", err)
	}
	if *restarts != 0 {
		t.Errorf("restarted %d times for a snippet that was never written", *restarts)
	}
}

// TestFastInstallProgram: carry from the live sets (one read), the saved copy where the table is gone,
// only into zones whose names did not change; the remote prefixes from RAM; the baseline recorded.
func TestFastInstallProgram(t *testing.T) {
	s := &Server{cfg: &config.Config{RoutingMode: "fast"}}
	plan := &pbr.Plan{Table: "wayhop_pbr", Zones: []pbr.Zone{
		{Name: "list_ai", Domains: []string{"openai.com"}},
		{Name: "list_blk", Domains: []string{"ads.example"}},
		{Name: "list_srs", RemoteList: "srs", DNSNoV6: true},
	}}
	prev := &pbr.Plan{Table: "wayhop_pbr", Zones: []pbr.Zone{
		{Name: "list_ai", Domains: []string{"openai.com"}},
		{Name: "list_blk", Domains: []string{"ads.example", "removed.example"}}, // names changed: no carry
	}}
	old := listDlistSets
	t.Cleanup(func() { listDlistSets = old })
	listDlistSets = func(_ context.Context, _, _ string, names []string) (map[string][]pbr.DlistElement, error) {
		return map[string][]pbr.DlistElement{
			"dlist_list_ai_4":  {{Addr: "192.0.2.1", Left: 3600}},
			"dlist_list_blk_4": {{Addr: "192.0.2.9", Left: 3600}},
		}, nil
	}
	s.fastDNS.remote = map[string]fastRemoteEntry{"srs": {fetched: time.Now(), set: pbr.RemoteSet{Source: "u", CIDRs: []string{"198.51.100.0/24"}}}}
	got := s.fastInstallProgram(context.Background(), "", plan, prev)
	if !strings.Contains(got, "add element inet wayhop_dns dlist_list_ai_4 { 192.0.2.1 timeout 3600s }\n") || strings.Contains(got, "192.0.2.9") {
		t.Errorf("carry:\n%s", got)
	}
	// The remote prefixes are a must-load program of their own.
	if must := s.fastMustLoad(context.Background(), plan); !strings.Contains(must, "add element inet wayhop_pbr rlist_list_srs_4 { 198.51.100.0/24 }\n") {
		t.Errorf("remote prefixes:\n%s", must)
	}
	if !s.fastDNS.seed[netip.MustParseAddr("192.0.2.1")] || s.fastDNS.seed[netip.MustParseAddr("192.0.2.9")] {
		t.Errorf("baseline %v", s.fastDNS.seed)
	}

	// The table is gone (after a restart): the copy saved at the last stop fills it, aged.
	listDlistSets = func(context.Context, string, string, []string) (map[string][]pbr.DlistElement, error) {
		return nil, errors.New("No such file or directory")
	}
	dir := t.TempDir()
	oldDir := fastDNSRunDir
	fastDNSRunDir = dir
	t.Cleanup(func() { fastDNSRunDir = oldDir })
	saved := "# written " + strconv.FormatInt(time.Now().Add(-100*time.Second).Unix(), 10) + "\n" +
		"add element inet wayhop_dns dlist_list_ai_6 { 2001:db8::1 timeout 600s, 2001:db8::2 timeout 50s }\n"
	if err := os.WriteFile(filepath.Join(dir, fastDNSCarryFile), []byte(saved), 0o600); err != nil {
		t.Fatal(err)
	}
	got = s.fastInstallProgram(context.Background(), "", plan, nil)
	if !strings.Contains(got, "dlist_list_ai_6 { 2001:db8::1 timeout 50") || strings.Contains(got, "2001:db8::2") {
		t.Errorf("carry from the saved copy:\n%s", got)
	}
}

func TestDnsAnswersNoServer(t *testing.T) {
	// Nothing listens on this port: no answer is an error, never a hang.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := dnsAnswers(ctx, "127.0.0.1:9", "localhost", "", 200*time.Millisecond); err == nil {
		t.Error("no resolver answered, yet it counts as up")
	}
}

// TestFastDNSFindingsReviewRound1 covers unknown LAN devices beside core-only lists, a dnsmasq that
// cannot serve the snippet, unrepresentable port rules and the name cap.
func TestFastDNSFindingsReviewRound1(t *testing.T) {
	prof := fastReviewProfile()
	prof.Rules = append(prof.Rules,
		model.Rule{ID: "p443", DomainSuffix: []string{"example.org"}, Port: []int{443}, Outbound: model.OutboundBlock},
		model.Rule{ID: "pcore", IPCIDR: []string{"198.51.100.0/24"}, Port: []int{443}, Outbound: "vl"})
	cfg := config.Config{RoutingMode: "fast"}
	plan, _, err := pbr.Compile(prof, pbr.Options{FastDNS: true, DNSEnforce: true})
	if err != nil {
		t.Fatal(err)
	}
	big := make([]string, fastNamesMax)
	for i := range big {
		big[i] = "n" + strconv.Itoa(i) + ".example"
	}
	got := findingIDs(fastDNSFindings(cfg, prof, plan, fastReviewFacts{nftset: 1, resolver: "dnsmasq is not running",
		remoteNames: map[string][]string{"srs": big}}))
	for _, id := range []string{"fast_path.lan_unknown", "fast_path.resolver", "fast_path.unrepresentable.p443"} {
		if f, ok := got[id]; !ok || f.Blocks != platform.BlocksApply {
			t.Errorf("%s: %+v", id, f)
		}
	}
	if _, ok := got["fast_path.unrepresentable.pcore"]; ok {
		t.Error("a port rule at a core-only outbound is the core's to match")
	}
	// The remote list has no zone in this plan (its content was not given to Compile), so the cap counts
	// the plan's own names only; give it a remote-backed zone.
	plan.Zones = append(plan.Zones, pbr.Zone{Name: "list_srs", RemoteList: "srs"})
	got = findingIDs(fastDNSFindings(cfg, prof, plan, fastReviewFacts{nftset: 1, remoteNames: map[string][]string{"srs": big}}))
	if f, ok := got["fast_path.names_cap"]; !ok || f.Blocks != platform.BlocksApply {
		t.Errorf("names cap: %+v", f)
	}
}

// TestFastDNSCoreKeepsKernelListsWithTUN: with core-only lists the TUN is
// back and the core keeps every list as hybrid emits it; without, the TUN is gone and the kernel lists
// leave the core.
func TestFastDNSCoreKeepsKernelListsWithTUN(t *testing.T) {
	prof := fastReviewProfile()
	prof.Rules = nil
	prof.RoutingLists = []model.RoutingList{
		{ID: "ai", Name: "AI", Manual: []string{"openai.com"}, Outbound: "awg2", Enabled: true},
		{ID: "yt", Name: "YT", Manual: []string{"youtube.com"}, Outbound: "vl", Enabled: true},
	}
	s := &Server{cfg: &config.Config{RoutingMode: "fast"}, platformOf: func() platform.Platform { return platform.OpenWrt }}
	opts, plan := s.genOptionsWithPlan(prof, *s.cfg)
	if plan == nil || !plan.CorePin || !opts.TunEnabled || opts.FastDNS {
		t.Fatalf("core list: TunEnabled=%v FastDNS=%v plan=%v", opts.TunEnabled, opts.FastDNS, plan != nil)
	}
	prof.RoutingLists = prof.RoutingLists[:1]
	opts, plan = s.genOptionsWithPlan(prof, *s.cfg)
	if plan == nil || plan.CorePin || opts.TunEnabled || !opts.FastDNS {
		t.Fatalf("no core list: TunEnabled=%v FastDNS=%v", opts.TunEnabled, opts.FastDNS)
	}
}

// TestSyncFastDNSKeepModeRestoresLastSnippet: a failed live reload puts the last
// working snippet back and does not mark the content loaded, so the loop retries.
func TestSyncFastDNSKeepModeRestoresLastSnippet(t *testing.T) {
	s, confDir, _ := fastSyncServer(t)
	plan, _, _ := pbr.Compile(fastReviewProfile(), pbr.Options{FastDNS: true})
	if err := s.syncFastDNS(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(filepath.Join(confDir, fastDNSSnippetName))
	// New content arrives (a remote list), and dnsmasq does not answer with it.
	plan.Zones = append(plan.Zones, pbr.Zone{Name: "list_srs", RemoteList: "srs"})
	s.fastDNS.remote = map[string]fastRemoteEntry{"srs": {fetched: time.Now(), set: pbr.RemoteSet{Source: "u", Domains: []string{"new.example"}}}}
	s.fastDNS.remoteGen++
	fastDNSAlive = func(_ context.Context, canary bool) error {
		b, _ := os.ReadFile(filepath.Join(confDir, fastDNSSnippetName))
		if strings.Contains(string(b), "new.example") {
			return errors.New("no answer")
		}
		return nil
	}
	if err := s.syncFastDNSMode(context.Background(), plan, true); err == nil {
		t.Fatal("the failed reload reported success")
	}
	now, _ := os.ReadFile(filepath.Join(confDir, fastDNSSnippetName))
	if _, _, key := s.planRemote(plan); string(now) != string(good) || s.fastDNS.loadedKey == key {
		t.Errorf("snippet restored=%v loadedKey=%s key=%s", string(now) == string(good), s.fastDNS.loadedKey, key)
	}
}

// TestFastDNSRemoteCopySurvivesRestart: content saved in /tmp is loaded at start.
func TestFastDNSRemoteCopySurvivesRestart(t *testing.T) {
	old := fastDNSRunDir
	fastDNSRunDir = t.TempDir()
	t.Cleanup(func() { fastDNSRunDir = old })
	saveRemoteCopy("srs", pbr.RemoteSet{Source: "https://example.test/x.srs", Domains: []string{"a.example"}, CIDRs: []string{"192.0.2.0/24"}})
	prof := fastReviewProfile()
	prof.Endpoints, prof.Groups, prof.Rules = prof.Endpoints[:1], nil, nil
	s := serverFor(t, *prof)
	s.LoadFastDNSRemoteCache()
	_, sets, gen := s.remoteNames()
	if gen == 0 || sets["srs"].Domains[0] != "a.example" || sets["srs"].CIDRs[0] != "192.0.2.0/24" {
		t.Errorf("loaded %+v gen %d", sets, gen)
	}
	// The pin waits for every remote list the plan carries.
	plan := &pbr.Plan{Zones: []pbr.Zone{{Name: "list_srs", RemoteList: "srs"}, {Name: "list_x", RemoteList: "other"}}}
	if remoteReady(plan, sets) {
		t.Error("ready with a list missing")
	}
}

// TestWriteFastSnippetFlashConfDir (live 22.11): a conf-dir on flash gets a pointer written once, the
// snippet goes to dnsmasq's RAM run dir, and both go with the plane.
func TestWriteFastSnippetFlashConfDir(t *testing.T) {
	flash := t.TempDir()
	ram := filepath.Join(t.TempDir(), "run-dnsmasq")
	oldRAM, oldIs := fastDNSRAMDir, fastDNSIsRAM
	fastDNSRAMDir = ram
	fastDNSIsRAM = func(dir string) bool { return dir == ram }
	t.Cleanup(func() { fastDNSRAMDir, fastDNSIsRAM = oldRAM, oldIs })
	changed, errs := writeFastSnippet("SNIPPET\n", []string{flash}, nil)
	if !changed || len(errs) != 0 {
		t.Fatalf("changed=%v errs=%v", changed, errs)
	}
	pointer, _ := os.ReadFile(filepath.Join(flash, fastDNSSnippetName))
	if !strings.Contains(string(pointer), "conf-dir="+ram+",*"+fastDNSRAMExt) {
		t.Errorf("pointer %q", pointer)
	}
	if b, _ := os.ReadFile(filepath.Join(ram, fastDNSRAMFile)); string(b) != "SNIPPET\n" {
		t.Errorf("RAM snippet %q", b)
	}
	// New content: only the RAM file moves; the flash pointer is not rewritten.
	st1, _ := os.Stat(filepath.Join(flash, fastDNSSnippetName))
	writeFastSnippet("SNIPPET2\n", []string{flash}, []string{flash})
	st2, _ := os.Stat(filepath.Join(flash, fastDNSSnippetName))
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Error("the flash pointer was rewritten for new content")
	}
	if b, _ := os.ReadFile(filepath.Join(ram, fastDNSRAMFile)); string(b) != "SNIPPET2\n" {
		t.Errorf("RAM snippet %q", b)
	}
	// Teardown: both go.
	writeFastSnippet("", []string{flash}, []string{flash})
	if _, err := os.Stat(filepath.Join(flash, fastDNSSnippetName)); !os.IsNotExist(err) {
		t.Error("pointer left on flash")
	}
	if _, err := os.Stat(filepath.Join(ram, fastDNSRAMFile)); !os.IsNotExist(err) {
		t.Error("RAM snippet left")
	}
}

// TestFastDNSGuard (live 22.11): DNS that resolved before the install and not after fails the step.
func TestFastDNSGuard(t *testing.T) {
	old := fastDNSUpstream
	t.Cleanup(func() { fastDNSUpstream = old })
	s := &Server{cfg: &config.Config{RoutingMode: "fast"}, platformOf: func() platform.Platform { return platform.OpenWrt }}
	plan := &pbr.Plan{FastDNS: true}
	up := true
	fastDNSUpstream = func(context.Context) error {
		if up {
			return nil
		}
		return errors.New("timeout")
	}
	oldWait := fastDNSGuardWait
	fastDNSGuardWait = time.Second
	t.Cleanup(func() { fastDNSGuardWait = oldWait })
	after := s.fastDNSGuard(context.Background(), plan)
	up = false
	if err := after(); err == nil || !strings.Contains(err.Error(), "DNS stopped working") {
		t.Errorf("err = %v", err)
	}
	// Broken before: not the install's to judge.
	fastDNSUpstream = func(context.Context) error { return errors.New("down") }
	if err := s.fastDNSGuard(context.Background(), plan)(); err != nil {
		t.Errorf("pre-broken DNS judged: %v", err)
	}
}

// TestFastDNSWatchBacksOut: only dnsmasq's own failure backs
// the snippet out, an upstream outage does not, an unarmed or replaced watch does nothing, and the loop
// puts the snippet back once dnsmasq answers again.
func TestFastDNSWatchBacksOut(t *testing.T) {
	s, confDir, _ := fastSyncServer(t)
	plan, _, _ := pbr.Compile(fastReviewProfile(), pbr.Options{FastDNS: true})
	if err := s.syncFastDNS(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	snippet := filepath.Join(confDir, fastDNSSnippetName)
	oldUp, oldAlive, oldFor, oldEvery := fastDNSUpstream, fastDNSAlive, fastDNSWatchFor, fastDNSWatchEvery
	t.Cleanup(func() {
		fastDNSUpstream, fastDNSAlive, fastDNSWatchFor, fastDNSWatchEvery = oldUp, oldAlive, oldFor, oldEvery
	})
	fastDNSWatchFor, fastDNSWatchEvery = 600*time.Millisecond, 30*time.Millisecond
	backedOut := func() bool {
		s.fastDNS.mu.Lock()
		defer s.fastDNS.mu.Unlock()
		return s.fastDNS.backedOut
	}
	waitWatch := func() { time.Sleep(fastDNSWatchFor + 200*time.Millisecond) }

	// The upstream is down, dnsmasq answers itself: nothing is backed out.
	fastDNSUpstream = func(context.Context) error { return errors.New("upstream timeout") }
	s.startFastDNSWatch(plan, true)
	waitWatch()
	if backedOut() {
		t.Fatal("an upstream outage backed the names out")
	}
	fastDNSUpstream = func(context.Context) error { return nil }

	// dnsmasq does not answer, but it did not before the install either (a boot): not watched.
	dnsmasqDown := true
	fastDNSAlive = func(context.Context, bool) error {
		if dnsmasqDown {
			return errors.New("no answer")
		}
		return nil
	}
	s.startFastDNSWatch(plan, false)
	waitWatch()
	if backedOut() {
		t.Fatal("an unarmed watch backed out")
	}

	// A watch replaced by a newer install stops.
	s.startFastDNSWatch(plan, true)
	s.startFastDNSWatch(plan, false) // the newer install, its DNS was down before
	waitWatch()
	if backedOut() {
		t.Fatal("a stale watch backed out a newer install")
	}

	// Armed and dnsmasq stalls: backed out, snippet gone, retried later.
	s.startFastDNSWatch(plan, true)
	// (the back-out restarts dnsmasq and waits up to ten seconds for it to answer)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && !backedOut() {
		time.Sleep(20 * time.Millisecond)
	}
	if !backedOut() || !strings.Contains(s.fastDNS.err, "three times") {
		t.Fatalf("not backed out: %+v", s.fastDNS.err)
	}
	if _, err := os.Stat(snippet); !os.IsNotExist(err) {
		t.Error("the snippet stayed after the back-out")
	}
	// dnsmasq recovers and the retry time has come: the loop restores the snippet.
	dnsmasqDown = false
	s.fastDNS.mu.Lock()
	s.fastDNS.retryAt = time.Now().Add(-time.Second)
	s.fastDNS.mu.Unlock()
	s.fastDNSRestore(context.Background(), plan)
	if backedOut() {
		t.Fatalf("not restored: %s", s.fastDNS.err)
	}
	if _, err := os.Stat(snippet); err != nil {
		t.Error("the snippet did not come back")
	}
}

// TestFastDNSBackoutBookkeeping: no snippet, no watch; back-outs in a row
// end the retries until the next install, and the backoff is not reset by a restore.
func TestFastDNSBackoutBookkeeping(t *testing.T) {
	s, _, _ := fastSyncServer(t)
	plan, _, _ := pbr.Compile(fastReviewProfile(), pbr.Options{FastDNS: true})
	oldAlive := fastDNSAlive
	t.Cleanup(func() { fastDNSAlive = oldAlive })
	// No snippet written yet: an armed watch does not start.
	fastDNSAlive = func(context.Context, bool) error { return errors.New("no canary") }
	s.startFastDNSWatch(plan, true)
	time.Sleep(50 * time.Millisecond)
	if s.fastDNS.backedOut {
		t.Fatal("a watch ran with no snippet")
	}
	fastDNSAlive = func(context.Context, bool) error { return nil }
	for i := 0; i < fastDNSMaxBackouts; i++ {
		gen := s.fastDNSWatchGen()
		s.fastDNSBackout(context.Background(), gen, "test stall")
	}
	if !s.fastDNS.gaveUp || !strings.Contains(s.fastDNS.err, "until the next Apply") || s.fastDNS.backoff != 4*time.Minute {
		t.Fatalf("gaveUp=%v backoff=%v err=%s", s.fastDNS.gaveUp, s.fastDNS.backoff, s.fastDNS.err)
	}
	s.fastDNS.retryAt = time.Now().Add(-time.Second)
	s.fastDNSRestore(context.Background(), plan)
	if !s.fastDNS.backedOut {
		t.Error("restored after giving up")
	}
	s.fastDNSInstalled()
	if s.fastDNS.gaveUp || s.fastDNS.backouts != 0 || s.fastDNS.backoff != 0 {
		t.Error("an install does not start the bookkeeping afresh")
	}
}

// TestFastDNSWatchHunt1122: an install of a plan without names, and a teardown,
// end an earlier install's watch; a back-out whose restart left dnsmasq silent restarts it again from
// the loop until it answers.
func TestFastDNSWatchHunt1122(t *testing.T) {
	s, _, restarts := fastSyncServer(t)
	plan, _, _ := pbr.Compile(fastReviewProfile(), pbr.Options{FastDNS: true})
	if err := s.syncFastDNS(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	oldAlive, oldFor, oldEvery := fastDNSAlive, fastDNSWatchFor, fastDNSWatchEvery
	t.Cleanup(func() { fastDNSAlive, fastDNSWatchFor, fastDNSWatchEvery = oldAlive, oldFor, oldEvery })
	fastDNSWatchFor, fastDNSWatchEvery = 600*time.Millisecond, 30*time.Millisecond
	backedOut := func() bool {
		s.fastDNS.mu.Lock()
		defer s.fastDNS.mu.Unlock()
		return s.fastDNS.backedOut
	}
	down := true
	fastDNSAlive = func(context.Context, bool) error {
		if down {
			return errors.New("no answer")
		}
		return nil
	}
	for _, next := range []func(){
		func() { s.startFastDNSWatch(&pbr.Plan{Table: "wayhop_pbr", FastDNS: true}, true) }, // a plan without names
		func() { s.stopFastDNSWatch() }, // a teardown
	} {
		s.startFastDNSWatch(plan, true)
		next()
		time.Sleep(fastDNSWatchFor + 200*time.Millisecond)
		if backedOut() {
			t.Fatal("a watch of a replaced install backed out")
		}
	}

	// Back-out whose restart leaves dnsmasq silent: owed, and the loop restarts it until it answers.
	s.startFastDNSWatch(plan, true)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && !backedOut() {
		time.Sleep(20 * time.Millisecond)
	}
	s.fastDNS.mu.Lock()
	owed := s.fastDNS.restartOwed
	s.fastDNS.mu.Unlock()
	if !backedOut() || !owed {
		t.Fatalf("backed out %v, restart owed %v", backedOut(), owed)
	}
	before := *restarts
	s.fastDNSRestartOwed(context.Background())
	if *restarts != before+1 {
		t.Errorf("no further restart while dnsmasq is silent (%d -> %d)", before, *restarts)
	}
	down = false
	s.fastDNSRestartOwed(context.Background())
	s.fastDNS.mu.Lock()
	owed = s.fastDNS.restartOwed
	s.fastDNS.mu.Unlock()
	if owed || *restarts != before+1 {
		t.Errorf("owed %v after dnsmasq answered, restarts %d", owed, *restarts)
	}
}

// TestFastInstallCarryNewSet: an Apply that adds a name zone keeps the other zones'
// addresses. The listing asks only for sets the installed plan has; a listing that fails anyway (a set
// missing) is retried set by set instead of losing every set's addresses.
func TestFastInstallCarryNewSet(t *testing.T) {
	s := &Server{cfg: &config.Config{RoutingMode: "fast"}}
	prev := &pbr.Plan{Table: "wayhop_pbr", Zones: []pbr.Zone{{Name: "list_a", Domains: []string{"a.example"}}}}
	plan := &pbr.Plan{Table: "wayhop_pbr", Zones: []pbr.Zone{
		{Name: "list_a", Domains: []string{"a.example"}},
		{Name: "list_b", Domains: []string{"b.example"}},
	}}
	live := map[string][]pbr.DlistElement{"dlist_list_a_4": {{Addr: "192.0.2.1", Left: 3600}}, "dlist_list_a_6": nil}
	var asked [][]string
	old := listDlistSets
	t.Cleanup(func() { listDlistSets = old })
	listDlistSets = func(_ context.Context, _, _ string, names []string) (map[string][]pbr.DlistElement, error) {
		asked = append(asked, append([]string(nil), names...))
		out := map[string][]pbr.DlistElement{}
		for _, n := range names {
			e, ok := live[n]
			if !ok {
				return nil, errors.New("Error: No such file or directory; list set inet wayhop_dns " + n)
			}
			out[n] = e
		}
		return out, nil
	}
	if got := s.fastInstallProgram(context.Background(), "", plan, prev); !strings.Contains(got, "dlist_list_a_4 { 192.0.2.1 timeout 3600s }") {
		t.Errorf("the existing zone's addresses were not carried:\n%s (asked %v)", got, asked)
	}
	for _, names := range asked {
		if strings.Contains(strings.Join(names, ","), "list_b") {
			t.Errorf("asked the live table for a set it cannot have: %v", names)
		}
	}
	// No installed plan known: every set is asked, the batch fails on the new one, each set alone.
	asked = nil
	if got := s.fastInstallProgram(context.Background(), "", plan, nil); !strings.Contains(got, "dlist_list_a_4 { 192.0.2.1 timeout 3600s }") {
		t.Errorf("one missing set lost the others' addresses:\n%s (asked %v)", got, asked)
	}
}

// TestFastRemoteLiveContent: the installed plane is filled only from content of
// the source it was reviewed with, and not from a refresh Review would refuse (the content in force
// stays, Diagnostics says why); a live reload loads the names before the prefixes, leaves the kernel
// alone when dnsmasq refuses them, and empties only the sets of a list whose names changed.
func TestFastRemoteLiveContent(t *testing.T) {
	s, confDir, _ := fastSyncServer(t)
	plan := &pbr.Plan{Table: "wayhop_pbr", FastDNS: true,
		Egresses: []pbr.Egress{{Tag: "awg2", Kind: pbr.EgressInterface, Iface: "awg2", Mark: 0x20000, Table: 151}},
		Zones: []pbr.Zone{
			{Name: "list_a", EgressTag: "awg2", Mark: 0x20000, RemoteList: "a", RemoteSource: "https://example.test/a.srs"},
			{Name: "list_b", EgressTag: "awg2", Mark: 0x20000, RemoteList: "b", RemoteSource: "https://example.test/b.srs"},
		}}
	setA := pbr.RemoteSet{Source: "https://example.test/a.srs", Domains: []string{"a.example"}, CIDRs: []string{"198.51.100.0/24"}}
	setB := pbr.RemoteSet{Source: "https://example.test/b.srs", Domains: []string{"b.example"}}
	entry := func(set pbr.RemoteSet) fastRemoteEntry { return fastRemoteEntry{set: set, fetched: time.Now()} }

	// #1: the saved profile's edited source for list a is fetched, but the plan was reviewed with a.srs.
	edited := pbr.RemoteSet{Source: "https://example.test/a2.srs", Domains: []string{"edited.example"}}
	s.fastDNS.remote = map[string]fastRemoteEntry{"a": entry(edited), "b": entry(setB)}
	if _, sets, _ := s.planRemote(plan); len(sets["a"].Domains) != 0 || sets["b"].Domains[0] != "b.example" {
		t.Fatalf("an unapplied source edit was used: %+v", sets)
	}
	s.markRemoteLive(map[string]pbr.RemoteSet{"a": setA})
	if _, sets, _ := s.planRemote(plan); sets["a"].Domains[0] != "a.example" {
		t.Fatalf("the applied content did not stay in force: %+v", sets)
	}

	// #8: a refresh of the reviewed source to content nothing can express is not taken live.
	bad := setA
	bad.Domains, bad.Unrepresentable = []string{"other.example"}, []string{"domain_keyword"}
	s.fastDNS.remote["a"] = entry(bad)
	if _, sets, _ := s.planRemote(plan); sets["a"].Domains[0] != "a.example" || !strings.Contains(s.fastDNS.rejected["a"], "domain_keyword") {
		t.Fatalf("an unusable refresh went live: %+v rejected %v", sets, s.fastDNS.rejected)
	}

	// #9: install state = setA + setB loaded; then list a's prefixes change (same names).
	s.fastDNS.remote["a"] = entry(setA)
	s.markRemoteLive(map[string]pbr.RemoteSet{"a": setA, "b": setB})
	if err := s.syncFastDNS(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	_, _, key := s.planRemote(plan)
	s.fastDNS.elemKey, s.fastDNS.pinReady = key, true
	var programs []string
	oldLoad := fastLoadProgram
	t.Cleanup(func() { fastLoadProgram = oldLoad })
	fastLoadProgram = func(_ context.Context, p string) error { programs = append(programs, p); return nil }
	moved := setA
	moved.CIDRs = []string{"203.0.113.0/24"}
	s.fastDNS.remote["a"] = entry(moved)
	s.fastRemoteReload(context.Background(), plan)
	if len(programs) != 1 || !strings.Contains(programs[0], "203.0.113.0/24") || strings.Contains(programs[0], "flush set inet wayhop_dns") {
		t.Fatalf("prefix-only change: %q", programs)
	}
	// list b's names change, and dnsmasq refuses the new snippet: nothing reaches the kernel.
	programs = nil
	s.fastDNS.retryAt = time.Time{}
	newB := setB
	newB.Domains = []string{"b2.example"}
	s.fastDNS.remote["b"] = entry(newB)
	fastDNSAlive = func(_ context.Context, canary bool) error {
		b, _ := os.ReadFile(filepath.Join(confDir, fastDNSSnippetName))
		if strings.Contains(string(b), "b2.example") {
			return errors.New("no answer")
		}
		return nil
	}
	s.fastRemoteReload(context.Background(), plan)
	if len(programs) != 0 {
		t.Fatalf("the kernel moved although the names were refused: %q", programs)
	}
	// dnsmasq takes it: only list b's resolver-fed sets are emptied.
	fastDNSAlive = func(context.Context, bool) error { return nil }
	s.fastDNS.retryAt = time.Time{}
	s.fastRemoteReload(context.Background(), plan)
	if len(programs) != 1 || !strings.Contains(programs[0], "flush set inet wayhop_dns dlist_list_b_4") || strings.Contains(programs[0], "dlist_list_a_4") {
		t.Fatalf("names change of b: %q", programs)
	}
}

// TestFastDNSSingleLabelNamed: a name without a dot is named in Review instead of
// vanishing from the plane; addresses and prefixes are not mistaken for one.
func TestFastDNSSingleLabelNamed(t *testing.T) {
	prof := fastReviewProfile()
	prof.RoutingLists = append(prof.RoutingLists, model.RoutingList{ID: "lan", Manual: []string{"intranet", "*.Printer", "openai.com", "10.0.0.0/8", "2001:db8::1"},
		Outbound: prof.RoutingLists[0].Outbound, Enabled: true})
	plan, _, err := pbr.Compile(prof, pbr.Options{FastDNS: true, DNSEnforce: true, LANIfaces: []string{"br-lan"}})
	if err != nil {
		t.Fatal(err)
	}
	got := findingIDs(fastDNSFindings(config.Config{RoutingMode: "fast"}, prof, plan, fastReviewFacts{remoteErr: map[string]string{}}))
	f, ok := got["fast_path.single_label"]
	if !ok || f.Blocks != platform.BlocksNothing || !strings.Contains(f.Detail, "intranet") || !strings.Contains(f.Detail, "printer") ||
		!strings.Contains(f.Detail, "2 name(s)") {
		t.Errorf("single-label note: %+v", f)
	}
}

// TestFastRemoteRefreshReviewChecks: a refresh is judged by Review's own checks over the
// installed plan. One that makes a name too wide for one dnsmasq line, or the names too many, keeps the
// content in force, and Diagnostics says why.
func TestFastRemoteRefreshReviewChecks(t *testing.T) {
	s, _, _ := fastSyncServer(t)
	plan := &pbr.Plan{Table: "wayhop_pbr", FastDNS: true}
	for i := 0; i < 12; i++ {
		plan.Zones = append(plan.Zones, pbr.Zone{Name: fmt.Sprintf("list_copy_%02d", i), RemoteList: "srs", RemoteSource: "u"})
	}
	inForce := pbr.RemoteSet{Source: "u", CIDRs: []string{"198.51.100.0/24"}}
	s.markRemoteLive(map[string]pbr.RemoteSet{"srs": inForce})
	s.fastDNS.remote = map[string]fastRemoteEntry{"srs": {fetched: time.Now(), set: pbr.RemoteSet{Source: "u", Domains: []string{"wide.example"}, CIDRs: inForce.CIDRs}}}
	names, sets, _ := s.planRemote(plan)
	if len(names["srs"]) != 0 || len(sets["srs"].Domains) != 0 || !strings.Contains(s.fastDNS.rejected["srs"], "one dnsmasq line") {
		t.Fatalf("an overfull refresh went live: %v rejected %v", names, s.fastDNS.rejected)
	}
	var many []string
	for i := 0; i <= fastNamesMax; i++ {
		many = append(many, fmt.Sprintf("n%d.example", i))
	}
	plan.Zones = plan.Zones[:1]
	s.fastDNS.remote["srs"] = fastRemoteEntry{fetched: time.Now(), set: pbr.RemoteSet{Source: "u", Domains: many}}
	if names, _, _ := s.planRemote(plan); len(names["srs"]) != 0 || !strings.Contains(s.fastDNS.rejected["srs"], "past") {
		t.Fatalf("a refresh past the name cap went live: %d names, rejected %v", len(names["srs"]), s.fastDNS.rejected)
	}
	s.fastDNS.remote["srs"] = fastRemoteEntry{fetched: time.Now(), set: pbr.RemoteSet{Source: "u", Domains: []string{"ok.example"}}}
	if names, _, _ := s.planRemote(plan); len(names["srs"]) != 1 || s.fastDNS.rejected["srs"] != "" {
		t.Fatalf("a good refresh was refused: %v %v", names, s.fastDNS.rejected)
	}
}

// TestFastRemoteReloadMinimal: a list that only gains names keeps every address its
// sets hold, and a reload touches the prefix sets of the lists whose prefixes moved only.
func TestFastRemoteReloadMinimal(t *testing.T) {
	s, _, _ := fastSyncServer(t)
	plan := &pbr.Plan{Table: "wayhop_pbr", FastDNS: true,
		Egresses: []pbr.Egress{{Tag: "awg2", Kind: pbr.EgressInterface, Iface: "awg2", Mark: 0x20000, Table: 151}},
		Zones: []pbr.Zone{
			{Name: "list_a", EgressTag: "awg2", Mark: 0x20000, RemoteList: "a", RemoteSource: "ua"},
			{Name: "list_b", EgressTag: "awg2", Mark: 0x20000, RemoteList: "b", RemoteSource: "ub"},
		}}
	setA := pbr.RemoteSet{Source: "ua", Domains: []string{"a.example"}, CIDRs: []string{"198.51.100.0/24"}}
	setB := pbr.RemoteSet{Source: "ub", Domains: []string{"b.example"}, CIDRs: []string{"203.0.113.0/24"}}
	entry := func(set pbr.RemoteSet) fastRemoteEntry { return fastRemoteEntry{set: set, fetched: time.Now()} }
	s.fastDNS.remote = map[string]fastRemoteEntry{"a": entry(setA), "b": entry(setB)}
	s.markRemoteLive(map[string]pbr.RemoteSet{"a": setA, "b": setB})
	if err := s.syncFastDNS(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	_, _, key := s.planRemote(plan)
	s.fastDNS.elemKey, s.fastDNS.pinReady = key, true
	var programs []string
	oldLoad := fastLoadProgram
	t.Cleanup(func() { fastLoadProgram = oldLoad })
	fastLoadProgram = func(_ context.Context, p string) error { programs = append(programs, p); return nil }
	grown := setA
	grown.Domains = []string{"a.example", "a2.example"}
	grown.CIDRs = []string{"198.51.100.0/24", "192.0.2.0/24"}
	s.fastDNS.remote["a"] = entry(grown)
	s.fastRemoteReload(context.Background(), plan)
	if len(programs) != 1 {
		t.Fatalf("programs %q", programs)
	}
	p := programs[0]
	if strings.Contains(p, "flush set inet wayhop_dns") || !strings.Contains(p, "rlist_list_a_4") || strings.Contains(p, "rlist_list_b_4") {
		t.Errorf("reload of a list that only grew:\n%s", p)
	}
}

// TestFastDNSBackoutRollbackOwesRestart: a Test the watch rolled back, after which dnsmasq
// does not answer, is owed the same further restart as a back-out.
func TestFastDNSBackoutRollbackOwesRestart(t *testing.T) {
	s, _, restarts := fastSyncServer(t)
	oldAlive := fastDNSAlive
	t.Cleanup(func() { fastDNSAlive = oldAlive })
	down := true
	fastDNSAlive = func(context.Context, bool) error {
		if down {
			return errors.New("no answer")
		}
		return nil
	}
	s.fastDNS.mu.Lock()
	s.fastDNS.restartOwed = false
	s.fastDNS.mu.Unlock()
	s.oweRestartIfSilent(context.Background()) // what the rollback branch of fastDNSBackout runs
	before := *restarts
	s.fastDNSRestartOwed(context.Background())
	if *restarts != before+1 {
		t.Errorf("no further restart after the rollback left dnsmasq silent")
	}
	down = false
	s.fastDNSRestartOwed(context.Background())
	if s.fastDNS.restartOwed {
		t.Error("still owed once dnsmasq answers")
	}
	// Bounded: a dnsmasq that never answers is restarted at most
	// fastDNSMaxOwedRestarts times.
	down = true
	s.oweRestartIfSilent(context.Background())
	before = *restarts
	for i := 0; i < fastDNSMaxOwedRestarts+5; i++ {
		s.fastDNSRestartOwed(context.Background())
	}
	if got := *restarts - before; got != fastDNSMaxOwedRestarts {
		t.Errorf("%d further restarts, want %d", got, fastDNSMaxOwedRestarts)
	}
}

// freshTable is a conntrack table of fixed entries that records deletions.
type freshTable struct {
	entries []ctflush.Entry
	deleted []netip.Addr
}

func (f *freshTable) Dump(fam uint8, yield func(ctflush.Entry)) error {
	if fam == 2 {
		for _, e := range f.entries {
			yield(e)
		}
	}
	return nil
}
func (f *freshTable) Delete(e ctflush.Entry) error { f.deleted = append(f.deleted, e.Src); return nil }
func (f *freshTable) Close() error                 { return nil }

// TestFastFreshTickBeyondWAN: an address a direct list's set already held that now
// enters a tunnel list's set resets the WAN flows to it, but not one from a device a device-scoped
// direct list keeps on the WAN anyway.
func TestFastFreshTickBeyondWAN(t *testing.T) {
	s := &Server{cfg: &config.Config{RoutingMode: "fast"}}
	plan := &pbr.Plan{Table: "wayhop_pbr", Mask: 0x00ff0000, FastDNS: true,
		Egresses: []pbr.Egress{{Tag: "direct", Kind: pbr.EgressWAN, Mark: 0x10000, Table: 254},
			{Tag: "awg2", Kind: pbr.EgressInterface, Iface: "awg2", Mark: 0x20000, Table: 151}},
		Zones: []pbr.Zone{
			{Name: "list_home", EgressTag: "direct", Mark: 0x10000, Domains: []string{"cdn.example"}},
			{Name: "list_kid", EgressTag: "direct", Mark: 0x10000, SrcScoped: true, SrcV4: []string{"192.168.77.50/32"}, V4: []string{"192.0.2.0/24"}},
			{Name: "list_tun", EgressTag: "awg2", Mark: 0x20000, Domains: []string{"video.example"}},
		}}
	addr := netip.MustParseAddr("203.0.113.47")
	inTun := false
	old := listDlistSets
	t.Cleanup(func() { listDlistSets = old })
	listDlistSets = func(context.Context, string, string, []string) (map[string][]pbr.DlistElement, error) {
		out := map[string][]pbr.DlistElement{"dlist_list_home_4": {{Addr: addr.String(), Left: 3600}}}
		if inTun {
			out["dlist_list_tun_4"] = []pbr.DlistElement{{Addr: addr.String(), Left: 3600}}
		}
		return out, nil
	}
	tbl := &freshTable{entries: []ctflush.Entry{
		{Src: netip.MustParseAddr("192.168.77.10"), Dst: addr, ReplySrc: addr, Mark: 0x10000},
		{Src: netip.MustParseAddr("192.168.77.50"), Dst: addr, ReplySrc: addr, Mark: 0x10000},
	}}
	oldOpen := ctflushOpen
	t.Cleanup(func() { ctflushOpen = oldOpen })
	ctflushOpen = func() (ctflush.Table, error) { return tbl, nil }
	st := s.fastFreshTick(context.Background(), fastFresh{}, plan) // first look records
	st = s.fastFreshTick(context.Background(), st, plan)           // nothing new
	if len(tbl.deleted) != 0 {
		t.Fatalf("reset with nothing new: %v", tbl.deleted)
	}
	inTun = true
	s.fastFreshTick(context.Background(), st, plan)
	if len(tbl.deleted) != 1 || tbl.deleted[0] != netip.MustParseAddr("192.168.77.10") {
		t.Errorf("deleted %v, want only the unexempted device's WAN flow", tbl.deleted)
	}
}
