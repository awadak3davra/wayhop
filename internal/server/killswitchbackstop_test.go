package server

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
	"wayhop/internal/rtblackhole"
)

// fakeRouteTable is a backstop table in memory that counts its operations.
type fakeRouteTable struct {
	routes     map[netip.Prefix]bool
	adds, dels int
	lists      int
	throwDels  []netip.Prefix
	ops        []string
	addErr     error // every Add fails with it
	delErr     error // every Del fails with it
	addDelay   time.Duration
	refuse6    error // every v6 Add and Del fails with it (a kernel without IPv6 routing)
}

func (f *fakeRouteTable) List() ([]netip.Prefix, error) {
	f.lists++
	var out []netip.Prefix
	for p := range f.routes {
		out = append(out, p)
	}
	return out, nil
}
func (f *fakeRouteTable) Add(p netip.Prefix) error {
	f.adds++
	f.ops = append(f.ops, "add "+p.String())
	time.Sleep(f.addDelay)
	if f.refuse6 != nil && p.Addr().Is6() {
		return f.refuse6
	}
	if f.addErr != nil {
		return f.addErr
	}
	f.routes[p] = true
	return nil
}
func (f *fakeRouteTable) Del(p netip.Prefix) error {
	f.dels++
	f.ops = append(f.ops, "del "+p.String())
	if f.refuse6 != nil && p.Addr().Is6() {
		return f.refuse6
	}
	if f.delErr != nil {
		return f.delErr
	}
	delete(f.routes, p)
	return nil
}
func (f *fakeRouteTable) DelThrow(p netip.Prefix) error {
	f.throwDels = append(f.throwDels, p)
	return nil
}
func (f *fakeRouteTable) Close() error { return nil }

func ksPlan(t *testing.T, mutate func(*model.Profile)) *pbr.Plan {
	t.Helper()
	p := &model.Profile{
		Endpoints: []model.Endpoint{{ID: "nl", Engine: model.EngineExternal, Enabled: true, Server: "203.0.113.1", Params: map[string]any{"interface": "nwg1"}}},
		Groups:    []model.Group{{ID: "grp", Type: model.GroupURLTest, Members: []string{"nl"}, KillSwitch: true}},
		RoutingLists: []model.RoutingList{
			{ID: "tg", Enabled: true, Outbound: "grp", Manual: []string{"149.154.160.0/20", "2001:67c:4e8::/48"}},
			{ID: "dom", Enabled: true, Outbound: "grp", Manual: []string{"t.me"}},
		},
	}
	if mutate != nil {
		mutate(p)
	}
	pl, _, err := pbr.Compile(p, pbr.Options{CollectDomainZones: true, ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	return pl
}

func TestParseIpsetMembers(t *testing.T) {
	out := "Name: wr_list_dom_4\nType: hash:net\nHeader: family inet hashsize 1024 maxelem 131072 timeout 86400\n" +
		"Size in memory: 1234\nReferences: 1\nMembers:\n149.154.167.99 timeout 86311\n203.0.113.0/24 timeout 0\n\n"
	got := parseIpsetMembers(out)
	// 203.0.113.0/24 timeout 0 is a static member: the plan carries it already.
	want := []netip.Prefix{netip.MustParsePrefix("149.154.167.99/32")}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
	if got := parseIpsetMembers("Members:\n2001:db8::1 timeout 5\n"); len(got) != 1 || got[0].Bits() != 128 {
		t.Fatalf("v6 member: %v", got)
	}
}

// The mirror adds what dnsmasq resolved, by diff (no rewrite), skips what a static prefix covers,
// removes what expired, and stops at the cap keeping what it already holds.
func TestKillSwitchBackstopMirrorDiffAndCap(t *testing.T) {
	pl := ksPlan(t, nil)
	table := &fakeRouteTable{routes: map[netip.Prefix]bool{}}
	b := &ksBackstop{open: func(int) (rtblackhole.Table, error) { return table, nil }}
	members := map[string][]netip.Prefix{
		"wr_list_dom_4": {netip.MustParsePrefix("198.51.100.1/32"), netip.MustParsePrefix("149.154.167.99/32")},
		"wr_list_dom_6": {netip.MustParsePrefix("2001:db8::1/128")},
	}
	read := func(_ context.Context, set string) ([]netip.Prefix, error) { return members[set], nil }
	ctx := context.Background()
	if err := b.sync(ctx, pl, pbr.IpsetOptions{}, read, 100, false, true); err != nil {
		t.Fatal(err)
	}
	// 149.154.160.0/20 + v6 /48 static; 198.51.100.1 + 2001:db8::1 mirrored; 149.154.167.99 is inside the /20.
	if len(table.routes) != 4 || table.routes[netip.MustParsePrefix("149.154.167.99/32")] {
		t.Fatalf("routes = %v", table.routes)
	}
	adds := table.adds
	if err := b.sync(ctx, pl, pbr.IpsetOptions{}, read, 100, false, false); err != nil || table.adds != adds || table.dels != 0 || table.lists != 1 {
		t.Fatalf("an unchanged tick touched the table: adds %d->%d dels %d lists %d err %v", adds, table.adds, table.dels, table.lists, err)
	}
	members["wr_list_dom_4"] = []netip.Prefix{netip.MustParsePrefix("198.51.100.2/32")}
	_ = b.sync(ctx, pl, pbr.IpsetOptions{}, read, 100, false, false)
	if table.routes[netip.MustParsePrefix("198.51.100.1/32")] || !table.routes[netip.MustParsePrefix("198.51.100.2/32")] || table.dels != 1 {
		t.Fatalf("expiry not mirrored: %v", table.routes)
	}
	// Cap 4: two static, the two installed members keep their place, a new one is not added.
	members["wr_list_dom_4"] = append(members["wr_list_dom_4"], netip.MustParsePrefix("1.1.1.1/32"))
	_ = b.sync(ctx, pl, pbr.IpsetOptions{}, read, 4, false, false)
	if len(table.routes) != 4 || table.routes[netip.MustParsePrefix("1.1.1.1/32")] || !b.capped {
		t.Fatalf("cap: %v capped=%v", table.routes, b.capped)
	}
	// Static routes over the cap: refused.
	if err := b.sync(ctx, pl, pbr.IpsetOptions{}, read, 1, false, false); err == nil {
		t.Fatal("static routes over the cap accepted")
	}
	// Add-only keeps routes the next plan does not want; the full sync after retire removes them.
	off := ksPlan(t, func(p *model.Profile) { p.Groups[0].KillSwitch = false })
	_ = b.sync(ctx, off, pbr.IpsetOptions{}, read, 100, true, false)
	if len(table.routes) != 4 {
		t.Fatalf("add-only removed routes: %v", table.routes)
	}
	_ = b.sync(ctx, off, pbr.IpsetOptions{}, read, 100, false, false)
	if len(table.routes) != 0 {
		t.Fatalf("routes left after the kill switch went: %v", table.routes)
	}
}

// Materialize refuses a kill switch the plane could not hold.
func TestKeeneticKillSwitchRefusal(t *testing.T) {
	pl := ksPlan(t, nil)
	cfg := config.Config{}
	ok := pbr.IpsetOptions{LANIfaces: []string{"br0"}, KillSwitchDNS: "127.0.0.1#5353"}
	if err := keeneticKillSwitchRefusal(pl, ok, cfg); err != nil {
		t.Fatalf("refused: %v", err)
	}
	for name, io := range map[string]pbr.IpsetOptions{
		"no LAN interface": {KillSwitchDNS: "127.0.0.1#5353"},
		"no DNS listener":  {LANIfaces: []string{"br0"}},
	} {
		if err := keeneticKillSwitchRefusal(pl, io, cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := keeneticKillSwitchRefusal(pl, ok, config.Config{KillSwitchBackstopMax: 1}); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Errorf("over the cap: %v", err)
	}
	if got := keeneticLANIfaces([]string{"br1", "eth3", "br0", "br0", "bad name"}, "eth3"); !slices.Equal(got, []string{"br0", "br1"}) {
		t.Errorf("LAN interfaces = %v", got)
	}
}

// Review on the Keenetic kernel plane: kill-switched names with no listener are refused (and fold
// into DNS_KILLSWITCH_LEAK), a backstop over the cap is refused, close to it and device-scoped lists
// are advice.
func TestKeeneticKillSwitchPreflight(t *testing.T) {
	prof := model.Profile{
		Endpoints: []model.Endpoint{{ID: "nl", Engine: model.EngineExternal, Enabled: true, Server: "203.0.113.1", Params: map[string]any{"interface": "nwg1"}}},
		Groups:    []model.Group{{ID: "grp", Type: model.GroupURLTest, Members: []string{"nl"}, KillSwitch: true}},
		RoutingLists: []model.RoutingList{
			{ID: "tg", Enabled: true, Outbound: "grp", Manual: []string{"149.154.160.0/20", "203.0.113.0/24"}},
			{ID: "dom", Enabled: true, Outbound: "grp", Manual: []string{"t.me"}},
			{ID: "kids", Enabled: true, Outbound: "grp", Manual: []string{"198.18.0.0/24"}, ScopeMode: "only", ScopeGroups: []string{"g"}},
		},
		DeviceGroups: []model.DeviceGroup{{ID: "g", Members: []model.DeviceMember{{MAC: "aa:bb:cc:dd:ee:01"}}}},
	}
	if got := keeneticKillSwitchPreflight(config.Config{}, prof, false); got != nil {
		t.Fatalf("off the kernel plane: %v", got)
	}
	settings := func(us []platform.Unsupported) []string {
		var s []string
		for _, u := range us {
			s = append(s, u.Setting)
		}
		return s
	}
	got := settings(keeneticKillSwitchPreflight(config.Config{}, prof, true))
	if !slices.Contains(got, "dns_path:killswitch:dom") || !slices.Contains(got, findingBackstopScoped+":kids") || slices.Contains(got, "dns_path:killswitch:tg") {
		t.Fatalf("findings = %v", got)
	}
	// The kill switch lives on the Entware volume; Review says what happens without it.
	if !slices.Contains(got, findingKillSwitchNeedsOpt) {
		t.Fatalf("no /opt finding: %v", got)
	}
	for _, f := range keeneticKillSwitchPreflight(config.Config{}, prof, true) {
		if f.Setting == findingBackstopScoped+":kids" && (f.Severity != platform.SeverityBlocked || !strings.Contains(f.Reason, "provider")) {
			t.Fatalf("scoped finding: %+v", f)
		}
	}
	served := config.Config{Ports: config.Ports{DNS: 5353}}
	prof.DNS = &model.DNSSettings{Enabled: true, ServeClients: true}
	if got := settings(keeneticKillSwitchPreflight(served, prof, true)); slices.Contains(got, "dns_path:killswitch:dom") {
		t.Fatalf("listener on, still refused: %v", got)
	}
	served.KillSwitchBackstopMax = 1
	if got := settings(keeneticKillSwitchPreflight(served, prof, true)); !slices.Contains(got, findingBackstopCap) {
		t.Fatalf("over the cap not refused: %v", got)
	}
	served.KillSwitchBackstopMax = 2
	if got := settings(keeneticKillSwitchPreflight(served, prof, true)); !slices.Contains(got, findingBackstopNear) {
		t.Fatalf("near the cap not reported: %v", got)
	}
	findings := evaluatePlanFindings(platform.CapabilitySet{}, keeneticKillSwitchPreflight(config.Config{KillSwitchBackstopMax: 1}, prof, true))
	for _, f := range findings {
		want := platform.BlocksNothing
		// A device-scoped kill-switched list has no backstop on this plane: refused.
		if f.Setting == findingBackstopCap || strings.HasPrefix(f.Setting, "dns_path:killswitch:") ||
			strings.HasPrefix(f.Setting, findingKillSwitchIntercept+":") || f.ID == findingBackstopScoped {
			want = platform.BlocksApply
		}
		if f.Blocks != want {
			t.Errorf("%s blocks %v, want %v", f.Setting, f.Blocks, want)
		}
	}
}

// The program holds the backstop table closed with a default blackhole until the daemon
// has filled it since boot. The first successful sync writes the tmpfs stamp FIRST (so the hook stops
// re-adding the hold) and then takes the hold away, v4 and v6.
func TestKillSwitchBackstopReleasesTheBootHold(t *testing.T) {
	pl := ksPlan(t, nil)
	hold4, hold6 := netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")
	table := &fakeRouteTable{routes: map[netip.Prefix]bool{hold4: true, hold6: true}}
	stamp := filepath.Join(t.TempDir(), "wayhop-backstop.ready")
	b := &ksBackstop{open: func(int) (rtblackhole.Table, error) { return table, nil }, ready: stamp}
	read := func(context.Context, string) ([]netip.Prefix, error) { return nil, nil }
	// An add-only sync (the Apply's first step) is enough: the static routes are in.
	if err := b.sync(context.Background(), pl, pbr.IpsetOptions{}, read, 100, true, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stamp); err != nil {
		t.Fatalf("no stamp after the first sync: %v", err)
	}
	if table.routes[hold4] || table.routes[hold6] || !table.routes[netip.MustParsePrefix("149.154.160.0/20")] {
		t.Fatalf("routes after the first sync: %v", table.routes)
	}
	// Without a kill switch there is nothing to hold and no stamp to write.
	stamp2 := filepath.Join(t.TempDir(), "ready")
	off := ksPlan(t, func(p *model.Profile) { p.Groups[0].KillSwitch = false })
	b2 := &ksBackstop{open: func(int) (rtblackhole.Table, error) { return &fakeRouteTable{routes: map[netip.Prefix]bool{}}, nil }, ready: stamp2}
	_ = b2.sync(context.Background(), off, pbr.IpsetOptions{}, read, 100, false, true)
	if _, err := os.Stat(stamp2); err == nil {
		t.Fatal("a stamp without a kill switch")
	}
}

// mirrorServer is a server whose committed plane has a kill-switched domain list, with the backstop
// table, the set reader and the hook stamp stood in.
func mirrorServer(t *testing.T) (*Server, *fakeRouteTable, string) {
	t.Helper()
	profile := killSwitchFastest()
	profile.RoutingLists = append(profile.RoutingLists, model.RoutingList{ID: "dom", Enabled: true, Outbound: "grp-awg31", Manual: []string{"t.me"}})
	s, _ := fastestServer(t, profile, &fakeTables{})
	k := &s.applyState.rec.Committed.Materialization.Kernel
	k.Ipset, k.Action = &executionKernelIpsetArtifactV1{LANIfaces: []string{"br0"}}, ExecutionEnsurePresent
	dir := t.TempDir()
	table := &fakeRouteTable{routes: map[netip.Prefix]bool{}}
	s.ksb.open = func(int) (rtblackhole.Table, error) { return table, nil }
	s.ksb.ready = filepath.Join(dir, "ready")
	s.ksb.probeIfaces = func() []string { return nil }
	s.ksb.uptime = func() (int, bool) { return 0, false } // no daemon lift unless a test says so
	s.leaks.stampPath = filepath.Join(dir, "hook.stamp")
	s.ksl.path = filepath.Join(dir, "learned.ipset")
	return s, table, s.leaks.stampPath
}

// The mirror reads the sets (a fork and a full member dump each) without applyMu, which
// every other TryLock user (elector, reconcile, core restart, DNS chain) skipped its turn on.
func TestKillSwitchMirrorReadsOutsideApplyLock(t *testing.T) {
	s, table, _ := mirrorServer(t)
	reads, locked := 0, 0
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(context.Context, string) ([]netip.Prefix, error) {
			reads++
			if s.applyMu.TryLock() {
				s.applyMu.Unlock()
			} else {
				locked++
			}
			return []netip.Prefix{netip.MustParsePrefix("198.51.100.9/32")}, nil
		}
	}
	s.killSwitchMirrorTick(context.Background())
	if reads == 0 || locked != 0 {
		t.Fatalf("set reads %d, %d of them under applyMu", reads, locked)
	}
	if !table.routes[netip.MustParsePrefix("198.51.100.9/32")] {
		t.Fatalf("the member read outside the lock was not mirrored: %v", table.routes)
	}
}

// A table emptied behind the daemon's back is re-read from the kernel on the tick after
// the next hook run, not up to five minutes later.
func TestKillSwitchMirrorResyncsAfterAHookRun(t *testing.T) {
	s, table, stamp := mirrorServer(t)
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(context.Context, string) ([]netip.Prefix, error) { return nil, nil }
	}
	ctx := context.Background()
	s.killSwitchMirrorTick(ctx)
	if len(table.routes) == 0 {
		t.Fatal("no static routes after the first tick")
	}
	table.routes = map[netip.Prefix]bool{} // flushed by someone else
	s.killSwitchMirrorTick(ctx)
	if len(table.routes) != 0 {
		t.Fatal("the test needs the stale copy to miss the flush without a hook run")
	}
	if err := os.WriteFile(stamp, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	s.killSwitchMirrorTick(ctx)
	if len(table.routes) == 0 {
		t.Fatal("the flushed table was not restored on the tick after a hook run")
	}
}

// What the kill switch cannot hold is said in Review.
//   - A kill-switched list of names is marked by what dnsmasq put in its set: a client that asks its own
//     resolver walks past it. Required: DNS interception with "refuse encrypted DNS" (blocking); the
//     Reason names what that still cannot catch (DoH to an arbitrary host).
//   - A tunnel server inside a kill-switched list: the chain leaves it unmarked, the backstop drops a
//     LAN device's own connection to it (the router's own is outside the backstop).
func TestKeeneticKillSwitchPreflightDNSAndBypass(t *testing.T) {
	prof := model.Profile{
		Endpoints: []model.Endpoint{{ID: "nl", Engine: model.EngineExternal, Enabled: true, Server: "203.0.113.1", Params: map[string]any{"interface": "nwg1"}}},
		Groups:    []model.Group{{ID: "grp", Type: model.GroupURLTest, Members: []string{"nl"}, KillSwitch: true}},
		RoutingLists: []model.RoutingList{
			{ID: "tg", Enabled: true, Outbound: "grp", Manual: []string{"149.154.160.0/20", "203.0.113.0/24"}},
			{ID: "dom", Enabled: true, Outbound: "grp", Manual: []string{"t.me"}},
		},
	}
	served := config.Config{Ports: config.Ports{DNS: 5353}}
	find := func(us []platform.Unsupported, setting string) *platform.Unsupported {
		for i := range us {
			if us[i].Setting == setting {
				return &us[i]
			}
		}
		return nil
	}
	for _, c := range []struct {
		name        string
		dns         *model.DNSSettings
		wantBlocked bool
	}{
		{"no DNS plane", nil, true},
		{"served, no interception", &model.DNSSettings{Enabled: true, ServeClients: true}, true},
		{"interception, encrypted DNS let through", &model.DNSSettings{Enabled: true, ServeClients: true, Intercept: true}, true},
		{"interception, encrypted refused", &model.DNSSettings{Enabled: true, ServeClients: true, Intercept: true, InterceptRejectEncrypted: true}, false},
	} {
		prof.DNS = c.dns
		got := keeneticKillSwitchPreflight(served, prof, true)
		f := find(got, findingKillSwitchIntercept+":dom")
		if (f != nil) != c.wantBlocked || (f != nil && f.Severity != platform.SeverityBlocked) {
			t.Errorf("%s: finding %+v", c.name, f)
		}
		if f != nil && !strings.Contains(f.Reason, "DNS over HTTPS") {
			t.Errorf("%s: the reason does not say what stays uncovered: %s", c.name, f.Reason)
		}
		if find(got, findingKillSwitchIntercept+":tg") != nil {
			t.Errorf("%s: an address-only list asked for interception", c.name)
		}
		b := find(got, findingBackstopBypass)
		if b == nil || !strings.Contains(b.Value, "203.0.113.1") || b.Severity != platform.SeverityDegraded {
			t.Errorf("%s: bypass overlap %+v", c.name, b)
		}
	}
}
