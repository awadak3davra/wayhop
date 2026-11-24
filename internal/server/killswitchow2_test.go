package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"wayhop/internal/clash"
	"wayhop/internal/ctflush"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// Stage-2 review of the nft kill switch (OW2): the learned addresses of kill-switched names, the
// hold's bound across reloads, the flush when the core returns, the loader, and what Review says.

func namesPaths(t *testing.T) {
	t.Helper()
	bootGuardPaths(t)
	old := ksBootLearnedFile
	ksBootLearnedFile = filepath.Join(filepath.Dir(ksBootGuardFile), "ks-learned.nft")
	if err := os.MkdirAll(filepath.Dir(ksBootLearnedFile), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ksBootLearnedFile = old })
}

// namedProfile is the reference router's profile with its group under a kill switch and a name in its list.
func namedProfile() model.Profile {
	p := refrouterProfile()
	p.Groups[0].KillSwitch = true
	p.RoutingLists[0].Manual = append(p.RoutingLists[0].Manual, "telegram.org")
	return p
}

func connTo(ip string, chains ...string) clash.Conn {
	return clash.Conn{Chains: chains, Metadata: clash.ConnMeta{DestinationIP: ip}}
}

// The addresses a kill-switched list's names are reached at are learned from the
// core's connections, put into the list's set in the guard, kept on flash with coalesced writes, and
// put back after a guard reload and after a restart.
func TestKillSwitchedNamesAreLearnedHeldAndPersisted(t *testing.T) {
	namesPaths(t)
	s, plan := openwrtServer(t, namedProfile(), &fakeTables{})
	s.cfg.RoutingMode = "hybrid"
	if len(plan.GuardNameSets) != 1 || plan.GuardNameSets[0].Set != "kn_tg_calls" || !slices.Equal(plan.GuardNameSets[0].Outbounds, []string{"grp-auto"}) {
		t.Fatalf("setup: name sets %+v", plan.GuardNameSets)
	}
	now := time.Unix(1_800_000_000, 0)
	s.ksn.now = func() time.Time { return now }
	var ran []string
	var fail error
	run := func(_ context.Context, program string) error {
		if fail != nil {
			return fail
		}
		ran = append(ran, program)
		return nil
	}
	conns := []clash.Conn{
		connTo("93.184.216.34", "ru", "grp-auto"),
		connTo("2a02:6b8::2:242", "grp-auto"),
		connTo("93.184.216.34", "fi", "grp-auto"), // the same address twice in one tick
		connTo("198.51.100.99", "direct"),         // not this list's outbound
		connTo("192.168.2.9", "grp-auto"),         // private
		connTo("198.18.0.5", "grp-auto"),          // one of the core's fake addresses
		connTo("", "grp-auto"),
	}
	ctx := context.Background()
	s.learnNames(ctx, plan, conns, run)
	want := pbr.RenderGuardLearn("kn_tg_calls", map[string]int{"93.184.216.34": ksNameTTL, "2a02:6b8::2:242": ksNameTTL})
	if len(ran) != 1 || ran[0] != want {
		t.Fatalf("learned program:\n%v\nwant:\n%s", ran, want)
	}
	if !s.ksn.w.Pending() {
		t.Fatal("new addresses did not mark the file's writer")
	}
	if _, err := os.Stat(ksBootLearnedFile); !os.IsNotExist(err) {
		t.Fatalf("the file was written at once instead of through the coalescing writer (%v)", err)
	}
	if err := s.ksn.w.Flush(); err != nil {
		t.Fatal(err)
	}
	file, err := os.ReadFile(ksBootLearnedFile)
	if err != nil {
		t.Fatal(err)
	}
	wantFile := ksNameFileHead +
		"add element inet wayhop_ks kn_tg_calls_4 { 93.184.216.34 timeout 86400s }\n" +
		"add element inet wayhop_ks kn_tg_calls_6 { 2a02:6b8::2:242 timeout 86400s }\n"
	if string(file) != wantFile {
		t.Fatalf("file:\n%s\nwant:\n%s", file, wantFile)
	}

	// Seen again an hour later: nothing to run, nothing to write.
	ran = nil
	now = now.Add(time.Hour)
	s.learnNames(ctx, plan, conns, run)
	if len(ran) != 0 || s.ksn.w.Pending() {
		t.Fatalf("a known address cost an nft call or a flash write: %v pending=%v", ran, s.ksn.w.Pending())
	}
	// Seen again with less than half its timeout left: renewed in the kernel, and still no write,
	// because the members did not change.
	now = now.Add(12 * time.Hour)
	s.learnNames(ctx, plan, conns[:1], run)
	if len(ran) != 1 || ran[0] != pbr.RenderGuardLearn("kn_tg_calls", map[string]int{"93.184.216.34": ksNameTTL}) || s.ksn.w.Pending() {
		t.Fatalf("renewal: %v pending=%v", ran, s.ksn.w.Pending())
	}
	// The kernel refuses an add: RAM must not claim the address is held.
	ran, fail = nil, errors.New("Error: No such file or directory")
	s.learnNames(ctx, plan, []clash.Conn{connTo("203.0.113.77", "grp-auto")}, run)
	fail = nil
	if strings.Contains(s.learnedNamesProgram(plan), "203.0.113.77") {
		t.Fatal("an address the kernel refused is remembered as held")
	}
	s.learnNames(ctx, plan, []clash.Conn{connTo("203.0.113.77", "grp-auto")}, run)
	if len(ran) != 1 || !strings.Contains(ran[0], "203.0.113.77 timeout 86400s") {
		t.Fatalf("the refused address was not tried again: %v", ran)
	}

	// A guard reload replaces the table and its sets: the load's own transaction puts the addresses
	// back, each with what its timeout has left.
	replay := s.learnedNamesProgram(plan)
	for _, line := range []string{
		"add element inet wayhop_ks kn_tg_calls_4 { 93.184.216.34 timeout 86400s }\n",
		"add element inet wayhop_ks kn_tg_calls_6 { 2a02:6b8::2:242 timeout 39600s }\n", // 24 h less the 13 that passed
		"add element inet wayhop_ks kn_tg_calls_4 { 203.0.113.77 timeout 86400s }\n",
	} {
		if !strings.Contains(replay, line) {
			t.Fatalf("replay lacks %q:\n%s", line, replay)
		}
	}
	artifact := killSwitchedArtifact()
	artifact.Plan.GuardNameSets = plan.GuardNameSets
	runner := &exactKernelRecordRunner{}
	adapter, _ := newExactKernelAdapter(runner)
	adapter.learned = s.learnedNamesProgram
	if err := adapter.apply(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	guard := artifact.Plan.RenderNftGuard()
	if runner.stdin[1] != guard+pbr.GuardProofProgram(guard)+replay {
		t.Fatalf("the guard's load does not carry the learned addresses:\n%s", runner.stdin[1])
	}

	// A restart: the file on flash is what the new daemon knows, timeouts floored at an hour.
	if err := s.ksn.w.Flush(); err != nil {
		t.Fatal(err)
	}
	s2, _ := openwrtServer(t, namedProfile(), &fakeTables{})
	s2.cfg.RoutingMode = "hybrid"
	s2.ksn.now = func() time.Time { return now }
	again := s2.learnedNamesProgram(plan)
	for _, addr := range []string{"93.184.216.34", "2a02:6b8::2:242", "203.0.113.77"} {
		if !strings.Contains(again, addr+" timeout ") {
			t.Fatalf("after a restart %s is forgotten:\n%s", addr, again)
		}
	}

	// A day after its last use an address is forgotten, here as in the kernel, and the file follows.
	now = now.Add(25 * time.Hour)
	ran = nil
	s.learnNames(ctx, plan, nil, run)
	if len(ran) != 0 || s.learnedNamesProgram(plan) != "" || !s.ksn.w.Pending() {
		t.Fatalf("expiry: ran %v, replay %q, pending %v", ran, s.learnedNamesProgram(plan), s.ksn.w.Pending())
	}

	// The kill switch over names is switched off and applied: a file naming a set the guard no
	// longer has would be refused as a whole at boot, so it goes.
	plain := *plan
	plain.GuardNameSets, plain.GuardNames = nil, false
	s.syncBootGuard(&plain)
	if _, err := os.Stat(ksBootLearnedFile); !os.IsNotExist(err) {
		t.Fatalf("the learned file outlived its sets (%v)", err)
	}
	if _, err := os.Stat(ksBootGuardFile); err != nil {
		t.Fatalf("the guard's boot copy must stay, the group is still kill-switched: %v", err)
	}
	// Nothing is learned or written on KeeneticOS or in the demo.
	s.platformOf = func() platform.Platform { return platform.Keenetic }
	if s.learnedNamesProgram(plan) != "" {
		t.Fatal("the nft guard's learned addresses on KeeneticOS")
	}
}

// The caps: a set never holds more than its share, and the address that would expire first makes room.
func TestLearnedNamesAreCapped(t *testing.T) {
	namesPaths(t)
	s, plan := openwrtServer(t, namedProfile(), &fakeTables{})
	now := time.Unix(1_800_000_000, 0)
	s.ksn.now = func() time.Time { return now }
	var ran []string
	run := func(_ context.Context, program string) error { ran = append(ran, program); return nil }
	first := []clash.Conn{connTo("203.0.113.1", "grp-auto")}
	s.learnNames(context.Background(), plan, first, run)
	now = now.Add(time.Minute)
	var conns []clash.Conn
	for i := 0; i < ksNameMaxPerSet; i++ {
		conns = append(conns, connTo(fmt.Sprintf("198.51.%d.%d", 100+i/250, 1+i%250), "grp-auto"))
	}
	ran = nil
	s.learnNames(context.Background(), plan, conns, run)
	if n := len(s.ksn.sets["kn_tg_calls"]); n != ksNameMaxPerSet {
		t.Fatalf("the set holds %d addresses, cap %d", n, ksNameMaxPerSet)
	}
	if len(ran) != 2 || ran[0] != "delete element inet wayhop_ks kn_tg_calls_4 { 203.0.113.1 }\n" {
		t.Fatalf("the oldest address should have made room, in its own transaction: %d program(s), first %q", len(ran), ran[0][:min(len(ran[0]), 120)])
	}
	if strings.Contains(s.learnedNamesProgram(plan), "203.0.113.1 ") {
		t.Fatal("the evicted address is still remembered")
	}
}

// A guard loaded while the core is down takes over what the hold had left rather than
// starting a fresh period with every Apply, rollback and list refresh.
func TestGuardReloadKeepsTheHoldsRemainingTime(t *testing.T) {
	artifact := killSwitchedArtifact()
	hold := pbr.NamesHold{Seconds: 600, Pass: []string{"whtun0", "awg0"}}
	guard := artifact.Plan.RenderNftGuardWith(hold)
	const listSet = "nft list set inet wayhop_ks wh_hold"
	const head = "table inet wayhop_ks {\n\tset wh_hold {\n\t\ttype inet_proto\n\t\tflags timeout\n"
	load := func(running bool, out map[string]string, fail map[string]error) (string, []string) {
		t.Helper()
		runner := &exactKernelRecordRunner{out: out, fail: fail}
		adapter, _ := newExactKernelAdapter(runner)
		adapter.hold = func(*pbr.Plan) pbr.NamesHold { return hold }
		adapter.coreRunning = func() bool { return running }
		if err := adapter.apply(context.Background(), artifact); err != nil {
			t.Fatal(err)
		}
		for i, c := range runner.calls {
			if c == "nft -f -" && strings.HasPrefix(runner.stdin[i], "table inet wayhop_ks {}") {
				return strings.TrimPrefix(runner.stdin[i], guard+pbr.GuardProofProgram(guard)), runner.calls
			}
		}
		t.Fatalf("no guard load in %v", runner.calls)
		return "", nil
	}
	counting := map[string]string{listSet: head + "\t\telements = { tcp timeout 10m expires 3m20s, udp timeout 10m expires 3m19s900ms }\n\t}\n}\n"}
	if extra, _ := load(false, counting, nil); extra != pbr.RenderGuardHoldRenew(200) {
		t.Fatalf("core down, 200 s left: the load ends with %q", extra)
	}
	if extra, _ := load(false, map[string]string{listSet: head + "\t}\n}\n"}, nil); extra != pbr.RenderGuardHoldLift() {
		t.Fatalf("core down, hold lapsed: the load must leave it lapsed, got %q", extra)
	}
	// No guard to read (the boot, a deleted table): one full period, as rendered.
	if extra, _ := load(false, nil, map[string]error{listSet: errors.New("Error: No such file or directory")}); extra != "" {
		t.Fatalf("no previous hold: %q", extra)
	}
	// The core runs: the renewal keeps the hold up anyway, and nothing is read.
	extra, calls := load(true, counting, nil)
	if extra != "" || slices.Contains(calls, listSet) {
		t.Fatalf("core running: %q %v", extra, calls)
	}
}

type directTable struct {
	entries []ctflush.Entry
	deleted []netip.Addr
	dumps   int
}

func (d *directTable) Dump(fam uint8, visit func(ctflush.Entry)) error {
	d.dumps++
	for _, e := range d.entries {
		if e.Family == fam {
			visit(e)
		}
	}
	return nil
}
func (d *directTable) Delete(e ctflush.Entry) error { d.deleted = append(d.deleted, e.Dst); return nil }
func (d *directTable) Close() error                 { return nil }

// When the core is seen running after it was not, the connections the LAN opened
// beside it are reset; otherwise one opened in a lapse of the hold would stay on the provider
// (offloaded, never judged again) for as long as it lived.
func TestCoreReturnResetsConnectionsOpenedBesideIt(t *testing.T) {
	origOpen, origLAN, origLocal := ctflushOpen, ksLANPrefixes, ctflushLocal
	t.Cleanup(func() { ctflushOpen, ksLANPrefixes, ctflushLocal = origOpen, origLAN, origLocal })
	ksLANPrefixes = func(*Server) []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("192.168.2.0/24")} }
	ctflushLocal = func() func(netip.Addr) bool {
		return func(a netip.Addr) bool { return a == netip.MustParseAddr("192.168.2.1") }
	}
	flow := func(dst, reply string, mark uint32) ctflush.Entry {
		return ctflush.Entry{Family: 2, Src: netip.MustParseAddr("192.168.2.20"), Dst: netip.MustParseAddr(dst), ReplySrc: netip.MustParseAddr(reply), Mark: mark}
	}
	tbl := &directTable{entries: []ctflush.Entry{
		flow("93.184.216.34", "93.184.216.34", 0),        // opened beside the core
		flow("198.51.100.135", "192.168.2.1", 0),         // redirected into the core
		flow("198.51.100.136", "198.51.100.136", 0x2023), // carried by the core's TUN
		flow("149.154.167.51", "149.154.167.51", 0),      // a kernel list's address
	}}
	opens := 0
	ctflushOpen = func() (ctflush.Table, error) { opens++; return tbl, nil }

	s, _ := openwrtServer(t, namedProfile(), &fakeTables{})
	s.cfg.RoutingMode = "hybrid"
	// The fixture is applied in fast mode; this is the hybrid plane's guard, so its plan is hybrid's
	// (fast mode's resolver-fed sets make the names' destinations a zone's).
	prof := namedProfile()
	plan, _, _ := pbr.Compile(&prof, s.pbrCompileOptions(*s.cfg))
	s.coreReturned(plan, false)
	if opens != 0 {
		t.Fatal("a core that is down flushed something")
	}
	s.coreReturned(plan, true)
	if opens != 1 || !slices.Equal(tbl.deleted, []netip.Addr{netip.MustParseAddr("93.184.216.34")}) {
		t.Fatalf("the core returned: %d open(s), deleted %v", opens, tbl.deleted)
	}
	s.coreReturned(plan, true)
	if opens != 1 {
		t.Fatal("a core that keeps running is not a return")
	}
	s.coreReturned(plan, false)
	s.coreReturned(plan, true)
	if opens != 2 {
		t.Fatalf("the second return: %d open(s)", opens)
	}
	// The daemon's first look at a running core counts: it does not know what happened before it.
	fresh, _ := openwrtServer(t, namedProfile(), &fakeTables{})
	fresh.cfg.RoutingMode = "hybrid"
	fresh.coreReturned(plan, true)
	if opens != 3 {
		t.Fatalf("first look: %d open(s)", opens)
	}
	// Fast mode (the provider is where unlisted traffic belongs) and a plan without kill-switched
	// names: nothing is touched.
	fast, _ := openwrtServer(t, namedProfile(), &fakeTables{})
	fast.coreReturned(plan, true)
	addrs := *plan
	addrs.GuardNames, addrs.GuardNameSets = false, nil
	other, _ := openwrtServer(t, namedProfile(), &fakeTables{})
	other.cfg.RoutingMode = "hybrid"
	other.coreReturned(&addrs, true)
	if opens != 3 {
		t.Fatalf("fast mode or no names flushed: %d open(s)", opens)
	}
}

// The guard passes the TUN the generated config names, not any "tun*", and
// the hold covers IPv6 only when that TUN carries it.
func TestNamesHoldFollowsTheGeneratedTun(t *testing.T) {
	s, plan := openwrtServer(t, namedProfile(), &fakeTables{})
	s.cfg.RoutingMode = "hybrid"
	// A plan stored before the config named its TUN: the old wildcard, IPv4 only.
	if hold := s.namesHold(plan); hold.Pass[0] != ksLegacyCoreTun || hold.V6 {
		t.Fatalf("stored plan: %+v", hold)
	}
	if g := s.nftGuardProgram(plan); !strings.Contains(g, "meta nfproto ipv4 meta l4proto @wh_hold counter drop") {
		t.Fatalf("beside an IPv4-only core the hold must leave IPv6 alone:\n%s", g)
	}
	named := *plan
	named.CoreTun, named.CoreTunV6 = "whtun0", true
	hold := s.namesHold(&named)
	if !slices.Equal(hold.Pass, []string{"whtun0", "awg0", "awg1", "awg2"}) || !hold.V6 {
		t.Fatalf("hold = %+v", hold)
	}
	g := s.nftGuardProgram(&named)
	if strings.Contains(g, "tun*") || !strings.Contains(g, `oifname { "awg0", "awg1", "awg2", "whtun0" } accept`) ||
		!strings.Contains(g, "\t\tmeta l4proto @wh_hold counter drop\n") {
		t.Fatalf("guard for a named dual-stack TUN:\n%s", g)
	}
	// Fast mode: no TUN and no broad hold; a learned address may leave by a tunnel only.
	s.cfg.RoutingMode = "fast"
	g = s.nftGuardProgram(&named)
	if strings.Contains(g, "wh_hold") || strings.Contains(g, "whtun0") ||
		!strings.Contains(g, "\tchain ks_names {\n\t\toifname { \"awg0\", \"awg1\", \"awg2\" } accept\n") ||
		!strings.Contains(g, "ip daddr @kn_tg_calls_4 jump ks_names") {
		t.Fatalf("fast mode guard:\n%s", g)
	}
}

// The loader does nothing once WayHop is disabled or gone, so the guard is not loaded at boot with
// nothing to route what it holds; and a sysupgrade keeps the guard's file together with its loader.
func TestBootLoaderNeedsAnEnabledWayHopAndSurvivesSysupgrade(t *testing.T) {
	check := strings.Index(ksBootGuardScript, "[ -x /usr/sbin/wayhop ] && [ -e /etc/rc.d/S95wayhop ] || return 0")
	load := strings.Index(ksBootGuardScript, "nft -f")
	if check < 0 || load < check {
		t.Fatalf("the loader must test for an enabled WayHop before it loads anything:\n%s", ksBootGuardScript)
	}
	if !strings.Contains(ksBootGuardScript, "nft -f /etc/wayhop/ks-learned.nft") {
		t.Fatal("the loader does not load the learned addresses")
	}
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("..", "..", "packaging", "openwrt", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	// The two paths the loader tests are the package's own.
	init := read("wayhop.init")
	if !strings.Contains(init, "\nSTART=95\n") || !strings.Contains(init, "\nPROG=/usr/sbin/wayhop\n") {
		t.Fatal("wayhop.init no longer starts /usr/sbin/wayhop at S95: the guard's loader tests exactly those")
	}
	keep := strings.Split(strings.TrimSpace(read("wayhop.keep")), "\n")
	for _, p := range []string{"/etc/wayhop", "/etc/init.d/wayhop-guard", "/etc/rc.d/S18wayhop-guard"} {
		if !slices.Contains(keep, p) {
			t.Fatalf("wayhop.keep lacks %s: %v", p, keep)
		}
	}
	if ksBootGuardInit != "/etc/init.d/wayhop-guard" || ksBootGuardEnable != "/etc/rc.d/S18wayhop-guard" ||
		filepath.ToSlash(filepath.Dir(ksBootGuardFile)) != "/etc/wayhop" || filepath.ToSlash(filepath.Dir(ksBootLearnedFile)) != "/etc/wayhop" {
		t.Fatal("the keep list names other paths than the daemon writes")
	}
	uninstall := read("uninstall.sh")
	for _, p := range []string{"/etc/rc.d/S18wayhop-guard", `"$INITD/wayhop-guard"`, `"$ETC/ks-guard.nft"`, `"$ETC/ks-learned.nft"`} {
		if !strings.Contains(uninstall, p) {
			t.Fatalf("uninstall.sh does not remove %s", p)
		}
	}
}

// What Review says after the stage-2 review: fast mode asks for an acknowledgement, flow
// offloading without the conntrack module too, a large guard is named, and a
// foreign rule on a kill-switched mark is called what it is, an outage of that list.
func TestReviewAfterTheStage2Review(t *testing.T) {
	profile := namedProfile()
	s, plan := openwrtServer(t, profile, &fakeTables{})
	got := s.namesHoldFindings(*s.cfg, plan)
	if len(got) != 1 || got[0].ID != findingNamesUnheld || got[0].Blocks != platform.BlocksFeature {
		t.Fatalf("fast mode must ask for an acknowledgement: %+v", got)
	}
	s.cfg.RoutingMode = "hybrid"
	got = s.namesHoldFindings(*s.cfg, plan)
	if len(got) != 1 || got[0].ID != findingNamesHold || got[0].Blocks != platform.BlocksNothing ||
		!strings.Contains(got[0].Detail, "notes the addresses") || !strings.Contains(got[0].Detail, "Stopping WayHop does not release") {
		t.Fatalf("hybrid: %+v", got)
	}

	origOpen := ctflushOpen
	t.Cleanup(func() { ctflushOpen = origOpen })
	const offloading = "firewall.@defaults[0]=defaults\nfirewall.@defaults[0].flow_offloading='1'\n"
	ctflushOpen = func() (ctflush.Table, error) { return nil, ctflush.ErrNoModule }
	off := offloadFindings(plan, offloading)
	if len(off) != 1 || off[0].ID != findingOffloadNoReset || off[0].Blocks != platform.BlocksFeature ||
		!strings.Contains(off[0].Remedy, "kmod-nf-conntrack-netlink") {
		t.Fatalf("offloading without the module: %+v", off)
	}
	if got := offloadFindings(plan, "firewall.@defaults[0].flow_offloading='0'\n"); len(got) != 0 {
		t.Fatalf("offloading off: %+v", got)
	}
	ctflushOpen = func() (ctflush.Table, error) { return &countingTable{}, nil }
	if got := offloadFindings(plan, offloading); len(got) != 0 {
		t.Fatalf("module present: %+v", got)
	}
	addrs := *plan
	addrs.GuardNames = false
	ctflushOpen = func() (ctflush.Table, error) { return nil, ctflush.ErrNoModule }
	if got := offloadFindings(&addrs, offloading); len(got) != 0 {
		t.Fatalf("addresses only: %+v", got)
	}

	if got := guardSizeFindings(plan); len(got) != 0 {
		t.Fatalf("a small guard: %+v", got)
	}
	big := *plan
	big.Zones = append([]pbr.Zone(nil), plan.Zones...)
	for i := range big.Zones {
		if big.Zones[i].EgressTag == "grp-auto" {
			for n := 0; n <= ksGuardCeiling; n++ {
				big.Zones[i].V4 = append(big.Zones[i].V4, fmt.Sprintf("198.%d.%d.%d/32", 18+n/65536, n/256%256, n%256))
			}
		}
	}
	if got := guardSizeFindings(&big); len(got) != 1 || got[0].ID != findingGuardLarge || !strings.Contains(got[0].Detail, "20003 addresses and prefixes") {
		t.Fatalf("a large guard: %+v", got)
	}

	// The script's rule takes the kill-switched group's mark to another table.
	mark, table := uint32(0), 0
	for _, e := range plan.Egresses {
		if e.Tag == "grp-auto" {
			mark, table = e.Mark, e.Table
		}
	}
	rules := fmt.Sprintf("0:\tfrom all lookup local\n145:\tfrom all fwmark %#x/0xff0000 lookup %d\n", mark, table+2)
	foreign := foreignRuleFindings(rules, "", plan.RenderIP(pbr.Options{}), plan)
	if len(foreign) != 1 || !strings.Contains(foreign[0].Detail, "the group grp-auto stops") {
		t.Fatalf("a foreign rule on a kill-switched mark: %+v", foreign)
	}
	// The same rule on a mark no kill switch covers keeps the plain warning.
	open := *plan
	open.Egresses = append([]pbr.Egress(nil), plan.Egresses...)
	for i := range open.Egresses {
		open.Egresses[i].FailClosed = false
	}
	if foreign = foreignRuleFindings(rules, "", plan.RenderIP(pbr.Options{}), &open); len(foreign) != 1 || strings.Contains(foreign[0].Detail, "stops") {
		t.Fatalf("a foreign rule on an open mark: %+v", foreign)
	}
}
