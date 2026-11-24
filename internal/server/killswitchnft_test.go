package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"wayhop/internal/failover"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// The kill switch on the nft plane, stage 2 (owrt-1122): the guard table, the postcheck that reads
// rules and routes back, the boot copy and the names hold. Shapes are the reference router's.

// killSwitchedArtifact is exactKernelTestArtifact with its tunnel under a kill switch.
func killSwitchedArtifact() executionKernelArtifactV1 {
	artifact := exactKernelTestArtifact()
	artifact.Plan.Egresses[1].FailClosed = true
	artifact.Nft = []byte(artifact.Plan.RenderNft())
	artifact.IP = artifact.Plan.RenderIP(pbr.Options{})
	artifact.Offload = []byte(artifact.Plan.RenderOffload())
	artifact.Teardown = artifact.Plan.RenderTeardown(pbr.Options{})
	return artifact
}

// The guard is loaded before anything of the plane is touched, as its own table with its marker, and
// no failure of the install takes it away: the rollback deletes `wayhop_pbr` and every rule and
// route, and the guard is then the only thing between the list and the provider.
func TestNftGuardLoadsFirstAndOutlivesARollback(t *testing.T) {
	artifact := killSwitchedArtifact()
	guard := artifact.Plan.RenderNftGuard()
	if guard == "" {
		t.Fatal("setup: the plan has a kill switch and must render a guard")
	}
	marker := guardChainCommand
	absent := errors.New("Error: No such file or directory")
	runner := &exactKernelRecordRunner{fail: map[string]error{marker: absent}}
	adapter, _ := newExactKernelAdapter(runner)
	if err := adapter.apply(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	if runner.calls[0] != marker || runner.calls[1] != "nft -f -" || runner.stdin[1] != guard+pbr.GuardProofProgram(guard) {
		t.Fatalf("the install must begin by loading the guard and its marker in one transaction:\n%v\n%s", runner.calls, runner.stdin[1])
	}
	if !strings.Contains(runner.stdin[1], "ip daddr @native_4 jump ks_0") ||
		!strings.Contains(runner.stdin[1], "oifname { \"awg0\" } accept\n\t\tiifname { \"awg0\" } accept\n\t\tcounter drop") {
		t.Fatalf("guard program:\n%s", runner.stdin[1])
	}
	for _, c := range runner.calls {
		if strings.HasPrefix(c, "nft delete") && strings.Contains(c, pbr.GuardTable) {
			t.Fatalf("an install with a kill switch must not delete the guard: %v", runner.calls)
		}
	}

	// The guard is already this plan's (a reinstall after drift, a daemon restart): it is not loaded
	// again, so the names hold's timeouts are not restarted by a plane that keeps being reinstalled.
	runner = &exactKernelRecordRunner{out: map[string]string{marker: guardChainListing(guard)}}
	adapter, _ = newExactKernelAdapter(runner)
	if err := adapter.apply(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	for _, in := range runner.stdin {
		if strings.Contains(in, "table inet wayhop_ks {") {
			t.Fatalf("a guard that is in place was loaded again: %v", runner.calls)
		}
	}
	// A guard whose chain was flushed (`nft flush chain`, `nft flush table`) is not in
	// place, whatever else of its table is left. It is loaded again.
	runner = &exactKernelRecordRunner{out: map[string]string{marker: guardChainFlushed}}
	adapter, _ = newExactKernelAdapter(runner)
	if err := adapter.apply(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	if runner.calls[1] != "nft -f -" || runner.stdin[1] != guard+pbr.GuardProofProgram(guard) {
		t.Fatalf("a flushed guard was taken for a loaded one: %v", runner.calls)
	}

	// The blackhole cannot be installed: the install rolls the plane back. The guard stays.
	runner = &exactKernelRecordRunner{fail: map[string]error{"route replace blackhole": errors.New("exit status 2: RTNETLINK answers: Operation not permitted")}}
	adapter, _ = newExactKernelAdapter(runner)
	if err := adapter.apply(context.Background(), artifact); !errors.Is(err, errExactKernelArtifact) {
		t.Fatalf("apply = %v", err)
	}
	if !slices.Contains(runner.calls, "nft delete table inet wayhop_pbr") {
		t.Fatalf("setup: the failed install should have rolled the plane back: %v", runner.calls)
	}
	for _, c := range runner.calls {
		if strings.HasPrefix(c, "nft delete") && strings.Contains(c, pbr.GuardTable) {
			t.Fatalf("the rollback removed the kill switch guard: %v", runner.calls)
		}
	}

	// Replacing another plane: the rollback puts that plane's guard back before it deletes anything.
	runner = &exactKernelRecordRunner{fail: map[string]error{"route replace blackhole": errors.New("exit status 2: RTNETLINK answers: Operation not permitted")}}
	adapter, _ = newExactKernelAdapter(runner)
	adapter.fallbackGuard = "table inet wayhop_ks {}\n# previous\n"
	_ = adapter.apply(context.Background(), artifact)
	back := slices.Index(runner.stdin, adapter.fallbackGuard+pbr.GuardProofProgram(adapter.fallbackGuard))
	gone := slices.Index(runner.calls, "nft delete table inet wayhop_pbr")
	if back < 0 || gone < 0 || back > gone {
		t.Fatalf("the previous guard must be back (call %d) before the plane is deleted (call %d): %v", back, gone, runner.calls)
	}
	// When the previous guard is the one in place (the install changed nothing of the
	// guard), the rollback does not load it: a load would start the names hold's period again.
	runner = &exactKernelRecordRunner{
		fail: map[string]error{"route replace blackhole": errors.New("exit status 2: RTNETLINK answers: Operation not permitted")},
		out:  map[string]string{marker: guardChainListing(guard)},
	}
	adapter, _ = newExactKernelAdapter(runner)
	adapter.fallbackGuard = guard
	_ = adapter.apply(context.Background(), artifact)
	if !slices.Contains(runner.calls, "nft delete table inet wayhop_pbr") {
		t.Fatalf("setup: no rollback ran: %v", runner.calls)
	}
	for _, in := range runner.stdin {
		if strings.Contains(in, "table inet wayhop_ks {") {
			t.Fatalf("the rollback reloaded a guard that was in place: %v", runner.calls)
		}
	}

	// A guard that does not load fails the install before the plane is touched.
	runner = &exactKernelRecordRunner{fail: map[string]error{marker: absent, "nft -f -": errors.New("Error: syntax error")}}
	adapter, _ = newExactKernelAdapter(runner)
	if err := adapter.apply(context.Background(), artifact); !errors.Is(err, errExactKernelArtifact) || len(runner.calls) != 2 {
		t.Fatalf("apply = %v after %v: nothing but the guard load may have run", err, runner.calls)
	}
}

// Reading one nft set is not enough: an `ip rule` or a kill-switch blackhole removed behind
// WayHop's back would go unnoticed and the marked traffic would leave by the main table. The
// postcheck reads the rules and the fail-closed routes back, and the guard's own marker; and still never judges which
// tunnel a table holds, because the elector moves that.
func TestOpenWrtPostcheckReadsRulesAndKillSwitchRoutes(t *testing.T) {
	artifact := killSwitchedArtifact()
	state := func() map[string]string { return kernelStateOf(artifact) }
	check := func(out map[string]string, fail map[string]error) ([]string, error) {
		runner := &exactKernelRecordRunner{out: out, fail: fail}
		adapter, _ := newExactKernelAdapter(runner)
		return runner.calls, adapter.postcheck(context.Background(), artifact)
	}
	calls, err := check(state(), nil)
	if err != nil {
		t.Fatalf("installed plane: %v", err)
	}
	guard := artifact.Plan.RenderNftGuard()
	if len(calls) != 4 || !strings.HasPrefix(calls[0], "nft list set inet wayhop_pbr wh_proof_") ||
		calls[1] != guardChainCommand || !pbr.GuardProofPresent(state()[guardChainCommand], guard) ||
		calls[2] != "ip rule show" || calls[3] != "ip route show table all" {
		t.Fatalf("postcheck ran %v", calls)
	}

	// The elector moved the table to another member, or emptied it: not drift.
	for name, line := range map[string]string{"elected": "default dev awg2 table 100 scope link\n", "all down": ""} {
		out := state()
		out["ip route show table all"] += line
		if _, err := check(out, nil); err != nil {
			t.Errorf("%s: a table's tunnel route is the elector's, not drift: %v", name, err)
		}
	}

	// `ip rule del pref 150` by another script.
	out := state()
	out["ip rule show"] = strings.Replace(out["ip rule show"], "150:\tfrom all fwmark 0x10000/0xff0000 lookup 100\n", "", 1)
	if out["ip rule show"] == state()["ip rule show"] {
		t.Fatalf("setup: the fwmark rule is not in the dump:\n%s", out["ip rule show"])
	}
	if _, err := check(out, nil); !errors.Is(err, errExactKernelArtifact) || !strings.Contains(err.Error(), "ip rule add fwmark 0x00010000/0x00ff0000 table 100 priority 150") {
		t.Fatalf("a missing fwmark rule = %v", err)
	}
	// The same rule at another priority, as an operator's script would add it, is not the plan's.
	out["ip rule show"] += "145:\tfrom all fwmark 0x10000/0xff0000 lookup 100\n"
	if _, err := check(out, nil); !errors.Is(err, errExactKernelArtifact) {
		t.Fatalf("a rule at another priority passed for the plan's: %v", err)
	}
	// `ip route flush table 100`.
	out = state()
	out["ip route show table all"] = strings.Replace(out["ip route show table all"], "blackhole default table 100 metric 1000\n", "", 1)
	if _, err := check(out, nil); !errors.Is(err, errExactKernelArtifact) || !strings.Contains(err.Error(), "blackhole default metric 1000 table 100") {
		t.Fatalf("a missing kill-switch blackhole = %v", err)
	}
	// The guard table is gone, or is another plan's.
	if _, err := check(state(), map[string]error{guardChainCommand: errors.New("Error: No such file or directory")}); !errors.Is(err, errExactKernelArtifact) {
		t.Fatalf("a missing guard = %v", err)
	}
	// `nft flush chain inet wayhop_ks ks_forward`. The table and its sets are there, the rules are
	// not; with the marker in a set this must not read as a loaded guard.
	out = state()
	out[guardChainCommand] = guardChainFlushed
	if _, err := check(out, nil); !errors.Is(err, errExactKernelArtifact) || !strings.Contains(err.Error(), "kill switch guard is not loaded") {
		t.Fatalf("a flushed guard = %v", err)
	}
	// A dump that cannot be read is not "nothing missing".
	if _, err := check(state(), map[string]error{"ip rule show": errors.New("ip: timed out")}); !errors.Is(err, errExactKernelArtifact) {
		t.Fatalf("an unreadable rule list = %v", err)
	}
}

// An Apply whose plan kill-switches nothing removes a guard an earlier plane left, after the new
// plane is in; switching kernel routing off removes it with the plane.
func TestNftGuardIsRemovedWithItsLastKillSwitch(t *testing.T) {
	runner := &exactKernelRecordRunner{fail: map[string]error{"nft delete table inet wayhop_ks": errors.New("Error: No such file or directory")}}
	adapter, _ := newExactKernelAdapter(runner)
	if err := adapter.apply(context.Background(), exactKernelTestArtifact()); err != nil {
		t.Fatalf("an absent guard failed the apply: %v", err)
	}
	if last := runner.calls[len(runner.calls)-1]; last != "nft delete table inet wayhop_ks" {
		t.Fatalf("the stale guard goes last, once the plane routes: %v", runner.calls)
	}
	runner = &exactKernelRecordRunner{fail: map[string]error{"nft delete table inet wayhop_ks": errors.New("Error: Operation not permitted")}}
	adapter, _ = newExactKernelAdapter(runner)
	if err := adapter.apply(context.Background(), exactKernelTestArtifact()); !errors.Is(err, errExactKernelArtifact) {
		t.Fatalf("a guard that could not be removed must not pass for removed: %v", err)
	}
}

func bootGuardPaths(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	f, i, e := ksBootGuardFile, ksBootGuardInit, ksBootGuardEnable
	ksBootGuardFile = filepath.Join(dir, "wayhop", "ks-guard.nft")
	ksBootGuardInit = filepath.Join(dir, "init.d", "wayhop-guard")
	ksBootGuardEnable = filepath.Join(dir, "rc.d", "S18wayhop-guard")
	if err := os.MkdirAll(filepath.Dir(ksBootGuardEnable), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ksBootGuardFile, ksBootGuardInit, ksBootGuardEnable = f, i, e })
}

// Boot: the guard's program is kept on flash with a loader that runs before the firewall and the
// network, so the seconds before WayHop starts are held too. Without a kill switch nothing is left.
func TestBootGuardFollowsTheInstalledPlan(t *testing.T) {
	bootGuardPaths(t)
	profile := refrouterProfile()
	profile.Groups[0].KillSwitch = true
	s, plan := openwrtServer(t, profile, &fakeTables{})
	if !plan.HasNftGuard() {
		t.Fatal("setup: the kill-switched group must be guarded")
	}
	s.syncBootGuard(plan)
	body, err := os.ReadFile(ksBootGuardFile)
	if err != nil {
		t.Fatal(err)
	}
	guard := plan.RenderNftGuard()
	if string(body) != guard+pbr.GuardProofProgram(guard) {
		t.Fatalf("the boot copy is not the guard the daemon loads:\n%s", body)
	}
	// Every tunnel the group may hold is let through by name, so the copy loads with no device up.
	if !strings.Contains(string(body), `oifname { "awg0", "awg1", "awg2" } accept`) {
		t.Fatalf("boot copy:\n%s", body)
	}
	script, err := os.ReadFile(ksBootGuardInit)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"#!/bin/sh /etc/rc.common\n", "\nSTART=18\n", "nft -f /etc/wayhop/ks-guard.nft", "return 0"} {
		if !strings.Contains(string(script), want) {
			t.Fatalf("loader lacks %q:\n%s", want, script)
		}
	}
	if runtime.GOOS != "windows" {
		if target, err := os.Readlink(ksBootGuardEnable); err != nil || target != "../init.d/wayhop-guard" {
			t.Fatalf("the loader is not enabled: %q %v", target, err)
		}
	}
	// The kill switch is switched off and applied: nothing of it stays on flash.
	profile.Groups[0].KillSwitch = false
	plain, _, err := pbr.Compile(&profile, pbr.Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	s.syncBootGuard(plain)
	for _, p := range []string{ksBootGuardFile, ksBootGuardInit, ksBootGuardEnable} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("%s is left behind (%v)", p, err)
		}
	}
	// KeeneticOS has its own backstop and no nft: nothing is written there.
	s.platformOf = func() platform.Platform { return platform.Keenetic }
	s.syncBootGuard(plan)
	if _, err := os.Lstat(ksBootGuardFile); !os.IsNotExist(err) {
		t.Fatal("the nft guard's boot copy was written on KeeneticOS")
	}
}

// Names. A kill-switched list's domains are routed by the core, so the guard cannot match them by
// address. In hybrid mode the guard carries one broad rule for the time the core is not running,
// bounded by the kernel: its set's elements time out unless the daemon renews them, and the daemon
// renews them only while the core runs.
func TestNamesHoldIsArmedInHybridAndRenewedOnlyWhileTheCoreRuns(t *testing.T) {
	profile := refrouterProfile()
	profile.Groups[0].KillSwitch = true
	profile.RoutingLists[0].Manual = append(profile.RoutingLists[0].Manual, "telegram.org")
	s, plan := openwrtServer(t, profile, &fakeTables{})
	if !plan.GuardNames {
		t.Fatal("a kill-switched list with a name must set GuardNames")
	}
	if hold := s.namesHold(plan); hold.Seconds != 0 {
		t.Fatalf("fast mode sends unlisted traffic by the provider on purpose: no hold, got %+v", hold)
	}
	s.cfg.RoutingMode = "hybrid"
	hold := s.namesHold(plan)
	if hold.Seconds != pbr.DefaultBootHoldLift || !slices.Equal(hold.Pass, []string{"tun*", "awg0", "awg1", "awg2"}) {
		t.Fatalf("hold = %+v", hold)
	}
	program := s.nftGuardProgram(plan)
	for _, want := range []string{
		"set wh_hold { type inet_proto; flags timeout; elements = { tcp timeout 600s,",
		`oifname { "awg0", "awg1", "awg2", "tun*" } accept`,
		"meta l4proto @wh_hold counter drop",
		"add rule inet wayhop_ks ks_forward accept comment \"wh_guard_",
	} {
		if !strings.Contains(program, want) {
			t.Fatalf("guard lacks %q:\n%s", want, program)
		}
	}
	// The adapter renders the same guard for install and postcheck when given the same hold.
	adapter, _ := newExactKernelAdapter(&exactKernelRecordRunner{})
	adapter.hold = s.namesHold
	if g := adapter.guardProgram(plan); g+pbr.GuardProofProgram(g) != program {
		t.Fatal("the adapter's guard differs from the boot copy's")
	}

	var ran []string
	run := func(_ context.Context, program string) error { ran = append(ran, program); return nil }
	s.renewNamesHold(context.Background(), plan, false, run)
	if len(ran) != 0 {
		t.Fatalf("the core is down: the hold must be left to run out, not renewed: %v", ran)
	}
	s.renewNamesHold(context.Background(), plan, true, run)
	if len(ran) != 1 || ran[0] != pbr.RenderGuardHoldRenew(600) {
		t.Fatalf("renewal ran %v", ran)
	}
	// Strict (kill_switch_boot_hold_lift < 0): elements without a timeout, nothing to renew.
	s.cfg.KillSwitchBootHoldLift = -1
	ran = nil
	if hold := s.namesHold(plan); hold.Seconds != -1 {
		t.Fatalf("strict hold = %+v", hold)
	}
	s.renewNamesHold(context.Background(), plan, true, run)
	if len(ran) != 0 {
		t.Fatalf("a strict hold was renewed: %v", ran)
	}
	// A short configured period is raised so the hold stands between two renewals.
	s.cfg.KillSwitchBootHoldLift = 20
	if hold := s.namesHold(plan); hold.Seconds != ksNamesHoldMin {
		t.Fatalf("short hold = %+v", hold)
	}
	// Addresses only: no hold at all.
	profile.RoutingLists[0].Manual = profile.RoutingLists[0].Manual[:2]
	addrs, _, err := pbr.Compile(&profile, pbr.Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	if addrs.GuardNames || s.namesHold(addrs).Seconds != 0 || strings.Contains(s.nftGuardProgram(addrs), "wh_hold") {
		t.Fatal("a kill switch over addresses only must not arm the names hold")
	}
}

// The keeper must not keep a table on a tunnel the Apply has just taken out of the group: it asks
// "is this one of this group's tunnels", not "is this an enabled tunnel of the plan".
func TestOpenWrtReinstallDoesNotKeepARemovedMember(t *testing.T) {
	profile := refrouterProfile()
	tables := &fakeTables{}
	s, plan := openwrtServer(t, profile, tables)
	table := egressTable(t, plan, "grp-auto")
	solo := egressTable(t, plan, "ru")
	tables.show = map[bool]string{false: openwrtTableDump(map[int]string{table: "awg0", solo: "awg1"})}
	tables.probes = handshakes("cp.cloudflare.com:80", map[string]int{"awg0": -1, "awg1": 95, "awg2": 38})
	s.monitor = healthWith(t, []string{"nl", "ru", "fi", "gw"}, "spare")
	s.listFailoverTick(context.Background())
	tables.show = map[bool]string{false: openwrtTableDump(map[int]string{table: "awg2", solo: "awg1"})}
	s.listFailoverTick(context.Background())
	seed := "ip route replace default dev awg0 table " + itoa(table)
	if keep := s.electedRouteKeeper(context.Background(), plan); keep == nil || !keep(seed) {
		t.Fatal("setup: the elected awg2 is kept across a reinstall of the same plan")
	}
	// fi (awg2) leaves the group; its endpoint stays enabled, so awg2 is still a tunnel of the plan.
	next := profile
	next.Groups = []model.Group{{ID: "grp-auto", Name: "Auto", Type: model.GroupURLTest, Members: []string{"nl", "ru", "gw"}}}
	target, _, err := pbr.Compile(&next, s.pbrCompileOptions(*s.cfg))
	if err != nil {
		t.Fatal(err)
	}
	if egressTable(t, target, "grp-auto") != table || !slices.Contains(target.MasqIfaces, "awg2") {
		t.Fatalf("setup: the group keeps its table and awg2 stays a tunnel: %+v %v", target.Egresses, target.MasqIfaces)
	}
	if keep := s.electedRouteKeeper(context.Background(), target); keep != nil && keep(seed) {
		t.Fatal("the table stays on awg2, which the Apply has just taken out of the group")
	}
}

// A list emptied because every tunnel is down ("send by the provider"), then changed to
// "stay on the last tunnel" and applied during the outage. The keeper must not read the old policy
// from the elector's state and keep the table empty, leaving the list on the provider.
func TestOpenWrtReinstallSeedsAnEmptiedListThatNowKeepsItsLastTunnel(t *testing.T) {
	profile := refrouterProfile()
	profile.RoutingLists[0].Outbound = "nl"
	profile.RoutingLists[0].Candidates = []string{"nl", "ru"}
	profile.RoutingLists[0].Fastest = &model.FastestPolicy{Enabled: true, Targets: []string{"149.154.167.51:443"}, OnAllDown: model.OnAllDownWAN}
	tables := &fakeTables{}
	s, plan := openwrtServer(t, profile, tables)
	list := egressTable(t, plan, model.ListEgressTag("tg-calls"))
	tables.show = map[bool]string{false: openwrtTableDump(map[int]string{list: "awg0"})}
	s.monitor = healthWith(t, []string{"nl", "ru", "fi", "gw"}, "spare")
	cleared := false
	s.routeTables.clear = func(context.Context, bool, string, int) error { cleared = true; return nil }
	for i := 0; i < 3 && !cleared; i++ {
		tables.probes = handshakes("149.154.167.51:443", map[string]int{"awg0": -1, "awg1": -1})
		tables.probes[failover.ProbeKey{Iface: failover.ReferenceIface, Target: "149.154.167.51:443"}] = failover.ProbeResult{Ran: true, Attempts: 3, Successes: 3, MedianMs: 20}
		s.requestFastestProbe("tg-calls")
		s.listFailoverTick(context.Background())
	}
	if !cleared {
		t.Fatal("setup: every tunnel dead and on_all_down wan must empty the table")
	}
	tables.show = map[bool]string{false: openwrtTableDump(map[int]string{})}
	s.listFailoverTick(context.Background())
	seed := "ip route replace default dev awg0 table " + itoa(list)
	if keep := s.electedRouteKeeper(context.Background(), plan); keep == nil || !keep(seed) {
		t.Fatal("setup: while the policy is \"by the provider\" the emptied table stays empty")
	}
	// The operator switches the list to "stay on the last tunnel" and applies.
	profile.RoutingLists[0].Fastest.OnAllDown = model.OnAllDownKeep
	if err := s.store.Replace(profile); err != nil {
		t.Fatal(err)
	}
	if keep := s.electedRouteKeeper(context.Background(), plan); keep != nil && keep(seed) {
		t.Fatal("the list now stays on its last tunnel, yet its table is kept empty and it leaves by the provider")
	}
}

// A list with every tunnel down gets a new tunnel by Apply. Rather than waiting for the list's
// next cycle, up to ten minutes away, the new candidate asks for a cycle at once.
func TestOpenWrtAllDownListMeasuresANewTunnelAtOnce(t *testing.T) {
	profile := refrouterProfile()
	profile.RoutingLists[0].Outbound = "nl"
	profile.RoutingLists[0].Candidates = []string{"nl", "ru"}
	profile.RoutingLists[0].Fastest = &model.FastestPolicy{Enabled: true, Targets: []string{"149.154.167.51:443"}, OnAllDown: model.OnAllDownBlock}
	tables := &fakeTables{}
	s, plan := openwrtServer(t, profile, tables)
	list := egressTable(t, plan, model.ListEgressTag("tg-calls"))
	tables.show = map[bool]string{false: openwrtTableDump(map[int]string{list: "awg0"})}
	s.monitor = healthWith(t, []string{"nl", "ru", "fi", "gw"}, "spare")
	cleared := false
	s.routeTables.clear = func(context.Context, bool, string, int) error { cleared = true; return nil }
	reference := failover.ProbeKey{Iface: failover.ReferenceIface, Target: "149.154.167.51:443"}
	answered := failover.ProbeResult{Ran: true, Attempts: 3, Successes: 3, MedianMs: 20}
	for i := 0; i < 3 && !cleared; i++ {
		tables.probes = handshakes("149.154.167.51:443", map[string]int{"awg0": -1, "awg1": -1})
		tables.probes[reference] = answered
		s.requestFastestProbe("tg-calls")
		s.listFailoverTick(context.Background())
	}
	if !cleared {
		t.Fatal("setup: every tunnel dead must empty the table")
	}
	tables.show = map[bool]string{false: openwrtTableDump(map[int]string{})}
	tables.writes = nil
	// Nothing changed: no cycle is asked for, the list waits for its interval.
	tables.probes = handshakes("149.154.167.51:443", map[string]int{"awg0": -1, "awg1": -1, "awg2": 40})
	tables.probes[reference] = answered
	s.listFailoverTick(context.Background())
	s.listFailoverTick(context.Background())
	if len(tables.writes) != 0 {
		t.Fatalf("setup: an unchanged all-down list must not be measured every tick: %v", tables.writes)
	}
	// The operator adds fi (awg2) to the list and applies.
	profile.RoutingLists[0].Candidates = []string{"nl", "ru", "fi"}
	if err := s.store.Replace(profile); err != nil {
		t.Fatal(err)
	}
	next, _, err := pbr.Compile(&profile, s.pbrCompileOptions(*s.cfg))
	if err != nil {
		t.Fatal(err)
	}
	if egressTable(t, next, model.ListEgressTag("tg-calls")) != list {
		t.Fatal("setup: the list keeps its table across the Apply")
	}
	s.applyState.rec.Committed.Desired.Profile = profile
	s.applyState.rec.Committed.Materialization.Kernel.Plan = next
	for i := 0; i < 3 && len(tables.writes) == 0; i++ {
		s.listFailoverTick(context.Background())
	}
	if want := "v4 awg2 " + itoa(list); len(tables.writes) == 0 || tables.writes[0] != want {
		t.Fatalf("the new tunnel was not measured and elected at once: writes %v, want %s", tables.writes, want)
	}
}

// A kill switch over names with WayHop not answering the home network's DNS: the router's own resolver
// looks the names up by its upstreams. Said in Review on OpenWrt as it is on KeeneticOS.
func TestReviewNamesTheResolverUnderAKillSwitch(t *testing.T) {
	profile := refrouterProfile()
	profile.Groups[0].KillSwitch = true
	profile.RoutingLists[0].Manual = append(profile.RoutingLists[0].Manual, "telegram.org")
	s, _ := openwrtServer(t, profile, &fakeTables{})
	got := killSwitchResolverFindings(*s.cfg, &profile)
	if len(got) != 1 || got[0].ID != "dns_path:killswitch:tg-calls" || got[0].Severity != platform.SeverityPrivacy {
		t.Fatalf("findings: %+v", got)
	}
	profile.DNS = &model.DNSSettings{Enabled: true, ServeClients: true}
	if got := killSwitchResolverFindings(*s.cfg, &profile); len(got) != 0 {
		t.Fatalf("WayHop answers the home network's DNS: %+v", got)
	}
	profile.DNS = nil
	profile.RoutingLists[0].Manual = profile.RoutingLists[0].Manual[:2]
	if got := killSwitchResolverFindings(*s.cfg, &profile); len(got) != 0 {
		t.Fatalf("addresses only: %+v", got)
	}
}
