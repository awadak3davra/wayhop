package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/pbr"
	"wayhop/internal/rtblackhole"
)

// killswitchbackstop.go installs and keeps the kill switch backstop's routes (pbr/backstop.go): the
// blackhole table the backstop rules look up, holding every kill-switched destination.
//
// Static CIDRs come from the plan. A domain list's addresses exist only once dnsmasq resolves a name
// and adds the answer to the list's ipset, so the daemon mirrors those sets into the table: a fixed
// cadence, a diff against what it installed (no full rewrite), nothing written to flash, and a hard
// cap on the table's size.

const (
	// ksBackstopDefaultMax bounds the table: two large public block-list feeds (16.7k and 25.4k
	// CIDRs) come to about 42k routes before aggregation. A route costs the kernel roughly
	// 130 bytes (IPv4: fib_alias + trie leaf) to 400 bytes (IPv6: fib6_info + node), so 60k routes is
	// some 8 MB of the 256-512 MB a KeeneticOS router has. Estimate; measured on a router it is not.
	ksBackstopDefaultMax = 60000
	// ksMirrorInterval is the domain mirror's cadence. The backstop matters only in NDM's rebuild
	// window, so a few seconds of lag cost only names first resolved inside it.
	ksMirrorInterval = 5 * time.Second
	// ksMirrorResync re-reads the table from the kernel every this many ticks, so a route removed
	// behind the daemon's back comes back.
	ksMirrorResync = 60
	// ksUnreadBackoffAfter syncs in a row that could not read a set put the owed re-read on every
	// ksUnreadBackoffEvery-th tick (once a minute) instead of every tick.
	ksUnreadBackoffAfter = 3
	ksUnreadBackoffEvery = 12
	// ksSetReadLimit bounds one `ipset list` read: 60k members of about 45 bytes.
	ksSetReadLimit = 4 << 20
)

// ksBackstopMax is the configured cap, the default when unset.
func ksBackstopMax(cfg config.Config) int {
	if cfg.KillSwitchBackstopMax > 0 {
		return cfg.KillSwitchBackstopMax
	}
	return ksBackstopDefaultMax
}

// keeneticKillSwitchOptions is the plane's options as an artifact records them, for the backstop.
func keeneticKillSwitchOptions(a executionKernelIpsetArtifactV1) pbr.IpsetOptions {
	io := keeneticPBROptions(a.WANIface)
	io.DynamicDomainSets = a.DynamicDomainSets
	io.LANIfaces, io.KillSwitchDNS, io.HandoffIface = a.LANIfaces, a.KillSwitchDNS, a.HandoffIface
	io.BackstopPref = a.BackstopPref
	io.FillTool, io.BootHoldLift = a.FillTool, a.BootHoldLift
	return io
}

// keeneticKillSwitchRefusal refuses a plane whose kill switch could not hold: no LAN interface for the
// backstop rules, kill-switched names with no sing-box DNS listener to pin them to, or more backstop
// routes than the cap.
func keeneticKillSwitchRefusal(plan *pbr.Plan, io pbr.IpsetOptions, cfg config.Config) error {
	if plan == nil {
		return nil
	}
	if plan.BackstopNeedsLAN(io) {
		return newMaterializeError("kernel",
			"a kill switch is on, and no LAN interface of the router could be read for its routing backstop",
			"Check that the router's bridges (br0, ...) are up, then apply again.")
	}
	if plan.KillSwitchDomains() && io.KillSwitchDNS == "" {
		return newMaterializeError("kernel",
			"a kill-switched list holds domain names, and WayHop's DNS listener is off, so the router's resolver would look them up by its own upstreams",
			"On the DNS page turn on the DNS plane with \"Serve clients\", or switch the kill switch off.")
	}
	// The Apply refuses a kill-switched zone scoped to some devices itself, not only the
	// review preflight: the backstop holds by interface, so those devices' traffic would leave by the
	// provider in every firewall rebuild and at boot.
	if zones := plan.KillSwitchScopedZones(); len(zones) > 0 {
		return newMaterializeError("kernel",
			fmt.Sprintf("a kill switch covers %s for some devices only, which KeeneticOS's routing backstop cannot hold (it holds by interface, not by device)", strings.Join(zones, ", ")),
			"Apply those lists or rules to all devices, or switch the kill switch off for their group.")
	}
	if n, max := plan.KillSwitchBackstop(io).Routes(), ksBackstopMax(cfg); n > max {
		return newMaterializeError("kernel",
			fmt.Sprintf("the kill switch backstop needs %d routes, more than the cap of %d", n, max),
			"Make the kill-switched lists smaller, or raise kill_switch_backstop_max in config.json if the router has the memory.")
	}
	return nil
}

// ksBackstop is the daemon's copy of what the backstop table holds.
type ksBackstop struct {
	mu        sync.Mutex
	open      func(table int) (rtblackhole.Table, error) // nil: rtblackhole.Open
	installed map[netip.Prefix]bool                      // nil: unknown, read from the kernel
	capped    bool                                       // the cap was hit (logged once per episode)
	// polls counts every mirror tick (the periodic re-read keys on it; a count of successful syncs
	// would stay at 0 while every sync fails), unreadStreak the syncs in a row that could not read a
	// set or failed. Atomic: the tick reads them before applyMu.
	polls, unreadStreak atomic.Int64
	// extra are the interfaces that came up after the Apply and got backstop rules from the mirror
	// with the options they were rendered with, so they can be taken away again.
	extra   []string
	extraIO pbr.IpsetOptions
	// probeIfaces reads the interfaces traffic can be forwarded from (nil: probeForwardIfaces).
	probeIfaces func() []string
	// reader reads an artifact's sets (nil: through the authenticated ipset; tests stand in).
	reader func(executionKernelIpsetArtifactV1) ksMembers
	// pref is where the mirror moved the backstop's rules after the Apply, ahead of a rule NDM added
	// since; 0 = the artifact's place. movedIfaces are the interfaces moved there.
	pref        int
	movedIfaces []string
	// unprecededSaid: a foreign rule at priority 1-2 was reported (once per process).
	unprecededSaid bool
	// unread: the last sync could not read a set; owed: a kernel re-read was asked for (a hook run,
	// a failed sync) and not done yet. syncFailed distinguishes an actual sync error from a nil sync
	// with unread sets when a backed-off tick skips the sync. All are atomic.
	unread, owed, syncFailed atomic.Bool
	// liftOwed keeps route deletion retryable after the lifted stamp was written; liftHook
	// remembers the alert's origin across such retries. liftAlerted caches the tmpfs .lifted.alerted
	// marker, which keeps the alert once per boot across restarts. liftFailureSaid suppresses
	// repeated logs and resets on success.
	liftOwed, liftHook, liftAlerted, liftFailureSaid atomic.Bool
	// hookPath is the netfilter.d hook (tests stand in; "" = keeneticPBRHookPath).
	hookPath string
	// fillToolOK checks the plane's fill tool (tests stand in; nil = the file system).
	fillToolOK func(string) bool
	// probeWAN reads the live uplink (nil: probeWANInterface); wanLive/wanApplied are the last
	// re-probe and the artifact's uplink then, under mu.
	probeWAN            func() (string, error)
	wanLive, wanApplied string
	// readRules and runRules stand in for `ip rule` and the program runner in tests (nil: the
	// artifact's authenticated tools).
	readRules func(context.Context, executionKernelIpsetArtifactV1) (string, error)
	runRules  func(context.Context, executionKernelIpsetArtifactV1, string) error
	// ready is the tmpfs stamp the program's boot hold waits for ("" = none, tests): written after the
	// first successful sync of a backstop, before the hold is taken away. Set once by New and never
	// written after, because it is read without the lock.
	ready string
	// no6Said: the kernel's refusal of IPv6 routes was logged (once per process); under mu.
	no6Said bool
	// uptime reads the seconds since boot (nil: /proc/uptime; tests stand in), for the daemon's own
	// lift of the boot hold.
	uptime func() (int, bool)
}

// readUptime is the whole seconds of /proc/uptime.
func readUptime() (int, bool) {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(raw))
	if len(f) == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(strings.SplitN(f[0], ".", 2)[0])
	return n, err == nil
}

// ksDaemonLift is the daemon's own bound on the broad boot hold. Past the plane's
// BootHoldLift seconds the defaults and shared throws go and .lifted is written; the narrow routes
// stay. An existing hook-side stamp is verified and alerted once, and an owed delete is
// retried regardless of stamps or uptime. Caller holds applyMu.
func (s *Server) ksDaemonLift(plan *pbr.Plan, a executionKernelIpsetArtifactV1) {
	s.ksDaemonLiftReason(plan, a, false)
}

// ksDaemonLiftAfterFailedSync is the hard bound for a daemon whose normal sync is still
// failing. It first makes a best-effort pass over every static prefix in the applied plan, outside
// the mirror's route cap, then lifts. Any failure is logged and the alert says the narrow routes may
// be incomplete; after this double failure availability (B) wins, as it does at the hook's hard bound.
func (s *Server) ksDaemonLiftAfterFailedSync(plan *pbr.Plan, a executionKernelIpsetArtifactV1) {
	bs := plan.KillSwitchBackstop(keeneticKillSwitchOptions(a))
	if !bs.Active() {
		return // No kill switch means no hold, lift stamp, or alert.
	}
	if !s.ksb.liftOwed.Load() && a.BootHoldLift > 0 && s.ksUptimeAtLeast(a.BootHoldLift+pbr.BootHoldLiftGrace) {
		if err := s.ksb.installStaticForLift(bs); err != nil {
			log.Printf("kill switch backstop: install static routes before the failed-sync lift: %v", err)
		}
	}
	// This also observes a hook-side stamp and retries an owed delete before the hard bound. With
	// neither stamp it waits for the failed-sync threshold in ksDaemonLiftReason.
	s.ksDaemonLiftReason(plan, a, true)
}

func (s *Server) ksUptimeAtLeast(seconds int) bool {
	up := s.ksb.uptime
	if up == nil {
		up = readUptime
	}
	n, ok := up()
	return ok && n >= seconds
}

func (s *Server) ksDaemonLiftReason(plan *pbr.Plan, a executionKernelIpsetArtifactV1, failedSync bool) {
	bs := plan.KillSwitchBackstop(keeneticKillSwitchOptions(a))
	if !bs.Active() {
		return // Guard every daemon lift path, including a !doSync tick.
	}
	owed := s.ksb.liftOwed.Load()
	r := s.ksb.readyPath()
	if !owed {
		if _, err := os.Stat(r); err == nil {
			return // A ready+lifted pair is a healthy completed boot, not a new alert.
		}
	}
	_, liftedErr := os.Stat(r + pbr.StampLifted)
	if !owed && liftedErr == nil {
		if s.ksb.liftAlerted.Load() {
			return
		}
		if _, err := os.Stat(r + pbr.StampLifted + ".alerted"); err == nil {
			s.ksb.liftAlerted.Store(true)
			return // The tmpfs marker survives a daemon restart.
		}
		// No lift is in flight in this process. The stamp names the daemon when an earlier process of
		// it wrote it (a restart between the stamp and the alert marker); otherwise another
		// actor, normally the hook, did. Either way the idempotent deletes are repeated once.
		s.ksb.liftHook.Store(!ksLiftStampIsDaemons(r))
	} else if !owed {
		s.ksb.liftHook.Store(false)
		if a.BootHoldLift <= 0 {
			return // strict: no bound in this plane
		}
		limit := a.BootHoldLift
		if failedSync {
			limit += pbr.BootHoldLiftGrace
		}
		if !s.ksUptimeAtLeast(limit) {
			return
		}
	}
	if err := s.ksb.liftHold(bs, r); err != nil {
		if !s.ksb.liftFailureSaid.Swap(true) {
			log.Printf("kill switch backstop: lift the boot hold: %v", err)
		}
		return
	}
	s.ksb.liftFailureSaid.Store(false) // Only one episode is suppressed, not every later error.
	if s.ksb.liftAlerted.Swap(true) {
		return
	}
	msg := fmt.Sprintf("the kill-switched sets were not all read %d s after boot; the daemon lifted the broad boot hold, only kill-switched destinations stay held", a.BootHoldLift)
	if failedSync {
		msg = fmt.Sprintf("the backstop sync was still failing %d s after boot; the daemon lifted the broad boot hold after trying the applied static routes, and static or learned narrow routes may be incomplete", a.BootHoldLift+pbr.BootHoldLiftGrace)
	}
	if s.ksb.liftHook.Load() {
		msg = "the hook lifted the broad boot hold before this daemon did; the daemon verified the broad boot hold is gone, only kill-switched destinations stay held"
	}
	origin := ksLiftOriginDaemon
	if s.ksb.liftHook.Load() {
		origin = "hook"
	}
	log.Printf("KILL SWITCH: %s", msg)
	s.alert("WayHop kill switch: " + msg)
	// The marker goes after the alert is handed over, never before. A daemon that dies
	// in between alerts once more after its restart instead of never in this boot.
	if err := os.WriteFile(r+pbr.StampLifted+".alerted", []byte(origin+"\n"), 0o644); err != nil {
		log.Printf("kill switch backstop: remember the lift alert: %v", err)
	}
}

// ksLiftOriginDaemon is what the daemon writes into the lifted stamp; the hook's stamp is empty.
const ksLiftOriginDaemon = "daemon"

// ksLiftStampIsDaemons reports whether the lifted stamp beside ready was written by a daemon.
func ksLiftStampIsDaemons(ready string) bool {
	raw, err := os.ReadFile(ready + pbr.StampLifted)
	return err == nil && strings.TrimSpace(string(raw)) == ksLiftOriginDaemon
}

// installStaticForLift installs every static prefix the applied plan knows, ignoring the mirror cap:
// that cap's overflow is precisely one failed-sync case that must not prevent the hard-bound lift.
// A table-list failure does not suppress the adds (Add replaces an existing route); the narrow data
// gets its best chance before availability forces the broad hold open. Caller holds applyMu.
func (b *ksBackstop) installStaticForLift(bs pbr.Backstop) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	open := b.open
	if open == nil {
		open = rtblackhole.Open
	}
	t, err := open(pbr.BackstopTable(pbr.Options{}))
	if err != nil {
		return fmt.Errorf("open the backstop table: %w", err)
	}
	defer t.Close()
	have, readErr := t.List()
	present := map[netip.Prefix]bool{}
	if readErr == nil {
		for _, p := range have {
			present[p] = true
		}
		b.installed = present
	}
	errs := []error{}
	if readErr != nil {
		errs = append(errs, fmt.Errorf("read the backstop table: %w", readErr))
	}
	for _, p := range append(append([]netip.Prefix(nil), bs.V4...), bs.V6...) {
		if readErr == nil && present[p] {
			continue
		}
		if err := t.Add(p); err != nil {
			if p.Addr().Is6() && errors.Is(err, rtblackhole.ErrFamilyUnsupported) {
				continue // a kernel without IPv6 routing forwards no such traffic
			}
			errs = append(errs, fmt.Errorf("add %s: %w", p, err))
			continue
		}
		if b.installed != nil {
			b.installed[p] = true
		}
	}
	return errors.Join(errs...)
}

// liftHold writes the lifted stamp before removing the broad hold: a stamp failure
// leaves every route alone instead of flapping the hold on each rebuild. Once stamped, liftOwed stays
// set until every default delete succeeds, so neither the stamp nor a later ready stamp suppresses
// the retry. A kernel that refuses IPv6 routes holds nothing there.
func (b *ksBackstop) liftHold(bs pbr.Backstop, ready string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// The stamp names its writer and an existing one is kept: the hook's empty stamp
	// stays the hook's when the daemon only repeats the deletes behind it.
	f, err := os.OpenFile(ready+pbr.StampLifted, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err == nil {
		_, err = f.WriteString(ksLiftOriginDaemon + "\n")
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	} else if os.IsExist(err) {
		err = nil
	}
	if err != nil {
		return fmt.Errorf("stamp: %w", err)
	}
	b.liftOwed.Store(true)
	open := b.open
	if open == nil {
		open = rtblackhole.Open
	}
	t, err := open(pbr.BackstopTable(pbr.Options{}))
	if err != nil {
		return fmt.Errorf("open the backstop table: %w", err)
	}
	defer t.Close()
	for _, p := range ksHold {
		if slices.Contains(bs.V4, p) || slices.Contains(bs.V6, p) {
			continue // a kill-switched list of everything: the route is the backstop's own
		}
		if err := t.Del(p); err != nil && !(p.Addr().Is6() && errors.Is(err, rtblackhole.ErrFamilyUnsupported)) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
		if b.installed != nil {
			delete(b.installed, p)
		}
	}
	releaseHoldThrows(t)
	b.liftOwed.Store(false)
	return nil
}

// ksBackstopReadyStamp is the backstop's "filled since boot" stamp, in RAM: a reboot removes it.
const ksBackstopReadyStamp = "/tmp/wayhop-backstop.ready"

// ksHold is the program's boot hold: a default blackhole in each family.
var ksHold = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

// releaseHold writes the stamp, then removes the boot hold. Caller holds b.mu.
func (b *ksBackstop) releaseHold(t rtblackhole.Table, want []netip.Prefix) {
	if b.ready == "" {
		return
	}
	if _, err := os.Stat(b.ready); err != nil {
		if err := os.WriteFile(b.ready, nil, 0o644); err != nil {
			log.Printf("kill switch backstop: the boot hold stays: stamp %s: %v", b.ready, err)
			return
		}
	}
	for _, p := range ksHold {
		if slices.Contains(want, p) {
			continue // a kill-switched list of everything: the route is the backstop's own
		}
		if err := t.Del(p); err != nil && !errors.Is(err, rtblackhole.ErrFamilyUnsupported) {
			log.Printf("kill switch backstop: remove the boot hold %s: %v", p, err)
		}
		delete(b.installed, p)
	}
	releaseHoldThrows(t)
}

// releaseHoldThrows removes the hold's shared-space throws: they must not outlive the
// hold, where a broader kill-switched prefix would be shadowed by them.
func releaseHoldThrows(t rtblackhole.Table) {
	for _, p := range pbr.HoldSharedThrows() {
		if err := t.DelThrow(p); err != nil {
			log.Printf("kill switch backstop: remove the boot hold's throw %s: %v", p, err)
		}
	}
}

// newForwardIfaces are the live forwarding interfaces the artifact's rules and the earlier additions
// do not cover yet.
func newForwardIfaces(live, installed, extra []string) []string {
	var out []string
	for _, i := range live {
		if !slices.Contains(installed, i) && !slices.Contains(extra, i) {
			out = append(out, i)
		}
	}
	return out
}

// coverNewIfaces adds backstop rules for interfaces that appeared after the Apply. The rules a
// netfilter rebuild does not touch, so they stay until the next Apply (which reads the interfaces
// again) or the plane's teardown takes them away (dropExtraIfaces).
func (s *Server) coverNewIfaces(ctx context.Context, plan *pbr.Plan, artifact executionKernelIpsetArtifactV1) {
	io := keeneticKillSwitchOptions(artifact)
	if s.ksb.pref != 0 {
		io.BackstopPref = s.ksb.pref // where the backstop is now
	}
	if !plan.KillSwitchBackstop(io).Active() {
		return
	}
	probe := s.ksb.probeIfaces
	if probe == nil {
		probe = probeForwardIfaces
	}
	add := newForwardIfaces(keeneticLANIfaces(probe(), artifact.WANIface), artifact.LANIfaces, s.ksb.extra)
	if len(add) == 0 {
		return
	}
	program := plan.BackstopRulesFor(exactKernelOptions(), io, add)
	if program == "" {
		return // nothing the renderer would cover: never recorded as covered
	}
	if err := s.runKSRules(ctx, artifact, program); err != nil {
		log.Printf("kill switch backstop: rules for %v: %v", add, err)
		return
	}
	log.Printf("kill switch backstop: now also covers %v", add)
	s.ksb.extra, s.ksb.extraIO = append(s.ksb.extra, add...), io
}

// runKSRules runs a rule program with the artifact's authenticated tools.
func (s *Server) runKSRules(ctx context.Context, artifact executionKernelIpsetArtifactV1, program string) error {
	if s.ksb.runRules != nil {
		return s.ksb.runRules(ctx, artifact, program)
	}
	adapter, err := newExactKeeneticKernelAdapter(artifact)
	if err != nil {
		return err
	}
	return adapter.runProgram(ctx, artifact, program)
}

// readKSRules reads the live rule list, v4 and, when v6 is backstopped, v6 after it (a foreign
// v6 rule moves both families too, as at capture). A v6 list that cannot be read is left out.
func (s *Server) readKSRules(ctx context.Context, artifact executionKernelIpsetArtifactV1, v6 bool) (string, error) {
	if s.ksb.readRules != nil {
		return s.ksb.readRules(ctx, artifact)
	}
	adapter, err := newExactKeeneticKernelAdapter(artifact)
	if err != nil {
		return "", err
	}
	dump, err := adapter.runner.Run(ctx, "", executionToolIP, "rule")
	if err != nil || !v6 {
		return dump, err
	}
	if d6, err6 := adapter.runner.Run(ctx, "", executionToolIP, "-6", "rule"); err6 == nil {
		dump += "\n" + d6
	}
	return dump, nil
}

// ksMovedPref finds backstop rules (table) at a priority below the artifact's place and its stage
// copy: the ones a mirror moved before the daemon restarted. 0 = none.
func ksMovedPref(dump string, table, artPref int) int {
	found := 0
	for _, line := range strings.Split(dump, "\n") {
		head, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || !strings.Contains(rest, " iif ") || !strings.HasSuffix(strings.TrimSpace(rest), "lookup "+strconv.Itoa(table)) {
			continue
		}
		p, err := strconv.Atoi(head)
		if err != nil || p < 1 || p >= artPref-1 {
			continue
		}
		if found == 0 || p < found {
			found = p
		}
	}
	return found
}

// keepBackstopAhead re-derives the backstop's priority from the live rule list. NDM adds an access
// policy's rules (typically priorities 100-109) when the operator creates one, long after the Apply
// that placed the backstop; those devices would then leave by the policy table in every rebuild window.
// When a foreign rule now precedes the backstop, its rules are added at the new place for every
// covered interface, make-before-break by construction: the old ones stay behind them (the hook keeps
// re-adding them there) until the next Apply re-derives the place or the teardown takes both away.
func (s *Server) keepBackstopAhead(ctx context.Context, plan *pbr.Plan, artifact executionKernelIpsetArtifactV1) {
	io := keeneticKillSwitchOptions(artifact)
	bs := plan.KillSwitchBackstop(io)
	if !bs.Active() {
		return
	}
	dump, err := s.readKSRules(ctx, artifact, len(bs.V6)+len(bs.Sets6) > 0)
	if err != nil {
		log.Printf("kill switch backstop: read the rule list: %v", err)
		return
	}
	opt := exactKernelOptions()
	ifaces := append(append([]string(nil), artifact.LANIfaces...), s.ksb.extra...)
	cur := s.ksb.pref
	if cur == 0 {
		cur = pbr.BackstopPrefFromRules("", opt)
		if io.BackstopPref >= 2 {
			cur = io.BackstopPref
		}
		// Rules moved before a restart are the backstop's place, not news: taken over
		// silently, so the next Apply or teardown removes them and no alert repeats.
		if moved := ksMovedPref(dump, pbr.BackstopTable(opt), cur); moved != 0 {
			log.Printf("kill switch backstop: rules moved ahead before a restart found at priority %d", moved)
			s.ksb.pref, s.ksb.movedIfaces, cur = moved, ifaces, moved
		}
	}
	if blocked := pbr.BackstopUnpreceded(dump, opt); len(blocked) > 0 && !s.ksb.unprecededSaid {
		s.ksb.unprecededSaid = true
		log.Printf("kill switch backstop: a router rule at priority %v cannot be preceded; traffic it routes is outside the kill switch's backstop", blocked)
		s.alert(fmt.Sprintf("WayHop kill switch: a router rule at priority %v is ahead of the routing backstop and cannot be stepped ahead of", blocked))
	}
	want := pbr.BackstopPrefFromRules(dump, opt)
	if want >= cur {
		return
	}
	io.BackstopPref = want
	program := plan.BackstopRulesFor(opt, io, ifaces)
	if program == "" {
		return
	}
	if err := s.runKSRules(ctx, artifact, program); err != nil {
		log.Printf("kill switch backstop: move ahead of a new rule at %d: %v", want+1, err)
		return
	}
	log.Printf("kill switch backstop: a rule NDM added since the Apply precedes it; moved from priority %d to %d (apply again to make the hook match)", cur, want)
	s.alert(fmt.Sprintf("WayHop kill switch: the routing backstop moved from priority %d to %d ahead of a new router policy; apply again", cur, want))
	s.ksb.pref, s.ksb.movedIfaces = want, ifaces
}

// reprobeWAN reads the uplink again after a rebuild: an uplink failover leaves the
// artifact's `-o <wan>` MASQUERADE on the old one. Logged once per change, shown in Diagnostics.
func (s *Server) reprobeWAN(applied string) {
	probe := s.ksb.probeWAN
	if probe == nil {
		probe = probeWANInterface
	}
	live, err := probe()
	if err != nil {
		return
	}
	s.ksb.mu.Lock()
	changed := live != s.ksb.wanLive
	s.ksb.wanLive, s.ksb.wanApplied = live, applied
	s.ksb.mu.Unlock()
	if changed && applied != "" && live != applied {
		log.Printf("kernel plane: the WAN uplink is now %s, the applied plane names %s; apply again", live, applied)
	}
}

// wanDriftCheck is the Diagnostics row for a WAN that changed since the Apply.
func (s *Server) wanDriftCheck(context.Context) healthRow {
	row := healthRow{ID: "wan_drift", Label: "WAN uplink matches the applied plane"}
	s.ksb.mu.Lock()
	live, applied := s.ksb.wanLive, s.ksb.wanApplied
	s.ksb.mu.Unlock()
	switch {
	case live == "" || applied == "":
		row.Status, row.Summary = "na", "not measured"
	case live == applied:
		row.Status, row.Summary = "pass", "the uplink is "+live
	default:
		row.Status = "warn"
		row.Summary = fmt.Sprintf("the uplink is now %s, the applied plane NATs on %s", live, applied)
		row.Fix = "Apply again so the plane follows the uplink."
	}
	return row
}

// dropExtraIfaces takes the mirror's additional rules away once a new plane is in (the ones it does
// not render itself at the same priority) or the plane is gone (next nil).
func (s *Server) dropExtraIfaces(ctx context.Context, plan *pbr.Plan, previous executionKernelIpsetArtifactV1, next *executionKernelIpsetArtifactV1) {
	if plan == nil {
		return
	}
	// The rules the mirror moved ahead of a new NDM rule, unless the next plane renders
	// them at the same place itself.
	if s.ksb.pref != 0 {
		if next == nil || next.BackstopPref != s.ksb.pref {
			io := keeneticKillSwitchOptions(previous)
			io.BackstopPref = s.ksb.pref
			if err := s.runKSRules(ctx, previous, ksSpareNext(plan.BackstopRulesTeardownFor(exactKernelOptions(), io, s.ksb.movedIfaces), next)); err != nil {
				log.Printf("kill switch backstop: drop the moved rules: %v", err)
			}
		}
		s.ksb.pref, s.ksb.movedIfaces = 0, nil
	}
	if len(s.ksb.extra) == 0 {
		return
	}
	var drop []string
	for _, i := range s.ksb.extra {
		if next == nil || !slices.Contains(next.LANIfaces, i) || next.BackstopPref != s.ksb.extraIO.BackstopPref {
			drop = append(drop, i)
		}
	}
	s.ksb.extra = nil
	if len(drop) == 0 {
		return
	}
	if err := s.runKSRules(ctx, previous, ksSpareNext(plan.BackstopRulesTeardownFor(exactKernelOptions(), s.ksb.extraIO, drop), next)); err != nil {
		log.Printf("kill switch backstop: drop the rules for %v: %v", drop, err)
	}
}

// ksSpareNext drops from a teardown program the deletes of a rule the next plane has just installed:
// the teardown also clears the stage slot (priority-1), which can be exactly the next
// plane's priority, for an interface it covers. A stage copy left behind is removed by the hook's
// next run.
func ksSpareNext(program string, next *executionKernelIpsetArtifactV1) string {
	if next == nil {
		return program
	}
	p := next.BackstopPref
	if p < 2 {
		p = pbr.BackstopPrefFromRules("", exactKernelOptions())
	}
	mark := fmt.Sprintf(" priority %d 2>/dev/null;", p)
	var keep []string
	for _, line := range strings.SplitAfter(program, "\n") {
		spare := false
		if strings.Contains(line, mark) {
			for _, i := range next.LANIfaces {
				if strings.Contains(line, " iif "+i+" ") {
					spare = true
					break
				}
			}
		}
		if !spare {
			keep = append(keep, line)
		}
	}
	return strings.Join(keep, "")
}

// ksMembers reads one ipset's members.
type ksMembers func(ctx context.Context, set string) ([]netip.Prefix, error)

// ksWant is the backstop's routes: static first, then mirrored members not inside a static prefix,
// up to max. Members already installed keep their place, so a full table does not churn.
func ksWant(bs pbr.Backstop, members []netip.Prefix, installed map[netip.Prefix]bool, max int) ([]netip.Prefix, bool, error) {
	want := append(append([]netip.Prefix(nil), bs.V4...), bs.V6...)
	if len(want) > max {
		return nil, true, fmt.Errorf("%d static routes, cap %d", len(want), max)
	}
	static := map[netip.Prefix]bool{}
	for _, p := range want {
		static[p] = true
	}
	covered := func(p netip.Prefix) bool {
		for bits := p.Bits(); bits >= 0; bits-- {
			if q, err := p.Addr().Prefix(bits); err == nil && static[q] {
				return true
			}
		}
		return false
	}
	var keep, fresh []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, p := range members {
		p = p.Masked()
		if seen[p] || covered(p) {
			continue
		}
		seen[p] = true
		if installed[p] {
			keep = append(keep, p)
		} else {
			fresh = append(fresh, p)
		}
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].Addr().Less(fresh[j].Addr()) })
	capped := false
	for _, p := range append(keep, fresh...) {
		if len(want) >= max {
			capped = true
			break
		}
		want = append(want, p)
	}
	return want, capped, nil
}

// sync makes the table hold the plan's backstop (nil plan: nothing). addOnly keeps routes the plan
// does not want, for the moment between installing a plane and retiring the one it replaces.
// fromKernel re-reads the table first instead of trusting the daemon's copy.
func (b *ksBackstop) sync(ctx context.Context, plan *pbr.Plan, io pbr.IpsetOptions, read ksMembers, max int, addOnly, fromKernel bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var bs pbr.Backstop
	if plan != nil {
		bs = plan.KillSwitchBackstop(io)
	}
	if !bs.Active() && b.installed != nil && len(b.installed) == 0 && !fromKernel {
		return nil // nothing installed, nothing wanted
	}
	var members []netip.Prefix
	readFailed := false
	for _, set := range append(append([]string(nil), bs.Sets4...), bs.Sets6...) {
		if read == nil {
			break
		}
		got, err := read(ctx, set)
		if err != nil {
			readFailed = true
			// A set not read keeps what was mirrored from it: dropping those routes would open the
			// window for exactly the names already resolved.
			log.Printf("kill switch backstop: read %s: %v", set, err)
			for p := range b.installed {
				members = append(members, p)
			}
			continue
		}
		members = append(members, got...)
	}
	want, capped, err := ksWant(bs, members, b.installed, max)
	if err != nil {
		return err
	}
	if capped && !b.capped {
		log.Printf("kill switch backstop: the cap of %d routes is reached; names resolved from now on are not backstopped until routes expire (raise kill_switch_backstop_max)", max)
	}
	b.capped = capped
	open := b.open
	if open == nil {
		open = rtblackhole.Open
	}
	t, err := open(pbr.BackstopTable(pbr.Options{}))
	if err != nil {
		if !bs.Active() {
			return nil // nothing to hold: a host without rtnetlink is not a failure then
		}
		return fmt.Errorf("open the backstop table: %w", err)
	}
	defer t.Close()
	if b.installed == nil || fromKernel {
		have, err := t.List()
		if err != nil {
			return fmt.Errorf("read the backstop table: %w", err)
		}
		b.installed = map[netip.Prefix]bool{}
		for _, p := range have {
			b.installed[p] = true
		}
	}
	have := make([]netip.Prefix, 0, len(b.installed))
	for p := range b.installed {
		have = append(have, p)
	}
	add, del := rtblackhole.Diff(have, want, addOnly)
	// A kernel that refuses IPv6 route operations forwards no IPv6; that family is skipped
	// for the rest of the sync, so it never keeps the hold. A refused IPv4 route fails the sync.
	no6 := false
	refused6 := func(p netip.Prefix, err error) bool {
		if !p.Addr().Is6() || !errors.Is(err, rtblackhole.ErrFamilyUnsupported) {
			return false
		}
		if !no6 && !b.no6Said {
			log.Printf("kill switch backstop: the kernel refuses IPv6 routes (%v); IPv6 is not routed here, its routes are skipped", err)
		}
		no6, b.no6Said = true, true
		return true
	}
	for _, p := range add {
		if no6 && p.Addr().Is6() {
			continue
		}
		if err := t.Add(p); err != nil {
			if refused6(p, err) {
				continue
			}
			return fmt.Errorf("add %s: %w", p, err)
		}
		b.installed[p] = true
	}
	for _, p := range del {
		if readFailed && slices.Contains(ksHold, p) {
			continue // the boot hold goes only with releaseHold, after a full read
		}
		if no6 && p.Addr().Is6() {
			delete(b.installed, p)
			continue
		}
		if err := t.Del(p); err != nil {
			if refused6(p, err) {
				delete(b.installed, p)
				continue
			}
			return fmt.Errorf("delete %s: %w", p, err)
		}
		delete(b.installed, p)
	}
	if bs.Active() && !readFailed {
		// Not after a failed set read: at boot that is a set the hook has not restored
		// yet, and the table would lack exactly the names already resolved.
		b.releaseHold(t, want)
	}
	// Not an error: an Apply syncs before its program has created a new set. The mirror owes a re-read.
	b.unread.Store(readFailed)
	return nil
}

// readyPath is the boot-hold stamp this backstop writes.
func (b *ksBackstop) readyPath() string {
	if b.ready != "" {
		return b.ready
	}
	return ksBackstopReadyStamp
}

// ipsetMembers reads a set's members through the authenticated ipset.
func ipsetMembers(adapter *exactKeeneticKernelAdapter) ksMembers {
	return func(ctx context.Context, set string) ([]netip.Prefix, error) {
		out, err := adapter.runner.runLimit(ctx, ksSetReadLimit, "", executionToolIpset, "list", set)
		if err != nil {
			return nil, err
		}
		return parseIpsetMembers(out), nil
	}
}

// parseIpsetMembers reads `ipset list <set>`: one entry per line after "Members:", the address or
// prefix first ("1.2.3.4 timeout 86311", "2001:db8::/48"). A member with `timeout 0` is one of the
// zone's own static prefixes, which the plan carries already (the backstop's static routes, the
// sweep's zone CIDRs): it is skipped, so a list that mixes names with a large feed does not turn its
// whole feed into a slice every tick.
func parseIpsetMembers(out string) []netip.Prefix {
	var ps []netip.Prefix
	in := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !in {
			in = line == "Members:"
			continue
		}
		f := strings.Fields(line)
		if len(f) == 0 || len(f) >= 3 && f[1] == "timeout" && f[2] == "0" {
			continue
		}
		if p, err := netip.ParsePrefix(f[0]); err == nil {
			ps = append(ps, p.Masked())
		} else if a, err := netip.ParseAddr(f[0]); err == nil {
			ps = append(ps, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return ps
}

// syncKillSwitchBackstop runs the backstop sync for a Keenetic artifact. previous is the plane being
// replaced (nil: none), read only by the Apply's pre-program sync (addOnly).
func (s *Server) syncKillSwitchBackstop(ctx context.Context, plan *pbr.Plan, artifact executionKernelIpsetArtifactV1, addOnly, fromKernel bool, previous *executionKernelArtifactV1) error {
	adapter, err := newExactKeeneticKernelAdapter(artifact)
	if err != nil {
		return err
	}
	read := ipsetMembers(adapter)
	if addOnly {
		var prevSets []string
		if previous != nil && previous.Plan != nil && previous.Ipset != nil {
			prevSets = previous.Plan.IpsetNames(keeneticKillSwitchOptions(*previous.Ipset))
		}
		read = ksNewSetsEmpty(read, func() (string, error) {
			return adapter.runner.runLimit(ctx, ksSetReadLimit, "", executionToolIpset, "list", "-n")
		}, prevSets)
	}
	err = s.ksb.sync(ctx, plan, keeneticKillSwitchOptions(artifact), read, ksBackstopMax(s.config()), addOnly, fromKernel)
	if err != nil || s.ksb.unread.Load() {
		s.ksb.owed.Store(true) // the mirror's next tick re-reads the kernel
	}
	return err
}

// ksNewSetsEmpty reads a set the program about to run will create as empty: before an Apply's
// program a kill-switched domain set of a new list does not exist yet. Read as a failure it would
// keep the broad hold up for the whole Apply (dropping all unlisted traffic), or let the hook lift it
// at once and leave a false "lifted" until the next reboot. A set the replaced plane had, or
// any set when the kernel's list of sets cannot be read, is read as before: missing there means not
// restored yet (a boot), and its learned members must stay held.
func ksNewSetsEmpty(read ksMembers, listNames func() (string, error), prevSets []string) ksMembers {
	var live map[string]bool
	return func(ctx context.Context, set string) ([]netip.Prefix, error) {
		if live == nil {
			out, err := listNames()
			if err != nil {
				return read(ctx, set)
			}
			live = map[string]bool{}
			for _, n := range strings.Fields(out) {
				live[n] = true
			}
		}
		if !live[set] && !slices.Contains(prevSets, set) {
			return nil, nil
		}
		return read(ctx, set)
	}
}

// clearKillSwitchBackstop empties the table once no plane is left to need it.
func (s *Server) clearKillSwitchBackstop(ctx context.Context) {
	if err := s.ksb.sync(ctx, nil, pbr.IpsetOptions{}, nil, ksBackstopMax(s.config()), false, true); err != nil {
		log.Printf("kill switch backstop: clear: %v", err)
	}
}

// killSwitchMirrorLoop keeps the backstop in step with the domain sets dnsmasq fills.
func (s *Server) killSwitchMirrorLoop(ctx context.Context) {
	ticker := time.NewTicker(ksMirrorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.killSwitchMirrorTick(ctx)
	}
}

// kernelBaseline is the supervised Keenetic kernel plane, or nil.
func (s *Server) kernelBaseline() *executionKernelArtifactV1 {
	base := s.supervisedBaseline()
	if base == nil || !base.Materialization.known() {
		return nil
	}
	k := base.Materialization.Kernel
	if k.Action != ExecutionEnsurePresent || k.Ipset == nil || k.Plan == nil {
		return nil
	}
	return &k
}

// ksPreRead reads the kill-switched domain sets before applyMu is taken: a full member dump per
// set, forked and parsed, must not hold the lock every other TryLock user skips its turn on.
func ksPreRead(ctx context.Context, bs pbr.Backstop, read ksMembers) ksMembers {
	got := map[string][]netip.Prefix{}
	errs := map[string]error{}
	for _, set := range append(append([]string(nil), bs.Sets4...), bs.Sets6...) {
		got[set], errs[set] = read(ctx, set)
	}
	return func(_ context.Context, set string) ([]netip.Prefix, error) { return got[set], errs[set] }
}

func (s *Server) killSwitchMirrorTick(ctx context.Context) {
	if s.applyInProgress.Load() || s.config().Demo || s.routingIsOff() {
		return
	}
	k := s.kernelBaseline()
	if k == nil {
		return
	}
	// Outside applyMu: the leak sweep (a conntrack dump) and the reads of the domain sets.
	hook := s.leaks.hookRan()
	if hook {
		s.sweepLeakedFlows(ctx, k.Plan, *k.Ipset, false, "a firewall rebuild")
	} else if s.leaks.owed() {
		s.sweepLeakedFlows(ctx, k.Plan, *k.Ipset, false, "a firewall rebuild (continued)")
	}
	bs := k.Plan.KillSwitchBackstop(keeneticKillSwitchOptions(*k.Ipset))
	// The table is re-read from the kernel after every hook run and every ksMirrorResync ticks, so a
	// table flushed or changed behind the daemon's back is repaired within one tick of the next rebuild
	// rather than within five minutes.
	// A re-read a hook run asked for is owed until a sync did it, and while the boot-hold stamp is
	// absent every tick syncs, so a tick that lost applyMu, or a failed sync, does not wait for the
	// periodic re-read five minutes later.
	_, readyErr := os.Stat(s.ksb.readyPath())
	if hook {
		s.ksb.owed.Store(true)
	}
	// A set that stays unreadable keeps owed (or the stamp absent) for good, which would make every
	// 5 s tick a full re-read (rule list, WAN probe, every route of every table). After
	// ksUnreadBackoffAfter such syncs in a row the owed re-read waits for every ksUnreadBackoffEvery-th
	// tick; a hook run still re-reads at once.
	poll := s.ksb.polls.Add(1)
	owedNow := s.ksb.owed.Load() || readyErr != nil
	if owedNow && s.ksb.unreadStreak.Load() >= ksUnreadBackoffAfter && poll%ksUnreadBackoffEvery != 0 {
		owedNow = false
	}
	fromKernel := hook || owedNow || (poll-1)%ksMirrorResync == 0
	doSync := bs.Active() && (len(bs.Sets4)+len(bs.Sets6) > 0 || fromKernel)
	tickCtx, cancel := context.WithTimeout(ctx, ksMirrorInterval*2)
	defer cancel()
	var read ksMembers
	if doSync {
		reader := s.ksb.reader
		if reader == nil {
			reader = func(a executionKernelIpsetArtifactV1) ksMembers {
				adapter, err := newExactKeeneticKernelAdapter(a)
				if err != nil {
					return func(context.Context, string) ([]netip.Prefix, error) { return nil, err }
				}
				return ipsetMembers(adapter)
			}
		}
		read = ksPreRead(tickCtx, bs, reader(*k.Ipset))
	}
	// Under applyMu, and only if the plane read above is still the one installed: a tick working from
	// the previous baseline while an Apply installs the next one could take away routes the new plane
	// has just put in before its rules.
	if !s.applyMu.TryLock() {
		return
	}
	defer s.applyMu.Unlock()
	if now := s.kernelBaseline(); now == nil || now.Plan != k.Plan || string(now.Ipset.Script) != string(k.Ipset.Script) {
		return
	}
	s.hok.tick(ctx, k.Plan, *k.Ipset)
	if fromKernel {
		// A rebuild is when NDM adds a new policy's rules: the place is re-derived then.
		s.keepBackstopAhead(ctx, k.Plan, *k.Ipset)
		s.reprobeWAN(k.Ipset.WANIface)
	}
	s.coverNewIfaces(ctx, k.Plan, *k.Ipset)
	if !doSync {
		// Static routes only: the Apply installed them; re-read now and then. This still services an
		// owed lift delete and notices a hook-side lift on every tick, even during unread backoff.
		// A skipped sync must not turn an earlier hard failure into the earlier successful-sync lift.
		if s.ksb.syncFailed.Load() {
			s.ksDaemonLiftAfterFailedSync(k.Plan, *k.Ipset)
		} else {
			s.ksDaemonLift(k.Plan, *k.Ipset)
		}
		return
	}
	err := s.ksb.sync(tickCtx, k.Plan, keeneticKillSwitchOptions(*k.Ipset), read, ksBackstopMax(s.config()), false, fromKernel)
	if err != nil {
		log.Printf("kill switch backstop: %v", err)
		s.ksb.owed.Store(true)
		s.ksb.syncFailed.Store(true)
		s.ksb.unreadStreak.Add(1)
		// The first grace is left to the hook; the daemon adds its own hard bound. An
		// already-owed delete is retried here without waiting for the next successful sync.
		s.ksDaemonLiftAfterFailedSync(k.Plan, *k.Ipset)
		return
	}
	// Only a sync that returned nil proves the narrow routes are in. A failed table read or route
	// add takes the error path above, which keeps the broad hold until BootHoldLift+grace.
	s.ksb.syncFailed.Store(false)
	s.ksDaemonLift(k.Plan, *k.Ipset)
	// The owed re-read is settled only after a sync that worked and read every set.
	unread := s.ksb.unread.Load()
	s.ksb.owed.Store(unread)
	if unread {
		s.ksb.unreadStreak.Add(1)
	} else {
		s.ksb.unreadStreak.Store(0)
	}
	if !unread {
		// What the sets hold now, for the boot after the next reboot: marks the writer
		// only on a change; it writes at most hourly.
		s.noteLearned(append(append([]string(nil), bs.Sets4...), bs.Sets6...), read)
	}
}
