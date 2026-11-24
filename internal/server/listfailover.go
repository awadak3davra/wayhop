package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"wayhop/internal/failover"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// listfailover.go makes a failover group mean something for ROUTING LISTS on the kernel plane.
//
// What the kernel plane installs on KeeneticOS, for example:
//
//	ip rule 150: from all fwmark 0x20000/0xff0000 lookup 151
//	table 151:   default dev nwg3
//
// Table 151 is WayHop's alone — no other interface has it and no other rule looks at it — and Apply
// writes it once, pinned to the group's elected member. Without an owner nothing re-points it: the
// group's other members sit idle while every list rides nwg3, and if nwg3 drops, the kernel flushes
// that route, the fwmark lookup finds an empty table and falls through to main — so the censored
// destinations the list exists for leave through the PROVIDER. That is a leak dressed as a failover.
//
// The plane's own renderer anticipates an owner for this: it seeds the table with `ip route add`
// rather than `replace` specifically so it cannot clobber "the 1-min failover cron's elected live
// egress". The router has no such cron (no /opt/etc/crontabs, no cron.d). This is that owner, in the
// daemon, where the health it needs already lives.
//
// Scope, deliberately narrow. It writes ONE command shape, `ip [-6] route replace default dev <iface>
// table <N>`, and only when all of the following hold: the table belongs to an egress the APPLIED
// kernel plan owns, the egress is a GROUP, and the interface is one of that group's own members.
// It never touches the main table, never the WAN, never a table the plan does not name. Anything
// wider belongs to Apply.

const (
	listFailoverInterval = 20 * time.Second
	listFailoverTimeout  = 6 * time.Second
	// listFailoverLockedPass bounds the pass that holds applyMu; it must stay well under applyLockWait.
	listFailoverLockedPass = 10 * time.Second
)

// listFailoverLoop re-points each group-backed list table at a healthy member.
func (s *Server) listFailoverLoop(ctx context.Context) {
	ticker := time.NewTicker(listFailoverInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.listFailoverTick(ctx)
	}
}

// listFailoverTick is one pass. Silent when nothing needs to move, which is the normal case.
func (s *Server) listFailoverTick(ctx context.Context) {
	// The demo runs nothing on the host.
	if s == nil || s.store == nil || s.monitor == nil || s.config().Demo {
		return
	}
	// Routing switched off: the tables this loop points are consulted by nothing, and a default
	// written into one now would be waiting there, chosen by nobody, when routing comes back.
	if s.routingIsOff() {
		return
	}
	// The one precondition that is really about this loop: it writes with iproute2, so iproute2 has to
	// be there.
	//
	// It does not require ipset AND iptables: that is a Keenetic-shaped question that answers "no"
	// on modern OpenWrt, which carries nftables and often no iptables binary at all. A routing list
	// backed by a native group on OpenWrt would then have no owner: the table would stay pinned to
	// whichever member Apply chose, and when that member died the fwmark lookup would find an empty
	// table and fall through to the provider, the exact leak this file exists to close.
	//
	// "Two owners for one decision" is still guarded, structurally rather than by platform:
	// listFailoverTables only yields a table that the APPLIED kernel plan owns for a GROUP egress of
	// kind EgressInterface. A group the core carries produces no such egress, so there is nothing
	// here to fight the core over.
	if s.routeTables == nil && !iprouteAvailable() {
		return
	}
	// The whole pass stands aside while an Apply runs and holds applyMu like the reconcile loop: Apply
	// renumbers the tables, and a pass that read the plan before it and wrote after it would put a
	// member's route into a table the new plan gave another egress, or a route back into a table
	// Apply is retiring, where it would outlive the plan.
	if s.applyInProgress.Load() {
		return
	}
	// The probes run BEFORE the lock: a cycle of handshakes through every candidate can take seconds,
	// and holding applyMu for them would turn an Apply from the panel into "another Apply is still
	// running". They read the plan only to know what to measure; the election below re-reads it under
	// the lock, and a unit the probes did not cover falls back to the monitor's verdict.
	probes, fresh := s.probeKernelUnits(ctx)
	// A list cycle that measured but never reached the election (an Apply held the lock, the tables
	// could not be read) is asked again for the next tick, so "probe now" and dead-after still count
	// cycles that were decided, not cycles that were only measured.
	decided := false
	defer func() {
		if !decided {
			s.fastestRetry(fresh)
		}
	}()
	if s.applyInProgress.Load() || !s.applyMu.TryLock() {
		return
	}
	defer s.applyMu.Unlock()
	// One deadline for the whole locked pass, well under applyLockWait: each ip read or write may take
	// several seconds on a wedged router, and two v6 group tables kept the lock long enough for an Apply
	// from the panel or the bot to give up with "another Apply is still running".
	ctx, cancel := context.WithTimeout(ctx, listFailoverLockedPass)
	defer cancel()
	// Re-read under the lock: the routing switch holds applyMu while it turns routing off, so a pass
	// that passed the check above just before it may only now get the lock.
	if s.routingIsOff() {
		return
	}
	// The tables the router holds are numbered by the APPLIED plan, not the saved profile. Recompiling
	// the saved profile here elected by the wrong numbers whenever an edit was pending: an unapplied
	// list through an endpoint that sorts before the group renumbered the group into another egress's
	// table, the pass wrote the group's member into it, and the group's real table went unwatched, so
	// its list fell through to the provider when the member died.
	plan, profile := s.supervisedKernelPlan()
	if plan == nil {
		return
	}
	io := s.tableIO()
	// One read per family serves both halves below, and a table that could not be read is not an
	// empty one. Treated as empty, every group's table looked unpointed and was written on every tick,
	// and every endpoint's table would look like it had lost its route. v4 is the pass's footing; v6 is
	// read only where the plane seeds `ip -6 route … table N` next to each v4 one, and a v6 family that
	// cannot be read is left alone.
	live4, ok := s.liveTableDefaults(ctx, false)
	if !ok {
		return
	}
	live := map[bool]map[int]string{false: live4}
	if plan.HasV6() {
		if live6, ok := s.liveTableDefaults(ctx, true); ok {
			live[true] = live6
		}
	}
	// The election itself: internal/failover decides per unit (a table with its candidates and probe
	// targets) by the group's own policy — urltest the fastest working member, fallback the first
	// working one in order, selector the pick while it works — with the deadband, min-dwell and
	// failback hold of the core-side runner. "First member that the monitor calls alive" for every
	// type would keep a urltest group on its first member forever, even while that member answers
	// its own ping target and drops the traffic routed into it.
	//
	// Both kernel planes: KeeneticOS's ipset plane and OpenWrt's nft one route a group through one
	// table with one `default dev`, and the same order-first election had the same urltest gap on
	// OpenWrt. legacyListFailover stays only for a record that names no kernel plan of either kind,
	// which supervisedKernelPlan above already refused.
	if !s.kernelElectionPlatform() {
		s.legacyListFailover(ctx, plan, profile, io, live)
		s.restoreLostTableRoutes(ctx, plan, profile, live)
		return
	}
	ifaceOf := kernelIfaceByEndpoint(profile, s.appliedKernelDevices())
	units := kernelUnitsFrom(plan, profile, ifaceOf)
	// A fastest list's unit is handed in on every tick (the elector forgets a unit it is not given)
	// but decides only on its own measurement cycle (fresh).
	now := time.Now().UnixMilli()
	units = append(units, s.fastestUnits(plan, profile, ifaceOf, fresh, now)...)
	s.attachThroughput(units) // the last successful samples, for the units that elect by them
	routes := &kernelTableRoutes{s: s, ctx: ctx, io: io, live: live}
	elector := s.kernelElector()
	evs := elector.Tick(units, s.fastestMerge(probes), s.monitor, routes, now)
	decided = true
	s.onFastestEvents(units, evs, plan, profile)
	if len(fresh) > 0 {
		s.rotateFastestTargets(elector.States())
	}
	s.persistFastestJournal(elector)
	for _, ev := range evs {
		if !ev.Wrote {
			continue // adopted what the table already held: nothing moved
		}
		if _, isList := model.ListEgressID(ev.Key.Owner); isList {
			continue // told by onFastestEvents
		}
		u := unitByTable(units, ev)
		log.Printf("list failover: %s (table %d) %s -> %s: %s (%s)", u.Name, u.Key.Table, orNone(ev.FromIface), ev.ToIface, ev.Reason, ev.Detail)
		s.monitor.RecordSwitch(u.Group, u.Name, orNone(ev.FromIface), ev.ToIface)
	}
	// Both families follow one election. Moving only v4 left marked v6 on the dead member: into the
	// dead tunnel while its device was up, out the WAN once the kernel flushed the route, and still out
	// the WAN after the member came back, because nothing re-seeded a group's v6 table.
	routes.syncV6(units)
	s.restoreLostTableRoutes(ctx, plan, profile, live)
}

// supervisedKernelPlan is the kernel plan the router holds, with the profile it was compiled from:
// the supervised baseline's, which the reconcile loop keeps installed. After a rollback that failed
// part way that is the committed one, and acting on the Test's tables would route by the plan the
// rollback was undoing. nil when no kernel plane is installed or the record cannot say what it was
// compiled from. Callers that act on it hold applyMu, as the reconcile loop does.
func (s *Server) supervisedKernelPlan() (*pbr.Plan, *model.Profile) {
	base := s.supervisedBaseline()
	if base == nil || base.Desired == nil || !base.Materialization.known() {
		return nil, nil
	}
	plan := base.Materialization.kernelPlan()
	if plan == nil {
		return nil, nil
	}
	return plan, &base.Desired.Profile
}

// A single-endpoint egress has nothing to elect between, so the loop above leaves it alone. Its device
// does not outlive everything, though: WayHop's userspace AmneziaWG recreates its TUN every time the supervisor relaunches amneziawg-go,
// and a tunnel the firmware bounces goes down with its routes. The kernel drops every route through
// a device that disappears or goes down, so the table's `default dev <iface>` vanishes and the
// fwmark lookup falls through to main - the provider - or, under a kill switch, into the blackhole,
// until the next Apply. Nothing else puts it back: Apply ran before the relaunch, the netfilter.d
// hook and the reconcile loop re-assert sets and rules (their postchecks do not look at routes), and
// the seed in the plane's own script only runs when the plane is installed.
//
// restoreLostTableRoutes is that re-seed, as narrow as the rest of this file. The table must belong
// to an interface egress of the APPLIED kernel plan - not the saved profile: its table numbers are
// the ones the router holds, and a pending edit can number them differently. It must have lost its
// device route outright; a route to another device was put there by someone and is left alone. The
// device must exist and be up again. It runs inside listFailoverTick's pass, which holds applyMu and
// stands aside while an Apply runs: Apply may be retiring that very table, and a route put back into
// it would outlive the plan. live holds each family the pass read; one it could not read is skipped,
// because unread is not empty and restoring on an unknown would re-seed routes that are there.
func (s *Server) restoreLostTableRoutes(ctx context.Context, plan *pbr.Plan, profile *model.Profile, live map[bool]map[int]string) {
	io := s.tableIO()
	restored := false
	for _, v6 := range []bool{false, true} {
		tables, read := live[v6]
		if !read {
			continue
		}
		for _, lost := range lostTableRoutes(plan, profile, tables, io.up) {
			if v6 && !io.carriesIPv6(lost.Iface) {
				s.noteTableV6Refused(lost, io.refuseV6(ctx, lost.Table))
				continue
			}
			err := io.write(ctx, v6, lost.Iface, lost.Table)
			s.noteTableRestore(v6, lost, err)
			restored = restored || err == nil
		}
	}
	// The device came back: the large lists' routes through it went with it (fastdns_routed.go).
	if restored {
		if err := s.syncRoutedTables(ctx, plan); err != nil {
			log.Printf("fast path: %v", err)
		}
	}
}

// tableRestore is a routing table that lost its device route, and the device to put back.
type tableRestore struct {
	Table int
	Iface string
}

// lostTableRoutes is the rule itself, apart from the router so it can be asserted directly: every
// interface egress of plan that belongs to one endpoint (a group's is the election's), whose table
// holds no device route now, and whose device is up.
func lostTableRoutes(plan *pbr.Plan, profile *model.Profile, live map[int]string, up func(string) bool) []tableRestore {
	var out []tableRestore
	for _, egress := range plan.Egresses {
		if egress.Kind != pbr.EgressInterface || egress.Table == 0 || egress.Iface == "" {
			continue
		}
		if profile.GroupByID(egress.Tag) != nil {
			continue // re-pointed from health by the loop above
		}
		if _, ok := model.ListEgressID(egress.Tag); ok {
			continue // a fastest list's table: the elector owns it, and may have emptied it on purpose
		}
		if live[egress.Table] != "" {
			continue // there, or pointing where someone else put it
		}
		if !up(egress.Iface) {
			continue // not back yet; the next tick looks again
		}
		out = append(out, tableRestore{Table: egress.Table, Iface: egress.Iface})
	}
	return out
}

// noteTableRestore logs a restored route every time - it marks a device that went away, which is
// worth a line - and a refusal only when it changes, so a device that keeps failing does not fill
// the router's bounded log.
func (s *Server) noteTableRestore(v6 bool, lost tableRestore, err error) {
	family := "IPv4"
	if v6 {
		family = "IPv6"
	}
	key := fmt.Sprintf("%s/%d", family, lost.Table)
	s.listFailoverErrMu.Lock()
	defer s.listFailoverErrMu.Unlock()
	if s.tableRestoreErr == nil {
		s.tableRestoreErr = map[string]string{}
	}
	if err == nil {
		delete(s.tableRestoreErr, key)
		log.Printf("list routing: table %d lost its %s route through %s (the device went away or down); restored", lost.Table, family, lost.Iface)
		return
	}
	if msg := err.Error(); s.tableRestoreErr[key] != msg {
		s.tableRestoreErr[key] = msg
		log.Printf("list routing: cannot restore table %d's %s route through %s, so its list has no exit: %v", lost.Table, family, lost.Iface, err)
	}
}

// noteTableV6Refused logs, once per change like noteTableRestore and under the same key, that a
// table's IPv6 is refused because its device carries none, or that refusing it failed.
func (s *Server) noteTableV6Refused(lost tableRestore, err error) {
	key := fmt.Sprintf("IPv6/%d", lost.Table)
	msg := "refused: no IPv6 on " + lost.Iface
	if err != nil {
		msg = err.Error()
	}
	s.listFailoverErrMu.Lock()
	defer s.listFailoverErrMu.Unlock()
	if s.tableRestoreErr == nil {
		s.tableRestoreErr = map[string]string{}
	}
	if s.tableRestoreErr[key] == msg {
		return
	}
	s.tableRestoreErr[key] = msg
	if err != nil {
		log.Printf("list routing: %s carries no IPv6 and table %d could not be told to refuse it, so its list's IPv6 may leave by another exit: %v", lost.Iface, lost.Table, err)
		return
	}
	log.Printf("list routing: %s carries no IPv6, so table %d answers IPv6 with unreachable and its list's clients use IPv4 through %s", lost.Iface, lost.Table, lost.Iface)
}

// routeTableIO is how the list-routing loop reads and writes table defaults and asks whether a
// device is up: iproute2 and the kernel's own interface list in production, a fake in tests.
type routeTableIO struct {
	read  func(ctx context.Context, v6 bool) (string, error)
	write func(ctx context.Context, v6 bool, iface string, table int) error
	up    func(iface string) bool
	// v6 says whether a device can hold an IPv6 route at all, and refuse installs the route that
	// answers "unreachable" in its place. A nil v6 means every device can.
	v6     func(iface string) bool
	refuse func(ctx context.Context, table int) error
	// clear removes a table's device default (a fastest list whose candidates are all down). nil
	// leaves such a table as it is.
	clear func(ctx context.Context, v6 bool, iface string, table int) error
	// probe measures the elector's (link, target) pairs. nil measures nothing, and every candidate
	// then stands on the monitor's verdict.
	probe func(ctx context.Context, keys []failover.ProbeKey) map[failover.ProbeKey]failover.ProbeResult
}

func (io routeTableIO) carriesIPv6(iface string) bool { return io.v6 == nil || io.v6(iface) }

func (io routeTableIO) refuseV6(ctx context.Context, table int) error {
	if io.refuse == nil {
		return errors.New("no way to refuse IPv6 here")
	}
	return io.refuse(ctx, table)
}

func (s *Server) tableIO() routeTableIO {
	if s.routeTables != nil {
		return *s.routeTables
	}
	return routeTableIO{read: readTableRoutes, write: writeTableDefault, up: linkIsUp, v6: linkCarriesIPv6, refuse: writeTableUnreachableV6, probe: s.probeUnitTargets, clear: clearTableDefault}
}

// clearTableDefault removes `default dev <iface>` from a table. A kill switch's blackhole (its own
// metric) stays, which is what on_all_down "block" relies on.
func clearTableDefault(ctx context.Context, v6 bool, iface string, table int) error {
	if iface == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, listFailoverTimeout)
	defer cancel()
	_, err := runHostCommandBounded(ctx, listFailoverTimeout, kernelCounterOutputLimit,
		applyHostCommandWaitDelay, "ip", familyArgs(v6, "route", "del", "default", "dev", iface, "table", fmt.Sprint(table))...)
	return err
}

// ipv6ConfDir is the kernel's per-device IPv6 settings; a variable so a test can stand in for it.
var ipv6ConfDir = "/proc/sys/net/ipv6/conf"

// linkCarriesIPv6 is false for a device the kernel set up no IPv6 for. On KeeneticOS that is
// amneziawg-go's awg1: it has no /proc/sys/net/ipv6/conf/awg1, every `ip -6 route … dev awg1` fails,
// and the list's v6 table stayed empty, so its marked IPv6 fell through to the main table and left by
// whatever tunnel held the v6 default there (another provider's WireGuard, on a Keenetic) - a list exit
// nobody chose. A kernel with no IPv6 config at all says nothing either way: true keeps the write.
func linkCarriesIPv6(name string) bool {
	if name == "" || strings.ContainsAny(name, "/") || name == "." || name == ".." {
		return true
	}
	if _, err := os.Stat(filepath.Join(ipv6ConfDir, "all")); err != nil {
		return true
	}
	b, err := os.ReadFile(filepath.Join(ipv6ConfDir, name, "disable_ipv6"))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) != "1"
}

// writeTableUnreachableV6 makes a table answer IPv6 with "no route", so a client gives up on IPv6 at
// once and uses IPv4, which this table's device does carry. It takes the device route's own slot
// (metric 1024, no metric given): the restore's `replace default dev` takes it back the moment the
// device gains IPv6, and the kill switch's blackhole sits below at its own metric, untouched.
func writeTableUnreachableV6(ctx context.Context, table int) error {
	ctx, cancel := context.WithTimeout(ctx, listFailoverTimeout)
	defer cancel()
	_, err := runHostCommandBounded(ctx, listFailoverTimeout, kernelCounterOutputLimit,
		applyHostCommandWaitDelay, "ip", familyArgs(true, "route", "replace", "unreachable", "default", "table", fmt.Sprint(table))...)
	return err
}

func readTableRoutes(ctx context.Context, v6 bool) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, listFailoverTimeout)
	defer cancel()
	return runHostCommandBounded(ctx, listFailoverTimeout, kernelCounterOutputLimit,
		applyHostCommandWaitDelay, "ip", familyArgs(v6, "route", "show", "table", "all")...)
}

func writeTableDefault(ctx context.Context, v6 bool, iface string, table int) error {
	ctx, cancel := context.WithTimeout(ctx, listFailoverTimeout)
	defer cancel()
	_, err := runHostCommandBounded(ctx, listFailoverTimeout, kernelCounterOutputLimit,
		applyHostCommandWaitDelay, "ip", familyArgs(v6, "route", "replace", "default", "dev", iface, "table", fmt.Sprint(table))...)
	return err
}

func familyArgs(v6 bool, args ...string) []string {
	if v6 {
		return append([]string{"-6"}, args...)
	}
	// The IPv4 side names its family too. BusyBox's `ip route show table all` lists the IPv6 routes
	// as well, and parseTableDefaults keeps the last line per table: on a Keenetic the v6 default
	// still on the group's first member overwrote the v4 one an outage had moved to the second, so
	// the loop read the table as already fine and never moved it back.
	return append([]string{"-4"}, args...)
}

// linkIsUp reports a device that exists and is administratively up - what a `dev` route needs.
func linkIsUp(name string) bool {
	iface, err := net.InterfaceByName(name)
	return err == nil && iface.Flags&net.FlagUp != 0
}

// kernelElectableMembers reports, per GROUP whose routing lists the KERNEL carries, which members
// that plane can actually route to.
//
// A group can mix a native tunnel with one an engine carries — an OpenWrt router has exactly
// that: group-failover is [tunnel-a (kernel link awg1), proxy-member (socks, sing-box)]. The Failover
// card counted both and printed "2 exits deep", a depth guarantee. For the four routing lists riding
// that group, one of which the kernel carries, the real depth is ONE: electMember skips a member
// with no kernel link, so when awg1 dies there is no candidate, the table keeps a route through a
// dead interface, and the fwmark lookup falls through to main — the provider. The card promised a
// second exit that the plane it belongs to cannot use.
//
// Computed from CAPABILITY, never from health: engine kind does not change while a tunnel is down,
// and a card that redraws its guarantee every time a member blinks teaches nobody anything. This is
// the same reasoning downloadPathChoices already applies to the download path.
//
// A group absent from this map is one the kernel plane does not route, so its members are whatever
// the core can reach and the ordinary count is honest. A group present with an EMPTY list is the
// worst case and is deliberately reported rather than omitted: its table exists and nothing can be
// elected into it at all.
func (s *Server) kernelElectableMembers() map[string][]string {
	if s == nil || s.store == nil {
		return nil
	}
	profile := s.store.Profile()
	plan, _, err := pbr.Compile(&profile, s.pbrCompileOptions(s.config()))
	if err != nil || plan == nil {
		return nil
	}
	ifaceOf := kernelIfaceByEndpoint(&profile, s.appliedKernelDevices())
	out := map[string][]string{}
	for _, egress := range plan.Egresses {
		if egress.Kind != pbr.EgressInterface || egress.Table == 0 {
			continue
		}
		group := profile.GroupByID(egress.Tag)
		if group == nil {
			continue // an endpoint egress has one interface and nothing to elect between
		}
		if _, seen := out[group.ID]; seen {
			continue
		}
		members := make([]string, 0, len(group.Members))
		for _, id := range group.Members {
			if ifaceOf[id] != "" {
				members = append(members, id)
			}
		}
		out[group.ID] = members
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// noteListFailoverWrite logs a table's write outcome only when it CHANGES, so a persistent refusal is
// visible without filling the router's bounded log with one line every tick. Kept per family: a
// table's v6 default can be refused while its v4 one is written, and one key for both would log that
// pair as a refusal and a recovery on every tick.
func (s *Server) noteListFailoverWrite(v6 bool, table int, err error) {
	family := "IPv4"
	if v6 {
		family = "IPv6"
	}
	key := fmt.Sprintf("%s/%d", family, table)
	s.listFailoverErrMu.Lock()
	defer s.listFailoverErrMu.Unlock()
	if s.listFailoverErr == nil {
		s.listFailoverErr = map[string]string{}
	}
	prev, had := s.listFailoverErr[key]
	if err == nil {
		if had {
			delete(s.listFailoverErr, key)
			log.Printf("list failover: table %d is writable again (%s)", table, family)
		}
		return
	}
	if msg := err.Error(); !had || msg != prev {
		s.listFailoverErr[key] = msg
		log.Printf("list failover: cannot repoint table %d (%s), so its list keeps the exit it has: %v", table, family, err)
	}
}

// iprouteAvailable reports whether the tool this loop writes with exists. Cached: the answer cannot
// change while the daemon runs, and this is asked on every tick.
var iprouteOnce struct {
	sync.Once
	ok bool
}

func iprouteAvailable() bool {
	iprouteOnce.Do(func() {
		_, err := exec.LookPath("ip")
		iprouteOnce.ok = err == nil
	})
	return iprouteOnce.ok
}

// legacyListFailover is the election the loop made before the kernel elector: first member the
// monitor calls alive, in the operator's order, for every group type, switched at once. The elector
// runs on both kernel planes, so the tick does not reach this while a plan is applied; it remains
// as the fallback.
func (s *Server) legacyListFailover(ctx context.Context, plan *pbr.Plan, profile *model.Profile, io routeTableIO, live map[bool]map[int]string) {
	for _, target := range s.listFailoverTargetsFrom(plan, profile, live[false]) {
		for _, v6 := range []bool{false, true} {
			tables, read := live[v6]
			if !read || tables[target.Table] == target.Elected {
				continue
			}
			if v6 && !io.carriesIPv6(target.Elected) {
				s.noteTableV6Refused(tableRestore{Table: target.Table, Iface: target.Elected}, io.refuseV6(ctx, target.Table))
				continue
			}
			err := io.write(ctx, v6, target.Elected, target.Table)
			s.noteListFailoverWrite(v6, target.Table, err)
			if err == nil && !v6 {
				s.monitor.RecordSwitch(target.Group, target.Name, orNone(target.Current), target.Elected)
			}
		}
	}
}

// listFailoverTarget is one table the legacy election may write, with the interface it holds now and
// the one health says it should hold.
type listFailoverTarget struct {
	Group   string
	Name    string
	Table   int
	Current string
	Elected string
}

// listFailoverTargetsFrom pairs the applied kernel plan, and the profile it was compiled from, with
// live health, by the legacy rule (electMember). endpoint id → kernel link goes through the COMPILER's
// own resolver: a list routed through a group uses the GROUP tag, so the plan's egresses alone name no
// member at all.
func (s *Server) listFailoverTargetsFrom(plan *pbr.Plan, profile *model.Profile, live map[int]string) []listFailoverTarget {
	ifaceOf := kernelIfaceByEndpoint(profile, s.appliedKernelDevices())
	var out []listFailoverTarget
	for _, owned := range listFailoverTables(plan, profile, ifaceOf) {
		elected, ok := s.electHealthyMember(owned.Group, ifaceOf)
		if !ok {
			continue
		}
		out = append(out, listFailoverTarget{
			Group: owned.Group.ID, Name: owned.Group.Name, Table: owned.Table,
			Current: live[owned.Table], Elected: elected,
		})
	}
	return out
}

// listFailoverTable is a routing table this loop owns: a group egress's table, with the group and the
// link the applied plan pinned it to.
type listFailoverTable struct {
	Group model.Group
	Table int
	Iface string
}

// listFailoverTables is what this loop CAN re-point, whatever health says: each interface egress of
// plan that is a GROUP with at least one member the kernel can route to. The loop elects among these
// on every tick, and the Failover page's "switches by itself" (selfSwitchingGroups) is this same list.
// Built from the election instead, that answer dropped a group exactly while all its members were
// down or not yet measured, telling the operator the group does not switch by itself while the loop
// stood ready to re-point it the moment a member came back.
func listFailoverTables(plan *pbr.Plan, profile *model.Profile, ifaceOf map[string]string) []listFailoverTable {
	var out []listFailoverTable
	for _, egress := range plan.Egresses {
		if egress.Kind != pbr.EgressInterface || egress.Table == 0 {
			continue
		}
		group := profile.GroupByID(egress.Tag)
		if group == nil {
			continue // an endpoint egress has one interface and nothing to elect between
		}
		for _, id := range group.Members {
			if ifaceOf[id] != "" {
				out = append(out, listFailoverTable{Group: *group, Table: egress.Table, Iface: egress.Iface})
				break
			}
		}
	}
	return out
}

// electHealthyMember asks the monitor which members are alive and applies the rule below.
func (s *Server) electHealthyMember(group model.Group, ifaceOf map[string]string) (string, bool) {
	if len(group.Members) == 0 {
		return "", false
	}
	alive := make(map[string]bool, len(group.Members))
	if s.monitor != nil { // no monitor, nothing known alive
		for _, h := range s.monitor.MemberHealth(group.Members) {
			alive[h.ID] = h.Alive
		}
	}
	return electMember(group, ifaceOf, alive)
}

// kernelIfaceByEndpoint maps each endpoint to the kernel link it binds to, through the COMPILER's own
// resolver, skipping the ones that have none — a proxy endpoint is carried by an engine, not a link.
// devices is the router's own naming (Server.appliedKernelDevices): on KeeneticOS a tunnel NDM created
// is NDM's nwgN, not the wr_* name derived for WayHop's own devices, and electing the derived name
// writes `ip route replace default dev wr_… table N`, which the kernel refuses.
//
// One definition because two callers elect over it: this loop, which repoints a routing list's table
// at a healthy member, and the component downloader, which binds its socket to one. They were the
// same fold written twice, and a second copy is a second answer to "which link is this endpoint" the
// day one of them learns about a new engine kind.
func kernelIfaceByEndpoint(p *model.Profile, devices map[string]string) map[string]string {
	out := make(map[string]string, len(p.Endpoints))
	for i := range p.Endpoints {
		e := &p.Endpoints[i]
		if iface := pbr.KernelDevice(e, devices); iface != "" {
			out[e.ID] = iface
		}
	}
	return out
}

// electMember is the rule itself, kept apart from the monitor so it can be asserted directly rather
// than through a live health source: the operator's ORDER, first healthy member wins — the same
// semantics the Failover page states for a native group and the same one Apply pins the table with.
//
// A member the plan cannot route has no interface and is not a candidate however healthy it looks.
// Everything down elects NOTHING: moving to another dead member is churn, and turning the resulting
// leak into a drop is Apply's decision (the fail-closed blackhole), not this loop's.
func electMember(group model.Group, ifaceOf map[string]string, alive map[string]bool) (string, bool) {
	for _, id := range group.Members {
		if !alive[id] {
			continue
		}
		if iface := ifaceOf[id]; iface != "" {
			return iface, true
		}
	}
	return "", false
}

// liveTableDefaults reads which interface each routing table of one family currently defaults to, so
// the loop writes only on a real change. ok is false when the tables could not be read at all: the
// caller must then write nothing, because an unknown table is not an empty one.
func (s *Server) liveTableDefaults(ctx context.Context, v6 bool) (map[int]string, bool) {
	text, err := s.tableIO().read(ctx, v6)
	if err != nil {
		return nil, false
	}
	return parseTableDefaults(text), true
}

// parseTableDefaults picks `default dev <iface> ... table <N>` lines out of `ip route show table all`.
// Only the metric-0 device route counts: the fail-closed blackhole and any via-gateway default belong
// to different questions.
func parseTableDefaults(text string) map[int]string {
	out := map[int]string{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "default" || fields[1] != "dev" {
			continue
		}
		iface := fields[2]
		table := 0
		for i := 3; i+1 < len(fields); i++ {
			if fields[i] == "table" {
				if _, err := fmt.Sscanf(fields[i+1], "%d", &table); err != nil {
					table = 0 // an unparsable value is not a table; the caller skips 0
				}
				break
			}
		}
		if table != 0 && iface != "" {
			out[table] = iface
		}
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
