package server

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wayhop/internal/failover"
	"wayhop/internal/model"
	"wayhop/internal/netdiag"
	"wayhop/internal/pbr"
)

// kernelelect.go feeds the kernel plane's runtime election (failover.TableElector): which tables it
// owns and what each is judged against (units), what the candidates measured (probes), and the one
// write it may make (`ip [-6] route replace default dev <iface> table <N>`, through tableIO).
//
// Why the plan stays valid when the elector moves a table: the applied plan fixes a group's TABLE, its
// MARK and its ip rule, and those are what the reconcile loop and the postchecks read back (sets,
// mangle rules, ip rules — see keeneticPlanePostcheck; on OpenWrt the nft proof set alone, see
// exactKernelAdapter.postcheck). The member inside the table is not part of that verification. A
// re-install never puts the compile-time pin back over an elected member either: KeeneticOS's install
// script seeds a table with `ip route add … || true`, and OpenWrt's `route replace` seed is skipped
// for a table that still holds the elected link (kernelkeep.go). The rule for the table's content is
// failover.TableUnit.Accepts: any candidate of the unit, nothing else.

const (
	// The cycle's handshake budget. Three attempts per (link, target), each bounded, at most eight
	// in flight across every unit, so eleven lists over five tunnels stay a background trickle.
	unitProbeAttempts    = 3
	unitProbeTimeout     = 3 * time.Second
	unitProbeConcurrency = 8
	unitProbeCycle       = 15 * time.Second
	unitResolveTimeout   = 3 * time.Second
)

// defaultUnitProbeURL is what a group without its own test URL is judged against: the same target the
// health monitor and the generated sing-box urltest use.
const defaultUnitProbeURL = "http://cp.cloudflare.com/generate_204"

// kernelElectionPlatform reports whether the router holds a kernel plane whose tables the elector
// owns: any applied plan, KeeneticOS's ipset plane or OpenWrt's nft one. Both route a group or a
// fastest list through one table with one `default dev`, and neither plane's postcheck reads that
// route (keeneticPlanePostcheck: sets, mangle rules, ip rules; exactKernelAdapter.postcheck: the nft
// proof set).
func (s *Server) kernelElectionPlatform() bool {
	base := s.supervisedBaseline()
	return base != nil && base.Materialization.kernelPlan() != nil
}

// engineRedirectPlane reports the plane whose host runs the proxy core's transparent redirect over
// the router's own connections: OpenWrt's (the nft artifact). The elector's handshakes carry the
// core's bypass mark there (unitProbeMark), and nowhere else, so KeeneticOS's probes stay as they were.
func (s *Server) engineRedirectPlane() bool {
	base := s.supervisedBaseline()
	return base != nil && base.Materialization.kernelPlan() != nil && base.Materialization.Kernel.Ipset == nil
}

// unitProbeMark is the fwmark of the elector's probe sockets: engineBypassMark on OpenWrt, none on
// KeeneticOS.
func (s *Server) unitProbeMark() int {
	if s.engineRedirectPlane() {
		return engineBypassMark
	}
	return 0
}

func (s *Server) kernelElector() *failover.TableElector {
	s.unitElectorOnce.Do(func() {
		s.unitElector = failover.NewTableElector()
		s.initFastestJournal(s.unitElector)
	})
	return s.unitElector
}

// kernelUnitsFrom is the group producer of units: one per table the applied plan gave a group whose
// members the kernel can route to. Its candidates are the group's members, its target the group's test
// URL. A later producer (a routing list with its own table and destinations) adds units beside these.
func kernelUnitsFrom(plan *pbr.Plan, profile *model.Profile, ifaceOf map[string]string) []failover.TableUnit {
	if plan == nil || profile == nil {
		return nil
	}
	var out []failover.TableUnit
	for _, owned := range listFailoverTables(plan, profile, ifaceOf) {
		g := owned.Group
		iface := make(map[string]string, len(g.Members))
		pick := ""
		for _, m := range g.Members {
			if link := ifaceOf[m]; link != "" {
				iface[m] = link
				if pick == "" || (link == owned.Iface && iface[pick] != owned.Iface) {
					pick = m // the member the applied plan pinned, else the first routable one
				}
			}
		}
		u := failover.TableUnit{
			Key:        failover.UnitKey{Owner: "group:" + g.ID, Table: owned.Table},
			Name:       g.Name,
			Group:      g.ID,
			Policy:     groupPolicy(g.Type),
			Candidates: append([]string(nil), g.Members...),
			Iface:      iface,
			Targets:    []string{groupProbeTarget(g)},
		}
		if g.Type == model.GroupURLTest {
			u.Policy = electionPolicy(g.Election())
		}
		if u.Policy == failover.PolicySelector {
			u.Pick = pick
		}
		if g.Test != nil && g.Test.Tolerance > 0 {
			u.Cfg.ToleranceMs = g.Test.Tolerance
		}
		out = append(out, u)
	}
	return out
}

// groupPolicy maps a group's type onto the decision policy. A type this build does not know keeps the
// conservative order-first behaviour the loop always had.
func groupPolicy(t model.GroupType) failover.Policy {
	switch t {
	case model.GroupURLTest:
		return failover.PolicyLatency
	case model.GroupSelector:
		return failover.PolicySelector
	}
	return failover.PolicyOrdered
}

// groupProbeTarget is "host:port" for the group's test URL: the scheme's port unless one is given, 443
// for a bare host or address.
func groupProbeTarget(g model.Group) string {
	raw := ""
	if g.Test != nil {
		raw = strings.TrimSpace(g.Test.URL)
	}
	if raw == "" {
		raw = defaultUnitProbeURL
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		u, _ = url.Parse(defaultUnitProbeURL)
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// probeKernelUnits measures every (link, target) the current units need, outside applyMu: every
// group unit each tick, a fastest list's unit only on its own cycle (fresh names those lists). nil
// probes when the loop would not run or nothing can be measured.
func (s *Server) probeKernelUnits(ctx context.Context) (probes map[failover.ProbeKey]failover.ProbeResult, fresh map[string]bool) {
	io := s.tableIO()
	if s.routingIsOff() || !s.kernelElectionPlatform() {
		return nil, nil
	}
	plan, profile := s.supervisedKernelPlan()
	if plan == nil {
		return nil, nil
	}
	ifaceOf := kernelIfaceByEndpoint(profile, s.appliedKernelDevices())
	units := kernelUnitsFrom(plan, profile, ifaceOf)
	now := time.Now().UnixMilli()
	lists := s.fastestUnits(plan, profile, ifaceOf, nil, now)
	s.fastestPolicyChanged(lists)
	fresh = s.fastestDue(lists, intervalOfList(profile), now)
	for _, u := range lists {
		if fresh[u.List.List] {
			units = append(units, u)
		}
	}
	if keys := failover.ProbeKeys(units); io.probe != nil && len(keys) > 0 {
		pctx, cancel := context.WithTimeout(ctx, unitProbeCycle)
		probes = io.probe(pctx, keys)
		cancel()
	}
	// A list whose targets answered through none of its tunnels: ask the router's own path before
	// anything calls the tunnels dead. Only those lists, at most three targets each.
	if io.probe != nil && len(probes) > 0 {
		if refs := referenceKeys(lists, fresh, probes); len(refs) > 0 {
			rctx, cancel := context.WithTimeout(ctx, unitProbeCycle/3)
			for k, v := range io.probe(rctx, refs) {
				probes[k] = v
			}
			cancel()
		}
	}
	s.fastestStore(lists, fresh, probes)
	return probes, fresh
}

// referenceKeys are the reference measurements a cycle needs: for every fresh list whose targets
// answered through none of its tunnels, its reference targets (failover.ReferenceTargets: a
// kill-switched list's are neutral addresses, never its own destinations) by the router's own path.
func referenceKeys(lists []failover.TableUnit, fresh map[string]bool, probes map[failover.ProbeKey]failover.ProbeResult) []failover.ProbeKey {
	var refs []failover.ProbeKey
	seen := map[string]bool{}
	for _, u := range lists {
		if u.List == nil || !fresh[u.List.List] || !failover.TargetsUnanswered(u, probes) {
			continue
		}
		if u.List.TargetsOnTrial {
			continue // unproven targets: their silence judges nothing, with or without a reference
		}
		for _, t := range failover.ReferenceTargets(u) {
			if !seen[t] {
				seen[t] = true
				refs = append(refs, failover.ProbeKey{Iface: failover.ReferenceIface, Target: t})
			}
		}
	}
	return refs
}

// probeUnitTargets is the production measurement: each target resolved once per cycle (public
// addresses only), then unitProbeAttempts TCP handshakes per (link, target), each socket bound to the
// candidate's link. A target that does not resolve is left unmeasured — the router's DNS failing says
// nothing about any tunnel — and its candidates fall back to the monitor.
func (s *Server) probeUnitTargets(ctx context.Context, keys []failover.ProbeKey) map[failover.ProbeKey]failover.ProbeResult {
	if !netdiag.CanBindToDevice() {
		return nil
	}
	return probeKeysWith(ctx, keys, netdiag.ResolveProbeTarget, unitProbeDialer(s.unitProbeMark()))
}

// unitProbeDialer is one handshake for a key: bound to the candidate's link, or by the router's own
// path for a reference key. mark is the socket's fwmark (unitProbeMark): on OpenWrt both kinds must
// carry the core's bypass mark, or the core's redirect answers for the tunnel and the "router's own
// path" is whatever the core routes the target by.
func unitProbeDialer(mark int) func(ctx context.Context, iface, addr string) (int, bool, bool) {
	return func(ctx context.Context, iface, addr string) (int, bool, bool) {
		if iface == failover.ReferenceIface {
			return netdiag.TCPConnectMark(ctx, addr, unitProbeTimeout, mark)
		}
		return netdiag.TCPConnectViaIfaceMark(ctx, iface, addr, unitProbeTimeout, mark)
	}
}

// probeKeysWith is the cycle's scheduling over a resolver and a dialer (tests stand in for both).
func probeKeysWith(ctx context.Context, keys []failover.ProbeKey, resolve func(context.Context, string) (string, error),
	dial func(ctx context.Context, iface, addr string) (int, bool, bool)) map[failover.ProbeKey]failover.ProbeResult {
	// Targets resolve in parallel on the same worker cap: one at a time, a resolver that is down
	// spent the whole cycle on 3 s timeouts before the first handshake.
	var targets []string
	seenT := map[string]bool{}
	for _, k := range keys {
		if !seenT[k.Target] {
			seenT[k.Target] = true
			targets = append(targets, k.Target)
		}
	}
	addr := make(map[string]string, len(targets))
	var mu sync.Mutex
	runWorkers(len(targets), func(i int) {
		rctx, cancel := context.WithTimeout(ctx, unitResolveTimeout)
		a, err := resolve(rctx, targets[i])
		cancel()
		if err != nil {
			a = ""
		}
		mu.Lock()
		addr[targets[i]] = a
		mu.Unlock()
	})
	// Jobs go out attempt by attempt, every key's first attempt before anyone's second, from a start
	// that moves every cycle: a budget too small for every key then shortens each key's sample instead
	// of starving the same keys at the end of the sorted list every cycle.
	var live []failover.ProbeKey
	for _, k := range keys {
		if addr[k.Target] != "" {
			live = append(live, k)
		}
	}
	type sample struct {
		ms      int
		ok, ran bool
	}
	samples := make(map[failover.ProbeKey][]sample, len(live))
	n := len(live)
	start := 0
	if n > 0 {
		start = int(probeRotation.Add(1) % uint32(n))
	}
	runWorkers(n*unitProbeAttempts, func(j int) {
		if ctx.Err() != nil {
			return
		}
		k := live[(start+j%n)%n]
		ms, ok, ran := dial(ctx, k.Iface, addr[k.Target])
		mu.Lock()
		samples[k] = append(samples[k], sample{ms, ok, ran})
		mu.Unlock()
	})
	out := make(map[failover.ProbeKey]failover.ProbeResult, len(samples))
	for k, ss := range samples {
		r := failover.ProbeResult{}
		var rtts []int
		for _, s := range ss {
			if !s.ran {
				continue
			}
			r.Ran = true
			r.Attempts++
			if s.ok {
				r.Successes++
				rtts = append(rtts, s.ms)
			}
		}
		r.MedianMs = failover.Median(rtts)
		out[k] = r
	}
	return out
}

// probeRotation moves the first probe job of each cycle.
var probeRotation atomic.Uint32

// runWorkers runs job(0..n-1) on at most unitProbeConcurrency goroutines: a fixed pool, not one
// goroutine per job (480 keys x 3 attempts at the cap was 1440 goroutines started at once).
func runWorkers(n int, job func(int)) {
	if n <= 0 {
		return
	}
	w := unitProbeConcurrency
	if n < w {
		w = n
	}
	next := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < w; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range next {
				job(j)
			}
		}()
	}
	for j := 0; j < n; j++ {
		next <- j
	}
	close(next)
	wg.Wait()
}

// kernelTableRoutes is the elector's view of the tables, over the reads the tick already made. Replace
// writes IPv4; syncV6 then makes each owned table's IPv6 follow the v4 member.
type kernelTableRoutes struct {
	s    *Server
	ctx  context.Context
	io   routeTableIO
	live map[bool]map[int]string
}

func (r *kernelTableRoutes) Current(table int) (string, bool) {
	tables, ok := r.live[false]
	if !ok {
		return "", false
	}
	return tables[table], true
}

// Clear empties a fastest list's table (on_all_down wan/block), both families: the lookup then falls
// through to the main table, or to the plane's blackhole for a fail-closed list.
func (r *kernelTableRoutes) Clear(table int) error {
	if r.io.clear == nil {
		return errors.New("no way to clear a table here")
	}
	if iface := r.live[false][table]; iface != "" {
		err := r.io.clear(r.ctx, false, iface, table)
		r.s.noteListFailoverWrite(false, table, err)
		if err != nil {
			return err
		}
		delete(r.live[false], table)
	}
	// IPv6 is cleared whether or not IPv4 had anything left, and a failure is said (once) and stays
	// in the reading: Leftover then has the elector ask again on the list's next cycle. It used to be
	// tried once, only together with an IPv4 route, and its failure dropped.
	if tables6, ok := r.live[true]; ok && tables6[table] != "" {
		err := r.io.clear(r.ctx, true, tables6[table], table)
		r.s.noteListFailoverWrite(true, table, err)
		if err == nil {
			delete(tables6, table)
		}
	}
	return nil
}

// Leftover reports an IPv6 device default still in a table whose IPv4 one is gone.
func (r *kernelTableRoutes) Leftover(table int) bool {
	return r.live[true][table] != ""
}

func (r *kernelTableRoutes) Replace(table int, iface string) error {
	err := r.io.write(r.ctx, false, iface, table)
	// A refusal is not a switch: the table still holds what it held, and the elector commits nothing.
	// It is said once, and again when it recovers, never every cycle.
	r.s.noteListFailoverWrite(false, table, err)
	if err == nil {
		r.live[false][table] = iface
	}
	return err
}

// syncV6 points each owned table's IPv6 default at the member its IPv4 default holds, when that member
// is one of the unit's candidates; a member without IPv6 gets the table's "unreachable" instead, so the
// list's IPv6 is refused rather than sent out by another exit.
func (r *kernelTableRoutes) syncV6(units []failover.TableUnit) {
	tables6, read := r.live[true]
	if !read {
		return
	}
	for _, u := range units {
		iface := r.live[false][u.Key.Table]
		if !u.Accepts(iface) || tables6[u.Key.Table] == iface {
			continue
		}
		if !r.io.carriesIPv6(iface) {
			r.s.noteTableV6Refused(tableRestore{Table: u.Key.Table, Iface: iface}, r.io.refuseV6(r.ctx, u.Key.Table))
			continue
		}
		err := r.io.write(r.ctx, true, iface, u.Key.Table)
		r.s.noteListFailoverWrite(true, u.Key.Table, err)
		if err == nil {
			tables6[u.Key.Table] = iface
		}
	}
}

func unitByTable(units []failover.TableUnit, ev failover.UnitEvent) failover.TableUnit {
	for _, u := range units {
		if u.Key == ev.Key {
			return u
		}
	}
	return failover.TableUnit{Key: ev.Key, Name: ev.Key.Owner}
}

// kernelElected is, per group the kernel plane steers, the member its table holds now as the elector
// last read it — the member the router actually uses, which is what the Failover page must show.
// owned lists every group the elector owns, with or without a reading yet.
func (s *Server) kernelElected() (elected map[string]string, owned map[string]bool, units []failover.UnitState) {
	elected, owned = map[string]string{}, map[string]bool{}
	if !s.kernelElectionPlatform() {
		return elected, owned, nil
	}
	for _, g := range s.selfSwitchingGroups() {
		owned[g] = true
	}
	if len(owned) == 0 {
		return elected, owned, nil
	}
	units = s.kernelElector().States()
	for _, u := range units {
		if u.Group != "" && u.Current != "" && owned[u.Group] {
			if _, seen := elected[u.Group]; !seen {
				elected[u.Group] = u.Current
			}
		}
	}
	return elected, owned, units
}
