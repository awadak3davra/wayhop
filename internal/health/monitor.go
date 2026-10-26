// Package health runs background latency probes against each endpoint and derives
// group health from the members that can actually carry traffic. It accumulates
// per-target stats: current state + latency,
// success rate, average latency, reconnection count, uptime, a handshake state,
// a probable failure cause (from the engine log via the knowledgebase), and
// per-endpoint traffic (rate + approximate total) from the Clash connections API.
package health

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"wayhop/internal/clash"
	"wayhop/internal/failover"
	"wayhop/internal/kb"
	"wayhop/internal/model"
	"wayhop/internal/netdiag"
	"wayhop/internal/store"
	"wayhop/internal/util"
)

type State string

const (
	Alive   State = "alive"
	Down    State = "down"
	Unknown State = "unknown"
)

// LogSource provides recent engine log lines (implemented by core.SingBox).
type LogSource interface {
	LogLines() []string
}

type stat struct {
	name, kind                       string
	probes, ok, fail                 int
	sumLatency                       int64
	lastLatency                      int
	state                            State
	reconnects                       int
	consecFail                       int   // consecutive Down probes not yet promoted to a flip (fast-out hysteresis)
	consecOK                         int   // consecutive Alive probes while still marked Down (slow-in recovery hysteresis)
	firstSeen, lastChange, lastProbe int64 // unix ms

	// traffic (from Clash /connections, best-effort)
	activeUp, activeDown int64 // last sampled active-connection byte sums
	rateUp, rateDown     int64 // bytes/s
	totalUp, totalDown   int64 // approx bytes since monitoring started
	lastConnSample       int64

	// Rolling window of the last healthWindow probe OUTCOMES (Alive/Down only), so
	// SuccessRate and AvgLatencyMs reflect RECENT health rather than the lifetime average —
	// a long-healthy endpoint that just died would otherwise keep a ~99% ratio for hours.
	// Circular: slots 0..recentN-1 are valid until full, then all healthWindow slots are.
	recent    [healthWindow]probeSample
	recentN   int
	recentPos int
}

// probeSample is one windowed probe outcome; latency is valid only when ok.
type probeSample struct {
	ok      bool
	latency int
}

// healthWindow is the rolling-window size for SuccessRate/AvgLatencyMs (~5 min at the
// default 10s probe cadence).
const healthWindow = 30

// flapThreshold is how many CONSECUTIVE Down probes must be seen before the monitor flips
// an endpoint's state to Down. It debounces a single transient probe failure (which would
// otherwise zero uptime + inflate the reconnect counter) on a lossy path. Demo mode uses 1
// (instant showcase). Unknown always commits immediately.
const flapThreshold = 2

// aliveThreshold is how many CONSECUTIVE Alive probes must be seen before the monitor promotes
// a target OUT of Down back to Alive. It is the symmetric counterpart to flapThreshold: every
// robust load balancer uses fast-out / slow-in (HAProxy rise 2 / fall 3, AWS ALB healthy 5 vs
// unhealthy 2), so a dead exit that answers ONE lucky probe doesn't instantly flip Alive,
// count a reconnect, and (once a health-driven selector loop exists) re-attract traffic. Only
// the Down→Alive recovery is gated; Unknown→Alive (initial bring-up) still commits immediately.
// Demo mode uses 1 (instant showcase).
const aliveThreshold = 2

func (s *stat) pushSample(p probeSample) {
	s.recent[s.recentPos] = p
	s.recentPos = (s.recentPos + 1) % healthWindow
	if s.recentN < healthWindow {
		s.recentN++
	}
}

// View is the JSON snapshot of a target's health + stats.
type View struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	State        string `json:"state"`     // alive | down | unknown
	Handshake    string `json:"handshake"` // ok | failed | unknown
	LatencyMs    int    `json:"latency_ms"`
	AvgLatencyMs int    `json:"avg_latency_ms"`
	SuccessRate  int    `json:"success_rate"`
	Probes       int    `json:"probes"`
	Reconnects   int    `json:"reconnects"`
	UptimeS      int64  `json:"uptime_s"`
	RateUpBps    int64  `json:"rate_up_bps"`
	RateDownBps  int64  `json:"rate_down_bps"`
	BytesUp      int64  `json:"bytes_up"`
	BytesDown    int64  `json:"bytes_down"`
	Cause        string `json:"cause,omitempty"` // why it's down (R6)
	CauseFix     string `json:"cause_fix,omitempty"`
	// CauseID names the cause for a reader that words it itself: causeEngineMissing, causeNoResponse,
	// or the kb entry's id.
	CauseID string `json:"cause_id,omitempty"`
}

// Monitor probes targets and accumulates their stats.
type Monitor struct {
	mu         sync.Mutex
	stats      map[string]*stat
	localFault bool // last tick saw EVERY endpoint down at once ⇒ likely local uplink, not N exits
	clash      *clash.Client
	store      *store.Store
	logs       LogSource
	demo       bool
	testURL    string
	interval   time.Duration
	timeoutMS  int
	// ifaceBytesFn reads a kernel iface's cumulative rx/tx byte counters (injectable for tests;
	// defaults to ifaceBytes/sysfs). Kernel-routed endpoints bypass sing-box and never appear in
	// Clash /connections, so their throughput is read from the tunnel iface here instead.
	ifaceBytesFn func(iface string) (rx, tx int64, ok bool)
	// nativeInterfaces resolves endpoint IDs to the exact interface identities persisted by the
	// authenticated Apply runtime. Strict native plans may assign wr_* on OpenWrt or WireguardN /
	// wrtunN on Keenetic; guessing those names from the editable profile reports healthy tunnels as
	// down and can read counters from the wrong interface. The resolver is replaceable after monitor
	// startup, so it has its own lock rather than sharing the stats lock across ledger I/O.
	interfaceMu      sync.RWMutex
	nativeInterfaces func() (map[string]string, bool)

	// causeFor scans the entire engine log on every call; since the derived cause
	// is global (not per-endpoint) and changes slowly, cache it for a short TTL so a
	// persistently-down target doesn't re-scan the whole log every tick/snapshot.
	// coreAvailable reports whether the compatibility core is installed, so a down endpoint that
	// needs it can be told the real reason. Replaceable and nil by default: the monitor is
	// constructed before the server knows, and a nil resolver means "not known", which keeps the
	// log-derived cause rather than guessing.
	coreMu        sync.RWMutex
	coreAvailable func() bool

	causeMu      sync.Mutex
	causeID      string
	causeTitle   string
	causeFix     string
	causeExpires int64 // unix ms; cache valid while nowMS() < causeExpires

	// Failover log (see events.go). Guarded by mu, because an event must never describe a
	// transition that was not also committed under the same lock.
	events  []Event           // ring buffer, cap eventCap
	evHead  int               // oldest slot once the ring has wrapped
	elected map[string]string // group id -> member the proxy core last reported routing through
}

// SetCoreAvailable installs the resolver that reports whether the compatibility core is present.
// Called by the server once it knows; until then the monitor answers "not known" and nothing about
// the core is claimed.
func (m *Monitor) SetCoreAvailable(fn func() bool) {
	m.coreMu.Lock()
	m.coreAvailable = fn
	m.coreMu.Unlock()
}

func (m *Monitor) coreState() (available, known bool) {
	m.coreMu.RLock()
	fn := m.coreAvailable
	m.coreMu.RUnlock()
	if fn == nil {
		return false, false
	}
	return fn(), true
}

// causeTTLms bounds how long a derived failure cause is reused before re-scanning.
const causeTTLms int64 = 30_000

// NewMonitor builds a Monitor probing every 10s with a 5s per-probe timeout.
// In demo mode it synthesizes plausible per-tunnel stats (so the dashboard shows
// what real data looks like without a running sing-box).
func NewMonitor(cl *clash.Client, st *store.Store, logs LogSource, demo bool) *Monitor {
	return &Monitor{
		stats:        map[string]*stat{},
		clash:        cl,
		store:        st,
		logs:         logs,
		demo:         demo,
		testURL:      "http://cp.cloudflare.com/generate_204",
		interval:     10 * time.Second,
		timeoutMS:    5000,
		ifaceBytesFn: ifaceBytes,
	}
}

// SetNativeInterfaceResolver installs the read-only bridge to the authenticated current execution
// snapshot. known=false means the ledger/runtime could not prove a current mapping; callers then
// retain the legacy profile-derived behavior for upgrade compatibility instead of claiming an
// empty authoritative set.
func (m *Monitor) SetNativeInterfaceResolver(resolver func() (map[string]string, bool)) {
	if m == nil {
		return
	}
	m.interfaceMu.Lock()
	m.nativeInterfaces = resolver
	m.interfaceMu.Unlock()
}

func (m *Monitor) currentNativeInterfaces() (map[string]string, bool) {
	if m == nil {
		return nil, false
	}
	m.interfaceMu.RLock()
	resolver := m.nativeInterfaces
	m.interfaceMu.RUnlock()
	if resolver == nil {
		return nil, false
	}
	return resolver()
}

func nowMS() int64 { return time.Now().UnixMilli() }

func (m *Monitor) record(id, name, kind string, state State, latency int, now int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.stats[id]
	if s == nil {
		s = &stat{state: Unknown, firstSeen: now, lastChange: now}
		m.stats[id] = s
	}
	if name != "" {
		s.name = name
	}
	if kind != "" {
		s.kind = kind
	}
	s.probes++
	s.lastProbe = now
	switch state {
	case Alive:
		s.ok++
		s.sumLatency += int64(latency)
		s.lastLatency = latency
		s.consecFail = 0
		s.consecOK++
		s.pushSample(probeSample{ok: true, latency: latency})
	case Down:
		s.fail++
		s.consecFail++
		s.consecOK = 0
		s.pushSample(probeSample{ok: false})
	}
	// Hysteresis (fast-out / slow-in): hold the current state until enough consecutive probes
	// confirm the transition. flapThreshold consecutive Down probes confirm a real outage (so one
	// dropped probe on a lossy path doesn't flip Alive→Down, zeroing uptime); aliveThreshold
	// consecutive Alive probes confirm a real recovery (so a dead exit answering one lucky probe
	// doesn't flip Down→Alive, count a reconnect, and re-attract traffic). Unknown commits
	// immediately, and so does Unknown→Alive initial bring-up; demo is instant both ways.
	downThreshold, upThreshold := flapThreshold, aliveThreshold
	if m.demo {
		downThreshold, upThreshold = 1, 1
	}
	commit := state
	switch {
	case state == Down && s.consecFail < downThreshold:
		commit = s.state
	case state == Alive && s.state == Down && s.consecOK < upThreshold:
		commit = s.state
	case state == Unknown && s.state != Unknown:
		// A transient Unknown (a non-ErrProxyDown probe glitch: a malformed 200 body, a connection
		// reset, or the local Clash API momentarily unreachable) must NOT launder a committed
		// Alive/Down state into Unknown. Holding the committed state (especially Down) preserves the
		// slow-in recovery gate and the reconnect count: otherwise Down→Unknown→Alive would flip to
		// Alive on the FIRST lucky probe, bypassing aliveThreshold and re-attracting failover traffic
		// to a flapping exit. The initial Unknown→Unknown bring-up still commits immediately (a fresh
		// stat starts state=Unknown, so this case does not fire for it).
		commit = s.state
	}
	if commit != s.state {
		if commit == Alive && s.state == Down {
			s.reconnects++
		}
		// Log the transition here, after hysteresis, so the failover log carries confirmed outages
		// and recoveries rather than every dropped probe. The initial Unknown->Alive bring-up is
		// skipped: a daemon starting up is not an exit coming back.
		if kind := eventKindFor(s.state, commit); kind != "" {
			m.pushEvent(Event{
				At: now, Kind: kind, ID: id, Name: s.name,
				From: string(s.state), To: string(commit), LatencyMS: latency,
			})
		}
		s.state = commit
		s.lastChange = now
	}
}

// eventKindFor names a committed transition, or "" when it is not worth logging. Only the crossings
// that change whether an exit can carry traffic qualify — Unknown->Alive is a first reading, not a
// recovery, and logging it would fill the log with the daemon's own startup.
func eventKindFor(from, to State) string {
	switch {
	case to == Down && from != Down:
		return EventDown
	case to == Alive && from == Down:
		return EventUp
	}
	return ""
}

// probe checks a target's reachability. A native interface-backed endpoint
// (AmneziaWG/WireGuard nwgN — iface set) is NOT a Clash proxy, so it is probed by
// pinging through that kernel interface; everything else uses the Clash delay test
// through proxy id (testURL = the per-tunnel health target, else the default).
func (m *Monitor) probe(ctx context.Context, id, testURL, iface string) (State, int) {
	if iface != "" {
		alive, ms, ran := netdiag.ReachableViaIfaceProbe(ctx, iface, ifaceProbeHost(testURL), 3)
		if !ran {
			// The probe never executed (no ping on this PATH, the interface is gone, the context
			// was cancelled). Reporting Down here would mark every native tunnel dead on such a
			// router and hand failover a reason to move traffic off a working exit. Unknown is
			// already handled downstream: it does not launder a committed Alive/Down state.
			return Unknown, 0
		}
		if alive {
			return Alive, ms
		}
		return Down, 0
	}
	if m.clash == nil {
		return Unknown, 0
	}
	url := testURL
	if url == "" {
		url = m.testURL
	}
	d, err := m.clash.Delay(ctx, id, url, m.timeoutMS)
	if err == nil {
		return Alive, d
	}
	if errors.Is(err, clash.ErrProxyDown) {
		return Down, 0
	}
	return Unknown, 0
}

// defaultIfaceProbeHost is what a kernel interface-backed exit is pinged at when its health-check
// target names no address.
const defaultIfaceProbeHost = "1.1.1.1"

// ifaceProbeHost is the address a kernel interface-backed exit is pinged at: its own health-check
// target when that names an address (a bare IP, or a URL whose host is one), else
// defaultIfaceProbeHost.
//
// The panel has always offered "or 1.1.1.1 / gateway IP" in that field and said it is what the
// tunnel pings, yet the kernel probe pinged 1.1.1.1 whatever it held. Measured on a live Keenetic: an
// exit to a VPS that forwards only Google's networks (to reach Gemini) never answered 1.1.1.1 and read
// Down at 0% while it carried the traffic routed into it; 8.8.8.8 answers through it.
//
// A hostname is not resolved here: ping would resolve it through the router's own DNS, outside the
// tunnel, so a name (a URL for the Clash delay test, say) falls back to the default like an empty
// target.
func ifaceProbeHost(target string) string {
	target = strings.TrimSpace(target)
	if ip, err := netip.ParseAddr(target); err == nil {
		return ip.Unmap().String()
	}
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
			return ip.Unmap().String()
		}
	}
	return defaultIfaceProbeHost
}

type target struct{ id, name, kind, testURL, iface string }

// EndpointIface is the kernel interface an endpoint's traffic leaves by, the one it is probed and
// measured through. With an authenticated native binding map (known) it is the applied binding, and
// an empty binding is meaningful: the core carries that endpoint, or it is not in the applied
// snapshot, so no legacy name is manufactured. Without one, EngineExternal carries it in
// params["interface"] and EngineAmneziaWG derives it from the id (mirrors pbr.kernelIface). "" for
// an endpoint with no kernel interface.
func EndpointIface(e model.Endpoint, native map[string]string, known bool) string {
	if known {
		return native[e.ID]
	}
	iface, _ := e.Params["interface"].(string)
	if iface == "" && e.Engine == model.EngineAmneziaWG {
		iface = util.AWGIface(e.ID)
	}
	return iface
}

// targetsFrom derives the probe targets from an already-fetched profile so a
// caller that also needs the profile (e.g. Snapshot's group derivation) does not
// pay for a second deep-cloning store.Profile() on the same tick.
func (m *Monitor) targetsFrom(p model.Profile) []target {
	nativeInterfaces, nativeKnown := m.currentNativeInterfaces()
	var t []target
	for _, e := range p.Endpoints {
		if e.Enabled {
			u := ""
			if e.Health != nil {
				u = e.Health.URL
			}
			// The kernel iface this endpoint is probed through (ReachableViaIfaceProbe) instead of a Clash
			// delay test. Without resolving the AWG iface, a kernel-routed AWG endpoint that is NOT a
			// sing-box outbound (fast mode) falls to the Clash probe, which can't see it, and shows
			// Unknown health even when the tunnel is up.
			iface := EndpointIface(e, nativeInterfaces, nativeKnown)
			t = append(t, target{e.ID, e.Name, "endpoint", u, iface})
		}
	}
	for _, g := range p.Groups {
		u := ""
		if g.Test != nil {
			u = g.Test.URL
		}
		t = append(t, target{g.ID, g.Name, "group", u, ""})
	}
	return t
}

// Run probes all targets on a ticker until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(m.interval)
	defer t.Stop()
	m.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.tick(ctx)
		}
	}
}

func (m *Monitor) tick(ctx context.Context) {
	if m.demo {
		m.demoTick(nowMS())
		return
	}
	// Bound the tick so a wedged Clash API can't leave probe goroutines hanging
	// forever (the shared HTTP client has no timeout because /traffic streams).
	// Headroom = the proxy-side delay timeout plus the HTTP round trip.
	tctx, cancel := context.WithTimeout(ctx, time.Duration(m.timeoutMS)*time.Millisecond+5*time.Second)
	defer cancel()
	p := m.store.Profile()
	tgs := m.targetsFrom(p)
	now := nowMS()
	// Probe concurrently into per-index result slots (distinct indices → no data race; wg.Wait
	// establishes the happens-before before we read them). Recording is deferred until after the
	// whole tick's results are in, so a tick-global decision (the local-fault gate) can be made
	// BEFORE any single Down flip is committed.
	states := make([]State, len(tgs))
	lats := make([]int, len(tgs))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, tg := range tgs {
		// A group is an aggregation/selection policy, not necessarily a concrete Clash outbound.
		// That is especially true on native-first Keenetic/OpenWrt plans, where the members are
		// kernel interfaces and no compatibility-core group tag exists. Probing the group ID through
		// Clash records a false Down even while every member is healthy. Probe only real endpoints;
		// applyResultsWithGroups derives the group result from their committed member health.
		if tg.kind == "group" {
			continue
		}
		wg.Add(1)
		go func(i int, tg target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			states[i], lats[i] = m.probe(tctx, tg.id, tg.testURL, tg.iface)
		}(i, tg)
	}
	wg.Wait()
	if tctx.Err() != nil {
		return
	}
	m.applyResultsWithGroups(tgs, p.Groups, states, lats, now)
	m.sampleTraffic(tctx, tgs, now)
	m.sampleElection(tctx)
	m.pruneStats(tgs)
}

// applyResults commits one tick's probe results, applying the local-fault (Envoy "panic
// threshold") gate first: if EVERY endpoint that returned a definite result this tick is Down (≥2
// of them, none Alive), the local uplink or a shared upstream is the likely cause — not N
// independent exits failing at once. Those endpoints' Down probes are then SUPPRESSED (state held
// instead of flipped, so uptime isn't zeroed, reconnects aren't inflated, and failover isn't
// thrashed) and the localFault flag is raised so the UI can show one honest "local network
// problem" banner rather than a wall of red exits. Split out from tick() so it is unit-testable
// without the probe machinery.
func (m *Monitor) applyResults(tgs []target, states []State, lats []int, now int64) {
	m.applyResultsWithGroups(tgs, nil, states, lats, now)
}

// applyResultsWithGroups commits endpoint probes first, then records each group's health from the
// endpoints/groups it contains. Group derivation deliberately uses the members' HYSTERESIS-
// COMMITTED states, not their raw result from this tick: one dropped endpoint probe therefore
// cannot manufacture a group outage. This one recorded truth feeds Snapshot, RecentWindows and
// the failover event log, preventing those APIs from contradicting each other.
func (m *Monitor) applyResultsWithGroups(tgs []target, groups []model.Group, states []State, lats []int, now int64) {
	localFault := allEndpointsDown(tgs, states)
	m.mu.Lock()
	m.localFault = localFault
	m.mu.Unlock()
	for i, tg := range tgs {
		if tg.kind != "endpoint" {
			continue // groups are derived below; never trust a standalone group probe
		}
		if localFault && tg.kind == "endpoint" && states[i] == Down {
			continue // suppress: don't advance this endpoint toward Down during a local fault
		}
		m.record(tg.id, tg.name, tg.kind, states[i], lats[i], now)
	}
	m.recordDerivedGroups(groups, now)
}

type derivedHealth struct {
	state   State
	latency int
}

// recordDerivedGroups derives groups to a fixpoint so a group may safely contain another group,
// even when the parent precedes the child in the profile. Existing group stats are intentionally
// excluded from the seed: they may be the false Clash self-probe result this path replaces.
func (m *Monitor) recordDerivedGroups(groups []model.Group, now int64) {
	if len(groups) == 0 {
		return
	}
	m.mu.Lock()
	byID := make(map[string]derivedHealth, len(m.stats)+1)
	for id, s := range m.stats {
		if s != nil && s.kind != "group" {
			byID[id] = derivedHealth{state: s.state, latency: s.lastLatency}
		}
	}
	m.mu.Unlock()
	byID[model.OutboundDirect] = derivedHealth{state: Alive}
	for _, g := range groups {
		byID[g.ID] = derivedHealth{state: Unknown}
	}

	for pass := 0; pass < len(groups); pass++ {
		changed := false
		for _, g := range groups {
			next := derivedHealth{state: Unknown}
			anyDown := false
			for _, member := range g.Members {
				mh, known := byID[member]
				if !known {
					continue
				}
				switch mh.state {
				case Alive:
					// The first alive member is a truthful representative without claiming that
					// WayHop knows the router/core's current election. Election is sampled and
					// reported separately when the platform can prove it.
					if next.state != Alive {
						next = mh
					}
				case Down:
					anyDown = true
				}
			}
			if next.state != Alive && anyDown {
				next = derivedHealth{state: Down}
			}
			if byID[g.ID] != next {
				byID[g.ID] = next
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	for _, g := range groups {
		h := byID[g.ID]
		m.record(g.ID, g.Name, "group", h.state, h.latency, now)
	}
}

// allEndpointsDown reports whether EVERY endpoint that returned a definite Alive/Down result this
// tick is Down (with at least two such endpoints) — the "the local side is down, not the exits"
// signal. Any Alive endpoint disproves it; Unknown results (e.g. Clash unreachable) are ignored.
func allEndpointsDown(tgs []target, states []State) bool {
	definite := 0
	for i, tg := range tgs {
		if tg.kind != "endpoint" {
			continue
		}
		switch states[i] {
		case Alive:
			return false
		case Down:
			definite++
		}
	}
	return definite >= 2
}

// LocalFault reports whether the last tick looked like a local-uplink/shared-upstream outage
// (every endpoint down at once) rather than individual exit failures. Surfaced so the UI can show
// one honest "local network problem" banner instead of a wall of red exits.
func (m *Monitor) LocalFault() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.localFault
}

// MemberHealth returns the given member ids' current health as the failover control loop sees them:
// Alive iff the monitor's hysteresis-committed state is Alive (so F1's fast-out/slow-in already
// applies), with the last measured latency. The builtin "direct" member (WAN) is always alive.
// An unknown/never-probed member reports Alive=false so the controller treats it as not-yet-selectable
// rather than guessing. Reads under the lock; ids are typically a managed group's members, in order.
func (m *Monitor) MemberHealth(ids []string) []failover.MemberHealth {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]failover.MemberHealth, 0, len(ids))
	for _, id := range ids {
		mh := failover.MemberHealth{ID: id}
		if id == "direct" {
			mh.Alive = true // WAN/direct is always reachable (mirrors Snapshot's group derivation)
		} else if s := m.stats[id]; s != nil {
			mh.Alive = s.state == Alive
			mh.LatencyMs = s.lastLatency
		}
		out = append(out, mh)
	}
	return out
}

// pruneStats drops stats for targets that no longer exist. genID rotates a target's id whenever an
// endpoint/group is added, deleted, renamed, reordered or disabled, so without this m.stats grows
// without bound over the life of a long-running daemon — a real (if slow) memory leak on a
// 128–256MB router. Only the current live target set is kept; each holds a fixed-size [30]sample
// ring, so the map's footprint stays bounded by the profile size, not by history. Locks m.mu.
func (m *Monitor) pruneStats(tgs []target) {
	live := make(map[string]struct{}, len(tgs))
	for _, tg := range tgs {
		live[tg.id] = struct{}{}
	}
	m.mu.Lock()
	for id := range m.stats {
		if _, ok := live[id]; !ok {
			delete(m.stats, id)
		}
	}
	m.mu.Unlock()
}

// addCumulativeTraffic updates a stat from a new pair of CUMULATIVE byte counters (the active-
// connection sums from Clash, or a tunnel iface's monotonic rx/tx): it derives per-second rates and
// accumulates totals from the delta since the last sample, ignoring a non-increase (a closed
// connection, or an iface that was recreated and reset to 0) so a drop never yields a negative rate
// or total. Caller holds m.mu.
func (s *stat) addCumulativeTraffic(up, down, now int64) {
	if s.lastConnSample > 0 && now > s.lastConnSample {
		dt := float64(now-s.lastConnSample) / 1000.0
		if du := up - s.activeUp; du > 0 {
			s.rateUp = int64(float64(du) / dt)
			s.totalUp += du
		} else {
			s.rateUp = 0
		}
		if dd := down - s.activeDown; dd > 0 {
			s.rateDown = int64(float64(dd) / dt)
			s.totalDown += dd
		} else {
			s.rateDown = 0
		}
	}
	s.activeUp, s.activeDown, s.lastConnSample = up, down, now
}

// sampleTraffic attributes per-endpoint/group throughput from two disjoint sources and derives a
// best-effort rate + accumulated total from sample-to-sample deltas:
//   - Clash /connections: a connection's chain names include the outbound + group tags, so
//     sing-box-carried endpoints/groups are summed by tag. Best-effort — when sing-box is stopped
//     (native-only fast mode) /connections is unreachable and simply contributes nothing.
//   - tunnel iface counters: a KERNEL-routed endpoint (AmneziaWG / adopted EngineExternal) bypasses
//     sing-box, never appears in /connections, and would otherwise read as zero — so its throughput
//     comes from its interface (up=tx, down=rx). A kernel endpoint is not a sing-box outbound, so
//     the two sources never double-count.
func (m *Monitor) sampleTraffic(ctx context.Context, tgs []target, now int64) {
	agg := map[string][2]int64{} // id -> {up, down}
	clashOK := false             // did the /connections poll actually succeed this tick?
	if m.clash != nil {
		if conns, err := m.clash.Connections(ctx); err == nil {
			clashOK = true
			for _, c := range conns.Connections {
				for _, tag := range c.Chains {
					v := agg[tag]
					agg[tag] = [2]int64{v[0] + c.Upload, v[1] + c.Download}
				}
			}
		}
	}
	kernelIface := map[string]bool{} // ids whose traffic source is a kernel iface, not clash /connections
	for _, tg := range tgs {
		if tg.kind != "endpoint" || tg.iface == "" {
			continue
		}
		kernelIface[tg.id] = true
		if rx, tx, ok := m.ifaceBytesFn(tg.iface); ok {
			agg[tg.id] = [2]int64{tx, rx} // up=tx (sent into the tunnel), down=rx
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, a := range agg {
		if s := m.stats[id]; s != nil {
			s.addCumulativeTraffic(a[0], a[1], now)
		}
	}
	// Decay endpoints that contributed NO bytes this tick (all their connections closed, e.g.
	// traffic moved off them after a failover; or a kernel iface that went away) to 0 — otherwise
	// rateUp/rateDown keep their last positive value on the dashboard/metrics forever. Reset the
	// active baseline too so a later reappearance computes a fresh delta, not a spike against a stale
	// total (a recreated iface restarts its counters at 0, so this stays correct there too).
	for id, s := range m.stats {
		if _, ok := agg[id]; ok {
			continue
		}
		s.rateUp, s.rateDown = 0, 0 // no traffic observed this tick → zero the displayed rate
		// PRESERVE the cumulative baseline of a sing-box-tagged stat when the clash /connections poll
		// FAILED (transport error / non-200 / decode error — none cancel ctx). We can't tell whether
		// its connections are still open, and resetting activeUp/Down to 0 would make the next
		// successful poll recount the entire still-open cumulative into totalUp/totalDown — a
		// permanent, self-compounding BytesUp/BytesDown inflation. A kernel-iface stat is authoritative
		// (its counter was read, or the iface is gone and legitimately resets), so it decays normally.
		if !clashOK && !kernelIface[id] {
			continue
		}
		s.activeUp, s.activeDown = 0, 0
		s.lastConnSample = now
	}
}

func hashStr(s string) int {
	h := 0
	for _, c := range s {
		h = h*131 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return h
}

// demoTick fabricates believable per-tunnel health so the demo dashboard shows
// ping/speed/traffic/uptime (and one endpoint "down" to show the failure cause).
func (m *Monitor) demoTick(now int64) {
	p := m.store.Profile()
	tgs := m.targetsFrom(p)
	lastEp := -1
	for i, tg := range tgs {
		if tg.kind != "endpoint" {
			continue
		}
		if tg.kind == "endpoint" {
			lastEp = i
		}
	}
	for i, tg := range tgs {
		base := hashStr(tg.id)
		state := Alive
		lat := 25 + base%90 + int((now/1000)%15)
		if i == lastEp && lastEp > 0 { // demonstrate the "down + cause" row
			state, lat = Down, 0
		}
		m.record(tg.id, tg.name, tg.kind, state, lat, now)
		m.mu.Lock()
		if s := m.stats[tg.id]; s != nil {
			if state == Alive {
				s.rateDown = int64(400_000 + base%3_000_000)
				s.rateUp = int64(80_000 + base%600_000)
				secs := int64(m.interval / time.Second)
				if secs < 1 {
					secs = 1
				}
				s.totalDown += s.rateDown * secs
				s.totalUp += s.rateUp * secs
			} else {
				s.rateDown, s.rateUp = 0, 0
			}
		}
		m.mu.Unlock()
	}
	m.recordDerivedGroups(p.Groups, now)
	// Demo mode is a full server with a real, editable store: deleting/renaming an
	// endpoint or group rotates its target id, so without pruning here (the real
	// tick() runs pruneStats at the end, but the demo branch returns before it) the
	// old ids' *stat entries leak in m.stats for the life of the demo session.
	m.pruneStats(tgs)
}

// ProbeOne probes a single target immediately and returns its view. An id that
// matches no current target is NOT probed or recorded — record() would otherwise
// create a permanent m.stats entry keyed by the (caller-supplied) id, so an
// attacker hitting POST /api/health/test/{random} could grow the map without
// bound. For an unknown id we return an empty/Unknown View (toView's nil path)
// without touching m.stats.
func (m *Monitor) ProbeOne(ctx context.Context, id string) View {
	p := m.store.Profile()
	var tgt target
	found := false
	for _, tg := range m.targetsFrom(p) {
		if tg.id == id {
			tgt = tg
			found = true
			break
		}
	}
	if !found {
		return toView(id, nil, nowMS())
	}
	if tgt.kind == "group" {
		// Manual group tests use the same member-derived truth as the background monitor. Calling
		// Clash Delay with a native-only group tag is the false-negative bug this branch prevents.
		m.recordDerivedGroups(p.Groups, nowMS())
		return m.viewWithCause(id)
	}
	tctx, cancel := context.WithTimeout(ctx, time.Duration(m.timeoutMS)*time.Millisecond+5*time.Second)
	defer cancel()
	st, lat := m.probe(tctx, id, tgt.testURL, tgt.iface)
	m.record(id, tgt.name, tgt.kind, st, lat, nowMS())
	return m.viewWithCause(id)
}

// Snapshot returns the current view for every active target.
func (m *Monitor) Snapshot() []View {
	p := m.store.Profile()
	tgs := m.targetsFrom(p)
	now := nowMS()
	m.mu.Lock()
	views := make([]View, 0, len(tgs))
	for _, tg := range tgs {
		v := toView(tg.id, m.stats[tg.id], now)
		if v.Name == "" {
			v.Name = tg.name
		}
		if v.Kind == "" {
			v.Kind = tg.kind
		}
		views = append(views, v)
	}
	m.mu.Unlock()
	// A group selector can't be Clash-delay-probed, so derive its health from its members:
	// alive if any member endpoint is alive (or a "direct"/WAN member, always reachable); down only
	// if at least one member is down and none alive; otherwise Unknown — all members unprobed/unknown
	// (e.g. before the first probe completes) is NOT a "down" and must not show a failover group as a
	// misleading down.
	stateByID := make(map[string]string, len(views))
	for _, v := range views {
		stateByID[v.ID] = v.State
	}
	// A group can nest another group, so a single pass would derive a group-of-groups from its member
	// group's STALE (pre-derivation) state. Iterate to a fixpoint, writing each derived state back into
	// stateByID so a parent group sees its member groups' derived health. Bounded by len(p.Groups)
	// passes (each pass that changes nothing ends it).
	for pass := 0; pass < len(p.Groups); pass++ {
		changed := false
		for _, g := range p.Groups {
			anyAlive, anyDown := false, false
			for _, mem := range g.Members {
				switch {
				case mem == "direct" || stateByID[mem] == string(Alive):
					anyAlive = true
				case stateByID[mem] == string(Down):
					anyDown = true
				}
			}
			st, hs := string(Unknown), ""
			switch {
			case anyAlive:
				st, hs = string(Alive), "ok"
			case anyDown:
				st, hs = string(Down), "failed"
			}
			if stateByID[g.ID] != st {
				stateByID[g.ID] = st
				changed = true
			}
			for i := range views {
				if views[i].ID != g.ID {
					continue
				}
				views[i].State = st
				if hs != "" {
					views[i].Handshake = hs
				}
			}
		}
		if !changed {
			break
		}
	}
	// Kernel groups have no Clash chain, so their view reads zero traffic even when their members
	// (iface-accounted) carry it. Fill any group still at zero by summing its members' bytes/rates; a
	// sing-box group already carries its chain totals, so non-zero groups are left untouched (no
	// double-count).
	idx := make(map[string]int, len(views))
	for i := range views {
		idx[views[i].ID] = i
	}
	// A kernel selector group can't be Clash-delay-probed, so its State/Handshake are overridden from
	// an alive member above, but its OWN secondary metrics (uptime/success-rate/latency) stay at the
	// zeros of its failed self-probe — a persistent dashboard contradiction (alive with 0% success,
	// 0 ms, 0 s uptime). Derive those from a representative alive member too, ONLY when the group's own
	// probe produced no valid measurement (all four zero), so a genuinely self-probed group is untouched.
	for _, g := range p.Groups {
		gi, ok := idx[g.ID]
		if !ok {
			continue
		}
		v := &views[gi]
		if v.State != string(Alive) || v.UptimeS != 0 || v.SuccessRate != 0 || v.LatencyMs != 0 || v.AvgLatencyMs != 0 {
			continue
		}
		for _, mem := range g.Members {
			mi, ok := idx[mem]
			if !ok {
				continue
			}
			mv := views[mi]
			if mv.State == string(Alive) && (mv.UptimeS != 0 || mv.SuccessRate != 0 || mv.LatencyMs != 0 || mv.AvgLatencyMs != 0) {
				v.UptimeS, v.SuccessRate, v.LatencyMs, v.AvgLatencyMs = mv.UptimeS, mv.SuccessRate, mv.LatencyMs, mv.AvgLatencyMs
				break
			}
		}
	}
	// A group can nest another group, so — exactly like the state derivation above — a single forward
	// pass would sum a group-of-groups from its member group's not-yet-filled ZERO traffic when the
	// parent is listed before the child in p.Groups, reporting zero throughput for a group that is
	// actually carrying it. Iterate to a fixpoint: each pass fills only groups still at zero, summing
	// into locals and committing once (so a member filled on a later pass is never double-counted), and
	// stops as soon as a pass fills nothing. Bounded by len(p.Groups) passes.
	for pass := 0; pass < len(p.Groups); pass++ {
		changed := false
		for _, g := range p.Groups {
			gi, ok := idx[g.ID]
			if !ok {
				continue
			}
			v := &views[gi]
			if v.BytesUp != 0 || v.BytesDown != 0 || v.RateUpBps != 0 || v.RateDownBps != 0 {
				continue
			}
			var bu, bd, ru, rd int64
			for _, mem := range g.Members {
				if mi, ok := idx[mem]; ok {
					bu += views[mi].BytesUp
					bd += views[mi].BytesDown
					ru += views[mi].RateUpBps
					rd += views[mi].RateDownBps
				}
			}
			if bu != 0 || bd != 0 || ru != 0 || rd != 0 {
				v.BytesUp, v.BytesDown = bu, bd
				v.RateUpBps, v.RateDownBps = ru, rd
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	// causeFor scans the whole engine log and is identical for every down target,
	// so compute it once per snapshot rather than re-scanning per down endpoint.
	var id, cause, fix string
	var computed bool
	// The engine per endpoint, so a down exit whose core is missing is told that instead of the
	// global log-derived cause. Built from the profile already in hand rather than re-fetching.
	engines := make(map[string]model.Engine, len(p.Endpoints))
	for _, e := range p.Endpoints {
		engines[e.ID] = e.Engine
	}
	coreAvail, coreKnown := m.coreState()
	for i := range views {
		if views[i].State == "down" {
			if t, f := coreMissingCause(engines[views[i].ID], coreKnown, coreAvail); t != "" {
				views[i].CauseID, views[i].Cause, views[i].CauseFix = causeEngineMissing, t, f
				continue
			}
			if !computed {
				id, cause, fix = m.causeFor()
				computed = true
			}
			views[i].CauseID, views[i].Cause, views[i].CauseFix = id, cause, fix
		}
	}
	return views
}

func (m *Monitor) viewWithCause(id string) View {
	m.mu.Lock()
	v := toView(id, m.stats[id], nowMS())
	m.mu.Unlock()
	if v.State != "down" {
		return v
	}
	// Same rule as the snapshot path. Both are reachable from the panel — the card reads the
	// snapshot, the Test button reads this one — and a remedy that changes with which control you
	// pressed would be its own defect.
	coreAvail, coreKnown := m.coreState()
	var engine model.Engine
	for _, e := range m.store.Profile().Endpoints {
		if e.ID == id {
			engine = e.Engine
			break
		}
	}
	if t, f := coreMissingCause(engine, coreKnown, coreAvail); t != "" {
		v.CauseID, v.Cause, v.CauseFix = causeEngineMissing, t, f
		return v
	}
	v.CauseID, v.Cause, v.CauseFix = m.causeFor()
	return v
}

// causeFor returns the probable failure cause, reusing a recently-derived result
// within causeTTLms so a persistently-down target does not re-scan the engine log
// on every tick/snapshot. The cause is global (not per-target) so one entry suffices.
func (m *Monitor) causeFor() (id, title, fix string) {
	now := nowMS()
	m.causeMu.Lock()
	defer m.causeMu.Unlock()
	if now < m.causeExpires {
		return m.causeID, m.causeTitle, m.causeFix
	}
	id, title, fix = m.deriveCause()
	m.causeID, m.causeTitle, m.causeFix, m.causeExpires = id, title, fix, now+causeTTLms
	return id, title, fix
}

// The causes the monitor words itself, as CauseID names them; a kb match is named by its entry.
const (
	causeEngineMissing = "engine-missing"
	causeNoResponse    = "no-response"
)

// coreMissingCause answers a question the log-derived cause cannot: is this endpoint down because
// the engine that would carry it is not installed?
//
// The generic fallback below says "No response (timed out or blocked)" and advises trying a
// camouflaged transport — Reality, WS-over-CDN — or AmneziaWG. Measured on a host reporting
// singbox.available=false: a freshly added VLESS exit came back down with exactly that advice, and
// every transport it names except AmneziaWG is a sing-box transport, so following it cannot help.
// The panel already held the truth on two other surfaces (the Components row said the exit "will not
// work until it is installed", and Check config said the configuration was not checked because
// sing-box is absent) while this one sent the operator to change transports.
//
// Only stated when the answer is KNOWN: a caller that cannot report core availability gets the
// log-derived cause it always got, because "no engine" asserted from ignorance would be a worse lie
// than the generic one.
func coreMissingCause(engine model.Engine, coreKnown, coreAvailable bool) (title, fix string) {
	if !coreKnown || coreAvailable || engine != model.EngineSingBox {
		return "", ""
	}
	return "The engine this exit needs is not installed",
		"Install sing-box on the Components page. This protocol runs inside it, so no change of server, port or transport can bring the exit up until it is there."
}

// deriveCause scans recent engine log lines (newest first) for a known error and
// returns its title + fix; falls back to a generic timeout explanation.
func (m *Monitor) deriveCause() (id, title, fix string) {
	if m.logs != nil {
		lines := m.logs.LogLines()
		for i := len(lines) - 1; i >= 0; i-- {
			if mm := kb.Match(lines[i]); len(mm) > 0 {
				return mm[0].ID, mm[0].Title, mm[0].Fix
			}
		}
	}
	return causeNoResponse, "No response (timed out or blocked)",
		"Run Diagnostics (ping/traceroute) to the server. If the path is filtered (DPI/TSPU), try a camouflaged transport (Reality/WS-CDN) or AmneziaWG."
}

func toView(id string, s *stat, now int64) View {
	if s == nil {
		return View{ID: id, State: string(Unknown), Handshake: "unknown"}
	}
	v := View{
		ID: id, Name: s.name, Kind: s.kind, State: string(s.state),
		LatencyMs: s.lastLatency, Probes: s.probes, Reconnects: s.reconnects,
		RateUpBps: s.rateUp, RateDownBps: s.rateDown, BytesUp: s.totalUp, BytesDown: s.totalDown,
	}
	switch s.state {
	case Alive:
		v.Handshake = "ok"
	case Down:
		v.Handshake = "failed"
	default:
		v.Handshake = "unknown"
	}
	// SuccessRate + AvgLatencyMs over the rolling window (recent health). Fall back to the
	// lifetime accumulators only before any windowed sample exists (recentN == 0).
	if s.recentN > 0 {
		okN, latSum, latN := 0, 0, 0
		for i := 0; i < s.recentN; i++ {
			if p := s.recent[i]; p.ok {
				okN++
				latSum += p.latency
				latN++
			}
		}
		v.SuccessRate = okN * 100 / s.recentN
		if latN > 0 {
			v.AvgLatencyMs = latSum / latN
		}
	} else if def := s.ok + s.fail; def > 0 {
		v.SuccessRate = s.ok * 100 / def
		if s.ok > 0 {
			v.AvgLatencyMs = int(s.sumLatency) / s.ok
		}
	}
	if s.state == Alive {
		v.UptimeS = (now - s.lastChange) / 1000
	}
	return v
}
