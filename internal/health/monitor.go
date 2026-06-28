// Package health runs background latency probes against each endpoint/group via
// the Clash API and accumulates per-target stats: current state + latency,
// success rate, average latency, reconnection count, uptime, a handshake state,
// a probable failure cause (from the engine log via the knowledgebase), and
// per-endpoint traffic (rate + approximate total) from the Clash connections API.
package health

import (
	"context"
	"errors"
	"sync"
	"time"

	"wakeroute/internal/clash"
	"wakeroute/internal/kb"
	"wakeroute/internal/model"
	"wakeroute/internal/netdiag"
	"wakeroute/internal/store"
	"wakeroute/internal/util"
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
	consecFail                       int   // consecutive Down probes not yet promoted to a flip (hysteresis)
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
// (instant showcase). Recovery (Alive) and Unknown always commit immediately.
const flapThreshold = 2

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
}

// Monitor probes targets and accumulates their stats.
type Monitor struct {
	mu        sync.Mutex
	stats     map[string]*stat
	clash     *clash.Client
	store     *store.Store
	logs      LogSource
	demo      bool
	testURL   string
	interval  time.Duration
	timeoutMS int
	// ifaceBytesFn reads a kernel iface's cumulative rx/tx byte counters (injectable for tests;
	// defaults to ifaceBytes/sysfs). Kernel-routed endpoints bypass sing-box and never appear in
	// Clash /connections, so their throughput is read from the tunnel iface here instead.
	ifaceBytesFn func(iface string) (rx, tx int64, ok bool)

	// causeFor scans the entire engine log on every call; since the derived cause
	// is global (not per-endpoint) and changes slowly, cache it for a short TTL so a
	// persistently-down target doesn't re-scan the whole log every tick/snapshot.
	causeMu      sync.Mutex
	causeTitle   string
	causeFix     string
	causeExpires int64 // unix ms; cache valid while nowMS() < causeExpires
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
		s.pushSample(probeSample{ok: true, latency: latency})
	case Down:
		s.fail++
		s.consecFail++
		s.pushSample(probeSample{ok: false})
	}
	// Hysteresis: hold the current state until flapThreshold consecutive Down probes confirm
	// a real outage, so one dropped probe on a lossy path doesn't flip Down→Alive (zeroing
	// uptime + counting a bogus reconnect). Alive/Unknown commit immediately; demo is instant.
	threshold := flapThreshold
	if m.demo {
		threshold = 1
	}
	commit := state
	if state == Down && s.consecFail < threshold {
		commit = s.state
	}
	if commit != s.state {
		if commit == Alive && s.state == Down {
			s.reconnects++
		}
		s.state = commit
		s.lastChange = now
	}
}

// probe checks a target's reachability. A native interface-backed endpoint
// (AmneziaWG/WireGuard nwgN — iface set) is NOT a Clash proxy, so it is probed by
// pinging through that kernel interface; everything else uses the Clash delay test
// through proxy id (testURL = the per-tunnel health target, else the default).
func (m *Monitor) probe(ctx context.Context, id, testURL, iface string) (State, int) {
	if iface != "" {
		if alive, ms := netdiag.ReachableViaIface(ctx, iface, "1.1.1.1", 3); alive {
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

type target struct{ id, name, kind, testURL, iface string }

func (m *Monitor) targets() []target {
	return m.targetsFrom(m.store.Profile())
}

// targetsFrom derives the probe targets from an already-fetched profile so a
// caller that also needs the profile (e.g. Snapshot's group derivation) does not
// pay for a second deep-cloning store.Profile() on the same tick.
func (m *Monitor) targetsFrom(p model.Profile) []target {
	var t []target
	for _, e := range p.Endpoints {
		if e.Enabled {
			u := ""
			if e.Health != nil {
				u = e.Health.URL
			}
			// The kernel iface this endpoint is probed through (ReachableViaIface) instead of a Clash
			// delay test. EngineExternal carries it in params["interface"]; EngineAmneziaWG derives it
			// from the id (mirrors pbr.kernelIface — keep in sync). Without resolving the AWG iface, a
			// kernel-routed AWG endpoint that is NOT a sing-box outbound (fast mode) falls to the Clash
			// probe, which can't see it, and shows Unknown health even when the tunnel is up.
			iface, _ := e.Params["interface"].(string)
			if iface == "" && e.Engine == model.EngineAmneziaWG {
				iface = util.AWGIface(e.ID)
			}
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
	tgs := m.targets()
	now := nowMS()
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, tg := range tgs {
		wg.Add(1)
		go func(tg target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			st, lat := m.probe(tctx, tg.id, tg.testURL, tg.iface)
			m.record(tg.id, tg.name, tg.kind, st, lat, now)
		}(tg)
	}
	wg.Wait()
	if tctx.Err() != nil {
		return
	}
	m.sampleTraffic(tctx, tgs, now)
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
	if m.clash != nil {
		if conns, err := m.clash.Connections(ctx); err == nil {
			for _, c := range conns.Connections {
				for _, tag := range c.Chains {
					v := agg[tag]
					agg[tag] = [2]int64{v[0] + c.Upload, v[1] + c.Download}
				}
			}
		}
	}
	for _, tg := range tgs {
		if tg.kind != "endpoint" || tg.iface == "" {
			continue
		}
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
		s.rateUp, s.rateDown = 0, 0
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
	tgs := m.targets()
	lastEp := -1
	for i, tg := range tgs {
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
}

// ProbeOne probes a single target immediately and returns its view. An id that
// matches no current target is NOT probed or recorded — record() would otherwise
// create a permanent m.stats entry keyed by the (caller-supplied) id, so an
// attacker hitting POST /api/health/test/{random} could grow the map without
// bound. For an unknown id we return an empty/Unknown View (toView's nil path)
// without touching m.stats.
func (m *Monitor) ProbeOne(ctx context.Context, id string) View {
	var tgt target
	found := false
	for _, tg := range m.targets() {
		if tg.id == id {
			tgt = tg
			found = true
			break
		}
	}
	if !found {
		return toView(id, nil, nowMS())
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
		for i := range views {
			if views[i].ID != g.ID {
				continue
			}
			switch {
			case anyAlive:
				views[i].State, views[i].Handshake = string(Alive), "ok"
			case anyDown:
				views[i].State, views[i].Handshake = string(Down), "failed"
			default:
				views[i].State = string(Unknown)
			}
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
	for _, g := range p.Groups {
		gi, ok := idx[g.ID]
		if !ok {
			continue
		}
		v := &views[gi]
		if v.BytesUp != 0 || v.BytesDown != 0 || v.RateUpBps != 0 || v.RateDownBps != 0 {
			continue
		}
		for _, mem := range g.Members {
			if mi, ok := idx[mem]; ok {
				v.BytesUp += views[mi].BytesUp
				v.BytesDown += views[mi].BytesDown
				v.RateUpBps += views[mi].RateUpBps
				v.RateDownBps += views[mi].RateDownBps
			}
		}
	}
	// causeFor scans the whole engine log and is identical for every down target,
	// so compute it once per snapshot rather than re-scanning per down endpoint.
	var cause, fix string
	var computed bool
	for i := range views {
		if views[i].State == "down" {
			if !computed {
				cause, fix = m.causeFor()
				computed = true
			}
			views[i].Cause, views[i].CauseFix = cause, fix
		}
	}
	return views
}

func (m *Monitor) viewWithCause(id string) View {
	m.mu.Lock()
	v := toView(id, m.stats[id], nowMS())
	m.mu.Unlock()
	if v.State == "down" {
		v.Cause, v.CauseFix = m.causeFor()
	}
	return v
}

// causeFor returns the probable failure cause, reusing a recently-derived result
// within causeTTLms so a persistently-down target does not re-scan the engine log
// on every tick/snapshot. The cause is global (not per-target) so one entry suffices.
func (m *Monitor) causeFor() (string, string) {
	now := nowMS()
	m.causeMu.Lock()
	defer m.causeMu.Unlock()
	if now < m.causeExpires {
		return m.causeTitle, m.causeFix
	}
	title, fix := m.deriveCause()
	m.causeTitle, m.causeFix, m.causeExpires = title, fix, now+causeTTLms
	return title, fix
}

// deriveCause scans recent engine log lines (newest first) for a known error and
// returns its title + fix; falls back to a generic timeout explanation.
func (m *Monitor) deriveCause() (string, string) {
	if m.logs != nil {
		lines := m.logs.LogLines()
		for i := len(lines) - 1; i >= 0; i-- {
			if mm := kb.Match(lines[i]); len(mm) > 0 {
				return mm[0].Title, mm[0].Fix
			}
		}
	}
	return "No response (timed out or blocked)",
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
