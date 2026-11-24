// Package failover is the daemon-side selection brain for MANAGED failover groups. Given each
// member's health (from internal/health) it decides which member a group should route through and
// whether that switch may commit now — applying the policy's latency or throughput deadband (don't
// leave a healthy member for a trivially-faster one) and a min-dwell guard, while ALWAYS
// letting an emergency (the current member died) through immediately. It is the mechanism sing-box
// 1.12.x cannot provide natively (no rise/fall, dampening, ordered fallback, or passive ejection).
//
// This package is PURE — no I/O, no Clash calls — so it is fully unit-tested. The live runner (a
// server goroutine that reads the monitor and issues clash.Select for groups a user has opted into
// managed mode) is layered on top; it is inert until a group is opted in, so building this changes
// nothing on the datapath. See docs/FAILOVER_CONTROL_LOOP.md in the development repository for the
// runner wiring (device-gated).
package failover

// ThroughputSample is one candidate's last successful throughput measurement. At is unix
// milliseconds; zero At or Kbps means no usable sample.
type ThroughputSample struct {
	ThroughputKbps int64
	ThroughputAt   int64
}

// MemberHealth is one member's current health, as the controller sees it. LatencyMs is meaningful
// only when Alive. ThroughputKbps/ThroughputAt carry the optional throughput sample. Members are
// passed to Decide in the group's configured (preference) order.
type MemberHealth struct {
	ID             string
	Alive          bool
	LatencyMs      int
	ThroughputKbps int64
	ThroughputAt   int64
}

// Policy is how a managed group chooses among healthy members. The legacy values equal
// model.GroupType so a group's existing type maps 1:1 (the caller casts model.GroupType → Policy).
type Policy string

const (
	PolicyLatency    Policy = "urltest"    // lowest-latency alive, with a tolerance deadband
	PolicyOrdered    Policy = "fallback"   // first alive in preference order (strict priority)
	PolicySelector   Policy = "selector"   // keep the manual pick while alive, else first alive
	PolicyThroughput Policy = "throughput" // highest fresh throughput, with latency fallback
	PolicyMixed      Policy = "mixed"      // latency-eligible candidates, then highest fresh throughput
)

// Config tunes a decision; zero values fall back to the defaults below.
type Config struct {
	ToleranceMs int   // latency deadband: don't leave the current member for one only this-much faster
	MinDwellMS  int64 // don't commit a non-emergency switch within this window of the last switch
	// TolerancePct widens the latency deadband to this percentage of the relevant latency when that
	// is larger than ToleranceMs. For throughput and mixed it is the throughput switch deadband;
	// 0 uses 20% there (and absolute-only for legacy managed-group latency).
	TolerancePct int
	// MixedLatencySlackMs is the mixed policy's latency cut: a member is an outlier, and out of the
	// throughput choice, when it is slower than the fastest alive one by more than this AND by more
	// than that member's own latency (over twice as slow). 0 = 150 ms.
	MixedLatencySlackMs int
	FailbackHoldMS      int64 // a non-emergency (failback/optimization) switch's target must stay stably wanted this long before it commits (the Runner enforces it); an emergency switch off a dead member ignores it
}

const (
	defaultToleranceMs            = 50
	defaultMinDwellMS             = 10000
	defaultFailbackHoldMS         = 30000
	defaultThroughputTolerancePct = 20
	defaultMixedLatencySlackMs    = 150
	throughputSampleFreshWindowMS = 24 * 60 * 60 * 1000
)

func (c Config) tolerance() int {
	if c.ToleranceMs > 0 {
		return c.ToleranceMs
	}
	return defaultToleranceMs
}

func (c Config) throughputTolerancePct() int {
	if c.TolerancePct > 0 {
		return c.TolerancePct
	}
	return defaultThroughputTolerancePct
}

func (c Config) minDwell() int64 {
	if c.MinDwellMS > 0 {
		return c.MinDwellMS
	}
	return defaultMinDwellMS
}

func (c Config) failbackHold() int64 {
	if c.FailbackHoldMS > 0 {
		return c.FailbackHoldMS
	}
	return defaultFailbackHoldMS
}

// DecideInput is one group's decision inputs.
type DecideInput struct {
	Policy     Policy
	Members    []MemberHealth // in configured (preference) order
	Current    string         // the member currently selected ("" if none/unknown)
	LastSwitch int64          // unix ms of the last committed switch (0 if never)
	Now        int64          // unix ms
	Cfg        Config
	// CurrentRawAlive, when set, replaces the Members-derived aliveness of Current in the
	// EMERGENCY classification only. Members may be a flap-damped view that hides a
	// suppressed-but-alive incumbent from SELECTION; without this override that hiding also
	// reclassified the move OFF that incumbent as an emergency, and min-dwell - which exists
	// precisely to pace graceful moves - was skipped for the one member the damper was trying
	// to leave gently. The caller passes its own verdict (raw health, minus outlier ejection,
	// which must stay immediate); selection still reads Members. nil keeps the old derivation
	// for single-view callers and tests.
	CurrentRawAlive *bool
	// Pick is a selector group's manual choice when it is held apart from Current. A Clash selector's
	// pick IS its current member, so the core path leaves this empty. On the kernel plane the table
	// holds whatever was elected last, and the operator's pick is what the applied plan pinned: a
	// selector goes back to it once it is alive again instead of staying on the stand-in forever.
	Pick string
}

func (in DecideInput) memberAlive(id string) (alive bool, latency int, present bool) {
	for _, m := range in.Members {
		if m.ID == id {
			return m.Alive, m.LatencyMs, true
		}
	}
	return false, 0, false
}

func (in DecideInput) firstAlive() (string, bool) {
	for _, m := range in.Members {
		if m.Alive {
			return m.ID, true
		}
	}
	return "", false
}

func (in DecideInput) lowestLatencyAlive() (string, int, bool) {
	best, bestLat, found := "", 0, false
	for _, m := range in.Members {
		if !m.Alive {
			continue
		}
		if !found || m.LatencyMs < bestLat {
			best, bestLat, found = m.ID, m.LatencyMs, true
		}
	}
	return best, bestLat, found
}

func freshThroughput(m MemberHealth, now int64) bool {
	return m.Alive && m.ThroughputAt > 0 && m.ThroughputKbps > 0 && m.ThroughputAt <= now &&
		now-m.ThroughputAt <= throughputSampleFreshWindowMS
}

// highestThroughput returns the first candidate with the highest fresh successful sample.
func highestThroughput(members []MemberHealth, now int64) (MemberHealth, bool) {
	var best MemberHealth
	found := false
	for _, m := range members {
		if freshThroughput(m, now) && (!found || m.ThroughputKbps > best.ThroughputKbps) {
			best, found = m, true
		}
	}
	return best, found
}

func throughputBeyond(challenger, incumbent int64, tolerancePct int) bool {
	// Percentages, not ToleranceMs, apply to Kbps. Strictly greater preserves the incumbent at the
	// exact deadband boundary; configured order already broke any challenger tie.
	return challenger > incumbent+incumbent*int64(tolerancePct)/100
}

// latencyIdeal is the legacy latency choice over an explicit candidate set. Throughput modes use it
// while the samples are not comparable (see throughputIdeal); PolicyLatency itself stays untouched below.
func latencyIdeal(in DecideInput, members []MemberHealth) (id, reason string) {
	var best MemberHealth
	found := false
	var current MemberHealth
	for _, m := range members {
		if m.ID == in.Current {
			current = m
		}
		if m.Alive && (!found || m.LatencyMs < best.LatencyMs) {
			best, found = m, true
		}
	}
	if !found {
		return in.Current, "no live member"
	}
	if in.Current == "" || !current.Alive {
		return best.ID, "select fastest alive"
	}
	tol := in.Cfg.tolerance()
	if rel := current.LatencyMs * in.Cfg.TolerancePct / 100; rel > tol {
		tol = rel
	}
	if current.LatencyMs-best.LatencyMs > tol {
		return best.ID, "a faster member beats current beyond tolerance"
	}
	return in.Current, "stable (within latency tolerance)"
}

// minComparableSamples is how many alive candidates must hold a fresh sample before throughput may
// decide anything: one figure has nothing to be compared with.
const minComparableSamples = 2

// FreshSamples counts the alive members and those of them holding a fresh throughput sample: what
// the panel needs to say which rule is in force.
func FreshSamples(members []MemberHealth, now int64) (sampled, alive int) {
	for _, m := range members {
		if m.Alive {
			alive++
		}
		if freshThroughput(m, now) {
			sampled++
		}
	}
	return sampled, alive
}

// throughputIdeal chooses over candidates (all alive members for throughput, the latency-eligible
// subset for mixed). An unsampled candidate is neither worse nor better than a sampled one, so
// throughput decides only between candidates that both have a fresh sample:
//   - fewer than two sampled candidates: the choice is by delay, over all candidates (one manual
//     measurement of one tunnel changes nothing);
//   - an alive incumbent without a fresh sample: by delay too, so the unit keeps optimizing instead
//     of being pinned to it or leaving it for a figure it cannot be compared with;
//   - otherwise the highest fresh throughput among the sampled, with the percentage deadband.
func throughputIdeal(in DecideInput, candidates []MemberHealth) (id, reason string) {
	sampled, _ := FreshSamples(candidates, in.Now)
	if sampled < minComparableSamples {
		id, reason = latencyIdeal(in, candidates)
		if sampled > 0 {
			reason += " (by delay: fewer than two fresh throughput samples)"
		}
		return id, reason
	}
	best, _ := highestThroughput(candidates, in.Now)
	var current MemberHealth
	for _, m := range candidates {
		if m.ID == in.Current {
			current = m
			break
		}
	}
	if in.Current == "" || !current.Alive {
		return best.ID, "select highest-throughput alive"
	}
	if !freshThroughput(current, in.Now) {
		id, reason = latencyIdeal(in, candidates)
		return id, reason + " (by delay: current has no fresh throughput sample)"
	}
	if best.ID == in.Current {
		return in.Current, "stable (highest fresh throughput)"
	}
	if throughputBeyond(best.ThroughputKbps, current.ThroughputKbps, in.Cfg.throughputTolerancePct()) {
		return best.ID, "a higher-throughput member beats current beyond tolerance"
	}
	return in.Current, "stable (within throughput tolerance)"
}

// mixedIdeal drops dead members and latency outliers before applying the throughput choice. The cut
// is deliberately wider than the switch deadband: a media list wants the tunnel that carries the most,
// and 190 ms against 60 ms does not disqualify one; three times the delay does. The incumbent keeps
// its place for one switch deadband past the cut, so a member hovering at it does not flap.
func mixedIdeal(in DecideInput) (id, reason string) {
	_, bestLat, ok := in.lowestLatencyAlive()
	if !ok {
		return in.Current, "no live member"
	}
	slack := in.Cfg.MixedLatencySlackMs
	if slack <= 0 {
		slack = defaultMixedLatencySlackMs
	}
	if bestLat > slack {
		slack = bestLat
	}
	threshold := bestLat + slack
	eligible := make([]MemberHealth, 0, len(in.Members))
	for _, m := range in.Members {
		limit := threshold
		if m.ID == in.Current {
			limit += in.Cfg.tolerance()
		}
		if m.Alive && m.LatencyMs <= limit {
			eligible = append(eligible, m)
		}
	}
	return throughputIdeal(in, eligible)
}

// ideal is the member the policy WANTS, ignoring the min-dwell guard.
func ideal(in DecideInput) (id, reason string) {
	curAlive, curLat, _ := in.memberAlive(in.Current)
	switch in.Policy {
	case PolicyThroughput:
		return throughputIdeal(in, in.Members)
	case PolicyMixed:
		return mixedIdeal(in)
	case PolicyOrdered:
		m, ok := in.firstAlive()
		if !ok {
			return "", "no live member"
		}
		if m == in.Current {
			return in.Current, "stable (top healthy member)"
		}
		if curAlive {
			return m, "higher-priority member recovered"
		}
		return m, "current down → next healthy in order"
	case PolicySelector:
		if pickAlive, _, _ := in.memberAlive(in.Pick); in.Pick != "" && pickAlive {
			if in.Pick == in.Current {
				return in.Current, "manual pick still healthy"
			}
			return in.Pick, "manual pick healthy again"
		}
		if in.Current != "" && curAlive {
			return in.Current, "manual pick still healthy"
		}
		m, ok := in.firstAlive()
		if !ok {
			return in.Current, "no live member"
		}
		return m, "manual pick down → first healthy"
	default: // PolicyLatency
		best, bestLat, ok := in.lowestLatencyAlive()
		if !ok {
			return in.Current, "no live member"
		}
		if in.Current == "" || !curAlive {
			return best, "select fastest alive"
		}
		tol := in.Cfg.tolerance()
		if rel := curLat * in.Cfg.TolerancePct / 100; rel > tol {
			tol = rel
		}
		if curLat-bestLat > tol {
			return best, "a faster member beats current beyond tolerance"
		}
		return in.Current, "stable (within latency tolerance)"
	}
}

// Decide returns the member the group SHOULD route through, a short reason, and whether that is a
// change from Current that may COMMIT now. A non-emergency switch (the current member is still
// alive — an optimization or a failback) is held until min-dwell elapses; an emergency (current
// member dead or unset) always commits immediately. A caller applies the switch (clash.Select)
// only when changed==true.
func Decide(in DecideInput) (desired, reason string, changed bool) {
	want, why := ideal(in)
	if want == "" || want == in.Current {
		return in.Current, why, false
	}
	curAlive, _, _ := in.memberAlive(in.Current)
	if in.CurrentRawAlive != nil {
		curAlive = *in.CurrentRawAlive
	}
	emergency := in.Current == "" || !curAlive
	if !emergency && in.LastSwitch > 0 && in.Now-in.LastSwitch < in.Cfg.minDwell() {
		return in.Current, "held (min-dwell)", false
	}
	return want, why, true
}
