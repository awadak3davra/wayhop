// Package failover is the daemon-side selection brain for MANAGED failover groups. Given each
// member's health (from internal/health) it decides which member a group should route through and
// whether that switch may commit now — applying a latency deadband (don't leave a healthy member
// for a trivially-faster one) and a min-dwell guard (don't switch again too soon), while ALWAYS
// letting an emergency (the current member died) through immediately. It is the mechanism sing-box
// 1.12.x cannot provide natively (no rise/fall, dampening, ordered fallback, or passive ejection).
//
// This package is PURE — no I/O, no Clash calls — so it is fully unit-tested. The live runner (a
// server goroutine that reads the monitor and issues clash.Select for groups a user has opted into
// managed mode) is layered on top; it is inert until a group is opted in, so building this changes
// nothing on the datapath. See docs/FAILOVER_CONTROL_LOOP.md for the runner wiring (device-gated).
package failover

// MemberHealth is one member's current health, as the controller sees it. LatencyMs is meaningful
// only when Alive. Members are passed to Decide in the group's configured (preference) order.
type MemberHealth struct {
	ID        string
	Alive     bool
	LatencyMs int
}

// Policy is how a managed group chooses among healthy members. Values equal model.GroupType so a
// group's existing type maps 1:1 (the caller casts model.GroupType → Policy).
type Policy string

const (
	PolicyLatency  Policy = "urltest"  // lowest-latency alive, with a tolerance deadband
	PolicyOrdered  Policy = "fallback" // first alive in preference order (strict priority)
	PolicySelector Policy = "selector" // keep the manual pick while alive, else first alive
)

// Config tunes a decision; zero values fall back to the defaults below.
type Config struct {
	ToleranceMs    int   // latency deadband: don't leave the current member for one only this-much faster
	MinDwellMS     int64 // don't commit a non-emergency switch within this window of the last switch
	FailbackHoldMS int64 // a non-emergency (failback/optimization) switch's target must stay stably wanted this long before it commits (the Runner enforces it); an emergency switch off a dead member ignores it
}

const (
	defaultToleranceMs    = 50
	defaultMinDwellMS     = 10000
	defaultFailbackHoldMS = 30000
)

func (c Config) tolerance() int {
	if c.ToleranceMs > 0 {
		return c.ToleranceMs
	}
	return defaultToleranceMs
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

// ideal is the member the policy WANTS, ignoring the min-dwell guard.
func ideal(in DecideInput) (id, reason string) {
	curAlive, curLat, _ := in.memberAlive(in.Current)
	switch in.Policy {
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
		if curLat-bestLat > in.Cfg.tolerance() {
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
	emergency := in.Current == "" || !curAlive
	if !emergency && in.LastSwitch > 0 && in.Now-in.LastSwitch < in.Cfg.minDwell() {
		return in.Current, "held (min-dwell)", false
	}
	return want, why, true
}
