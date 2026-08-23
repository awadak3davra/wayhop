package failover

// OutlierDetector implements Envoy-style PASSIVE outlier detection for failover members: a member
// that fails REAL traffic (from Clash /connections error patterns) is EJECTED from selection for a
// growing window even while its synthetic health probe still passes — catching the "probe green,
// traffic dead" class of failures (a DPI-hijacked or captive exit that answers a 204 but kills real
// flows). Unlike the Damper (which reacts to probe up/down flaps), this reacts to real-traffic
// outcomes. PURE + deterministic (clock passed in); the Runner feeds it per-member outcomes and
// hides ejected members from Decide.
type OutlierDetector struct {
	cfg   OutlierConfig
	state map[string]*outlierState
}

type outlierState struct {
	consecFails  int
	ejections    int   // times ejected so far — grows the ejection window (Envoy base_ejection_time growth)
	ejectedUntil int64 // unix ms; a member is ejected while now < ejectedUntil
}

// OutlierConfig tunes the detector; zero fields fall back to the defaults below.
type OutlierConfig struct {
	ConsecutiveFailures int   // eject after this many consecutive real-traffic failures
	BaseEjectionMS      int64 // ejection window, multiplied by the ejection count
	MaxEjectionMS       int64 // cap on a single ejection window
}

const (
	defaultConsecutiveFailures = 5
	defaultBaseEjectionMS      = 30_000
	defaultMaxEjectionMS       = 300_000
)

func (c OutlierConfig) consecutiveFailures() int {
	if c.ConsecutiveFailures > 0 {
		return c.ConsecutiveFailures
	}
	return defaultConsecutiveFailures
}
func (c OutlierConfig) baseEjection() int64 {
	if c.BaseEjectionMS > 0 {
		return c.BaseEjectionMS
	}
	return defaultBaseEjectionMS
}
func (c OutlierConfig) maxEjection() int64 {
	if c.MaxEjectionMS > 0 {
		return c.MaxEjectionMS
	}
	return defaultMaxEjectionMS
}

// NewOutlierDetector builds a detector with the given config (zero fields → defaults).
func NewOutlierDetector(cfg OutlierConfig) *OutlierDetector {
	return &OutlierDetector{cfg: cfg, state: map[string]*outlierState{}}
}

func (o *OutlierDetector) get(member string) *outlierState {
	s := o.state[member]
	if s == nil {
		s = &outlierState{}
		o.state[member] = s
	}
	return s
}

// Record folds one real-traffic outcome for a member. A success resets the consecutive-failure run;
// a failure advances it, and once it reaches ConsecutiveFailures the member is ejected for a window
// that grows with each ejection (base × ejection-count, capped at MaxEjection). A new ejection is
// only started when the member isn't already inside one.
func (o *OutlierDetector) Record(member string, success bool, now int64) {
	s := o.get(member)
	if success {
		s.consecFails = 0
		return
	}
	s.consecFails++
	if s.consecFails >= o.cfg.consecutiveFailures() && now >= s.ejectedUntil {
		s.ejections++
		window := o.cfg.baseEjection() * int64(s.ejections)
		if window > o.cfg.maxEjection() {
			window = o.cfg.maxEjection()
		}
		s.ejectedUntil = now + window
		s.consecFails = 0 // start a fresh run; the window is what keeps it out
	}
}

// Ejected reports whether a member is currently ejected (inside its ejection window).
func (o *OutlierDetector) Ejected(member string, now int64) bool {
	s := o.state[member]
	return s != nil && now < s.ejectedUntil
}
