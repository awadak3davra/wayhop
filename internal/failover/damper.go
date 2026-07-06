package failover

import "math"

// Damper implements BGP-style route-flap damping for failover members: each flap (a member dropping)
// adds a penalty that decays exponentially over time; a member whose penalty crosses the suppress
// threshold is EXCLUDED from selection until its penalty decays below the reuse threshold
// (hysteresis) or a hard max-suppress cap elapses. This stops a chronically-flapping exit from
// repeatedly stealing traffic the instant one probe passes. Router-scaled (half-life ~90s, not
// BGP's 15 minutes). PURE + deterministic — the caller passes the clock in, so it is fully
// unit-tested; the Runner feeds it flaps and consults Suppressed() before deciding.
type Damper struct {
	cfg   DampConfig
	state map[string]*dampState
}

type dampState struct {
	penalty    float64
	lastUpdate int64 // unix ms of the last decay/penalize
	seen       bool  // lastUpdate has been set (distinguishes an initial timestamp of 0 from "unset")
	suppressed bool
	suppSince  int64 // unix ms suppression began (for the max-suppress cap)
}

// DampConfig tunes the damper; zero fields fall back to the defaults below.
type DampConfig struct {
	FlapPenalty   float64 // added per flap
	HalfLifeMS    int64   // penalty half-life
	SuppressAt    float64 // suppress once penalty exceeds this
	ReuseAt       float64 // un-suppress once penalty drops below this (hysteresis; < SuppressAt)
	MaxSuppressMS int64   // hard cap on how long a member may stay suppressed
}

const (
	defaultFlapPenalty   = 1000.0
	defaultHalfLifeMS    = 90_000
	defaultSuppressAt    = 2000.0
	defaultReuseAt       = 750.0
	defaultMaxSuppressMS = 600_000
)

func (c DampConfig) flapPenalty() float64 {
	if c.FlapPenalty > 0 {
		return c.FlapPenalty
	}
	return defaultFlapPenalty
}
func (c DampConfig) halfLife() int64 {
	if c.HalfLifeMS > 0 {
		return c.HalfLifeMS
	}
	return defaultHalfLifeMS
}
func (c DampConfig) suppressAt() float64 {
	if c.SuppressAt > 0 {
		return c.SuppressAt
	}
	return defaultSuppressAt
}
func (c DampConfig) reuseAt() float64 {
	if c.ReuseAt > 0 {
		return c.ReuseAt
	}
	return defaultReuseAt
}
func (c DampConfig) maxSuppress() int64 {
	if c.MaxSuppressMS > 0 {
		return c.MaxSuppressMS
	}
	return defaultMaxSuppressMS
}

// NewDamper builds a damper with the given config (zero fields → defaults).
func NewDamper(cfg DampConfig) *Damper {
	return &Damper{cfg: cfg, state: map[string]*dampState{}}
}

func (d *Damper) get(member string) *dampState {
	s := d.state[member]
	if s == nil {
		s = &dampState{}
		d.state[member] = s
	}
	return s
}

// decay applies exponential penalty decay from s.lastUpdate to now (halving every half-life).
func (d *Damper) decay(s *dampState, now int64) {
	if s.seen && now > s.lastUpdate {
		s.penalty *= math.Exp2(-float64(now-s.lastUpdate) / float64(d.cfg.halfLife()))
	}
	s.lastUpdate = now
	s.seen = true
}

// Penalize records a flap for a member (its penalty is decayed to now, then bumped).
func (d *Damper) Penalize(member string, now int64) {
	s := d.get(member)
	d.decay(s, now)
	s.penalty += d.cfg.flapPenalty()
}

// Suppressed reports whether a member is currently damped-out of selection. It decays the penalty to
// now, then applies suppress/reuse hysteresis and the max-suppress cap: an un-suppressed member is
// suppressed once its penalty exceeds SuppressAt; a suppressed member is released once its penalty
// falls below ReuseAt OR it has been suppressed for MaxSuppress.
func (d *Damper) Suppressed(member string, now int64) bool {
	s := d.state[member]
	if s == nil {
		return false
	}
	d.decay(s, now)
	if s.suppressed {
		if s.penalty <= d.cfg.reuseAt() || now-s.suppSince >= d.cfg.maxSuppress() {
			s.suppressed = false
		}
	} else if s.penalty > d.cfg.suppressAt() {
		s.suppressed = true
		s.suppSince = now
	}
	return s.suppressed
}
