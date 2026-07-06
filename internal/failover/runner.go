package failover

// GroupSpec describes one MANAGED group as the runner needs it: its id, the policy (== the group's
// model.GroupType), its members in preference order, and the decision tuning.
type GroupSpec struct {
	ID      string
	Policy  Policy
	Members []string
	Cfg     Config
}

// HealthSource supplies per-member health in member order (implemented by health.Monitor.MemberHealth).
type HealthSource interface {
	MemberHealth(ids []string) []MemberHealth
}

// Selector is the runner's view of the LIVE selection state, implemented by an adapter over
// clash.Client: the currently-selected member of each group (from Clash `now`), a way to switch it
// (clash.Select), and a way to drop a group's in-flight connections (close them via the Clash
// /connections API) so they re-establish through the new member.
type Selector interface {
	Selections() map[string]string       // groupID → currently-selected member ("now"); "" if unknown
	Select(groupID, member string) error // switch a group's selection
	Interrupt(groupID string) error      // drop the group's existing connections (used on an emergency switch)
}

// FailureSource reports which members are currently failing REAL traffic (derived from Clash
// /connections error patterns) even if their synthetic probe passes — the input for passive outlier
// ejection (F8). Implemented by a device-gated adapter over the monitor's /connections consumption;
// nil (unset) leaves passive ejection inactive.
type FailureSource interface {
	Failing() map[string]bool // set of member ids currently failing real traffic
}

// Switch is one selection change the runner committed this tick (feeds the F13 event log).
type Switch struct {
	Group, From, To, Reason string
	// Emergency is true when the incumbent was dead/gone — the switch hard-cut the group's existing
	// connections (so stuck flows move now) rather than draining them, which is what a graceful
	// failback to a still-healthy member does (F11).
	Emergency bool
}

// Runner drives MANAGED failover groups. Each Tick it asks failover.Decide which member every
// managed group should route through and applies the change via the Selector, honoring min-dwell
// (tracking the last committed switch) AND failback dampening (a switch away from a still-healthy
// member must stay wanted for Config.FailbackHold before it commits; an emergency off a dead member
// bypasses it). It holds no locks — call Tick from a single goroutine (the server's monitor loop).
// It is inert when no group is managed. Nothing constructs or starts it yet: the server-goroutine
// wiring + a live Selector adapter over clash.Client are the DEVICE-GATED next step (see
// docs/FAILOVER_CONTROL_LOOP.md), so building this changes nothing.
type Runner struct {
	lastSwitch map[string]int64         // groupID → unix ms of the last committed switch
	pending    map[string]pendingSwitch // groupID → an in-progress failback/optimization awaiting its hold
	damper     *Damper                  // BGP-style flap damping (F7)
	lastAlive  map[string]bool          // memberID → last-seen alive, for flap detection
	outlier    *OutlierDetector         // Envoy-style passive outlier ejection (F8)
	failures   FailureSource            // real-traffic failure signal for F8; nil ⇒ passive ejection inactive
}

// pendingSwitch is a non-emergency switch the runner is DAMPENING: the target it wants to move to
// and when that want first appeared. The switch commits only once the target has stayed wanted for
// Config.FailbackHold — so a preferred member that recovers then flaps never steals traffic back.
type pendingSwitch struct {
	to    string
	since int64
}

// NewRunner builds an empty runner (no groups have switched yet) with default flap damping and
// passive outlier detection. The outlier detector is inert until a FailureSource is wired via
// SetFailureSource (device-gated).
func NewRunner() *Runner {
	return &Runner{
		lastSwitch: map[string]int64{},
		pending:    map[string]pendingSwitch{},
		damper:     NewDamper(DampConfig{}),
		lastAlive:  map[string]bool{},
		outlier:    NewOutlierDetector(OutlierConfig{}),
	}
}

// SetFailureSource wires the real-traffic failure signal for passive outlier ejection (F8). Nil
// (the default) leaves passive ejection off. The source is a device-gated adapter over the monitor's
// Clash /connections consumption.
func (r *Runner) SetFailureSource(fs FailureSource) { r.failures = fs }

// filteredHealth hides members that Decide must not pick from a group's raw health: chronically
// FLAPPING members (F7 damper) and members failing REAL traffic (F8 passive outlier ejection). It
// records this tick's flap + real-traffic outcomes into the detectors first, then applies both
// exclusions — but NEVER removes the group's last alive member (routing through a flappy/outlier
// exit beats blackholing every exit; Envoy's max_ejection_percent principle).
func (r *Runner) filteredHealth(health []MemberHealth, now int64) []MemberHealth {
	if r.damper == nil {
		return health
	}
	var failing map[string]bool
	if r.failures != nil && r.outlier != nil {
		failing = r.failures.Failing()
	}
	for _, mh := range health {
		if prev, ok := r.lastAlive[mh.ID]; ok && prev && !mh.Alive {
			r.damper.Penalize(mh.ID, now) // a member that just dropped earns a flap penalty
		}
		r.lastAlive[mh.ID] = mh.Alive
		if failing != nil {
			r.outlier.Record(mh.ID, !failing[mh.ID], now) // fold the real-traffic outcome
		}
	}
	out := make([]MemberHealth, len(health))
	copy(out, health)
	aliveBefore, aliveAfter := 0, 0
	for i := range out {
		if out[i].Alive {
			aliveBefore++
			if r.damper.Suppressed(out[i].ID, now) || (failing != nil && r.outlier.Ejected(out[i].ID, now)) {
				out[i].Alive = false
			}
		}
	}
	for i := range out {
		if out[i].Alive {
			aliveAfter++
		}
	}
	if aliveBefore > 0 && aliveAfter == 0 {
		copy(out, health) // exclusion would eject every exit — keep the flappy/outlier ones instead
	}
	return out
}

// currentDeadOrEmpty reports whether the current selection is an EMERGENCY to move off of: nothing
// selected, or the selected member is not alive (or no longer a member). An emergency switch bypasses
// the failback hold; a switch away from a still-healthy member is a failback/optimization and is damped.
func currentDeadOrEmpty(current string, health []MemberHealth) bool {
	if current == "" {
		return true
	}
	for _, m := range health {
		if m.ID == current {
			return !m.Alive
		}
	}
	return true
}

// Tick decides and applies the selection for every managed group, returning the switches it
// committed. A group whose Decide reports no change, or whose Selector.Select errors (left to retry
// next tick, so min-dwell isn't charged for a failed apply), records nothing. Safe with nil deps or
// no groups (returns nil).
func (r *Runner) Tick(groups []GroupSpec, hs HealthSource, sel Selector, now int64) []Switch {
	if r == nil || hs == nil || sel == nil || len(groups) == 0 {
		return nil
	}
	current := sel.Selections()
	var switches []Switch
	for _, g := range groups {
		from := current[g.ID] // capture before applying — Select() may invalidate the live map
		health := hs.MemberHealth(g.Members)
		// Decide over the FLAP-DAMPED view (a chronically-flapping member is hidden from selection),
		// but judge EMERGENCY from the raw health — a flappy-but-currently-alive incumbent isn't a
		// dead-exit emergency, so moving off it stays a graceful, hold-gated, drain-not-cut switch.
		desired, reason, changed := Decide(DecideInput{
			Policy:     g.Policy,
			Members:    r.filteredHealth(health, now),
			Current:    from,
			LastSwitch: r.lastSwitch[g.ID],
			Now:        now,
			Cfg:        g.Cfg,
		})
		if !changed {
			delete(r.pending, g.ID) // the want went away — reset any in-progress failback hold
			continue
		}
		emergency := currentDeadOrEmpty(from, health)
		// Failback dampening: a switch AWAY from a still-healthy member (a failback to a preferred
		// member, or a latency optimization) must stay wanted for Config.FailbackHold before it
		// commits, so a member that recovers then flaps can't repeatedly steal traffic back. An
		// EMERGENCY (the current member is dead/gone) bypasses the hold and moves immediately.
		if !emergency {
			p, ok := r.pending[g.ID]
			if !ok || p.to != desired {
				r.pending[g.ID] = pendingSwitch{to: desired, since: now}
				continue // (re)start the hold; don't apply yet
			}
			if now-p.since < g.Cfg.failbackHold() {
				continue // still holding
			}
			// hold satisfied → fall through and apply
		}
		if err := sel.Select(g.ID, desired); err != nil {
			continue // apply failed — don't record; retry next tick (dwell/hold not charged)
		}
		// F11 decision-aware interruption: on an EMERGENCY switch hard-cut the group's existing
		// connections so flows stuck on the dead incumbent move to the new member now; on a graceful
		// failback leave them to drain on the still-healthy old member. Best-effort — the switch has
		// already committed, so a failed Interrupt just leaves those flows to time out on their own.
		if emergency {
			_ = sel.Interrupt(g.ID)
		}
		switches = append(switches, Switch{Group: g.ID, From: from, To: desired, Reason: reason, Emergency: emergency})
		r.lastSwitch[g.ID] = now
		delete(r.pending, g.ID)
	}
	return switches
}
