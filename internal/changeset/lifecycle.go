package changeset

// Lifecycle is WHERE a configuration currently sits between "the user typed something" and "the
// router provably runs it". §1.1 forbids collapsing these into one ambiguous "Saved"/"Applied"
// message: they mean very different things, offer different actions, and carry different risk.
//
// StateDraft is deliberately NOT computed here — an unconfirmed form lives only in the browser and
// the server has never seen it. It is defined so clients name it identically.
type Lifecycle struct {
	State   State    `json:"state"`
	Label   string   `json:"label"`             // short, non-technical
	Detail  string   `json:"detail"`            // one sentence a non-expert can act on
	Actions []string `json:"actions,omitempty"` // the actions valid in THIS state
	// Attention marks the states a user must not ignore (drift, unverified, uncommitted window).
	Attention bool `json:"attention"`
}

// State enumerates the configuration lifecycle. Values are stable API strings.
type State string

const (
	// StateDraft: edited in an open form, not yet confirmed. Client-side only.
	StateDraft State = "draft"
	// StateSavedNotApplied: stored by WayHop but NOT active on the router.
	StateSavedNotApplied State = "saved_not_applied"
	// StateLiveNotCommitted: active inside a fail-safe window and still revertible.
	StateLiveNotCommitted State = "live_not_committed"
	// StateCommitted: verified runtime matches the committed state.
	StateCommitted State = "committed"
	// StateExternalDrift: the router was changed outside WayHop; runtime no longer matches.
	StateExternalDrift State = "external_drift"
	// StateUnverified: runtime could not be verified — never claim success (spec §4).
	StateUnverified State = "unverified"
	// StateNothingConfigured: a proven-empty installation. Nothing is applied, nothing is saved that
	// wants applying, and the ledger attests both. Distinct from StateUnverified: there is no runtime
	// to verify rather than a runtime we failed to verify, and distinct from StateCommitted: nothing
	// was ever applied to be committed.
	StateNothingConfigured State = "nothing_configured"
)

// LifecycleInputs are the facts the server can observe.
type LifecycleInputs struct {
	PendingChanges  int    // reviewable differences between saved and applied
	FailSafeArmed   bool   // an un-confirmed fail-safe window is open
	Effective       string // "applied" | "drift" | "unknown" (runtime verification verdict)
	EffectiveReason string
	// NothingConfigured: the ledger attests an explicit-none baseline AND the saved configuration
	// asks for no datapath. Effective is "unknown" in that case for the honest reason that there is
	// no runtime to attribute, which must not be reported as a verification failure.
	NothingConfigured bool
}

// Describe maps observed facts onto exactly one lifecycle state.
//
// Order matters and encodes the priority the UI must show: an OPEN fail-safe window outranks
// everything (it is time-critical and revertible), then unverifiable runtime, then genuine drift,
// then unapplied edits, and only a fully verified, quiet system reports committed.
func Describe(in LifecycleInputs) Lifecycle {
	switch {
	case in.FailSafeArmed:
		return Lifecycle{
			State: StateLiveNotCommitted, Label: "Live — not saved permanently",
			Detail:    "These changes are running now but will roll back automatically unless you confirm them.",
			Actions:   []string{"apply_permanently", "rollback_now", "review_changes"},
			Attention: true,
		}

	case in.Effective == "drift":
		return Lifecycle{
			State: StateExternalDrift, Label: "Router changed outside WayHop",
			Detail:    reasonOr(in.EffectiveReason, "The router's live configuration no longer matches what WayHop applied."),
			Actions:   []string{"review_changes", "reapply", "accept_router_state", "run_diagnostics"},
			Attention: true,
		}

	// Ordered after the two alarming states on purpose: an open fail-safe window or observed drift
	// both prove something IS on the router, so if either ever co-occurred with this flag the alarm
	// must still win. Ordered before "unknown" because a proven-empty install reaches Effective
	// "unknown" by construction, and calling that a verification failure is what put a fresh
	// installation behind a red NOT VERIFIED badge with nothing configured on it.
	case in.NothingConfigured:
		return Lifecycle{
			State: StateNothingConfigured, Label: "No changes",
			Detail:    "Nothing is configured yet. Add a connection to get started.",
			Actions:   []string{"review_changes"},
			Attention: false,
		}

	case in.Effective == "unknown":
		return Lifecycle{
			State: StateUnverified, Label: "Not verified",
			Detail:    reasonOr(in.EffectiveReason, "WayHop cannot confirm what the router is actually running."),
			Actions:   []string{"run_diagnostics", "review_changes"},
			Attention: true,
		}

	case in.PendingChanges > 0:
		return Lifecycle{
			State: StateSavedNotApplied, Label: "Saved — not applied yet",
			Detail:    "Your changes are stored but the router is still running the previous configuration.",
			Actions:   []string{"review_changes", "test_changes", "apply_permanently", "discard_all"},
			Attention: false,
		}
	}
	return Lifecycle{
		State: StateCommitted, Label: "Applied and confirmed",
		Detail:  "The router is verified to be running this configuration.",
		Actions: []string{"review_changes"},
	}
}

func reasonOr(reason, fallback string) string {
	if reason == "" {
		return fallback
	}
	return reason
}
