package changeset

import (
	"strings"
	"testing"
)

// §1.1: the five states must be DISTINCT — different label, different actions. Collapsing any two
// into a generic "Saved"/"Applied" is exactly what the spec forbids.
func TestDescribe_StatesAreDistinct(t *testing.T) {
	cases := []struct {
		name string
		in   LifecycleInputs
		want State
	}{
		{"nothing pending, verified", LifecycleInputs{Effective: "applied"}, StateCommitted},
		{"edits not applied", LifecycleInputs{PendingChanges: 3, Effective: "applied"}, StateSavedNotApplied},
		{"failsafe window open", LifecycleInputs{FailSafeArmed: true, Effective: "applied"}, StateLiveNotCommitted},
		{"router changed externally", LifecycleInputs{Effective: "drift"}, StateExternalDrift},
		{"runtime unverifiable", LifecycleInputs{Effective: "unknown"}, StateUnverified},
	}

	seenLabels := map[string]State{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Describe(c.in)
			if got.State != c.want {
				t.Fatalf("state = %q, want %q", got.State, c.want)
			}
			if got.Label == "" || got.Detail == "" {
				t.Error("every state needs a label and a plain-language detail")
			}
			if len(got.Actions) == 0 {
				t.Error("every state must offer at least one action")
			}
			if prev, dup := seenLabels[got.Label]; dup {
				t.Errorf("label %q is shared with state %q — states must be visually distinct", got.Label, prev)
			}
			seenLabels[got.Label] = got.State
		})
	}
}

// An open fail-safe window is time-critical and revertible: it outranks every other signal.
func TestDescribe_FailSafeWindowWins(t *testing.T) {
	got := Describe(LifecycleInputs{FailSafeArmed: true, PendingChanges: 5, Effective: "drift"})
	if got.State != StateLiveNotCommitted {
		t.Errorf("an armed fail-safe must dominate, got %q", got.State)
	}
	if !hasAction(got, "apply_permanently") || !hasAction(got, "rollback_now") {
		t.Errorf("the window state must offer confirm AND rollback, got %v", got.Actions)
	}
}

// Drift and unverified must demand attention, and must NEVER be reported as committed.
func TestDescribe_NeverFalselyCommitted(t *testing.T) {
	for _, eff := range []string{"drift", "unknown"} {
		got := Describe(LifecycleInputs{Effective: eff})
		if got.State == StateCommitted {
			t.Errorf("effective=%q must not report committed", eff)
		}
		if !got.Attention {
			t.Errorf("effective=%q must flag attention", eff)
		}
	}
	// Only a quiet, verified system is committed.
	if got := Describe(LifecycleInputs{Effective: "applied"}); got.State != StateCommitted || got.Attention {
		t.Errorf("a verified idle system should be committed without attention, got %+v", got)
	}
}

// The reason from the runtime verifier is surfaced verbatim so the user learns WHY.
func TestDescribe_SurfacesReason(t *testing.T) {
	got := Describe(LifecycleInputs{Effective: "drift", EffectiveReason: "core exited: rule-set invalid"})
	if !strings.Contains(got.Detail, "rule-set invalid") {
		t.Errorf("detail should carry the verifier's reason, got %q", got.Detail)
	}
	// With no reason it still says something useful rather than an empty string.
	if d := Describe(LifecycleInputs{Effective: "drift"}).Detail; d == "" {
		t.Error("a missing reason must fall back to a readable sentence")
	}
}

// Pending edits offer review/test/apply/discard — the §1.4 button set.
func TestDescribe_SavedNotAppliedActions(t *testing.T) {
	got := Describe(LifecycleInputs{PendingChanges: 1, Effective: "applied"})
	for _, want := range []string{"review_changes", "test_changes", "apply_permanently", "discard_all"} {
		if !hasAction(got, want) {
			t.Errorf("missing action %q in %v", want, got.Actions)
		}
	}
}

func hasAction(l Lifecycle, a string) bool {
	for _, x := range l.Actions {
		if x == a {
			return true
		}
	}
	return false
}

func TestDescribeProvenEmptyInstallIsNotAVerificationFailure(t *testing.T) {
	// A clean install reaches Effective "unknown" by construction: there is no runtime to attribute.
	// Reporting that as StateUnverified put a fresh installation behind a NOT VERIFIED badge with
	// attention set, over a configuration nobody had touched.
	life := Describe(LifecycleInputs{
		NothingConfigured: true, Effective: "unknown", EffectiveReason: "nothing applied yet",
	})
	if life.State != StateNothingConfigured || life.Attention {
		t.Fatalf("proven-empty install = %#v", life)
	}

	// The alarming states prove something IS on the router, so they still outrank the flag.
	armed := Describe(LifecycleInputs{NothingConfigured: true, FailSafeArmed: true})
	if armed.State != StateLiveNotCommitted {
		t.Fatalf("open fail-safe window = %#v", armed)
	}
	drift := Describe(LifecycleInputs{NothingConfigured: true, Effective: "drift"})
	if drift.State != StateExternalDrift {
		t.Fatalf("observed drift = %#v", drift)
	}

	// Without the flag an unknown runtime must still report unverified.
	unknown := Describe(LifecycleInputs{Effective: "unknown"})
	if unknown.State != StateUnverified || !unknown.Attention {
		t.Fatalf("unverifiable runtime = %#v", unknown)
	}
}
