package failsafe

import (
	"testing"
	"time"
)

// The escalation this guards ends in rebooting the router. It used to be driven by a bool in which
// "the target did not answer" and "the probe could not run" were the same value, so a device with no
// ping binary on the init system's PATH would roll back and reboot after every Apply while its
// internet worked perfectly.

func unknownMgr(t *testing.T) *Manager {
	t.Helper()
	m := New(Durations{
		Grace:         0,
		Interval:      time.Second,
		KeepWindow:    60 * time.Second,
		RollbackAfter: 10 * time.Second,
		RebootAfter:   30 * time.Second,
	})
	// Arm the window directly, without starting the goroutine: these tests drive tickHealth.
	m.pending = true
	m.phase = "armed"
	m.deadline = 60_000
	return m
}

func TestTickHealth_UnknownNeverRollsBackOrReboots(t *testing.T) {
	m := unknownMgr(t)
	// Two full minutes of "cannot measure" — well past both the rollback and the reboot deadline.
	for now := int64(1000); now <= 120_000; now += 1000 {
		if act := m.tickHealth(now, HealthUnknown); act != ActNone {
			t.Fatalf("an unmeasurable probe produced %v at t=%dms — it must never escalate", act, now)
		}
	}
	if m.phase != "unverified" {
		t.Errorf("phase should say the window is unverified, got %q", m.phase)
	}
	if !m.pending {
		t.Error("the window must stay open: nothing was established either way")
	}
}

// Unknown must not COMPLETE the window either. Passing the keep deadline blind is not evidence the
// configuration works, and marking it live would be the same error in the opposite direction.
func TestTickHealth_UnknownDoesNotCompleteTheKeepWindow(t *testing.T) {
	m := unknownMgr(t)
	if act := m.tickHealth(70_000, HealthUnknown); act != ActNone {
		t.Fatalf("blind past the deadline should not complete the window, got %v", act)
	}
	if !m.pending {
		t.Error("the window must still be pending")
	}
	// A real measurement afterwards still decides it.
	if act := m.tick(71_000, true); act != ActDone {
		t.Errorf("a genuine success after the deadline should complete the window, got %v", act)
	}
}

// Time spent unable to measure must not itself push the router toward a rollback.
func TestTickHealth_UnknownDoesNotAdvanceTheBadTimer(t *testing.T) {
	m := unknownMgr(t)
	m.tick(1000, false) // one genuine failure starts the countdown
	// 20 s blind — longer than RollbackAfter (10 s). If the blind period counted, this would roll back.
	for now := int64(2000); now <= 22_000; now += 1000 {
		if act := m.tickHealth(now, HealthUnknown); act != ActNone {
			t.Fatalf("blind time triggered %v at t=%dms — it must be excluded from the countdown", act, now)
		}
	}
	// One more genuine failure: only ~1 s of MEASURED badness has accumulated, so still no rollback.
	if act := m.tick(23_000, false); act != ActNone {
		t.Fatalf("after 1s of measured badness and 20s blind, got %v — the blind time was counted", act)
	}
	// Sustained measured failure past the deadline still rolls back: the hold is not a disable.
	var got Action
	for now := int64(24_000); now <= 40_000; now += 1000 {
		if a := m.tick(now, false); a != ActNone {
			got = a
			break
		}
	}
	if got != ActRollback {
		t.Fatalf("measured failure must still roll back, got %v", got)
	}
}

// Recovery observed after a blind spell behaves exactly as it would have without it.
func TestTickHealth_RecoveryAfterBlindSpellClearsTheCountdown(t *testing.T) {
	m := unknownMgr(t)
	m.tick(1000, false)
	m.tickHealth(2000, HealthUnknown)
	m.tickHealth(3000, HealthUnknown)
	if act := m.tick(4000, true); act != ActNone {
		t.Fatalf("recovery inside the keep window should just clear the countdown, got %v", act)
	}
	if m.bad {
		t.Error("a measured success must clear the bad flag")
	}
}

// The two-valued form must keep meaning exactly what it meant, so the 40-odd existing cases that
// use it still test what they were written to test.
func TestTick_BoolFormIsUnchanged(t *testing.T) {
	a := unknownMgr(t)
	b := unknownMgr(t)
	for now := int64(1000); now <= 45_000; now += 1000 {
		if got, want := a.tick(now, false), b.tickHealth(now, HealthDown); got != want {
			t.Fatalf("tick(false) and tickHealth(Down) diverged at t=%dms: %v vs %v", now, got, want)
		}
	}
}

// HealthUnknown must be the zero value: a Health that was never set cannot default to a verdict.
func TestHealthZeroValueIsUnknown(t *testing.T) {
	var h Health
	if h != HealthUnknown {
		t.Fatalf("the zero Health must be Unknown, got %v", h)
	}
}

// The escalation's value is its ORDER: try the previous configuration, and only reboot if that did
// not help. The reboot threshold used to be tested before the rollback one, so a single tick that
// arrived past BOTH deadlines — a hung probe, a suspended process, a clock jump — rebooted the
// router without ever attempting the rollback. Observed as a flaky test under parallel load, which
// is the same event a loaded router would produce.
func TestTickHealth_RebootNeverPrecedesTheRollbackAttempt(t *testing.T) {
	m := unknownMgr(t) // RollbackAfter 10s, RebootAfter 30s
	// One bad probe starts the countdown, then the NEXT observation arrives 10 minutes later:
	// past both deadlines at once.
	m.tick(1000, false)
	if act := m.tick(600_000, false); act != ActRollback {
		t.Fatalf("a tick past both deadlines must still roll back first, got %v", act)
	}
	// Only now may it reboot.
	if act := m.tick(601_000, false); act != ActReboot {
		t.Fatalf("after the rollback, the next bad tick should reboot, got %v", act)
	}
}

// A rollback that the caller could not perform must not wedge the escalation: tick marks rolledBack
// before run() invokes the closure, so the reboot is still reachable.
func TestTickHealth_RebootStillReachableAfterAFailedRollback(t *testing.T) {
	m := unknownMgr(t)
	m.tick(1000, false)
	if act := m.tick(20_000, false); act != ActRollback {
		t.Fatalf("expected the rollback first, got %v", act)
	}
	// The caller's rollback failed — nothing reports back into tick, which is the point.
	if act := m.tick(40_000, false); act != ActReboot {
		t.Fatalf("a failed rollback must not block the last resort, got %v", act)
	}
}
