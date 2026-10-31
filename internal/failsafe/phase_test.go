package failsafe

import (
	"errors"
	"testing"
)

// The phase a window closes with is what the panel toasts and Telegram announces. These pin the
// two ways it used to close with a verdict that did not happen.

// Auto-reboot is off by default. The window still ends at RebootAfter, but it used to end as
// "reboot": the panel said the fail-safe escalated to a reboot and Telegram sent a critical
// "Rebooting the router" while nothing rebooted, and a preceding rollback_failed was overwritten.
func TestTickHealth_NoRebootPhaseWhenRebootIsDisabled(t *testing.T) {
	for _, failRB := range []bool{false, true} {
		m := unknownMgr(t) // RollbackAfter 10s, RebootAfter 30s, allowReboot false
		m.tick(1000, false)
		if act := m.tick(20_000, false); act != ActRollback {
			t.Fatalf("expected the rollback first, got %v", act)
		}
		want := "rolled_back"
		if failRB {
			m.markRollbackFailed(m.epoch, errors.New("restore failed"))
			want = "rollback_failed"
		}
		if act := m.tick(40_000, false); act != ActReboot {
			t.Fatalf("the window must still end at RebootAfter, got %v", act)
		}
		s := m.Status()
		if s.Pending {
			t.Fatal("the window must close at RebootAfter")
		}
		if s.Phase != want {
			t.Fatalf("failRB=%v: phase=%q, want %q — no reboot is going to happen", failRB, s.Phase, want)
		}
		if failRB && s.LastError == "" {
			t.Fatal("the rollback error must survive the close")
		}
	}
}

func TestTickHealth_RebootPhaseWhenRebootWillRun(t *testing.T) {
	m := unknownMgr(t)
	m.allowReboot, m.reboot = true, func() {}
	m.tick(1000, false)
	m.tick(20_000, false)
	if act := m.tick(40_000, false); act != ActReboot {
		t.Fatalf("got %v, want ActReboot", act)
	}
	if s := m.Status(); s.Phase != "reboot" {
		t.Fatalf("phase=%q, want reboot", s.Phase)
	}
}

// A blind probe after the rollback used to relabel the window "unverified", and the next healthy
// tick closed it with that label: no rollback toast in the panel, a quiet "ended" in Telegram, and a
// rollback_failed hidden behind it.
func TestTickHealth_UnknownAfterRollbackKeepsTheRollbackPhase(t *testing.T) {
	for _, failRB := range []bool{false, true} {
		m := unknownMgr(t)
		m.tick(1000, false)
		if act := m.tick(20_000, false); act != ActRollback {
			t.Fatalf("expected the rollback, got %v", act)
		}
		want := "rolled_back"
		if failRB {
			m.markRollbackFailed(m.epoch, errors.New("restore failed"))
			want = "rollback_failed"
		}
		m.tickHealth(21_000, HealthUnknown)
		if got := m.Status().Phase; got != want {
			t.Fatalf("failRB=%v: a blind tick relabelled the window %q, want %q", failRB, got, want)
		}
		if act := m.tickHealth(22_000, HealthUp); act != ActDone {
			t.Fatalf("recovery after the rollback must close the window, got %v", act)
		}
		if s := m.Status(); s.Pending || s.Phase != want {
			t.Fatalf("failRB=%v: closed as pending=%v phase=%q, want %q", failRB, s.Pending, s.Phase, want)
		}
	}
}
