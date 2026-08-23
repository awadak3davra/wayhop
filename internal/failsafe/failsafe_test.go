package failsafe

import (
	"testing"
	"time"
)

func mgr() *Manager {
	return New(Durations{
		Grace: 0, Interval: time.Millisecond,
		RollbackAfter: 1000 * time.Millisecond,
		RebootAfter:   3000 * time.Millisecond,
		KeepWindow:    2000 * time.Millisecond,
	})
}

func TestHealthyKeepsLive(t *testing.T) {
	m := mgr()
	m.pending, m.phase, m.deadline = true, "armed", 2000
	if a := m.tick(500, true); a != ActNone {
		t.Fatalf("t=500 ok -> %v, want None", a)
	}
	if a := m.tick(2001, true); a != ActDone {
		t.Fatalf("t=2001 ok past deadline -> %v, want Done", a)
	}
	if m.Status().Phase != "live_unsaved" {
		t.Fatalf("phase=%s, want live_unsaved", m.Status().Phase)
	}
}

func TestBadRollsBackThenReboots(t *testing.T) {
	m := mgr()
	m.pending, m.deadline = true, 100000
	if a := m.tick(0, false); a != ActNone {
		t.Fatalf("first bad -> %v", a)
	}
	if a := m.tick(500, false); a != ActNone {
		t.Fatalf("badFor=500 -> %v (< rollbackAfter)", a)
	}
	if a := m.tick(1000, false); a != ActRollback {
		t.Fatalf("badFor=1000 -> %v, want Rollback", a)
	}
	if a := m.tick(1500, false); a != ActNone {
		t.Fatalf("post-rollback still bad -> %v", a)
	}
	if a := m.tick(3000, false); a != ActReboot {
		t.Fatalf("badFor=3000 -> %v, want Reboot", a)
	}
}

func TestRecoversAfterRollback(t *testing.T) {
	m := mgr()
	m.pending, m.deadline = true, 100000
	m.tick(0, false)
	m.tick(1000, false) // rollback
	if !m.rolledBack {
		t.Fatal("expected rolledBack=true")
	}
	if a := m.tick(1200, true); a != ActDone {
		t.Fatalf("recovered after rollback -> %v, want Done", a)
	}
}

func TestConfirm(t *testing.T) {
	m := mgr()
	m.pending = true
	m.Confirm()
	if s := m.Status(); s.Pending || s.Phase != "committed" {
		t.Fatalf("confirm: pending=%v phase=%s", s.Pending, s.Phase)
	}
}
