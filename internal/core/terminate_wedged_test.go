package core

import (
	"path/filepath"
	"testing"
)

// terminate_wedged_test.go covers the wedge guard's way of stopping the core: it must stay desired,
// so the watchdog brings it back through StartIfDesiredDead, and it must not touch a process other
// than the one the guard looked at.

func TestPID_ZeroWhenNothingRuns(t *testing.T) {
	stub := corelifecycle_buildStub(t)
	s := New(stub, filepath.Join(t.TempDir(), "config.json"))
	if pid := s.PID(); pid != 0 {
		t.Fatalf("PID() = %d before Start, want 0", pid)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	corelifecycle_waitFor(t, "process to become Alive", s.Alive)
	if s.PID() == 0 {
		t.Fatal("PID() = 0 for a running process")
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if pid := s.PID(); pid != 0 {
		t.Fatalf("PID() = %d after Stop, want 0", pid)
	}
}

func TestTerminateWedged_StaysDesiredAndRestarts(t *testing.T) {
	stub := corelifecycle_buildStub(t)
	s := New(stub, filepath.Join(t.TempDir(), "config.json"))
	t.Cleanup(func() { _ = s.Stop() })
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	corelifecycle_waitFor(t, "process to become Alive", s.Alive)
	pid := s.PID()

	stopped, err := s.TerminateWedged(pid)
	if err != nil || !stopped {
		t.Fatalf("TerminateWedged(%d) = %v, %v; want true, nil", pid, stopped, err)
	}
	if s.Alive() {
		t.Fatal("still alive after TerminateWedged")
	}
	if !s.Desired() {
		t.Fatal("no longer desired, so the watchdog would never bring it back")
	}

	started, err := s.StartIfDesiredDead()
	if err != nil || !started {
		t.Fatalf("StartIfDesiredDead() = %v, %v; want true, nil", started, err)
	}
	corelifecycle_waitFor(t, "new process to become Alive", s.Alive)
	if next := s.PID(); next == pid || next == 0 {
		t.Fatalf("PID() = %d after the restart, was %d", next, pid)
	}
}

func TestTerminateWedged_LeavesAnotherProcessAlone(t *testing.T) {
	stub := corelifecycle_buildStub(t)
	s := New(stub, filepath.Join(t.TempDir(), "config.json"))
	t.Cleanup(func() { _ = s.Stop() })
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	corelifecycle_waitFor(t, "process to become Alive", s.Alive)

	stopped, err := s.TerminateWedged(s.PID() + 1)
	if err != nil || stopped {
		t.Fatalf("TerminateWedged(other) = %v, %v; want false, nil", stopped, err)
	}
	if !s.Alive() {
		t.Fatal("the running process was killed for another pid")
	}
}

func TestTerminateWedged_NoopOnceDeliberatelyStopped(t *testing.T) {
	stub := corelifecycle_buildStub(t)
	s := New(stub, filepath.Join(t.TempDir(), "config.json"))
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	corelifecycle_waitFor(t, "process to become Alive", s.Alive)
	pid := s.PID()
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	stopped, err := s.TerminateWedged(pid)
	if err != nil || stopped {
		t.Fatalf("TerminateWedged after Stop = %v, %v; want false, nil", stopped, err)
	}
	if s.Desired() {
		t.Fatal("TerminateWedged promoted a stopped core back to desired")
	}
}
