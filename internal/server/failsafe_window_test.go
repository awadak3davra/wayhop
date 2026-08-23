package server

import "testing"

// TestArmFailSafe_ArmsTheWindow pins that a Test apply arms the connectivity window and that the
// window's rollback closure restores the committed record (drops the live one).
func TestArmFailSafe_ArmsTheWindow(t *testing.T) {
	s := applyhealth_server(t)
	t.Cleanup(func() { s.failsafe.Confirm() }) // cancel the armed window's background run() goroutine

	if s.failsafe.Status().Pending {
		t.Fatal("no fail-safe window should be open on a fresh server")
	}
	live := &appliedRevision{Rev: "live", At: 1, Materialization: applyhealth_demoMaterialization()}
	s.recordApplied(false, live)
	// armFailSafe runs under applyMu in production (runApply holds it end-to-end).
	s.applyMu.Lock()
	s.armFailSafe(live)
	s.applyMu.Unlock()
	if st := s.failsafe.Status(); !st.Pending || st.Phase != "armed" {
		t.Fatalf("armFailSafe must arm the window: %+v", st)
	}
	// A manual rollback drives the closure: the live revision is dropped.
	if err := s.failsafe.RollbackNow(); err != nil {
		t.Fatalf("RollbackNow: %v", err)
	}
	if s.liveRevision() != nil {
		t.Error("the rollback closure must drop the live revision")
	}
	if st := s.failsafe.Status(); st.Phase != "rolled_back" || st.Pending {
		t.Errorf("after rollback: %+v", st)
	}
}
