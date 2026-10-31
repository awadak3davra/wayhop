package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Keep is refused while a rollback is outstanding, so the status the banner polls must say so: the
// panel kept offering "Keep & Save" over a Test that no longer ran as tested.
func TestApplyStatus_ReportsAnOutstandingRollback(t *testing.T) {
	s, _ := applytest_server(t)
	m := applyboot_kernelMaterialization()
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, Materialization: m})
	live := &appliedRevision{Rev: "tested", At: 2, Materialization: m}
	s.recordApplied(false, live)

	status := func() (failed bool, msg string) {
		w := httptest.NewRecorder()
		s.handleApplyStatus(w, httptest.NewRequest(http.MethodGet, "/api/apply/status", nil))
		var st struct {
			Failed bool   `json:"rollback_failed"`
			Error  string `json:"rollback_error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		return st.Failed, st.Error
	}
	if failed, _ := status(); failed {
		t.Fatal("no rollback failed yet, but the status says one did")
	}
	s.noteRollbackFailed(live, rollbackPlaneCommitted, errors.New("sing-box did not stop"))
	if failed, msg := status(); !failed || msg != "sing-box did not stop" {
		t.Errorf("status = (%v, %q), want the outstanding rollback and its error", failed, msg)
	}
}
