package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wayhop/internal/failsafe"
	"wayhop/internal/tgbot"
)

// windowServer is a demo server whose fail-safe never checks or rolls back on its own during a test.
func windowServer(t *testing.T) *Server {
	t.Helper()
	s := tgServer(t)
	s.failsafe = failsafe.New(failsafe.Durations{Grace: time.Hour, Interval: time.Hour, RollbackAfter: time.Hour, RebootAfter: time.Hour, KeepWindow: time.Hour})
	t.Cleanup(func() { s.failsafe.Disarm() })
	return s
}

// testApply records rev as a Test Apply does, under applyMu, and arms its window when armed (false:
// the window passed and it runs unsaved).
func testApply(s *Server, rev string, at int64, armed bool) {
	r := &appliedRevision{Rev: rev, At: at, Materialization: applyhealth_demoMaterialization()}
	s.recordApplied(false, r)
	if armed {
		s.armFailSafe(s.liveRevision())
	}
}

// A Test B from the panel holds applyMu for its whole run. An owner pressed Keep on Test A's message
// meanwhile: the bot's look at the window passed (B was not recorded yet), Keep waited for applyMu and
// then committed whatever was live, B, untested and never asked about. Roll back waited the same way
// and rolled back B after A's window had passed, or was refused as superseded inside it. The decision
// names A's window, and the daemon refuses it under the lock.
func TestBotDecisionOnAReplacedTestChangesNothing(t *testing.T) {
	for _, tc := range []struct {
		name        string
		keep, armed bool
	}{{"keep in the window", true, true}, {"keep after it", true, false}, {"roll back in the window", false, true}, {"roll back after it", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := windowServer(t)
			s.applyMu.Lock()
			testApply(s, "rev-a", 100, tc.armed)
			s.applyMu.Unlock()
			wA := applyWindow(s.liveRevision())

			s.applyMu.Lock() // Test B is running
			done := make(chan error, 1)
			go func() {
				if tc.keep {
					done <- tgBackend{s}.ConfirmApply(context.Background(), wA)
				} else {
					done <- tgBackend{s}.RollbackApply(context.Background(), wA)
				}
			}()
			time.Sleep(50 * time.Millisecond) // the press reaches applyMu and waits there
			testApply(s, "rev-b", 200, true)
			s.applyMu.Unlock()

			var err error
			select {
			case err = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the decision did not return")
			}
			if !errors.Is(err, tgbot.ErrWindowChanged) {
				t.Fatalf("decision on A with B running: %v", err)
			}
			if live := s.liveRevision(); live == nil || live.Rev != "rev-b" {
				t.Fatalf("Test B was decided: live %+v, committed %+v", live, s.committedRevision())
			}
			if st := s.failsafe.Status(); !st.Pending || st.Phase != "armed" {
				t.Fatalf("B's window: %+v", st)
			}
			// B's own name still decides B.
			wB := applyWindow(s.liveRevision())
			if tc.keep {
				err = tgBackend{s}.ConfirmApply(context.Background(), wB)
			} else {
				err = tgBackend{s}.RollbackApply(context.Background(), wB)
			}
			if err != nil || s.liveRevision() != nil {
				t.Fatalf("deciding B by its own name: %v, live %+v", err, s.liveRevision())
			}
		})
	}
}

// The panel's calls are unchanged: no window (its banner posts {}) decides what runs unsaved. A named
// one is checked, and /api/apply/status names the window to send.
func TestApplyDecisionHandlersTakeAnOptionalWindow(t *testing.T) {
	s := windowServer(t)
	s.applyMu.Lock()
	testApply(s, "rev-a", 100, true)
	s.applyMu.Unlock()

	w := httptest.NewRecorder()
	s.handleApplyStatus(w, httptest.NewRequest(http.MethodGet, "/api/apply/status", nil))
	wA := applyWindow(s.liveRevision())
	if !strings.Contains(w.Body.String(), `"window":"`+wA+`"`) {
		t.Fatalf("status does not name the window: %s", w.Body)
	}

	for _, path := range []string{"/api/apply/confirm", "/api/apply/rollback"} {
		w = httptest.NewRecorder()
		h := s.handleApplyConfirm
		if strings.HasSuffix(path, "rollback") {
			h = s.handleApplyRollback
		}
		h(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"window":"0123456789"}`)))
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), applyCodeWindowChanged) {
			t.Fatalf("%s for another window = %d %s", path, w.Code, w.Body)
		}
		w = httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"window":`)))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s with a broken body = %d %s", path, w.Code, w.Body)
		}
	}
	if s.liveRevision() == nil {
		t.Fatal("a refused decision decided the Test")
	}
	w = httptest.NewRecorder()
	s.handleApplyConfirm(w, httptest.NewRequest(http.MethodPost, "/api/apply/confirm", strings.NewReader(`{}`)))
	if w.Code != http.StatusOK || s.liveRevision() != nil || s.committedRevision() == nil || s.committedRevision().Rev != "rev-a" {
		t.Fatalf("the panel's Keep = %d %s", w.Code, w.Body)
	}
	// A kept Test keeps its window's name as the committed revision: the watcher tells a Keep from a
	// newer Test replacing it by that when both fall inside one pulse.
	if c := (tgBackend{s}).Pulse(context.Background()).FailSafe.Committed; c != wA {
		t.Fatalf("the committed revision is named %q, the kept window %q", c, wA)
	}
}
