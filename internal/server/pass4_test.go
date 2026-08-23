package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/pbr"
)

// pbrApplyServer builds a non-demo Server with an injected RecordRunner (which marks a test that
// wants the kernel-plane logic to run without touching the host). sing-box stays unavailable (the
// builder points at a missing binary). RoutingMode defaults to "hybrid".
func pbrApplyServer(t *testing.T) (*Server, *pbr.RecordRunner) {
	t.Helper()
	s := opshandlers_server(t)
	s.cfg.Demo = false
	s.cfg.RoutingMode = "hybrid"
	rr := &pbr.RecordRunner{}
	s.pbrRunner = rr
	return s, rr
}

// TestPass4_RoutingModePersists guards the pre-existing blocker: handlePutConfig must
// copy routing_mode, else the whole hybrid path is unreachable from the panel/API.
func TestPass4_RoutingModePersists(t *testing.T) {
	s := opshandlers_server(t)
	// Give the live config a file path so Save() works (Default() has none).
	path := t.TempDir() + "/config.json"
	data, _ := json.Marshal(s.cfg)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s.cfg = loaded
	cfgCapableHost(s) // this test means a router that can run hybrid; see the helper

	cfg := s.config()
	cfg.RoutingMode = "hybrid"
	body, _ := json.Marshal(cfg)
	w := httptest.NewRecorder()
	s.handlePutConfig(w, httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(string(body))))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /api/config = %d: %s", w.Code, w.Body.String())
	}
	if s.config().RoutingMode != "hybrid" {
		t.Errorf("RoutingMode = %q, want hybrid (handlePutConfig dropped it)", s.config().RoutingMode)
	}
}

// TestPass4_ConcurrentApplyRollbackNoDeadlock guards the failsafe-rollback-applyMu contract: the
// rollback closure takes applyMu to serialize with runApply. A concurrent Apply + manual RollbackNow
// must BOTH complete — a lock-ordering cycle would hang here (caught by the deadline), and -race
// catches any data race on shared state.
func TestPass4_ConcurrentApplyRollbackNoDeadlock(t *testing.T) {
	s := opshandlers_server(t)
	t.Cleanup(func() { s.failsafe.Confirm() })
	if err := s.store.UpsertEndpoint(opshandlers_awgEndpoint("awgA")); err != nil {
		t.Fatal(err)
	}
	// First apply arms the fail-safe window (stores the rollback closure).
	if w := opshandlers_post(s.handleApply, "/api/apply", `{"save":false}`); w.Code != http.StatusOK {
		t.Fatalf("arming apply: %d (%s)", w.Code, w.Body.String())
	}
	// Race a second apply against a manual rollback. They serialize on applyMu; without a correct
	// lock order this deadlocks.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = opshandlers_post(s.handleApply, "/api/apply", `{"save":false}`)
	}()
	go func() { defer wg.Done(); _ = s.failsafe.RollbackNow() }()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock: concurrent handleApply + RollbackNow did not complete within 20s")
	}
}
