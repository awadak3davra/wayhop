package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// applystate_server builds an isolated *Server whose applied.json lives in the
// temp data dir. The default config points DataDir at /opt/var/wayhop, which does
// not exist on the test host, so we redirect it at the same temp dir the store uses.
func applystate_server(t *testing.T) *Server {
	t.Helper()
	s, cfgPath := sharehandlers_server(t)
	s.cfg.DataDir = filepath.Dir(cfgPath)
	return s
}

// applystate_pending computes the same saved!=applied view handleState exposes,
// so a test can assert "pending" without going through the HTTP layer.
func applystate_pending(s *Server) bool {
	saved := s.canonicalHash(s.config(), s.store.Profile())
	s.applyStateMu.Lock()
	applied := s.appliedHash
	s.applyStateMu.Unlock()
	return applied != "" && saved != applied
}

// applystate_record is the test shorthand for "a successful Apply of the CURRENT
// saved state" — it snapshots (config, profile) exactly like handleApply does.
func applystate_record(s *Server) {
	s.recordApplied(s.config(), s.store.Profile())
}

// TestApplyState_CanonicalHashDeterministic guards the core assumptions: the same
// inputs always hash identically (an untouched system never shows "pending"), a
// PROFILE edit changes the hash, and — new in v2 — a CONFIG edit that feeds the
// apply (routing mode / TUN / offload) changes it too, because Apply materializes
// config, not just the profile.
func TestApplyState_CanonicalHashDeterministic(t *testing.T) {
	s := applystate_server(t)
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "NL")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	c, p := s.config(), s.store.Profile()
	h1, h2 := s.canonicalHash(c, p), s.canonicalHash(c, p)
	if h1 == "" || h1 != h2 {
		t.Fatalf("hash not deterministic: %q vs %q", h1, h2)
	}
	// A profile edit must change the hash.
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "Renamed")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if s.canonicalHash(s.config(), s.store.Profile()) == h1 {
		t.Fatal("hash did not change after a profile edit")
	}
	// A CONFIG edit that feeds the apply must change it too (v2: canonical snapshot
	// of ALL applied inputs, not just the profile).
	base := s.canonicalHash(s.config(), s.store.Profile())
	s.cfg.Gateway = !s.cfg.Gateway
	if s.canonicalHash(s.config(), s.store.Profile()) == base {
		t.Fatal("hash did not change after a config (TUN/gateway) edit — config inputs not in the snapshot")
	}
	s.cfg.Gateway = !s.cfg.Gateway // restore
	s.cfg.Offload = "sw"
	if s.canonicalHash(s.config(), s.store.Profile()) == base {
		t.Fatal("hash did not change after a config (offload) edit")
	}
}

// TestApplyState_PendingSurvivesReload is the headline regression: an edit that
// was saved but not applied must STILL read as pending after the daemon restarts
// / the page reloads. A frontend-only snapshot would reset to "all applied".
func TestApplyState_PendingSurvivesReload(t *testing.T) {
	s := applystate_server(t)
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "NL")); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Bootstrap: no applied.json yet -> applied := saved -> not pending.
	s.loadAppliedState()
	if applystate_pending(s) {
		t.Fatal("fresh bootstrap must not be pending (applied := saved)")
	}
	if s.appliedHash == "" {
		t.Fatal("bootstrap must set an applied hash")
	}

	// A successful Apply of the current state records it as the applied revision.
	applystate_record(s)
	appliedAfterApply := s.appliedHash
	if applystate_pending(s) {
		t.Fatal("right after Apply, saved==applied -> not pending")
	}

	// The user edits the profile but does NOT apply.
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v2", "DE")); err != nil {
		t.Fatalf("edit: %v", err)
	}
	if !applystate_pending(s) {
		t.Fatal("an unapplied edit must be pending")
	}

	// Simulate a daemon RESTART / page RELOAD: drop the in-memory state and
	// re-load from applied.json.
	s.appliedHash, s.appliedAt = "", 0
	s.prevAppliedHash, s.prevAppliedAt = "", 0
	s.loadAppliedState()
	if s.appliedHash != appliedAfterApply {
		t.Fatalf("applied hash not persisted across reload: got %q want %q", s.appliedHash, appliedAfterApply)
	}
	if !applystate_pending(s) {
		t.Fatal("PENDING MUST SURVIVE RELOAD (the bug this fixes): edited-but-not-applied reset to applied")
	}

	// Applying now clears pending, and that also survives a reload.
	applystate_record(s)
	if applystate_pending(s) {
		t.Fatal("after applying the edit, not pending")
	}
	s.appliedHash, s.appliedAt = "", 0
	s.loadAppliedState()
	if applystate_pending(s) {
		t.Fatal("cleared pending must survive reload")
	}
}

// TestApplyState_FailedApplyKeepsPending covers the Apply-failure / retry path:
// when Apply fails (reload/commit/PBR error), handleApply must NOT record the
// state as applied, so the change stays pending and the user can retry.
func TestApplyState_FailedApplyKeepsPending(t *testing.T) {
	s := applystate_server(t)
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "NL")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s.loadAppliedState()
	applystate_record(s) // baseline: v1 applied
	before := s.appliedHash

	// Edit, then simulate a FAILED apply: handleApply computes applyOK=false and
	// does NOT call recordApplied. The applied revision must not advance.
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v2", "DE")); err != nil {
		t.Fatalf("edit: %v", err)
	}
	// (no recordApplied — the apply failed)
	if !applystate_pending(s) {
		t.Fatal("failed apply must leave the edit pending")
	}
	if s.appliedHash != before {
		t.Fatalf("failed apply advanced the applied revision: got %q want %q", s.appliedHash, before)
	}

	// It survives a reload, so the retry affordance persists.
	s.appliedHash, s.appliedAt = "", 0
	s.loadAppliedState()
	if !applystate_pending(s) {
		t.Fatal("pending after a failed apply must survive reload so the user can retry")
	}
}

// TestApplyState_RollbackRestoresRevision is the v2 headline: after the fail-safe
// rolls the engine back to the pre-window config, the applied revision must revert
// too — /api/state has to say "pending" again (the user's saved changes are NOT
// active), and that reversal must survive a daemon restart (it is also what the
// router actually runs after the reboot escalation).
func TestApplyState_RollbackRestoresRevision(t *testing.T) {
	s := applystate_server(t)
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "NL")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s.loadAppliedState()
	applystate_record(s) // baseline: v1 applied
	v1 := s.appliedHash

	// Edit + apply the edit (the apply that will later be rolled back).
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v2", "DE")); err != nil {
		t.Fatalf("edit: %v", err)
	}
	applystate_record(s)
	if applystate_pending(s) {
		t.Fatal("after the second apply, not pending")
	}
	if s.prevAppliedHash != v1 {
		t.Fatalf("recordApplied must keep the replaced revision as the rollback target: prev=%q want %q", s.prevAppliedHash, v1)
	}

	// Fail-safe fires: the engine is restored to the pre-window config.
	s.restorePrevApplied()
	if s.appliedHash != v1 {
		t.Fatalf("rollback must restore the applied revision: got %q want %q", s.appliedHash, v1)
	}
	if !applystate_pending(s) {
		t.Fatal("after a rollback the saved (new) state is NOT active -> must be pending again")
	}

	// The reversal is persisted: a restart still shows pending.
	s.appliedHash, s.appliedAt = "", 0
	s.prevAppliedHash, s.prevAppliedAt = "", 0
	s.loadAppliedState()
	if s.appliedHash != v1 {
		t.Fatalf("restored revision not persisted: got %q want %q", s.appliedHash, v1)
	}
	if !applystate_pending(s) {
		t.Fatal("post-rollback pending must survive a restart")
	}

	// Idempotent: a second restore (double rollback signal) must not corrupt state.
	s.restorePrevApplied()
	if s.appliedHash != v1 {
		t.Fatal("double restore must be a no-op")
	}
}

// TestApplyState_HandleStateJSON pins the /api/state contract the Apply banner
// consumes: saved_hash / applied_hash / pending, with hashes equal when applied.
func TestApplyState_HandleStateJSON(t *testing.T) {
	s := applystate_server(t)
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "NL")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s.loadAppliedState() // applied := saved

	get := func() map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
		w := httptest.NewRecorder()
		s.handleState(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("state: got %d, want 200 (%s)", w.Code, w.Body.String())
		}
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatalf("decode: %v (%s)", err, w.Body.String())
		}
		return m
	}

	m := get()
	if m["pending"] != false {
		t.Errorf("fresh state pending = %v, want false", m["pending"])
	}
	if m["saved_hash"] == "" || m["saved_hash"] != m["applied_hash"] {
		t.Errorf("fresh state: saved_hash should equal applied_hash, got saved=%v applied=%v", m["saved_hash"], m["applied_hash"])
	}

	// Edit -> pending true, hashes differ.
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v2", "DE")); err != nil {
		t.Fatalf("edit: %v", err)
	}
	m = get()
	if m["pending"] != true {
		t.Errorf("after edit pending = %v, want true", m["pending"])
	}
	if m["saved_hash"] == m["applied_hash"] {
		t.Errorf("after edit saved_hash should differ from applied_hash")
	}

	// A config-only edit must ALSO flip pending (v2: all applied inputs).
	applystate_record(s)
	s.cfg.Offload = "hw"
	m = get()
	if m["pending"] != true {
		t.Errorf("after a config-only edit pending = %v, want true", m["pending"])
	}
}
