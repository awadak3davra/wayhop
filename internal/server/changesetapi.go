package server

import (
	"net/http"
	"reflect"

	"wayhop/internal/changeset"
	"wayhop/internal/config"
	"wayhop/internal/model"
)

// The change set is the diff between the applied baseline (the apply-state record's live or
// committed revision) and the currently saved state. It is what the review panel shows and what
// Undo reverts against.

// handleChangeSetUndo (POST /api/changeset/undo) REVERTS part of the pending change set in the real
// stored data — removing a row from the review must undo the underlying change, not merely hide it.
// Scopes: field | object | subsystem | all.
//
// It is baseline-pinned: an undo computed against a superseded baseline is rejected (409), because
// reverting "to the baseline" is meaningless once the baseline has moved. baseline_rev is optional.
func (s *Server) handleChangeSetUndo(w http.ResponseWriter, r *http.Request) {
	var body struct {
		changeset.UndoRequest
		BaselineRev string `json:"baseline_rev,omitempty"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		writeErrNoStore(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// Serialize with Apply, and do the staleness check + baseline read INSIDE the lock: checking
	// outside would let an Apply land between the check and the write, so the undo would revert
	// against a baseline that is no longer current — the exact race the check exists to stop.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	base := s.appliedBaseline()
	if base == nil || base.Desired == nil {
		writeErrNoStore(w, http.StatusConflict, "no applied baseline to undo against — apply once first")
		return
	}
	if body.BaselineRev != "" && body.BaselineRev != base.Rev {
		writeErrNoStore(w, http.StatusConflict, "the applied configuration changed since you reviewed it — reload the change list and review again")
		return
	}

	// applyMu does not stop the other writers: a Settings save takes only cfgMu, and a feed refresh or
	// a native-tunnel reconcile only the store's lock. So neither write below may start from a copy
	// read before it waited. The profile undo is computed INSIDE the store's write lock from the
	// profile as it is then; replacing it with a copy read earlier published that copy over a refresh
	// that landed meanwhile. The settings write then touches only what the undo changed (see
	// setUndoneSettings).
	curCfg := s.config()
	var newCfg config.Config
	var undoErr, invalid error
	err := s.store.Reconcile(func(p *model.Profile) bool {
		np, nc, err := changeset.Undo(base.Desired.Profile, *p, base.Desired.Config, curCfg, body.UndoRequest)
		if err != nil {
			undoErr = err
			return false
		}
		newCfg = nc
		if reflect.DeepEqual(np, *p) {
			return false // a settings-only undo: no profile write, no flash wear
		}
		// The full gate Replace applies; the store's own publish check refuses less.
		if err := np.Validate(); err != nil {
			invalid = err
			return false
		}
		*p = np
		return true
	})
	if undoErr != nil {
		writeErrNoStore(w, http.StatusBadRequest, undoErr.Error())
		return
	}
	if err == nil {
		err = invalid
	}
	if err != nil {
		writeErrNoStore(w, http.StatusBadRequest, "undo failed: "+err.Error())
		return
	}
	if !changesetSettingsEqual(curCfg, newCfg) {
		if err := s.setUndoneSettings(curCfg, newCfg); err != nil {
			writeErrNoStore(w, http.StatusInternalServerError, "undo saved the profile but the settings write failed: "+err.Error())
			return
		}
	}
	// Report the RECOMPUTED set so the caller updates its count/banner from truth, not by assuming.
	desired, err := s.captureDesiredSnapshot()
	if err != nil {
		writeErrNoStore(w, http.StatusServiceUnavailable, "the saved configuration is changing — retry")
		return
	}
	cs := changeset.Diff(base.Rev, desired.DesiredRev, base.Desired.Profile, desired.Profile, base.Desired.Config, desired.Config)
	writeJSONNoStore(w, http.StatusOK, map[string]any{
		"undone":         true,
		"count":          cs.Count(),
		"requires_apply": cs.RequiresApply(),
		"may_interrupt":  cs.MayInterrupt(),
		"changes":        cs.Changes,
		"pending":        base.Rev != desired.DesiredRev,
	})
}

// changesetSettingsEqual reports whether the reviewable settings are unchanged, so an undo that only
// touched the profile does not rewrite config.json needlessly.
func changesetSettingsEqual(a, b config.Config) bool {
	return a.RoutingMode == b.RoutingMode && a.Offload == b.Offload && a.RuleSetDetour == b.RuleSetDetour &&
		a.CoreOverride == b.CoreOverride
}

// setUndoneSettings writes the reviewable settings an undo changed (from -> to) onto the LIVE config,
// read under cfgMu at write time, and saves it. Writing a whole config copied before the undo
// waited for the store reverted every Settings save that answered 200 meanwhile (allowed hosts,
// ports, fail-safe), and a reviewable setting the undo did not touch keeps whatever is live now.
// Like persistConfig, a failed Save rolls memory back so it never diverges from config.json.
func (s *Server) setUndoneSettings(from, to config.Config) error {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	snap := cloneConfig(s.cfg)
	if from.RoutingMode != to.RoutingMode {
		s.cfg.RoutingMode = to.RoutingMode
	}
	if from.Offload != to.Offload {
		s.cfg.Offload = to.Offload
	}
	if from.RuleSetDetour != to.RuleSetDetour {
		s.cfg.RuleSetDetour = to.RuleSetDetour
	}
	if from.CoreOverride != to.CoreOverride {
		s.cfg.CoreOverride = to.CoreOverride
	}
	if err := s.cfg.Save(); err != nil {
		*s.cfg = snap
		return err
	}
	return nil
}

// handleChangeSet (GET /api/changeset) returns the canonical, structured list of everything an Apply
// would change: the diff between the APPLIED baseline and the currently saved (desired) state.
//
// It is the data behind the review panel — grouped by subsystem, with per-field before/after,
// impact, apply/restart requirements and connectivity risk. Secrets are never included (the differ
// reports only "Not set → Set" / "Changed" / "Removed").
//
// baseline_available=false means no applied baseline exists yet (fresh install). The UI must then
// say "no baseline to compare against" instead of presenting every object as newly added.
func (s *Server) handleChangeSet(w http.ResponseWriter, r *http.Request) {
	desired, err := s.captureDesiredSnapshot()
	if err != nil {
		writeErrNoStore(w, http.StatusServiceUnavailable, "the saved configuration is changing — retry")
		return
	}
	base := s.appliedBaseline()
	changes := s.planChanges(desired, base)
	resp := map[string]any{
		"baseline_available": changes.BaselineAvailable,
		"baseline_rev":       changes.BaselineRev,
		"desired_rev":        desired.DesiredRev,
		"pending":            changes.Pending,
		"changes":            changes.Changes,
	}
	if !changes.BaselineAvailable {
		resp["reason"] = changes.Reason
		writeJSONNoStore(w, http.StatusOK, resp)
		return
	}
	resp["count"] = changes.Count
	resp["requires_apply"] = changes.RequiresApply
	resp["may_interrupt"] = changes.MayInterrupt
	resp["by_subsystem"] = changes.BySubsystem
	writeJSONNoStore(w, http.StatusOK, resp)
}
