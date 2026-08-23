package server

import (
	"encoding/json"
	"net/http"

	"wayhop/internal/changeset"
	"wayhop/internal/config"
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
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

	curCfg, curProfile := s.config(), s.store.Profile()
	newProfile, newCfg, err := changeset.Undo(base.Desired.Profile, curProfile, base.Desired.Config, curCfg, body.UndoRequest)
	if err != nil {
		writeErrNoStore(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.Replace(newProfile); err != nil {
		writeErrNoStore(w, http.StatusBadRequest, "undo failed: "+err.Error())
		return
	}
	if !changesetSettingsEqual(curCfg, newCfg) {
		// Write back the CURRENT config with only the reviewable settings replaced — never the whole
		// baseline snapshot, which would silently revert unrelated settings (ports, allowed hosts,
		// secrets) that the review never showed and that a concurrent PUT /api/config may have changed.
		merged := curCfg
		merged.RoutingMode = newCfg.RoutingMode
		merged.Offload = newCfg.Offload
		merged.RuleSetDetour = newCfg.RuleSetDetour
		newCfg = merged
		if err := s.persistConfig(&newCfg); err != nil {
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
	return a.RoutingMode == b.RoutingMode && a.Offload == b.Offload && a.RuleSetDetour == b.RuleSetDetour
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
