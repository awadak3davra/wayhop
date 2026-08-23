package server

import (
	"encoding/json"
	"net/http"
	"strings"
)

// handleDriftIgnore implements the spec's "ignore this unmanaged object" drift action.
//
//	POST /api/drift/ignore  {"endpoint_id": "...", "ignore": true|false}
//
// Dismissing is per-object and reversible. Both properties are deliberate: a suppress-everything
// switch would hide the NEXT tunnel that disappears unexpectedly, and a permanent dismissal would
// leave a user who changed their mind editing config files by hand.
//
// This changes what the user is TOLD, never what the router does — nothing is deleted, disabled or
// applied. That separation is what makes it safe to offer as a one-click action next to a warning.
func (s *Server) handleDriftIgnore(w http.ResponseWriter, r *http.Request) {
	var body struct {
		EndpointID string `json:"endpoint_id"`
		Ignore     *bool  `json:"ignore"` // pointer so an omitted field is an error, not a silent un-ignore
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	id := strings.TrimSpace(body.EndpointID)
	if id == "" {
		writeErr(w, http.StatusBadRequest, "endpoint_id is required")
		return
	}
	if body.Ignore == nil {
		writeErr(w, http.StatusBadRequest, "ignore must be true or false")
		return
	}

	list, err := s.setIgnoredDrift(id, *body.Ignore)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ignored_drift": list})
}

// setIgnoredDrift applies the dismissal under cfgMu and persists it, rolling the in-memory change
// back if Save fails so RAM never diverges from disk.
//
// It deliberately does NOT go through persistConfig, and that is the whole of this fix. persistConfig
// writes via applyConfigFields, which copies the fields the bulk Settings PUT owns — and IgnoredDrift
// is not one of them: the Settings page never sends `ignored_drift` (zero occurrences in web/dist), so
// a field copied there would be wiped to nil by every save of an unrelated setting. Going through it
// anyway cost the dismissal outright: applyConfigFields had no line for the field, so the handler
// answered 200 with the new list while the daemon kept nothing at all — measured against the running
// demo, POST then GET, the id was gone. This writes under cfgMu and Saves directly, which is the
// only shape that survives applyConfigFields not carrying the field.
func (s *Server) setIgnoredDrift(id string, ignore bool) ([]string, error) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	old := s.cfg.IgnoredDrift // applyIgnore allocates, so old still backs the pre-change list
	s.cfg.IgnoredDrift = applyIgnore(old, id, ignore)
	if err := s.cfg.Save(); err != nil {
		s.cfg.IgnoredDrift = old
		return nil, err
	}
	// A copy: the caller writes this to the response after the lock is released, and the next
	// dismissal replaces the slice this one would otherwise still be reading.
	return append([]string(nil), s.cfg.IgnoredDrift...), nil
}

// applyIgnore adds or removes id, keeping the list free of duplicates. Pure, so the set semantics
// are testable without touching config persistence.
func applyIgnore(list []string, id string, ignore bool) []string {
	out := make([]string, 0, len(list)+1)
	seen := false
	for _, v := range list {
		if v == id {
			seen = true
			if !ignore {
				continue // removing
			}
		}
		// Drop duplicates that may already be present from a hand-edited config.
		dup := false
		for _, kept := range out {
			if kept == v {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, v)
		}
	}
	if ignore && !seen {
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil // keep the field omitempty-clean rather than persisting an empty array
	}
	return out
}
