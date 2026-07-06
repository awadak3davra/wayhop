package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"wayhop/internal/model"
	"wayhop/internal/serverstore"
	"wayhop/internal/version"
)

// backupSchemaVersion is the on-disk schema version of a full-setup backup
// bundle. A future incompatible change bumps this; handleBackupRestore refuses a
// bundle whose wayhop_backup is not exactly this value.
const backupSchemaVersion = 1

// backupBundle is the single-file, portable snapshot of the user's whole setup:
// the routing profile (endpoints/groups/rules/lists — which carries connection
// SECRETS, intended for a PERSONAL backup), the saved-server registry, and the
// two non-access-critical config knobs that shape routing (routing_mode +
// gateway). It deliberately omits the access-critical config (listen/ports/host
// allow-list/subscription token/clash secret) so a restore can NEVER move the
// panel's address or lock the operator out (see handleBackupRestore).
type backupBundle struct {
	Schema      int                  `json:"wayhop_backup"`          // schema marker; must equal backupSchemaVersion
	Version     string               `json:"version"`                // build version that produced the file (informational)
	Profile     model.Profile        `json:"profile"`                // endpoints/groups/rules/lists (carries secrets)
	Servers     []serverstore.Server `json:"servers,omitempty"`      // saved-server registry (no SSH creds — see serverstore)
	RoutingMode string               `json:"routing_mode,omitempty"` // config.RoutingMode
	Gateway     bool                 `json:"gateway"`                // config.Gateway
}

// handleBackupExport (GET /api/backup) streams the whole-setup backup as a
// downloadable JSON attachment. It is served behind the same access gate as the
// rest of /api (the panel middleware chain). The bundle carries connection
// secrets by design — it is a PERSONAL backup, not a shareable one.
func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	cfg := s.config()
	bundle := backupBundle{
		Schema:      backupSchemaVersion,
		Version:     version.Version,
		Profile:     s.store.Profile(),
		Servers:     s.servers.List(),
		RoutingMode: cfg.RoutingMode,
		Gateway:     cfg.Gateway,
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "marshal failed: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="wayhop-backup.json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleBackupRestore (POST /api/backup/restore) restores a whole-setup backup.
// It is SAFE BY DESIGN: it validates the profile BEFORE touching anything, never
// auto-applies (the user reviews and presses Apply, which goes through the
// existing fail-safe path), and NEVER writes the access-critical config — so a
// restore cannot change the panel's bind/port/allow-list/subscription token and
// lock the operator out (mirrors the handleConfigReset carve-out).
func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	var bundle backupBundle
	if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if bundle.Schema != backupSchemaVersion {
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("not a WayHop backup (wayhop_backup=%d, want %d)", bundle.Schema, backupSchemaVersion))
		return
	}
	// Validate the profile BEFORE mutating any state so a bad bundle changes
	// NOTHING. store.Replace validates again (defense in depth), but validating
	// here lets us fail closed with a clear 400 before we touch the server store
	// or the config.
	if err := bundle.Profile.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid profile in backup: "+err.Error())
		return
	}
	// Replace the whole profile (validates + persists atomically).
	if err := s.store.Replace(bundle.Profile); err != nil {
		writeErr(w, http.StatusInternalServerError, "restore profile failed: "+err.Error())
		return
	}
	// Restore the saved-server registry best-effort. serverstore has no
	// replace-all API (only List/Upsert), so we Upsert each record from the
	// bundle by ID — additive: existing servers not in the bundle are left
	// untouched, and same-ID records are overwritten. A single bad record is
	// reported but does not undo the profile restore.
	servers := 0
	for _, sv := range bundle.Servers {
		if sv.ID == "" {
			continue // serverstore.Upsert would reject it; skip rather than fail the whole restore
		}
		if err := s.servers.Upsert(sv); err != nil {
			writeErr(w, http.StatusInternalServerError, "restore server "+sv.ID+" failed: "+err.Error())
			return
		}
		servers++
	}
	// Config: restore ONLY the two routing-shaping knobs, under cfgMu like every
	// other config writer. The access-critical fields (Listen / Ports.UI /
	// AllowedHosts / Subscription.Token / Clash secret) are deliberately left as
	// they are — preserving them is what keeps the panel reachable after a
	// restore. Validate the resulting config before Save so an unknown
	// routing_mode in the bundle can't persist an unstartable config.
	if err := s.restoreConfig(bundle.RoutingMode, bundle.Gateway); err != nil {
		writeErr(w, http.StatusBadRequest, "restore config failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"restored":  true,
		"endpoints": len(bundle.Profile.Endpoints),
		"groups":    len(bundle.Profile.Groups),
		"servers":   servers,
		"note":      "review and Apply to activate",
	})
}

// restoreConfig sets only RoutingMode + Gateway on the live config and saves it,
// under cfgMu (the single authority for s.cfg writes — see (*Server).config()).
// It validates the candidate config before persisting and leaves the live config
// untouched if validation fails, so a bundle carrying an unknown routing_mode
// can never brick startup.
func (s *Server) restoreConfig(routingMode string, gateway bool) error {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	candidate := *s.cfg
	candidate.RoutingMode = routingMode
	candidate.Gateway = gateway
	if err := candidate.Validate(); err != nil {
		return err
	}
	s.cfg.RoutingMode = routingMode
	s.cfg.Gateway = gateway
	return s.cfg.Save()
}
