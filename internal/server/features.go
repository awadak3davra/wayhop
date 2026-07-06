package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	qrcode "github.com/skip2/go-qrcode"

	"wayhop/internal/config"
	"wayhop/internal/feature"
	"wayhop/internal/featurestore"
)

// This file wires the Plugins section: the compiled-in feature-module registry (internal/feature)
// into the server. "Installing" a plugin is flipping config.Features[id].Enabled — a HOT field, no
// restart. Module routes are mounted UNCONDITIONALLY (the mux is built once) and each module gates
// on the enabled flag inside its own handlers; the management routes below flip the flag.

// SetFeatures wires the per-module state store + the dir modules write files to. Called from main.go
// after New() (kept off New's signature so the many test constructors need no change).
func (s *Server) SetFeatures(fs *featurestore.Store, dataDir string) {
	s.features = fs
	s.featureDataDir = dataDir
}

// featureDeps builds the shared services every module receives. Fetch is the SSRF-guarded
// subscription client, which already honors the test-only allowInternalFetch bypass, so a module's
// httptest suites can reach loopback exactly like the subscription/CIDR-feed tests.
func (s *Server) featureDeps() *feature.Deps {
	return &feature.Deps{
		Cfg:       s.config,
		Fetch:     s.subscriptionFetchClient,
		QR:        func(text string, size int) ([]byte, error) { return qrcode.Encode(text, qrcode.Medium, size) },
		Store:     s.features,
		DataDir:   s.featureDataDir,
		Endpoints: s.featureEndpoints,
	}
}

// featureEndpoints exposes the user's ENABLED proxy endpoints (id/name/server only) to modules — a
// read-only projection of the profile, so a module can relate itself to the exits without reaching
// into the store or the full model.Endpoint. Used by the IPTV module to infer per-list exit countries.
func (s *Server) featureEndpoints() []feature.EndpointMeta {
	p := s.store.Profile()
	out := make([]feature.EndpointMeta, 0, len(p.Endpoints))
	for _, e := range p.Endpoints {
		if !e.Enabled {
			continue
		}
		out = append(out, feature.EndpointMeta{ID: e.ID, Name: e.Name, Server: e.Server})
	}
	return out
}

// registerFeatureRoutes mounts every compiled-in module's routes on the shared mux (called ONCE from
// Handler()). Each module's handler is responsible for gating on featureEnabled — a disabled module
// still has its routes mounted but they 404, so a toggle needs no mux rebuild / restart.
func (s *Server) registerFeatureRoutes(mux *http.ServeMux) {
	deps := s.featureDeps()
	for _, m := range feature.All() {
		m.Routes(mux, deps)
	}
}

// StartFeatures launches each module's background loop. Every Start must no-op while its module is
// disabled (re-checking the flag per tick), so this is safe to call unconditionally at boot.
func (s *Server) StartFeatures(ctx context.Context) {
	deps := s.featureDeps()
	for _, m := range feature.All() {
		go m.Start(ctx, deps)
	}
}

// featureEnabled reports whether a module id is installed (config.Features[id].Enabled). Modules call
// this at the top of every handler so a disabled plugin's routes 404.
func (s *Server) featureEnabled(id string) bool {
	fc, ok := s.config().Features[id]
	return ok && fc.Enabled
}

func knownFeature(id string) bool {
	for _, m := range feature.All() {
		if m.Descriptor().ID == id {
			return true
		}
	}
	return false
}

// featureRow is the GET /api/features list shape.
type featureRow struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Icon    string `json:"icon,omitempty"`
	Tip     string `json:"tip,omitempty"`
	Enabled bool   `json:"enabled"`
}

// handleFeaturesList lists every compiled-in module with its install state (GET /api/features),
// so the Plugins page can render the card grid + the nav can inject enabled modules.
func (s *Server) handleFeaturesList(w http.ResponseWriter, r *http.Request) {
	cfg := s.config()
	mods := feature.All()
	rows := make([]featureRow, 0, len(mods))
	for _, m := range mods {
		d := m.Descriptor()
		rows = append(rows, featureRow{ID: d.ID, Name: d.Name, Icon: d.Icon, Tip: d.Tip,
			Enabled: cfg.Features[d.ID].Enabled})
	}
	writeJSON(w, http.StatusOK, rows)
}

// handleFeatureToggle installs/uninstalls a module (PUT /api/features/{id}, body {enabled:bool}).
// Persisted via its own path (config.Features is NOT touched by the bulk config PUT), so a Settings
// save can't clobber it and vice-versa. Hot field — no restart.
func (s *Server) handleFeatureToggle(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !knownFeature(id) {
		writeErr(w, http.StatusNotFound, "unknown plugin")
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.setFeatureEnabled(id, body.Enabled); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": body.Enabled})
}

// setFeatureEnabled flips config.Features[id].Enabled under cfgMu and persists, rolling the in-memory
// change back if Save fails (so RAM never diverges from disk).
func (s *Server) setFeatureEnabled(id string, enabled bool) error {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if s.cfg.Features == nil {
		s.cfg.Features = map[string]config.FeatureConfig{}
	}
	old, existed := s.cfg.Features[id]
	fc := old
	fc.Enabled = enabled
	s.cfg.Features[id] = fc
	if err := s.cfg.Save(); err != nil {
		if existed {
			s.cfg.Features[id] = old
		} else {
			delete(s.cfg.Features, id)
		}
		return err
	}
	return nil
}

// handleFeatureSettingsGet returns a module's opaque settings blob (GET /api/features/{id}/settings).
func (s *Server) handleFeatureSettingsGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !knownFeature(id) {
		writeErr(w, http.StatusNotFound, "unknown plugin")
		return
	}
	raw := s.config().Features[id].Settings
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// handleFeatureSettingsPut stores a module's opaque settings blob (PUT /api/features/{id}/settings).
func (s *Server) handleFeatureSettingsPut(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !knownFeature(id) {
		writeErr(w, http.StatusNotFound, "unknown plugin")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body")
		return
	}
	if !json.Valid(raw) {
		writeErr(w, http.StatusBadRequest, "settings must be valid JSON")
		return
	}
	if err := s.setFeatureSettings(id, raw); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": true})
}

// setFeatureSettings persists a module's Settings blob under cfgMu (rollback on Save failure).
func (s *Server) setFeatureSettings(id string, raw json.RawMessage) error {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if s.cfg.Features == nil {
		s.cfg.Features = map[string]config.FeatureConfig{}
	}
	old, existed := s.cfg.Features[id]
	fc := old
	fc.Settings = append(json.RawMessage(nil), raw...)
	s.cfg.Features[id] = fc
	if err := s.cfg.Save(); err != nil {
		if existed {
			s.cfg.Features[id] = old
		} else {
			delete(s.cfg.Features, id)
		}
		return err
	}
	return nil
}
