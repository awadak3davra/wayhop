package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/feature"
	"wayhop/internal/featurestore"
)

// fakeFeat is a test feature module.
type fakeFeat struct{ id string }

func (m fakeFeat) Descriptor() feature.Descriptor {
	return feature.Descriptor{ID: m.id, Name: "Test " + m.id, Icon: "t", Tip: "a test plugin"}
}
func (m fakeFeat) Routes(*http.ServeMux, *feature.Deps) {}
func (m fakeFeat) Start(context.Context, *feature.Deps) {}
func (m fakeFeat) Stop()                                {}

// registered once so multiple test funcs (in this or a later slice) don't duplicate it in the
// process-global registry.
var testFeatOnce sync.Once

func ensureTestFeat() { testFeatOnce.Do(func() { feature.Register(fakeFeat{id: "test-feat"}) }) }

func featureTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg, err := config.Load(cfgPath) // creates + saves a default → Save() works
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	fs, err := featurestore.Open(filepath.Join(dir, "features.json"))
	if err != nil {
		t.Fatalf("featurestore.Open: %v", err)
	}
	return &Server{cfg: cfg, features: fs, featureDataDir: dir}, cfgPath
}

func TestFeatureManagement(t *testing.T) {
	ensureTestFeat()
	s, cfgPath := featureTestServer(t)

	// GET /api/features lists the module, disabled by default.
	w := httptest.NewRecorder()
	s.handleFeaturesList(w, httptest.NewRequest("GET", "/api/features", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", w.Code, w.Body)
	}
	var rows []featureRow
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if !hasFeat(rows, "test-feat", false) {
		t.Fatalf("test-feat missing or wrongly enabled: %+v", rows)
	}
	if s.featureEnabled("test-feat") {
		t.Error("featureEnabled true before install")
	}

	// PUT toggles it on and persists (no restart).
	putFeat(t, s, "test-feat", `{"enabled":true}`, http.StatusOK)
	if !s.featureEnabled("test-feat") {
		t.Error("not enabled after toggle")
	}
	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Features["test-feat"].Enabled {
		t.Error("toggle not persisted to disk")
	}

	// Unknown plugin id → 404.
	req := httptest.NewRequest("PUT", "/api/features/nope", strings.NewReader(`{"enabled":true}`))
	req.SetPathValue("id", "nope")
	w = httptest.NewRecorder()
	s.handleFeatureToggle(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown feature toggle = %d, want 404", w.Code)
	}

	// Settings PUT then GET round-trips.
	settingsReq := func(method, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/features/test-feat/settings", strings.NewReader(body))
		r.SetPathValue("id", "test-feat")
		rec := httptest.NewRecorder()
		if method == "GET" {
			s.handleFeatureSettingsGet(rec, r)
		} else {
			s.handleFeatureSettingsPut(rec, r)
		}
		return rec
	}
	if rec := settingsReq("PUT", `{"country":"it"}`); rec.Code != http.StatusOK {
		t.Fatalf("settings put = %d: %s", rec.Code, rec.Body)
	}
	if rec := settingsReq("GET", ""); strings.TrimSpace(rec.Body.String()) != `{"country":"it"}` {
		t.Errorf("settings get = %q", rec.Body.String())
	}
	if rec := settingsReq("PUT", `not json`); rec.Code != http.StatusBadRequest {
		t.Errorf("invalid settings json = %d, want 400", rec.Code)
	}
}

func hasFeat(rows []featureRow, id string, enabled bool) bool {
	for _, r := range rows {
		if r.ID == id {
			return r.Enabled == enabled && r.Name != "" && r.Icon != ""
		}
	}
	return false
}

func putFeat(t *testing.T, s *Server, id, body string, wantCode int) {
	t.Helper()
	req := httptest.NewRequest("PUT", "/api/features/"+id, strings.NewReader(body))
	req.SetPathValue("id", id)
	w := httptest.NewRecorder()
	s.handleFeatureToggle(w, req)
	if w.Code != wantCode {
		t.Fatalf("toggle %s = %d, want %d: %s", id, w.Code, wantCode, w.Body)
	}
}
