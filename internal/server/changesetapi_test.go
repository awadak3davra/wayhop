package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// decodeChangeSetResp reads the /api/changeset body.
func decodeChangeSetResp(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("bad JSON: %v (%s)", err, w.Body.String())
	}
	return m
}

// changesetapi_recordBaseline records profile as the committed baseline of s, the way a saving Apply
// does, and returns its rev.
func changesetapi_recordBaseline(t *testing.T, s *Server, profile model.Profile) string {
	t.Helper()
	desired, err := newDesiredSnapshot(s.config(), profile, 1)
	if err != nil {
		t.Fatal(err)
	}
	s.recordApplied(true, &appliedRevision{
		Rev: desired.DesiredRev, At: 1,
		Desired:         &appliedDesired{Profile: profile, Config: desired.Config},
		Materialization: applyhealth_demoMaterialization(),
	})
	return desired.DesiredRev
}

// With no applied baseline yet, the endpoint must say so rather than presenting every existing
// object as newly "Added" (which is what diffing against an empty profile would do).
func TestHandleChangeSet_NoBaseline(t *testing.T) {
	s := applyhealth_server(t)
	w := httptest.NewRecorder()
	s.handleChangeSet(w, httptest.NewRequest(http.MethodGet, "/api/changeset", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	m := decodeChangeSetResp(t, w)
	if m["baseline_available"] != false {
		t.Errorf("baseline_available should be false with no baseline, got %v", m["baseline_available"])
	}
	if reason, _ := m["reason"].(string); !strings.Contains(reason, "no applied baseline") {
		t.Errorf("expected an explanatory reason, got %q", reason)
	}
}

// After an Apply records a baseline, an edit shows up as a real per-field change.
func TestHandleChangeSet_DiffAgainstAppliedBaseline(t *testing.T) {
	s := applyhealth_server(t)

	base := model.Profile{Endpoints: []model.Endpoint{{
		ID: "a", Name: "Alpha", Engine: model.EngineSingBox, Protocol: model.ProtoTrojan,
		Server: "203.0.113.9", Port: 443, Enabled: true, Params: map[string]any{"password": "p"},
	}}}
	baseRev := changesetapi_recordBaseline(t, s, base)

	// Now the saved profile differs by one field.
	edited := base
	edited.Endpoints = []model.Endpoint{base.Endpoints[0]}
	edited.Endpoints[0].Port = 8443
	if err := s.store.Replace(edited); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleChangeSet(w, httptest.NewRequest(http.MethodGet, "/api/changeset", nil))
	m := decodeChangeSetResp(t, w)

	if m["baseline_available"] != true {
		t.Fatalf("baseline_available should be true, got %v (%s)", m["baseline_available"], w.Body.String())
	}
	if m["baseline_rev"] != baseRev {
		t.Errorf("baseline_rev = %v, want %s", m["baseline_rev"], baseRev)
	}
	if c, _ := m["count"].(float64); c < 1 {
		t.Fatalf("expected at least one change, got %v: %s", m["count"], w.Body.String())
	}
	if m["pending"] != true {
		t.Errorf("pending = %v, want true", m["pending"])
	}
	changes, _ := m["changes"].([]any)
	var found bool
	for _, raw := range changes {
		ch, _ := raw.(map[string]any)
		if ch["field"] == "Port" && ch["before"] == "443" && ch["after"] == "8443" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a Port 443 → 8443 change, got %s", w.Body.String())
	}
	// The secret must never appear anywhere in the response.
	if strings.Contains(w.Body.String(), "\"p\"") && strings.Contains(w.Body.String(), "password") {
		t.Errorf("possible secret leak in changeset response: %s", w.Body.String())
	}
}

// Undo reverts the real stored data against the applied baseline; a stale baseline_rev is refused
// and an omitted one is tolerated.
func TestHandleChangeSetUndo_RevertsAgainstBaseline(t *testing.T) {
	s := applyhealth_server(t)
	base := model.Profile{Endpoints: []model.Endpoint{{
		ID: "a", Name: "Alpha", Engine: model.EngineSingBox, Protocol: model.ProtoTrojan,
		Server: "203.0.113.9", Port: 443, Enabled: true, Params: map[string]any{"password": "p"},
	}}}
	baseRev := changesetapi_recordBaseline(t, s, base)
	edited := base
	edited.Endpoints = []model.Endpoint{base.Endpoints[0]}
	edited.Endpoints[0].Port = 8443
	if err := s.store.Replace(edited); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	post := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleChangeSetUndo(w, httptest.NewRequest(http.MethodPost, "/api/changeset/undo", strings.NewReader(body)))
		return w
	}
	if w := post(`{"scope":"all","baseline_rev":"stale"}`); w.Code != http.StatusConflict {
		t.Fatalf("stale baseline_rev: got %d, want 409 (%s)", w.Code, w.Body.String())
	}
	if p := s.store.Profile(); p.Endpoints[0].Port != 8443 {
		t.Fatal("a refused undo must not touch the store")
	}
	w := post(`{"scope":"all","baseline_rev":"` + baseRev + `"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("undo: got %d (%s)", w.Code, w.Body.String())
	}
	m := decodeChangeSetResp(t, w)
	if m["undone"] != true || m["pending"] != false {
		t.Errorf("undo response = %v", m)
	}
	if p := s.store.Profile(); p.Endpoints[0].Port != 443 {
		t.Errorf("undo did not revert the port: %+v", p.Endpoints[0])
	}
	// Omitted baseline_rev is tolerated: the request reaches the differ, which now has nothing to
	// discard and says so (400), rather than being refused as stale (409).
	if w := post(`{"scope":"all"}`); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "no pending changes") {
		t.Fatalf("undo without baseline_rev: got %d (%s)", w.Code, w.Body.String())
	}
}

// Undo without any applied baseline is a 409 that says so.
func TestHandleChangeSetUndo_NoBaselineIs409(t *testing.T) {
	s := applyhealth_server(t)
	w := httptest.NewRecorder()
	s.handleChangeSetUndo(w, httptest.NewRequest(http.MethodPost, "/api/changeset/undo", strings.NewReader(`{"scope":"all"}`)))
	if w.Code != http.StatusConflict {
		t.Fatalf("got %d, want 409 (%s)", w.Code, w.Body.String())
	}
}
