package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"velinx/internal/model"
)

// TestHandleRestoreProfile: a valid backup replaces the whole profile; an invalid one (fails
// Validate) or malformed JSON is rejected with 400 and leaves the current profile untouched.
func TestHandleRestoreProfile(t *testing.T) {
	s, _ := sharehandlers_server(t)
	post := func(body []byte) int {
		req := httptest.NewRequest(http.MethodPost, "/api/profile", bytes.NewReader(body))
		w := httptest.NewRecorder()
		s.handleRestoreProfile(w, req)
		return w.Code
	}

	good, _ := json.Marshal(model.Profile{Endpoints: []model.Endpoint{
		{ID: "e1", Name: "E1", Protocol: model.ProtoVLESS, Server: "1.2.3.4", Port: 443, Enabled: true},
	}})
	if code := post(good); code != http.StatusOK {
		t.Fatalf("valid restore: status=%d", code)
	}
	if got := s.store.Profile(); len(got.Endpoints) != 1 || got.Endpoints[0].ID != "e1" {
		t.Fatalf("profile not replaced: %+v", got.Endpoints)
	}

	// A rule with no matcher and an unresolvable outbound fails Validate → 400, store untouched.
	bad, _ := json.Marshal(model.Profile{Rules: []model.Rule{{ID: "r", Outbound: "nope"}}})
	if code := post(bad); code != http.StatusBadRequest {
		t.Fatalf("invalid restore: status=%d, want 400", code)
	}
	if got := s.store.Profile(); len(got.Endpoints) != 1 {
		t.Errorf("a rejected restore must not change the store: %+v", got)
	}

	if code := post([]byte("{not json")); code != http.StatusBadRequest {
		t.Errorf("malformed JSON: status=%d, want 400", code)
	}
}
