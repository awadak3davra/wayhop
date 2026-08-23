package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"wayhop/internal/model"
)

// A connection check that never ran the engine must not read like one that did.
//
// Without the sing-box binary the handler only proves the generator could translate the endpoint —
// a real verdict, but a far weaker one. It used to answer a bare {"ok":true}, identical to a full
// `sing-box check`, so on a native-only router every connection reported the same "OK" whether or
// not anything had validated it. The verdict has to name its checker.
func TestHandleEndpointCheck_NamesItsChecker(t *testing.T) {
	s := dnsSeed(t) // builds a Server whose sing-box is deliberately unavailable
	if s.singbox != nil && s.singbox.Available() {
		t.Skip("this case is about the engine being absent; it is present here")
	}

	ep := model.Endpoint{
		ID: "chk1", Name: "chk1", Engine: "singbox", Protocol: "vless",
		Server: "198.51.100.10", Port: 443, Enabled: true,
		Params: map[string]any{"uuid": "00000000-0000-0000-0000-000000000000"},
	}
	if err := s.store.UpsertEndpoint(ep); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}

	r := httptest.NewRequest(http.MethodPost, "/api/endpoints/chk1/check", nil)
	r.SetPathValue("id", "chk1")
	w := httptest.NewRecorder()
	s.handleEndpointCheck(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("check should answer 200, got %d: %s", w.Code, w.Body)
	}
	var got struct {
		OK        bool   `json:"ok"`
		CheckedBy string `json:"checked_by"`
		Error     string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body)
	}
	if got.CheckedBy == "" {
		t.Fatal("verdict does not say what produced it — this is the whole defect")
	}
	if got.CheckedBy != checkedByGenerator {
		t.Errorf("engine is absent, so the checker must be %q, got %q", checkedByGenerator, got.CheckedBy)
	}
	// The weaker verdict is still a pass; the point is that it is labelled, not that it fails.
	if !got.OK {
		t.Errorf("a translatable endpoint should still pass: %+v", got)
	}
}

// A missing connection is a 404, not a silently-passing check.
func TestHandleEndpointCheck_UnknownID(t *testing.T) {
	s := dnsSeed(t)
	r := httptest.NewRequest(http.MethodPost, "/api/endpoints/ghost/check", nil)
	r.SetPathValue("id", "ghost")
	w := httptest.NewRecorder()
	s.handleEndpointCheck(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown connection should be 404, got %d: %s", w.Code, w.Body)
	}
}
