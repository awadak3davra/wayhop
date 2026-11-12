package server

import (
	"net/http"
	"testing"
)

func TestRestoreProfileRefusesANonObject(t *testing.T) {
	s := bindTestServer(t, feedProfile(), "")
	before := s.store.Profile()
	if len(before.RoutingLists)+len(before.Endpoints)+len(before.Rules) == 0 {
		t.Fatal("the fixture profile should not be empty")
	}
	for _, body := range []string{`null`, `[]`, `"x"`, `1`, `  null  `} {
		w := tgDo(t, s, http.MethodPost, "/api/profile", body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%q: status %d, want 400: %s", body, w.Code, w.Body.String())
		}
		after := s.store.Profile()
		if len(after.RoutingLists) != len(before.RoutingLists) || len(after.Endpoints) != len(before.Endpoints) ||
			len(after.Rules) != len(before.Rules) {
			t.Fatalf("%q erased the profile", body)
		}
	}
}

func TestSaveEndpointWithoutAnIDIsABadRequest(t *testing.T) {
	s := bindTestServer(t, feedProfile(), "")
	w := tgDo(t, s, http.MethodPost, "/api/endpoints", `{"name":"missing id"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", w.Code, w.Body.String())
	}
}
