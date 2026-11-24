package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// A shared export masks the update mirrors (a prefix can carry a token); importing that export keeps
// the mirrors the router has.
func TestConfigImport_KeepsTheRedactedMirrors(t *testing.T) {
	s, _ := sharehandlers_server(t)
	real := []string{"", "https://proxy.example/tok123/"}
	s.cfg.Updater.Mirrors = real
	exported := s.config().Redacted()
	if reflect.DeepEqual(exported.Updater.Mirrors, real) {
		t.Fatalf("the export carries the real mirrors: %v", exported.Updater.Mirrors)
	}
	body, _ := json.Marshal(exported)
	w := httptest.NewRecorder()
	s.handleConfigImport(w, httptest.NewRequest(http.MethodPost, "/api/config/import", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("import: %d %s", w.Code, w.Body)
	}
	if got := s.config().Updater.Mirrors; !reflect.DeepEqual(got, real) {
		t.Errorf("after import: %v", got)
	}
}
