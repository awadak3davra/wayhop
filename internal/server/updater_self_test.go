package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/config"
)

// TestHandleSelfAuto: the self-update auto toggle rejects bad JSON (400) and PERSISTS the flag to the
// config file (it drives background auto-swap of the running binary, so a broken persist is
// high-consequence).
func TestHandleSelfAuto(t *testing.T) {
	s, cfgPath := sharehandlers_server(t)
	put := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleSelfAuto(w, httptest.NewRequest(http.MethodPut, "/api/updater/self/auto", strings.NewReader(body)))
		return w
	}
	if w := put("{bad"); w.Code != http.StatusBadRequest {
		t.Fatalf("bad body = %d, want 400", w.Code)
	}
	if w := put(`{"enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("enable = %d (%s)", w.Code, w.Body)
	}
	if !s.cfg.Updater.AutoUpdate {
		t.Fatal("in-memory flag not set")
	}
	if reloaded, err := config.Load(cfgPath); err != nil || !reloaded.Updater.AutoUpdate {
		t.Fatalf("flag not persisted to disk (err=%v)", err)
	}
	if w := put(`{"enabled":false}`); w.Code != http.StatusOK {
		t.Fatalf("disable = %d", w.Code)
	}
	if reloaded, _ := config.Load(cfgPath); reloaded.Updater.AutoUpdate {
		t.Fatal("disable not persisted to disk")
	}
}
