package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestConfigConcurrentAccessNoRace hammers the shared config writer and readers
// concurrently. Run with -race; all of them must serialize on the server's config lock.
func TestConfigConcurrentAccessNoRace(t *testing.T) {
	s, _ := sharehandlers_server(t)
	putBody := `{"listen":":8088","demo":true,"ports":{"ui":8088,"clash":9090,"dns":5353,"mixed":7890},"watchdog":{"notify_url":"https://hook.test/x"}}`

	var wg sync.WaitGroup
	for i := 0; i < 60; i++ {
		wg.Add(4)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(putBody))
			w := httptest.NewRecorder()
			s.handlePutConfig(w, req)
		}()
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
			w := httptest.NewRecorder()
			s.handleGetConfig(w, req)
		}()
		// The previously-unlocked read paths: handleHealth reads cfg.Demo and
		// genOptions reads cfg.Ports/Clash — both must now snapshot via config().
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
			w := httptest.NewRecorder()
			s.handleHealth(w, req)
		}()
		go func() { defer wg.Done(); pf := s.store.Profile(); _ = s.genOptions(&pf) }()
	}
	wg.Wait()
}
