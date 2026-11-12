package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"wayhop/internal/model"
)

// The lists' status asks each source once a minute at most and never downloads the rule set: it used
// to read every body to the end on every visit to the Dashboard or to Routing.
func TestRoutingStatusAsksOnceAndReadsNoBody(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	var hits, sent atomic.Int64
	chunk := []byte(strings.Repeat("x", 64<<10))
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 512; i++ { // 32 MiB if anyone reads it all
			n, err := w.Write(chunk)
			sent.Add(int64(n))
			if err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}))
	defer src.Close()
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "big", Name: "Big", Source: src.URL + "/rules.srs", Outbound: "direct", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	ask := func() (ok bool, status int) {
		t.Helper()
		w := httptest.NewRecorder()
		s.handleRoutingStatus(w, httptest.NewRequest(http.MethodGet, "/api/routing/status", nil))
		var res []struct {
			ID     string `json:"id"`
			OK     bool   `json:"ok"`
			Status int    `json:"status"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil || len(res) != 1 {
			t.Fatalf("status answer: %v %s", err, w.Body)
		}
		return res[0].OK, res[0].Status
	}
	if ok, status := ask(); !ok || status != http.StatusOK {
		t.Fatalf("first answer ok=%v status=%d", ok, status)
	}
	if ok, status := ask(); !ok || status != http.StatusOK {
		t.Fatalf("remembered answer ok=%v status=%d", ok, status)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("the source was asked %d times for two status reads, want 1", n)
	}
	src.CloseClientConnections()
	if n := sent.Load(); n > 8<<20 {
		t.Fatalf("%d bytes of the rule set were taken to read a status line", n)
	}

	// "Refresh sources" forgets the answers.
	s.forgetRoutingProbes()
	ask()
	if n := hits.Load(); n != 2 {
		t.Fatalf("after forgetting, the source was asked %d times in total, want 2", n)
	}
}
