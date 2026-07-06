package iptv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// probeMux answers with a distinct response per path so one httptest server drives every case.
func probeMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/alive", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		_, _ = w.Write([]byte("#EXTM3U\n#EXTINF:-1,x\nhttp://seg"))
	})
	mux.HandleFunc("/hls", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("#EXTM3U\n#EXT-X-VERSION:3\n"))
	})
	mux.HandleFunc("/geo", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	mux.HandleFunc("/dead", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	mux.HandleFunc("/html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>blocked</body></html>"))
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	})
	return mux
}

func TestProbeClassify(t *testing.T) {
	srv := httptest.NewServer(probeMux())
	defer srv.Close()
	chs := []Channel{
		{Name: "A", URL: srv.URL + "/alive"},
		{Name: "B", URL: srv.URL + "/hls"},
		{Name: "C", URL: srv.URL + "/geo"},
		{Name: "D", URL: srv.URL + "/dead"},
		{Name: "E", URL: srv.URL + "/html"},
	}
	p := NewProber(ProbeConfig{Concurrency: 4})
	if n := p.Probe(context.Background(), srv.Client(), chs, 1000); n != len(chs) {
		t.Fatalf("probed %d, want %d", n, len(chs))
	}
	want := []struct {
		status string
		live   bool
	}{{"alive", true}, {"alive", true}, {"geo", false}, {"dead", false}, {"dead", false}}
	for i, w := range want {
		if chs[i].Status != w.status || chs[i].Live != w.live {
			t.Errorf("%s: status=%q live=%v, want %q/%v", chs[i].Name, chs[i].Status, chs[i].Live, w.status, w.live)
		}
	}
	// A first-time success stamps LastGood; a failure stamps LastFail.
	if chs[0].LastGood != 1000 {
		t.Errorf("alive LastGood=%d, want 1000", chs[0].LastGood)
	}
	if chs[2].LastFail != 1000 {
		t.Errorf("geo LastFail=%d, want 1000", chs[2].LastFail)
	}
}

func TestProbeTimeoutIsDead(t *testing.T) {
	srv := httptest.NewServer(probeMux())
	defer srv.Close()
	chs := []Channel{{Name: "slow", URL: srv.URL + "/slow"}}
	p := NewProber(ProbeConfig{Timeout: 60 * time.Millisecond})
	p.Probe(context.Background(), srv.Client(), chs, 1)
	if chs[0].Live || chs[0].Status != "dead" {
		t.Fatalf("timed-out probe: live=%v status=%q, want dead", chs[0].Live, chs[0].Status)
	}
}

// TestApplyHysteresis pins the fast-out / slow-in state machine directly (deterministic, clock-free).
func TestApplyHysteresis(t *testing.T) {
	// Never-probed + first success → up immediately (Unknown→Alive).
	c := &Channel{}
	apply(c, true, false, 10)
	if !c.Live {
		t.Fatal("first success should come up immediately")
	}
	// Live channel: one failure holds, second failure drops (fast-out debounced).
	apply(c, false, false, 20)
	if !c.Live {
		t.Fatal("one failure must not drop a live channel")
	}
	apply(c, false, false, 30)
	if c.Live {
		t.Fatal("two failures must drop a live channel")
	}
	// Recovery after failing: needs two successes (slow-in), not one.
	apply(c, true, false, 40)
	if c.Live {
		t.Fatal("one success must not revive a previously-failed channel")
	}
	apply(c, true, false, 50)
	if !c.Live {
		t.Fatal("two successes must revive the channel")
	}
	if c.LastGood != 50 || c.LastFail != 30 {
		t.Fatalf("timestamps: LastGood=%d LastFail=%d", c.LastGood, c.LastFail)
	}
}

// TestProbeRotation: a BatchSize smaller than the list advances a cursor so successive passes cover
// every channel rather than probing all each tick.
func TestProbeRotation(t *testing.T) {
	srv := httptest.NewServer(probeMux())
	defer srv.Close()
	chs := make([]Channel, 5)
	for i := range chs {
		chs[i].URL = srv.URL + "/alive"
	}
	p := NewProber(ProbeConfig{BatchSize: 2})
	probedThisPass := func() int {
		n := 0
		for i := range chs {
			if chs[i].Status != "" {
				n++
			}
		}
		return n
	}
	if got := p.Probe(context.Background(), srv.Client(), chs, 1); got != 2 {
		t.Fatalf("pass 1 probed %d, want 2", got)
	}
	if probedThisPass() != 2 {
		t.Fatalf("after pass 1, %d channels have status, want 2", probedThisPass())
	}
	p.Probe(context.Background(), srv.Client(), chs, 2) // idx 2,3
	p.Probe(context.Background(), srv.Client(), chs, 3) // idx 4,0 (wraps)
	if probedThisPass() != 5 {
		t.Fatalf("after 3 passes every channel should be covered, got %d/5", probedThisPass())
	}
}

func TestProbeNilClientAndEmpty(t *testing.T) {
	p := NewProber(ProbeConfig{})
	if n := p.Probe(context.Background(), nil, []Channel{{URL: "http://x"}}, 1); n != 0 {
		t.Fatalf("nil client should probe nothing, got %d", n)
	}
	if n := p.Probe(context.Background(), http.DefaultClient, nil, 1); n != 0 {
		t.Fatalf("empty slice should probe nothing, got %d", n)
	}
}
