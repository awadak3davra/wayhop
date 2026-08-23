package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"wayhop/internal/clash"
	"wayhop/internal/model"
	"wayhop/internal/store"
)

// health_logs is a fake LogSource returning a fixed set of lines, newest last.
type health_logs struct{ lines []string }

func (l health_logs) LogLines() []string { return l.lines }

// health_newStore writes a profile JSON to a temp file and opens a real Store
// over it (no network, no sing-box). Endpoints come before groups in targets().
func health_newStore(t *testing.T, p model.Profile) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "profile.json")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Replace(p); err != nil {
		t.Fatalf("store.Replace: %v", err)
	}
	return st
}

// health_demoProfile has two enabled endpoints + one group. demoTick marks the
// LAST endpoint (index lastEp, here index 1, which is >0) as down.
func health_demoProfile() model.Profile {
	return model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ep-alive", Name: "Alive EP", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "a.example", Port: 443, Enabled: true},
			{ID: "ep-down", Name: "Down EP", Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2, Server: "b.example", Port: 443, Enabled: true},
			// A disabled endpoint must be skipped entirely by targets().
			{ID: "ep-off", Name: "Disabled", Engine: model.EngineSingBox, Protocol: model.ProtoTrojan, Server: "c.example", Port: 443, Enabled: false},
		},
		Groups: []model.Group{
			{ID: "grp", Name: "Main", Type: model.GroupURLTest, Members: []string{"ep-alive", "ep-down"}},
		},
	}
}

func health_viewByID(vs []View, id string) (View, bool) {
	for _, v := range vs {
		if v.ID == id {
			return v, true
		}
	}
	return View{}, false
}

// TestHashStrDeterministic verifies hashStr is a pure function: same input ->
// same non-negative output, and distinct inputs we use here differ.
func TestHashStrDeterministic(t *testing.T) {
	for _, s := range []string{"", "ep-alive", "ep-down", "grp", "a longer string with spaces"} {
		if got := hashStr(s); got != hashStr(s) {
			t.Fatalf("hashStr(%q) not deterministic", s)
		}
		if hashStr(s) < 0 {
			t.Fatalf("hashStr(%q) negative: %d", s, hashStr(s))
		}
	}
	if hashStr("ep-alive") == hashStr("ep-down") {
		t.Fatalf("expected distinct hashes for distinct ids")
	}
	// Empty string hashes to 0.
	if got := hashStr(""); got != 0 {
		t.Fatalf("hashStr(\"\")=%d want 0", got)
	}
	// Known small value: "ab" = 'a'*131 + 'b' = 97*131 + 98 = 12805.
	if got := hashStr("ab"); got != 97*131+98 {
		t.Fatalf("hashStr(\"ab\")=%d want %d", got, 97*131+98)
	}
}

// TestDemoTickSynthesizesStats drives the demo path once and checks that alive
// endpoints get plausible ping/rate/bytes/uptime/success_rate while the last
// endpoint is reported down with a failed handshake.
func TestDemoTickSynthesizesStats(t *testing.T) {
	st := health_newStore(t, health_demoProfile())
	m := NewMonitor(nil, st, nil, true)
	if !m.demo {
		t.Fatal("expected demo monitor")
	}

	const now = int64(1_700_000_000_000) // fixed clock -> deterministic
	m.demoTick(now)

	views := m.Snapshot()
	// targets(): 2 enabled endpoints + 1 group = 3 (disabled endpoint skipped).
	if len(views) != 3 {
		t.Fatalf("snapshot len=%d want 3 (2 enabled ep + 1 group)", len(views))
	}
	if _, ok := health_viewByID(views, "ep-off"); ok {
		t.Fatal("disabled endpoint must not appear in snapshot")
	}

	alive, ok := health_viewByID(views, "ep-alive")
	if !ok {
		t.Fatal("ep-alive missing from snapshot")
	}
	if alive.State != "alive" {
		t.Fatalf("ep-alive state=%s want alive", alive.State)
	}
	if alive.Handshake != "ok" {
		t.Fatalf("ep-alive handshake=%s want ok", alive.Handshake)
	}
	if alive.Name != "Alive EP" || alive.Kind != "endpoint" {
		t.Fatalf("ep-alive name/kind wrong: %+v", alive)
	}
	if alive.LatencyMs <= 0 {
		t.Fatalf("ep-alive latency=%d want >0", alive.LatencyMs)
	}
	// One probe, all ok -> 100%% success rate.
	if alive.SuccessRate != 100 {
		t.Fatalf("ep-alive success_rate=%d want 100", alive.SuccessRate)
	}
	if alive.Probes != 1 {
		t.Fatalf("ep-alive probes=%d want 1", alive.Probes)
	}
	// demoTick sets rate floors of 400_000 down / 80_000 up.
	if alive.RateDownBps < 400_000 {
		t.Fatalf("ep-alive rate_down=%d want >=400000", alive.RateDownBps)
	}
	if alive.RateUpBps < 80_000 {
		t.Fatalf("ep-alive rate_up=%d want >=80000", alive.RateUpBps)
	}
	// Totals accumulate rate * interval-seconds (interval=10s) over one tick.
	if alive.BytesDown != alive.RateDownBps*10 {
		t.Fatalf("ep-alive bytes_down=%d want rate*10=%d", alive.BytesDown, alive.RateDownBps*10)
	}
	if alive.BytesUp != alive.RateUpBps*10 {
		t.Fatalf("ep-alive bytes_up=%d want rate*10=%d", alive.BytesUp, alive.RateUpBps*10)
	}
	// Snapshot computes uptime against the real wall clock (nowMS), so it is
	// some non-negative value for an alive endpoint. The exact uptime math is
	// asserted deterministically against the internal stat below.
	if alive.UptimeS < 0 {
		t.Fatalf("ep-alive uptime=%d want >=0", alive.UptimeS)
	}
	// Deterministic uptime check via toView with a controlled clock: the stat's
	// lastChange was set to `now`; 7s later uptime must read 7.
	m.mu.Lock()
	uv := toView("ep-alive", m.stats["ep-alive"], now+7000)
	m.mu.Unlock()
	if uv.UptimeS != 7 {
		t.Fatalf("uptime via toView=%d want 7 (now+7s since lastChange)", uv.UptimeS)
	}

	down, ok := health_viewByID(views, "ep-down")
	if !ok {
		t.Fatal("ep-down missing from snapshot")
	}
	if down.State != "down" {
		t.Fatalf("ep-down state=%s want down", down.State)
	}
	if down.Handshake != "failed" {
		t.Fatalf("ep-down handshake=%s want failed", down.Handshake)
	}
	if down.LatencyMs != 0 {
		t.Fatalf("ep-down latency=%d want 0", down.LatencyMs)
	}
	if down.RateDownBps != 0 || down.RateUpBps != 0 {
		t.Fatalf("ep-down rates must be 0, got up=%d down=%d", down.RateUpBps, down.RateDownBps)
	}
	if down.SuccessRate != 0 {
		t.Fatalf("ep-down success_rate=%d want 0", down.SuccessRate)
	}
	// Down rows carry a cause (here the generic fallback, logs==nil).
	if down.Cause == "" || down.CauseFix == "" {
		t.Fatalf("ep-down must have a cause+fix, got %+v", down)
	}

	// The group is alive (only the last *endpoint* is forced down).
	grp, ok := health_viewByID(views, "grp")
	if !ok {
		t.Fatal("grp missing from snapshot")
	}
	if grp.State != "alive" || grp.Kind != "group" {
		t.Fatalf("group view wrong: %+v", grp)
	}
}

// TestDemoTickDeterministicAndAccumulates verifies demoTick is a pure function
// of `now`+ids (two monitors with identical inputs match) and that totals grow
// across successive ticks while rates stay stable for a fixed clock.
func TestDemoTickDeterministicAndAccumulates(t *testing.T) {
	const now = int64(1_700_000_000_000)

	m1 := NewMonitor(nil, health_newStore(t, health_demoProfile()), nil, true)
	m2 := NewMonitor(nil, health_newStore(t, health_demoProfile()), nil, true)
	m1.demoTick(now)
	m2.demoTick(now)

	a1, _ := health_viewByID(m1.Snapshot(), "ep-alive")
	a2, _ := health_viewByID(m2.Snapshot(), "ep-alive")
	if a1.LatencyMs != a2.LatencyMs || a1.RateDownBps != a2.RateDownBps || a1.RateUpBps != a2.RateUpBps {
		t.Fatalf("demo synthesis not deterministic: %+v vs %+v", a1, a2)
	}

	// Second tick at the same clock: rates identical, totals doubled.
	m1.demoTick(now)
	a1b, _ := health_viewByID(m1.Snapshot(), "ep-alive")
	if a1b.RateDownBps != a1.RateDownBps {
		t.Fatalf("rate changed across ticks at fixed clock: %d -> %d", a1.RateDownBps, a1b.RateDownBps)
	}
	if a1b.BytesDown != 2*a1.BytesDown || a1b.BytesUp != 2*a1.BytesUp {
		t.Fatalf("totals did not accumulate: down %d->%d up %d->%d", a1.BytesDown, a1b.BytesDown, a1.BytesUp, a1b.BytesUp)
	}
	if a1b.Probes != 2 {
		t.Fatalf("probes=%d want 2 after two ticks", a1b.Probes)
	}
}

// TestDemoSingleEndpointNeverDown documents the lastEp>0 guard: with exactly one
// endpoint, lastEp==0 so the "force down" branch never fires and it stays alive.
func TestDemoSingleEndpointNeverDown(t *testing.T) {
	p := model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "solo", Name: "Solo", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "s.example", Port: 443, Enabled: true},
		},
	}
	m := NewMonitor(nil, health_newStore(t, p), nil, true)
	m.demoTick(1_700_000_000_000)
	v, ok := health_viewByID(m.Snapshot(), "solo")
	if !ok {
		t.Fatal("solo endpoint missing")
	}
	if v.State != "alive" {
		t.Fatalf("single endpoint state=%s want alive (lastEp==0 guard)", v.State)
	}
}

// TestDemoDownCauseFromKB verifies the down row's cause comes from kb.Match over
// the engine log (newest line first). A wireguard handshake-timeout line must
// map to that knowledgebase entry rather than the generic timeout fallback.
func TestDemoDownCauseFromKB(t *testing.T) {
	logs := health_logs{lines: []string{
		"info starting",
		"error: wireguard: handshake did not complete after 5 seconds",
	}}
	m := NewMonitor(nil, health_newStore(t, health_demoProfile()), logs, true)
	m.demoTick(1_700_000_000_000)

	down, ok := health_viewByID(m.Snapshot(), "ep-down")
	if !ok {
		t.Fatal("ep-down missing")
	}
	if !strings.Contains(down.Cause, "WireGuard handshake never completed") {
		t.Fatalf("cause=%q want WireGuard handshake entry from kb", down.Cause)
	}
	if down.CauseFix == "" {
		t.Fatal("expected a fix string from the kb entry")
	}
}

// TestCauseForPicksNewestMatch verifies causeFor scans lines newest-first: when
// two different kb-matching lines exist, the LAST line (newest) wins.
func TestCauseForPicksNewestMatch(t *testing.T) {
	m := &Monitor{logs: health_logs{lines: []string{
		"error: connection refused by server", // older -> "Connection refused"
		"error: no such host: relay.example",  // newest -> "DNS resolution failed"
	}}}
	title, fix := m.causeFor()
	if !strings.Contains(title, "DNS resolution failed") {
		t.Fatalf("title=%q want DNS resolution failed (newest line wins)", title)
	}
	if fix == "" {
		t.Fatal("expected a fix from kb")
	}
}

// TestCauseForFallback verifies the generic fallback when no log source is set.
func TestCauseForFallback(t *testing.T) {
	m := &Monitor{logs: nil}
	title, fix := m.causeFor()
	if !strings.Contains(title, "timed out") {
		t.Fatalf("fallback title=%q want a timeout explanation", title)
	}
	if fix == "" {
		t.Fatal("fallback fix must be non-empty")
	}
}

// --- non-demo path: real Clash client against an httptest server ---

// health_clashServer serves /proxies/{name}/delay and /connections from the
// given maps. delay[name] -> ms (alive); names absent or with ms<0 -> down.
func health_clashServer(t *testing.T, delay map[string]int, conns clash.Connections) *clash.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/proxies/") && strings.HasSuffix(p, "/delay"):
			name := strings.TrimSuffix(strings.TrimPrefix(p, "/proxies/"), "/delay")
			ms, ok := delay[name]
			if !ok || ms < 0 {
				w.WriteHeader(http.StatusRequestTimeout)
				_, _ = w.Write([]byte(`{"message":"delay test failed"}`))
				return
			}
			_, _ = w.Write([]byte(`{"delay":` + strconv.Itoa(ms) + `}`))
		case p == "/connections":
			writeJSON(t, w, conns)
		default:
			http.NotFound(w, r)
		}
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c, err := clash.New(strings.TrimPrefix(ts.URL, "http://"), "")
	if err != nil {
		t.Fatalf("clash.New: %v", err)
	}
	return c
}

// TestRealTickStateTransitionAndCause runs the real (non-demo) tick against a
// fake Clash server: an alive endpoint, a down endpoint that picks up a cause
// from the kb, plus traffic attribution from /connections chains.
func TestRealTickStateTransitionAndCause(t *testing.T) {
	st := health_newStore(t, model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "up", Name: "Up", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "u.example", Port: 443, Enabled: true},
			{ID: "bad", Name: "Bad", Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2, Server: "x.example", Port: 443, Enabled: true},
		},
	})
	conns := clash.Connections{Connections: []clash.Conn{
		{Upload: 1000, Download: 5000, Chains: []string{"up"}},
		{Upload: 200, Download: 800, Chains: []string{"up"}},
	}}
	logs := health_logs{lines: []string{"error: REALITY: invalid connection"}}
	cl := health_clashServer(t, map[string]int{"up": 42}, conns) // "bad" absent -> down
	m := NewMonitor(cl, st, logs, false)

	ctx := context.Background()
	// First tick establishes baseline; second tick produces a rate from deltas.
	m.tick(ctx)
	m.tick(ctx)

	views := m.Snapshot()
	up, ok := health_viewByID(views, "up")
	if !ok {
		t.Fatal("up endpoint missing")
	}
	if up.State != "alive" || up.Handshake != "ok" {
		t.Fatalf("up state/handshake wrong: %+v", up)
	}
	if up.LatencyMs != 42 {
		t.Fatalf("up latency=%d want 42", up.LatencyMs)
	}
	// Both ticks return identical /connections byte totals, so the sample-to-
	// sample delta is 0 and the rate stays 0 (rate is only set on positive
	// deltas). The delta->rate math is covered by TestRealTickTrafficRateFromDelta.
	if up.RateUpBps != 0 || up.RateDownBps != 0 {
		t.Fatalf("up rates want 0 for identical samples, got up=%d down=%d", up.RateUpBps, up.RateDownBps)
	}

	bad, ok := health_viewByID(views, "bad")
	if !ok {
		t.Fatal("bad endpoint missing")
	}
	if bad.State != "down" || bad.Handshake != "failed" {
		t.Fatalf("bad state/handshake wrong: %+v", bad)
	}
	if !strings.Contains(bad.Cause, "Reality rejected the connection") {
		t.Fatalf("bad cause=%q want Reality entry from kb", bad.Cause)
	}
}

// TestRealTickTrafficRateFromDelta feeds growing connection byte counts across
// two ticks and checks sampleTraffic derives a positive rate and accumulates a
// total for the attributed endpoint.
func TestRealTickTrafficRateFromDelta(t *testing.T) {
	st := health_newStore(t, model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "up", Name: "Up", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "u.example", Port: 443, Enabled: true},
		},
	})
	m := NewMonitor(nil, st, nil, false)

	now1 := int64(1_700_000_000_000)
	now2 := now1 + 2000 // +2s

	// Probe so the stat exists, then sample traffic twice with rising bytes.
	m.record("up", "Up", "endpoint", Alive, 10, now1)
	m.sampleTrafficWith(t, now1, clash.Connections{Connections: []clash.Conn{
		{Upload: 1000, Download: 4000, Chains: []string{"up"}},
	}})
	m.sampleTrafficWith(t, now2, clash.Connections{Connections: []clash.Conn{
		{Upload: 3000, Download: 14000, Chains: []string{"up"}},
	}})

	v, _ := health_viewByID(m.Snapshot(), "up")
	// up delta = 3000-1000 = 2000 over 2s => 1000 B/s. down = 10000/2 = 5000 B/s.
	if v.RateUpBps != 1000 {
		t.Fatalf("rate_up=%d want 1000", v.RateUpBps)
	}
	if v.RateDownBps != 5000 {
		t.Fatalf("rate_down=%d want 5000", v.RateDownBps)
	}
	// Totals accumulate the positive deltas.
	if v.BytesUp != 2000 {
		t.Fatalf("bytes_up=%d want 2000", v.BytesUp)
	}
	if v.BytesDown != 10000 {
		t.Fatalf("bytes_down=%d want 10000", v.BytesDown)
	}
}

// sampleTrafficWith points the monitor at a fresh fake server serving the given
// /connections payload, then runs sampleTraffic at clock `now`. This exercises
// the real sampleTraffic delta logic deterministically.
func (m *Monitor) sampleTrafficWith(t *testing.T, now int64, conns clash.Connections) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, conns)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	c, err := clash.New(strings.TrimPrefix(ts.URL, "http://"), "")
	if err != nil {
		t.Fatalf("clash.New: %v", err)
	}
	old := m.clash
	m.clash = c
	m.sampleTraffic(context.Background(), nil, now)
	m.clash = old
}

// --- tiny JSON/itoa helpers (avoid extra deps, keep tests hermetic) ---

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("encode: %v", err)
	}
}
