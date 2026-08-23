package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/clash"
	"wayhop/internal/model"
)

// TestMonitorGracefulWhenClashUnreachable locks the stability property the P4 native-only sing-box
// skip relies on: when the clash API client EXISTS but its endpoint is unreachable (sing-box
// stopped — e.g. a fully-kernel-native fast-mode profile), the monitor must degrade gracefully —
// report Unknown (never a false Down), and leave traffic stats untouched — with no panic and no
// per-tick logging. A permanently-absent core must not crash the monitor or spam the tiny overlay.
func TestMonitorGracefulWhenClashUnreachable(t *testing.T) {
	// A clash client whose endpoint refuses connections: start a server, capture its address, then
	// close it so the address is dead. clash.New only stores the address (connects per-request).
	ts := httptest.NewServer(http.NewServeMux())
	addr := strings.TrimPrefix(ts.URL, "http://")
	ts.Close()
	c, err := clash.New(addr, "")
	if err != nil {
		t.Fatalf("clash.New: %v", err)
	}
	m := NewMonitor(c, health_newStore(t, model.Profile{}), nil, false)

	// A group probe (no iface) goes via clash.Delay; an unreachable API must yield Unknown — not
	// Down (which would falsely mark a healthy kernel tunnel as failed) and not a panic.
	if st, _ := m.probe(context.Background(), "g", "", ""); st != Unknown {
		t.Errorf("probe with unreachable clash = %v, want Unknown", st)
	}

	// sampleTraffic must be a harmless no-op (no panic, stats untouched) when /connections fails.
	m.stats["x"] = &stat{totalUp: 42}
	m.sampleTraffic(context.Background(), nil, nowMS())
	if got := m.stats["x"].totalUp; got != 42 {
		t.Errorf("sampleTraffic must not mutate stats when clash is unreachable: totalUp=%d, want 42", got)
	}
}

// TestSampleTrafficPreservesBaselineOnClashFailure: a transient clash /connections failure must NOT
// reset a sing-box-tagged stat's cumulative baseline (activeUp/activeDown) — resetting it would make
// the next successful poll recount the still-open connection's full cumulative into totalUp/totalDown
// (a permanent, self-compounding inflation). Only the displayed rate is zeroed.
func TestSampleTrafficPreservesBaselineOnClashFailure(t *testing.T) {
	ts := httptest.NewServer(http.NewServeMux())
	addr := strings.TrimPrefix(ts.URL, "http://")
	ts.Close()
	c, err := clash.New(addr, "")
	if err != nil {
		t.Fatalf("clash.New: %v", err)
	}
	m := NewMonitor(c, health_newStore(t, model.Profile{}), nil, false)
	m.stats["sb"] = &stat{activeUp: 1000, activeDown: 2000, rateUp: 500, lastConnSample: 5000}

	m.sampleTraffic(context.Background(), nil, 9000) // clash fails, no iface targets

	s := m.stats["sb"]
	if s.activeUp != 1000 || s.activeDown != 2000 {
		t.Errorf("a failed clash poll must PRESERVE the active baseline (else recovery double-counts): activeUp=%d activeDown=%d, want 1000/2000", s.activeUp, s.activeDown)
	}
	if s.rateUp != 0 {
		t.Errorf("the displayed rate should be zeroed on a poll with no observed traffic: rateUp=%d", s.rateUp)
	}
}

// TestSnapshotDerivesGroupSecondaryMetricsFromMember: a kernel selector group whose own Clash probe
// never succeeds is shown alive (from its members), so its uptime/success-rate/latency must also be
// derived from a representative alive member rather than staying at its failed-probe zeros.
func TestSnapshotDerivesGroupSecondaryMetricsFromMember(t *testing.T) {
	p := model.Profile{
		Endpoints: []model.Endpoint{{ID: "e", Name: "E", Protocol: model.ProtoVLESS, Server: "1.2.3.4", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u"}}},
		Groups:    []model.Group{{ID: "g", Name: "G", Type: model.GroupSelector, Members: []string{"e"}}},
	}
	m := NewMonitor(nil, health_newStore(t, p), nil, false)
	now := nowMS()
	for i := 0; i < 5; i++ {
		m.record("e", "E", "endpoint", Alive, 30, now-int64((5-i)*1000))
	}
	m.record("g", "G", "group", Unknown, 0, now) // the group's own probe never succeeds

	views := map[string]View{}
	for _, v := range m.Snapshot() {
		views[v.ID] = v
	}
	g, e := views["g"], views["e"]
	if g.State != "alive" {
		t.Fatalf("group should derive alive from its member, got %q", g.State)
	}
	if e.SuccessRate == 0 || e.LatencyMs == 0 {
		t.Fatalf("setup: member should have non-zero metrics, got success=%d latency=%d", e.SuccessRate, e.LatencyMs)
	}
	if g.SuccessRate != e.SuccessRate || g.LatencyMs != e.LatencyMs {
		t.Errorf("group secondary metrics must derive from the alive member: group success=%d latency=%d, member success=%d latency=%d", g.SuccessRate, g.LatencyMs, e.SuccessRate, e.LatencyMs)
	}
}
