package health

import (
	"testing"

	"wayhop/internal/clash"
	"wayhop/internal/model"
)

// TestSampleTrafficDecaysWhenConnsGone guards the stale-rate fix: once an endpoint's
// connections all disappear (e.g. traffic moved off it after a failover), its reported
// rate must decay to 0 rather than freezing at the last positive value forever.
func TestSampleTrafficDecaysWhenConnsGone(t *testing.T) {
	st := health_newStore(t, model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "up", Name: "Up", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "u.example", Port: 443, Enabled: true},
		},
	})
	m := NewMonitor(nil, st, nil, false)
	now1 := int64(1_700_000_000_000)
	now2 := now1 + 2000

	m.record("up", "Up", "endpoint", Alive, 10, now1)
	m.sampleTrafficWith(t, now1, clash.Connections{Connections: []clash.Conn{
		{Upload: 1000, Download: 4000, Chains: []string{"up"}},
	}})
	m.sampleTrafficWith(t, now2, clash.Connections{Connections: []clash.Conn{
		{Upload: 3000, Download: 14000, Chains: []string{"up"}},
	}})

	// Precondition: a positive rate is showing.
	if v, _ := health_viewByID(m.Snapshot(), "up"); v.RateDownBps == 0 {
		t.Fatalf("precondition failed: expected a positive rate before decay")
	}

	// The endpoint's connections are now GONE (empty payload). Its rate must decay to 0.
	m.sampleTrafficWith(t, now2+2000, clash.Connections{})
	v, _ := health_viewByID(m.Snapshot(), "up")
	if v.RateUpBps != 0 || v.RateDownBps != 0 {
		t.Errorf("rate after all conns gone = up %d / down %d, want 0/0 (stale-rate decay)", v.RateUpBps, v.RateDownBps)
	}
}
