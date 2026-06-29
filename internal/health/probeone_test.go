package health

import (
	"context"
	"testing"

	"velinx/internal/model"
)

// TestProbeOneUnknownIDDoesNotRecord verifies Fix #5: probing an id that matches
// no current target must NOT create an m.stats entry (record() would otherwise
// add a permanent map entry keyed by the caller-supplied id, an unbounded-growth
// vector via POST /api/health/test/{random}). The returned View must be the
// empty/Unknown view (with the requested id preserved).
func TestProbeOneUnknownIDDoesNotRecord(t *testing.T) {
	// nil clash + nil log source: probe() short-circuits to Unknown,0 — fully
	// offline, so this never touches the network even for a known id.
	m := NewMonitor(nil, health_newStore(t, model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ep-known", Name: "Known EP", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "a.example", Port: 443, Enabled: true},
		},
	}), nil, false)

	v := m.ProbeOne(context.Background(), "ghost")

	m.mu.Lock()
	_, exists := m.stats["ghost"]
	n := len(m.stats)
	m.mu.Unlock()
	if exists {
		t.Fatalf("unknown id created an m.stats entry")
	}
	if n != 0 {
		t.Fatalf("m.stats grew to %d entries for an unknown id, want 0", n)
	}
	if v.ID != "ghost" {
		t.Errorf("view id = %q, want ghost", v.ID)
	}
	if v.State != string(Unknown) || v.Handshake != "unknown" {
		t.Errorf("unknown-id view = {state:%q handshake:%q}, want unknown/unknown", v.State, v.Handshake)
	}
	if v.Probes != 0 || v.Name != "" {
		t.Errorf("unknown-id view should be empty: probes=%d name=%q", v.Probes, v.Name)
	}
}

// TestProbeOneKnownIDProbesAndRecords verifies the known-id path is unchanged:
// a target that exists is probed and recorded (an m.stats entry appears with at
// least one probe), and the returned View carries the target's id.
func TestProbeOneKnownIDProbesAndRecords(t *testing.T) {
	// nil clash -> probe() returns Unknown,0 for a non-iface endpoint, but record()
	// still runs and creates the stat entry (probes incremented).
	m := NewMonitor(nil, health_newStore(t, model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ep-known", Name: "Known EP", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "a.example", Port: 443, Enabled: true},
		},
	}), nil, false)

	v := m.ProbeOne(context.Background(), "ep-known")

	m.mu.Lock()
	s := m.stats["ep-known"]
	m.mu.Unlock()
	if s == nil {
		t.Fatalf("known id did not create an m.stats entry")
	}
	if s.probes < 1 {
		t.Fatalf("known id was not probed: probes=%d", s.probes)
	}
	if v.ID != "ep-known" {
		t.Errorf("view id = %q, want ep-known", v.ID)
	}
}
