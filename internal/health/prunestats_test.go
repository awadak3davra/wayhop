package health

import (
	"testing"

	"wayhop/internal/model"
)

// TestPruneStats: stats for targets no longer in the live set are dropped, so m.stats can't grow
// without bound as endpoints are added/removed/renamed (each churn rotates the target id).
func TestPruneStats(t *testing.T) {
	m := NewMonitor(nil, health_newStore(t, model.Profile{}), nil, false)
	now := int64(1000)
	m.record("keep", "Keep", "endpoint", Alive, 10, now)
	m.record("stale-a", "A", "endpoint", Down, 0, now)
	m.record("stale-b", "B", "endpoint", Down, 0, now)

	m.mu.Lock()
	before := len(m.stats)
	m.mu.Unlock()
	if before != 3 {
		t.Fatalf("setup: want 3 stats, got %d", before)
	}

	m.pruneStats([]target{{id: "keep"}})

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.stats) != 1 {
		t.Fatalf("after prune: want 1 stat, got %d (%v)", len(m.stats), m.stats)
	}
	if _, ok := m.stats["keep"]; !ok {
		t.Error("live target 'keep' must survive prune")
	}
	if _, ok := m.stats["stale-a"]; ok {
		t.Error("stale target must be pruned")
	}
}

// TestDemoTickPrunesStaleStats: the demo tick path must prune stale stats too. demoTick
// used to return before tick()'s pruneStats, so deleting/renaming an endpoint or group
// in the (real, editable) demo store left the rotated id's *stat in m.stats forever — a
// slow but unbounded map leak over a long demo session on a memory-constrained router.
func TestDemoTickPrunesStaleStats(t *testing.T) {
	epV := func(id, host string) model.Endpoint {
		return model.Endpoint{ID: id, Name: id, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: host, Port: 443, Enabled: true}
	}
	st := health_newStore(t, model.Profile{
		Endpoints: []model.Endpoint{epV("ep-a", "a.example"), epV("ep-b", "b.example")},
	})
	m := NewMonitor(nil, st, nil, true) // demo mode

	m.demoTick(nowMS())
	m.mu.Lock()
	_, hadB := m.stats["ep-b"]
	m.mu.Unlock()
	if !hadB {
		t.Fatalf("setup: demoTick should have recorded a stat for ep-b")
	}

	// Remove ep-b from the store: the live target set rotates, dropping ep-b's id.
	if err := st.Replace(model.Profile{Endpoints: []model.Endpoint{epV("ep-a", "a.example")}}); err != nil {
		t.Fatalf("store.Replace: %v", err)
	}
	m.demoTick(nowMS())

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.stats["ep-b"]; ok {
		t.Error("stale demo stat 'ep-b' not pruned after the endpoint was removed")
	}
	if _, ok := m.stats["ep-a"]; !ok {
		t.Error("live demo stat 'ep-a' must survive the prune")
	}
}
