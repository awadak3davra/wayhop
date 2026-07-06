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
