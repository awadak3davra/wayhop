package plugin

import (
	"testing"

	"wayhop/internal/model"
)

func specs_awg(id string) Spec {
	return Spec{ID: id, Endpoint: model.Endpoint{
		ID: id, Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
		Server: "1.2.3.4", Port: 51820, Enabled: true,
		Params: map[string]any{"private_key": "k", "peer_public_key": "p"},
	}}
}

// TestManagerSpecsTracksLastSync: Specs() returns a copy of the most recent desired set
// passed to Sync — the fail-safe rollback uses it to restore the pre-window plugin set.
// (No engine binaries on the test host, so the AmneziaWG starts degrade to needs_binary
// and no real ip/awg command runs; lastSpecs is still tracked.)
func TestManagerSpecsTracksLastSync(t *testing.T) {
	m := New(t.TempDir(), t.TempDir())
	defer m.StopAll()

	if got := m.Specs(); len(got) != 0 {
		t.Fatalf("fresh manager Specs = %v, want empty", got)
	}
	m.Sync([]Spec{specs_awg("a")})
	got := m.Specs()
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("Specs after Sync([a]) = %v, want [a]", got)
	}
	// Specs returns a COPY — mutating it must not affect the manager's record.
	got[0].ID = "mutated"
	if m.Specs()[0].ID != "a" {
		t.Error("Specs() did not return a copy (caller mutation leaked into the manager)")
	}
	m.Sync(nil)
	if got := m.Specs(); len(got) != 0 {
		t.Errorf("Specs after Sync(nil) = %v, want empty", got)
	}
}

// After StopAll nothing may start again: an Apply or a Components install still running past the
// daemon's shutdown called Sync, which created procs nobody would ever stop (QA-097).
func TestSyncAfterStopAllStartsNothing(t *testing.T) {
	m := New(t.TempDir(), t.TempDir())
	m.StopAll()
	m.Sync([]Spec{specs_awg("late")})
	m.mu.Lock()
	n := len(m.procs)
	m.mu.Unlock()
	if n != 0 {
		t.Fatalf("Sync after StopAll created %d proc(s)", n)
	}
}
