package health

import (
	"os"
	"path/filepath"
	"testing"

	"velinx/internal/model"
)

// TestIfaceBytesFrom: parse rx/tx from a sysfs-shaped temp dir; missing iface -> ok=false.
func TestIfaceBytesFrom(t *testing.T) {
	root := t.TempDir()
	statDir := filepath.Join(root, "awg0", "statistics")
	if err := os.MkdirAll(statDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(statDir, "rx_bytes"), []byte("873438809020\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(statDir, "tx_bytes"), []byte("20063487228"), 0o644); err != nil {
		t.Fatal(err)
	}
	rx, tx, ok := ifaceBytesFrom(root, "awg0")
	if !ok || rx != 873438809020 || tx != 20063487228 {
		t.Fatalf("ifaceBytesFrom = (%d, %d, %v), want (873438809020, 20063487228, true)", rx, tx, ok)
	}
	if _, _, ok := ifaceBytesFrom(root, "nope"); ok {
		t.Error("absent iface must return ok=false")
	}
}

// TestSampleTrafficKernelIface: a kernel-routed endpoint (AmneziaWG, no Clash) gets its throughput
// from the iface counters — up=tx, down=rx — with rates/totals derived from sample-to-sample deltas.
// This is the per-endpoint traffic that clash /connections can't see for kernel-routed endpoints.
func TestSampleTrafficKernelIface(t *testing.T) {
	p := model.Profile{Endpoints: []model.Endpoint{{
		ID: "awg", Name: "AWG", Protocol: model.ProtoAmneziaWG, Engine: model.EngineAmneziaWG,
		Server: "1.2.3.4", Port: 51820, Enabled: true,
		Params: map[string]any{"private_key": "k", "peer_public_key": "k", "local_address": []string{"10.0.0.2/32"}},
	}}}
	m := NewMonitor(nil, health_newStore(t, p), nil, false)
	var rx, tx int64 = 1000, 100
	m.ifaceBytesFn = func(string) (int64, int64, bool) { return rx, tx, true }

	now := nowMS()
	m.record("awg", "AWG", "endpoint", Alive, 5, now) // create the stat (sampleTraffic skips nil stats)
	tgs := m.targetsFrom(p)

	// First sample: baseline only (no prior sample -> no delta).
	m.sampleTraffic(nil, tgs, now)
	// Second sample 1s later: +2000 rx (down), +200 tx (up).
	rx, tx = 3000, 300
	m.sampleTraffic(nil, tgs, now+1000)

	s := m.stats["awg"]
	if s.totalDown != 2000 || s.rateDown != 2000 {
		t.Errorf("down: total=%d rate=%d, want 2000/2000", s.totalDown, s.rateDown)
	}
	if s.totalUp != 200 || s.rateUp != 200 {
		t.Errorf("up: total=%d rate=%d, want 200/200", s.totalUp, s.rateUp)
	}
}
