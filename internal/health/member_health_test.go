package health

import "testing"

// TestMemberHealth maps the monitor's committed state to the failover controller's input: alive
// members carry their latency, a confirmed-down member is not alive, an unprobed member is not
// alive (never guessed), and the builtin "direct"/WAN member is always alive.
func TestMemberHealth(t *testing.T) {
	m := &Monitor{stats: map[string]*stat{}} // demo=false

	m.record("a", "A", "endpoint", Alive, 23, 1000)
	// Two downs to cross flapThreshold and commit "b" to Down.
	m.record("b", "B", "endpoint", Down, 0, 1000)
	m.record("b", "B", "endpoint", Down, 0, 2000)
	// "c" is never probed.

	got := m.MemberHealth([]string{"a", "b", "c", "direct"})
	if len(got) != 4 {
		t.Fatalf("MemberHealth returned %d entries, want 4", len(got))
	}
	byID := map[string]struct {
		alive bool
		lat   int
	}{}
	for _, h := range got {
		byID[h.ID] = struct {
			alive bool
			lat   int
		}{h.Alive, h.LatencyMs}
	}
	if !byID["a"].alive || byID["a"].lat != 23 {
		t.Errorf("a = %+v, want alive latency 23", byID["a"])
	}
	if byID["b"].alive {
		t.Errorf("b = %+v, want not alive (confirmed down)", byID["b"])
	}
	if byID["c"].alive {
		t.Errorf("c = %+v, want not alive (never probed)", byID["c"])
	}
	if !byID["direct"].alive {
		t.Errorf("direct = %+v, want always alive (WAN)", byID["direct"])
	}
}
