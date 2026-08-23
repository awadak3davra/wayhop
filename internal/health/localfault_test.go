package health

import "testing"

func TestAllEndpointsDown(t *testing.T) {
	ep := func(id string) target { return target{id: id, kind: "endpoint"} }
	grp := target{id: "g", kind: "group"}
	tests := []struct {
		name   string
		tgs    []target
		states []State
		want   bool
	}{
		{"two endpoints both down", []target{ep("a"), ep("b")}, []State{Down, Down}, true},
		{"one alive disproves", []target{ep("a"), ep("b")}, []State{Down, Alive}, false},
		{"single endpoint down is not enough", []target{ep("a")}, []State{Down}, false},
		{"two downs + an unknown ⇒ fault (unknown ignored)", []target{ep("a"), ep("b"), ep("c")}, []State{Down, Down, Unknown}, true},
		{"one down + unknowns ⇒ not enough definite downs", []target{ep("a"), ep("b"), ep("c")}, []State{Down, Unknown, Unknown}, false},
		{"three downs qualify", []target{ep("a"), ep("b"), ep("c")}, []State{Down, Down, Down}, true},
		{"groups ignored in the count", []target{grp, ep("a"), ep("b")}, []State{Down, Down, Down}, true},
		{"all unknown ⇒ no fault", []target{ep("a"), ep("b")}, []State{Unknown, Unknown}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allEndpointsDown(tt.tgs, tt.states); got != tt.want {
				t.Errorf("allEndpointsDown = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestLocalFaultSuppressesDownFlips proves the gate: when every endpoint is down at once, the
// monitor raises LocalFault and does NOT flip the individual endpoints to Down (their probes are
// suppressed), so a local-uplink outage doesn't paint every exit red or inflate reconnects.
func TestLocalFaultSuppressesDownFlips(t *testing.T) {
	m := &Monitor{stats: map[string]*stat{}}
	tgs := []target{{id: "a", kind: "endpoint"}, {id: "b", kind: "endpoint"}}

	// Both up first.
	m.applyResults(tgs, []State{Alive, Alive}, []int{10, 12}, 1000)
	if m.LocalFault() {
		t.Fatal("LocalFault set while both endpoints alive")
	}

	// Both go down at once, repeatedly (past flapThreshold): local-fault gate holds them.
	for i := 0; i < flapThreshold+2; i++ {
		m.applyResults(tgs, []State{Down, Down}, []int{0, 0}, int64(2000+i*1000))
	}
	if !m.LocalFault() {
		t.Fatal("LocalFault not set when all endpoints down at once")
	}
	for _, id := range []string{"a", "b"} {
		if v := toView(id, m.stats[id], 9000); v.State == "down" {
			t.Errorf("endpoint %s flipped to down during a local fault (should be held): state=%s", id, v.State)
		}
		if v := toView(id, m.stats[id], 9000); v.Reconnects != 0 {
			t.Errorf("endpoint %s reconnects=%d, want 0 (no thrash during local fault)", id, v.Reconnects)
		}
	}

	// A real single-exit failure (the other still alive) is NOT a local fault and DOES flip.
	for i := 0; i < flapThreshold; i++ {
		m.applyResults(tgs, []State{Down, Alive}, []int{0, 8}, int64(10000+i*1000))
	}
	if m.LocalFault() {
		t.Fatal("LocalFault set when one endpoint is still alive")
	}
	if v := toView("a", m.stats["a"], 13000); v.State != "down" {
		t.Errorf("endpoint a should be down after a genuine single-exit failure, got %s", v.State)
	}
}
