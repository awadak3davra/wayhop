package health

import (
	"context"
	"testing"
)

// A native tunnel (AmneziaWG/WireGuard) is probed by pinging through its kernel interface, and the
// old helper returned a bare bool: false for a missing ping binary, false for an interface the
// kernel does not have, and false for a genuine unreachable. probe() mapped every false to Down, so
// on a router without ping on the service PATH every native tunnel would be marked dead — and
// failover reads those states to decide where traffic goes.

// Built through the constructor: a bare &Monitor{} has a nil stats map and panics on record().
func probeMonitor() *Monitor { return NewMonitor(nil, nil, nil, false) }

// An interface name the validator rejects means nothing was executed. That must read as Unknown,
// not as a measured outage.
func TestProbe_UnrunnableIfaceProbeIsUnknownNotDown(t *testing.T) {
	m := probeMonitor()
	// ValidIface rejects this, so ReachableViaIfaceProbe returns ran=false without running anything.
	st, ms := m.probe(context.Background(), "ep1", "", "not a valid iface; rm -rf /")
	if st == Down {
		t.Fatal("a probe that never ran reported Down — this is what marks working tunnels dead")
	}
	if st != Unknown {
		t.Errorf("expected Unknown, got %q", st)
	}
	if ms != 0 {
		t.Errorf("no measurement means no latency, got %d", ms)
	}
}

// A cancelled context is likewise an absence of measurement.
func TestProbe_CancelledIfaceProbeIsUnknown(t *testing.T) {
	m := probeMonitor()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if st, _ := m.probe(ctx, "ep1", "", "eth0"); st == Down {
		t.Fatal("a cancelled probe measured nothing and must not report Down")
	} else if st != Unknown {
		t.Errorf("expected Unknown, got %q", st)
	}
}

// The Unknown that the iface path now produces must keep the property the monitor already relies
// on: it must not launder a committed state. A tunnel known to be Down stays Down while blind.
func TestRecord_UnknownDoesNotLaunderACommittedDown(t *testing.T) {
	m := probeMonitor()
	// Enough consecutive failures that Down is genuinely committed past the hysteresis threshold.
	for i := 0; i < 10; i++ {
		m.record("ep1", "ep1", "endpoint", Down, 0, int64(i))
	}
	// Read the committed state directly: Snapshot() reaches into the store, which this test has no
	// reason to build, and the property under test is the hysteresis commit itself.
	state := func() State {
		st, ok := m.stats["ep1"]
		if !ok {
			t.Fatal("ep1 was never recorded")
		}
		return st.state
	}
	if got := state(); got != Down {
		t.Fatalf("setup: expected a committed Down, got %q", got)
	}
	m.record("ep1", "ep1", "endpoint", Unknown, 0, 100)
	if got := state(); got != Down {
		t.Errorf("a blind probe rewrote a committed Down to %q — the recovery gate would be bypassed", got)
	}
}

// A kernel exit is pinged at the address its own health-check target names. A VPS that forwards only
// some networks (measured: Google only, for Gemini) never answers the default, so pinging 1.1.1.1
// whatever the target said read a working exit as Down.
func TestIfaceProbeHost_UsesTheExitsTargetAddress(t *testing.T) {
	for target, want := range map[string]string{
		"":                                      defaultIfaceProbeHost,
		"8.8.8.8":                               "8.8.8.8",
		" 203.0.113.7 ":                         "203.0.113.7",
		"http://198.51.100.1/generate_204":      "198.51.100.1",
		"http://[2001:db8::1]:80/x":             "2001:db8::1",
		"::ffff:192.0.2.5":                      "192.0.2.5",
		"http://cp.cloudflare.com/generate_204": defaultIfaceProbeHost, // a name is not resolved here
		"gateway.example":                       defaultIfaceProbeHost,
	} {
		if got := ifaceProbeHost(target); got != want {
			t.Errorf("ifaceProbeHost(%q) = %q, want %q", target, got, want)
		}
	}
}
