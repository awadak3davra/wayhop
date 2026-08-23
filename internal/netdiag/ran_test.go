package netdiag

import (
	"context"
	"testing"
	"time"
)

// Ok=false used to mean two different things: the target did not answer, and the probe never ran.
// The fail-safe reads a failure as lost connectivity, rolls the configuration back and then reboots
// the router — so on a device without ping on the init system's PATH, an Apply would reboot a box
// whose internet was fine. Ran is what separates them.
func TestPing_InvalidTargetDidNotRun(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// ValidTarget rejects this before anything is executed: nothing was measured.
	r := Ping(ctx, "not a host; rm -rf /", 1)
	if r.Ok {
		t.Fatal("an invalid target cannot be reachable")
	}
	if r.Ran {
		t.Error("nothing was executed, so Ran must be false — this is the distinction the fail-safe needs")
	}
}

// A cancelled context means the measurement did not complete, not that the target is down.
func TestPing_CancelledDidNotRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := Ping(ctx, "127.0.0.1", 1)
	if r.Ran {
		t.Errorf("a cancelled probe measured nothing, got Ran=true (output %q)", r.Output)
	}
	if r.Ok {
		t.Error("a cancelled probe cannot report reachable")
	}
}

// Loopback is reachable everywhere this suite runs, and it proves the positive path still sets both.
func TestPing_LoopbackRanAndOk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r := Ping(ctx, "127.0.0.1", 1)
	if !r.Ran {
		t.Skipf("no usable ping on this host (%q) — the case under test cannot be exercised here", r.Output)
	}
	if !r.Ok {
		t.Errorf("loopback should be reachable: loss=%d output=%q", r.LossPct, r.Output)
	}
	if r.LossPct < 0 {
		t.Error("Ran implies a parsed loss figure")
	}
}

// Ran must never be true without a loss figure behind it: it is a claim that a measurement exists.
func TestPing_RanImpliesAParsedResult(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, target := range []string{"127.0.0.1", "192.0.2.1"} { // TEST-NET-1: routable, never answers
		r := Ping(ctx, target, 1)
		if r.Ran && r.LossPct < 0 {
			t.Errorf("%s: Ran=true with no loss figure", target)
		}
		if r.Ok && !r.Ran {
			t.Errorf("%s: Ok=true without a measurement", target)
		}
	}
}
