package server

import (
	"strings"
	"testing"
)

// TestCoreEffectiveNeverClaimsAnUnattributableCore (L5): "applied" is a claim about WayHop's own
// record, and it must not be made about a process WayHop neither started nor can inspect.
//
// MONITOR MODE — the core is up, WayHop did not start it — returned effectiveApplied with the reason
// "core running the applied config". Three separate statements in the same file said the opposite:
// the branch's own comment ("may be serving a completely different config — unverifiable by
// construction"), the doc above effectiveState ("returns unknown whenever attribution is impossible
// — notably MONITOR MODE"), and the line immediately below it ("cannot attribute runtime to the
// applied config"). Nothing exercised the case, because the predicates it reads are unexported state
// on the core manager; that is why the decision now lives in a pure function.
func TestCoreEffectiveNeverClaimsAnUnattributableCore(t *testing.T) {
	// The case that was wrong: running, but not ours.
	v, reason := coreEffective(true, false, true)
	if v != effectiveUnknown {
		t.Errorf("a core WayHop did not start cannot prove the applied revision: %q (%s)", v, reason)
	}
	if v == effectiveApplied {
		t.Fatal("claiming applied here is the defect")
	}
	if !strings.Contains(reason, "did not start") {
		t.Errorf("and the reason must say why it cannot be attributed: %q", reason)
	}

	// The case that was right, and must stay right: WayHop started it and it is up.
	if v, _ := coreEffective(true, true, true); v != effectiveApplied {
		t.Errorf("a core WayHop started and that is running IS attributable: %q", v)
	}
	// Started and dead is drift, not unknown: WayHop asked for it, so the gap is a fact about the
	// applied config rather than a gap in knowledge.
	if v, _ := coreEffective(true, true, false); v != effectiveDrift {
		t.Errorf("started-and-not-running is drift: %q", v)
	}
	// No binary at all: provably not running the applied config.
	if v, _ := coreEffective(false, true, true); v != effectiveDrift {
		t.Errorf("with no binary nothing can be running the applied config: %q", v)
	}
	// Neither started nor running: nothing to attribute either way.
	if v, _ := coreEffective(true, false, false); v != effectiveUnknown {
		t.Errorf("nothing running and nothing started is unknown: %q", v)
	}
}
