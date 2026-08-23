package failover

import "testing"

func TestOutlierEjectsAfterConsecutiveFailures(t *testing.T) {
	o := NewOutlierDetector(OutlierConfig{ConsecutiveFailures: 3, BaseEjectionMS: 1000, MaxEjectionMS: 100000})

	// Two failures: not yet ejected.
	o.Record("m", false, 0)
	o.Record("m", false, 0)
	if o.Ejected("m", 0) {
		t.Fatal("two failures should not eject (threshold 3)")
	}
	// Third consecutive failure → ejected for base window (1s).
	o.Record("m", false, 0)
	if !o.Ejected("m", 0) {
		t.Fatal("three consecutive failures should eject")
	}
	if !o.Ejected("m", 999) {
		t.Fatal("still ejected within the 1s window")
	}
	// After the window elapses → available again.
	if o.Ejected("m", 1000) {
		t.Fatal("should be available once the ejection window elapses")
	}
}

func TestOutlierSuccessResetsRun(t *testing.T) {
	o := NewOutlierDetector(OutlierConfig{ConsecutiveFailures: 3})
	o.Record("m", false, 0)
	o.Record("m", false, 0)
	o.Record("m", true, 0) // clean traffic resets the consecutive run
	o.Record("m", false, 0)
	o.Record("m", false, 0)
	if o.Ejected("m", 0) {
		t.Fatal("a success in between should reset the run — only 2 consecutive since, no ejection")
	}
}

func TestOutlierEjectionWindowGrows(t *testing.T) {
	o := NewOutlierDetector(OutlierConfig{ConsecutiveFailures: 1, BaseEjectionMS: 1000, MaxEjectionMS: 100000})
	// First ejection at t=0 → 1× base = 1s (until 1000).
	o.Record("m", false, 0)
	if o.Ejected("m", 1000) {
		t.Fatal("first ejection window is 1s")
	}
	// Second ejection at t=1000 → 2× base = 2s (until 3000).
	o.Record("m", false, 1000)
	if !o.Ejected("m", 2500) {
		t.Fatal("second ejection window should be 2s (grows)")
	}
	if o.Ejected("m", 3000) {
		t.Fatal("second window ends at 3000")
	}
}

func TestOutlierMaxEjectionCap(t *testing.T) {
	o := NewOutlierDetector(OutlierConfig{ConsecutiveFailures: 1, BaseEjectionMS: 1000, MaxEjectionMS: 2000})
	now := int64(0)
	for i := 0; i < 10; i++ { // many ejections would grow past the cap
		o.Record("m", false, now)
		now = o.state["m"].ejectedUntil // jump to the end of each window
	}
	// The last window must be capped at MaxEjection (2s), not 10× base.
	if got := o.state["m"].ejectedUntil - (now - 2000); got > 2000 {
		t.Errorf("ejection window %d exceeded the 2s cap", got)
	}
}

func TestOutlierUnknownMemberNotEjected(t *testing.T) {
	o := NewOutlierDetector(OutlierConfig{})
	if o.Ejected("never-seen", 1000) {
		t.Error("a member with no recorded traffic must not be ejected")
	}
}

func TestOutlierConfigDefaults(t *testing.T) {
	c := OutlierConfig{}
	if c.consecutiveFailures() != defaultConsecutiveFailures || c.baseEjection() != defaultBaseEjectionMS || c.maxEjection() != defaultMaxEjectionMS {
		t.Errorf("zero OutlierConfig did not fall back to defaults: %+v", c)
	}
}
