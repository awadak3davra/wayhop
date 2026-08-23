package server

import (
	"context"
	"testing"
)

func TestDiskVerdict(t *testing.T) {
	// 13 MiB is the size of the real arm64 binary, so `needed` works out at ~15 MiB: the swap stages
	// the new one beside the old. The AX3000T's 12.6 MB free is the case this rewrite exists for —
	// Diagnostics called it "enough free space" while the Components page, which knows what an install
	// costs, called the same filesystem "Little room on internal flash".
	const selfSize = 13 << 20
	// The second threshold is what a COMPONENT install needs. Between the two the verdict stays a
	// pass, but it must name which question it answered: an unqualified "enough free space" here is
	// the sentence that contradicted the Components page about one disk.
	const floor = componentInstallFloor
	cases := []struct {
		avail    uint64
		ok       bool
		selfSize uint64
		status   string
		scoped   bool // pass, but only to the swap question — must say so
	}{
		{0, false, selfSize, "na", false},          // unreadable — not a verdict
		{1 << 20, true, selfSize, "fail", false},   // 1 MiB — critical
		{2 << 20, true, selfSize, "fail", false},   // 2 MiB — critical
		{5 << 20, true, selfSize, "warn", false},   // 5 MiB — cannot swap
		{12 << 20, true, selfSize, "warn", false},  // the AX3000T: was "pass" under the flat 10 MiB rule
		{15 << 20, true, selfSize, "warn", false},  // 13 + 10% + 1 = 15.3 MiB needed, so 15 is still short
		{16 << 20, true, selfSize, "pass", true},   // clear of the swap need, under the install floor
		{31 << 20, true, selfSize, "pass", true},   // still under it
		{32 << 20, true, selfSize, "pass", false},  // at the floor — the unqualified sentence is true
		{500 << 20, true, selfSize, "pass", false}, //
		{12 << 20, true, 0, "pass", true},          // size unknown ⇒ the old 10 MiB floor, not "everything is fine"
		{5 << 20, true, 0, "warn", false},          //
	}
	for _, c := range cases {
		got, summary, _ := diskVerdict(c.avail, c.ok, c.selfSize, floor)
		if got != c.status {
			t.Errorf("diskVerdict(%d MiB, ok=%v, self=%d MiB) = %q, want %q", c.avail>>20, c.ok, c.selfSize>>20, got, c.status)
		}
		// A warn has to carry the numbers, because "storage low" over 12 MiB free is exactly the
		// message that read as fine next to a page saying the opposite.
		if got == "warn" && c.selfSize > 0 && summary == "router storage low" {
			t.Errorf("warn summary lost its numbers: %q", summary)
		}
		if got != "pass" {
			continue
		}
		bare := summary == "enough free space"
		if c.scoped && bare {
			t.Errorf("diskVerdict(%d MiB) passed with the unqualified %q while a component needs %d MiB — "+
				"that is the sentence the Components page contradicts", c.avail>>20, summary, floor>>20)
		}
		if !c.scoped && !bare {
			t.Errorf("diskVerdict(%d MiB) is clear of both thresholds but hedged: %q", c.avail>>20, summary)
		}
	}
}

// TestDiskSpaceCheck: the battery probe returns a disk-space row with a valid status (the dev host
// has ample space → pass, or non-Linux → warn).
func TestDiskSpaceCheck(t *testing.T) {
	s, _ := sharehandlers_server(t)
	got := s.diskSpaceCheck(context.Background())
	if got.ID != "disk-space" {
		t.Fatalf("id=%q, want disk-space", got.ID)
	}
	switch got.Status {
	case "pass", "warn", "fail", "na":
	default:
		t.Fatalf("status=%q, want pass/warn/fail/na", got.Status)
	}
}
