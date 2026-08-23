package server

import (
	"context"
	"testing"
)

func TestConntrackVerdict(t *testing.T) {
	cases := []struct {
		count, max int
		want       string
	}{
		// No table means nothing was measured, which is not the same answer as "measured, and it
		// has room" — the row now says so instead of joining the greens.
		{0, 0, "na"},        // table not exposed (non-Linux / module absent)
		{100, 0, "na"},      // max 0 → div-by-zero guard
		{100, 1000, "pass"}, // 10%
		{799, 1000, "pass"}, // just under the warn threshold
		{800, 1000, "warn"}, // 80%
		{949, 1000, "warn"}, // just under fail
		{950, 1000, "fail"}, // 95%
		{1000, 1000, "fail"},
	}
	for _, c := range cases {
		if got, _, _ := conntrackVerdict(c.count, c.max); got != c.want {
			t.Errorf("conntrackVerdict(%d/%d) = %q, want %q", c.count, c.max, got, c.want)
		}
	}
}

// TestConntrackCheck: the battery probe returns the conntrack row with a valid status (the dev host
// has no /proc/sys/net/netfilter → not-in-use → pass).
func TestConntrackCheck(t *testing.T) {
	got := conntrackCheck(context.Background())
	if got.ID != "conntrack" {
		t.Fatalf("id=%q, want conntrack", got.ID)
	}
	switch got.Status {
	case "pass", "warn", "fail", "na":
	default:
		t.Fatalf("status=%q, want pass/warn/fail/na", got.Status)
	}
}
