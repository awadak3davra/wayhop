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
		{0, 0, "pass"},      // table not exposed (non-Linux / module absent)
		{100, 0, "pass"},    // max 0 → div-by-zero guard
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
	case "pass", "warn", "fail":
	default:
		t.Fatalf("status=%q, want pass/warn/fail", got.Status)
	}
}
