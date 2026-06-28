package server

import (
	"context"
	"testing"
	"time"
)

func TestSubscriptionVerdict(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	cases := []struct {
		name   string
		hours  int
		last   time.Time
		errStr string
		want   string
	}{
		{"last fetch failed", 6, now.Add(-1 * time.Hour), "dial timeout", "warn"},
		{"never run yet", 6, time.Time{}, "", "pass"},
		{"fresh", 6, now.Add(-5 * time.Hour), "", "pass"},
		{"within grace (2x+1h)", 6, now.Add(-12 * time.Hour), "", "pass"},
		{"stale", 6, now.Add(-20 * time.Hour), "", "warn"}, // > 2*6+1 = 13h
	}
	for _, c := range cases {
		if got, _, _ := subscriptionVerdict(c.hours, c.last, c.errStr, now); got != c.want {
			t.Errorf("%s: verdict = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSubscriptionCheck: with no auto-refreshing subscription configured (the default in the test
// harness), the probe passes; the row is well-formed.
func TestSubscriptionCheck(t *testing.T) {
	s, _ := sharehandlers_server(t)
	got := s.subscriptionCheck(context.Background())
	if got.ID != "subscription" {
		t.Fatalf("id=%q, want subscription", got.ID)
	}
	if got.Status != "pass" {
		t.Fatalf("no-subscription should pass, got %q", got.Status)
	}
}
