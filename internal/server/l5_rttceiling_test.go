package server

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestSingleFlowCeiling: the arithmetic this row exists to state. 65535 bytes of window over the
// measured round trip. The 145 ms case is the operator's own tunnel, where a connection whose far
// end skipped window scaling ran at 0.44 MB/s with zero loss and zero retransmissions — the number
// below is where that came from.
func TestSingleFlowCeiling(t *testing.T) {
	cases := []struct{ rtt, want int }{
		{0, 0},        // not measured is not "infinitely fast"
		{-5, 0},       //
		{145, 452000}, // the measured tunnel: ~0.43 MB/s
		{30, 2184500}, // a nearby exit: the same window is no longer the limit
		{1, 65535000},
	}
	for _, c := range cases {
		got := singleFlowCeiling(c.rtt)
		// Integer division, so allow the rounding but not a wrong formula.
		if c.want == 0 && got != 0 {
			t.Errorf("rtt=%d returned %d, want 0", c.rtt, got)
			continue
		}
		if c.want != 0 && (got < c.want-1000 || got > c.want+1000) {
			t.Errorf("rtt=%d ms: ceiling %d B/s, want about %d B/s", c.rtt, got, c.want)
		}
	}
}

// TestRTTCeilingVerdict: the row must warn exactly where the effect is visible as a failed download,
// and must never claim the cap is in force — whether a server negotiates scaling is that server's
// choice, per connection.
func TestRTTCeilingVerdict(t *testing.T) {
	if st, sum, _ := rttCeilingVerdict("", 0); st != "na" || sum == "" {
		t.Errorf("unmeasured round trip gave %q/%q, want a spoken na", st, sum)
	}
	// 145 ms: 0.43 MB/s, under the threshold — this is the measured case.
	st, sum, fix := rttCeilingVerdict("RU exit", 145)
	if st != "warn" {
		t.Fatalf("145 ms gave %q, want warn — this is the case that reads as a broken download", st)
	}
	if !strings.Contains(sum, "145 ms") || !strings.Contains(sum, "RU exit") {
		t.Errorf("summary drops the measurement it is based on: %q", sum)
	}
	// The claim has to stay conditional: the cap applies only when the far end skips scaling.
	if !strings.Contains(strings.ToLower(sum), "window scaling") {
		t.Errorf("summary states the cap unconditionally: %q", sum)
	}
	// And the remedy must not send the operator hunting for a fault that does not exist.
	if !strings.Contains(strings.ToLower(fix), "nothing is broken") {
		t.Errorf("remedy does not say the path is healthy: %q", fix)
	}
	if !strings.Contains(strings.ToLower(fix), "several connections") {
		t.Errorf("remedy does not name the workaround that works: %q", fix)
	}
	// 30 ms: the same arithmetic, comfortably above the threshold — no warning.
	if st2, sum2, fix2 := rttCeilingVerdict("NL exit", 30); st2 != "pass" || fix2 != "" {
		t.Errorf("30 ms gave %q with fix %q — nothing to warn about at 2 MB/s: %q", st2, fix2, sum2)
	}
}

// TestRTTCeilingRegistered: an unregistered row measures nothing.
func TestRTTCeilingRegistered(t *testing.T) {
	raw, err := os.ReadFile("healthcheck.go")
	if err != nil {
		t.Fatalf("read healthcheck.go: %v", err)
	}
	b := string(raw)
	if !strings.Contains(b, "rttCeilingCheck") {
		t.Fatal("rttCeilingCheck is not in the battery list")
	}
}

// TestRTTCeilingSurvivesNoMonitor: the battery runs each row in its own goroutine, so a panic in one
// is not a failed row — it is an unrecovered panic that takes the daemon down. This row reached into
// a monitor that server builds without one leave nil, and the full-package run caught the crash. The
// recover here is deliberate: the assertion IS "it does not panic", and a bare call would abort the
// run instead of reporting it.
func TestRTTCeilingSurvivesNoMonitor(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the row panicked with no monitor, which on a router kills the daemon: %v", r)
		}
	}()
	s := &Server{} // monitor deliberately nil, as the harnesses that crashed leave it
	got := s.rttCeilingCheck(context.TODO())
	if got.Status != "na" {
		t.Errorf("status %q with nothing measured, want na", got.Status)
	}
	if got.Summary == "" {
		t.Error("the row says nothing at all")
	}
}
