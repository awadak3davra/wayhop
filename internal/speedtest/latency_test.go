package speedtest

import "testing"

// A latency probe that did not complete used to leave LatencyMs at its zero value, and the panel
// renders the number directly — so a FAILED probe displayed as "0 ms". Not merely wrong: 0 ms is
// the best possible reading, so a broken measurement looked like an excellent one.
//
// Tested through newResult rather than Run: Tester has no injectable endpoints, so exercising Run
// would mean a real network call in a unit test — and a test that skips proves nothing.
func TestNewResult_StartsWithNoLatencyMeasurement(t *testing.T) {
	for _, viaProxy := range []bool{false, true} {
		res := newResult(viaProxy)
		if res.LatencyMs >= 0 {
			t.Errorf("viaProxy=%v: a fresh result reports latency %d — it must be negative until something measures it",
				viaProxy, res.LatencyMs)
		}
		if res.LatencyMs == 0 {
			t.Errorf("viaProxy=%v: zero is the specific value that displays as a perfect 0 ms", viaProxy)
		}
	}
}

// Via must still be right, since newResult now owns it.
func TestNewResult_NamesThePath(t *testing.T) {
	if got := newResult(false).Via; got != "direct" {
		t.Errorf("viaProxy=false should be direct, got %q", got)
	}
	if got := newResult(true).Via; got != "proxy" {
		t.Errorf("viaProxy=true should be proxy, got %q", got)
	}
}

// The other measured fields legitimately start at zero — a download of 0 bytes at 0 Mbps is what
// "not started" looks like for throughput, and the panel omits an absent upload figure entirely.
// Recorded so the -1 above reads as a deliberate exception, not an inconsistency.
func TestNewResult_ThroughputFieldsStartAtZero(t *testing.T) {
	res := newResult(false)
	if res.DownMbps != 0 || res.UpMbps != 0 || res.DownBytes != 0 {
		t.Errorf("throughput fields should start at zero, got %+v", res)
	}
}
