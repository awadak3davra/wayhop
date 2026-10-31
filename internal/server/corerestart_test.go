package server

import (
	"testing"
	"time"
	_ "time/tzdata" // the DST case needs a real zone on any test host
)

// A daily time fires once in its minute; an interval counts from the last restart, or from start.
func TestCoreRestartDue(t *testing.T) {
	loc := time.FixedZone("MSK", 3*3600)
	at := func(h, m int) time.Time { return time.Date(2026, 10, 29, h, m, 15, 0, loc) }
	start := at(1, 0)
	for _, tc := range []struct {
		name       string
		spec       string
		now, last  time.Time
		wantFiring bool
	}{
		{"off", "", at(4, 30), time.Time{}, false},
		{"daily, its minute", "04:30", at(4, 30), time.Time{}, true},
		{"daily, the minute before", "04:30", at(4, 29), time.Time{}, false},
		{"daily, already fired this minute", "04:30", at(4, 30).Add(20 * time.Second), at(4, 30), false},
		{"daily, fired yesterday", "04:30", at(4, 30), at(4, 30).Add(-24 * time.Hour), true},
		{"every 6h, 5h59 after start", "6h", start.Add(5*time.Hour + 59*time.Minute), time.Time{}, false},
		{"every 6h, 6h after start", "6h", start.Add(6 * time.Hour), time.Time{}, true},
		{"every 6h, 3h after the last", "6h", at(10, 0), at(7, 0), false},
		{"every 6h, 6h after the last", "6h", at(13, 0), at(7, 0), true},
		{"malformed never fires", "4:30am", at(4, 30), time.Time{}, false},
	} {
		if got := coreRestartDue(tc.spec, tc.now, loc, tc.last, start); got != tc.wantFiring {
			t.Errorf("%s: due = %v, want %v", tc.name, got, tc.wantFiring)
		}
	}
}

// The night clocks go back repeats an hour: a daily time inside it is the same minute twice, an hour
// apart, and must restart the core once.
func TestCoreRestartDueOnceInARepeatedHour(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	// 2026-10-25 03:00 CEST becomes 02:00 CET: 02:30 happens at 00:30 and again at 01:30 UTC.
	first := time.Date(2026, 10, 25, 0, 30, 10, 0, time.UTC)
	second := first.Add(time.Hour)
	if a, b := first.In(berlin).Format("15:04"), second.In(berlin).Format("15:04"); a != "02:30" || b != "02:30" {
		t.Fatalf("test setup: %s and %s are not the repeated 02:30", a, b)
	}
	if !coreRestartDue("02:30", first, berlin, time.Time{}, first.Add(-time.Hour)) {
		t.Fatal("the first 02:30 must fire")
	}
	if coreRestartDue("02:30", second, berlin, first, first.Add(-time.Hour)) {
		t.Error("the repeated 02:30 fired the restart a second time")
	}
	if !coreRestartDue("02:30", second.Add(24*time.Hour), berlin, first, first.Add(-time.Hour)) { // CET from here on
		t.Error("the next night's 02:30 must fire")
	}
}
