package config

import (
	"testing"
	"time"
)

func TestParseCoreRestart(t *testing.T) {
	for v, want := range map[string][3]int{"": {0, 0, 0}, "04:30": {4, 30, 0}, "00:00": {0, 0, 0}, "23:59": {23, 59, 0}, "4:30": {4, 30, 0}, "6h": {0, 0, 6}, "24h": {0, 0, 24}} {
		h, m, every, err := ParseCoreRestart(v)
		if err != nil || h != want[0] || m != want[1] || every != time.Duration(want[2])*time.Hour {
			t.Errorf("%q = %d:%d every %v err %v", v, h, m, every, err)
		}
	}
	for _, bad := range []string{"24:00", "12:60", "0h", "25h", "daily", "04:30:00", "-1h",
		// Atoi took these; the panel's check does not.
		"+4:30", "-0:30", "007:30", "4:+5", "006h", "+6h"} {
		if _, _, _, err := ParseCoreRestart(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	c := Default()
	c.CoreRestart = "4:30am"
	if err := c.Validate(); err == nil {
		t.Error("Validate must refuse a malformed schedule")
	}
}
