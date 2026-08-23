package server

import (
	"math"
	"testing"
)

func TestParseSystem(t *testing.T) {
	mem := "MemTotal:         123456 kB\n" +
		"MemFree:           10000 kB\n" +
		"MemAvailable:      61728 kB\n" +
		"Buffers:            2000 kB\n"
	si := parseSystem(mem, "0.50 0.40 0.30 1/123 4567", "3600.42 7000.00\n")
	if !si.Available {
		t.Fatal("expected Available=true with valid meminfo")
	}
	if si.MemTotalKB != 123456 {
		t.Errorf("MemTotalKB = %d, want 123456", si.MemTotalKB)
	}
	if si.MemAvailKB != 61728 {
		t.Errorf("MemAvailKB = %d, want 61728", si.MemAvailKB)
	}
	// used = 123456-61728 = 61728 → 50%
	if math.Abs(si.MemUsedPct-50.0) > 0.01 {
		t.Errorf("MemUsedPct = %.3f, want 50.0", si.MemUsedPct)
	}
	if si.Load1 != 0.5 {
		t.Errorf("Load1 = %v, want 0.5", si.Load1)
	}
	if si.UptimeS != 3600 {
		t.Errorf("UptimeS = %d, want 3600", si.UptimeS)
	}
}

func TestParseSystemUnavailable(t *testing.T) {
	// Empty/garbage meminfo (e.g. non-Linux) → not available, no divide-by-zero.
	si := parseSystem("", "", "")
	if si.Available {
		t.Error("expected Available=false with empty meminfo")
	}
	if si.MemUsedPct != 0 {
		t.Errorf("MemUsedPct = %v, want 0", si.MemUsedPct)
	}
}

func TestParseMeminfo(t *testing.T) {
	// Both keys present (MemFree in between must not confuse the single-pass scan).
	total, avail := parseMeminfo("MemTotal:  80000 kB\nMemFree: 5000 kB\nMemAvailable: 40000 kB\n")
	if total != 80000 || avail != 40000 {
		t.Errorf("parseMeminfo = (%d,%d), want (80000,40000)", total, avail)
	}
	// MemAvailable absent (older kernels) → avail 0, total still read.
	if total, avail := parseMeminfo("MemTotal:  80000 kB\n"); total != 80000 || avail != 0 {
		t.Errorf("partial meminfo = (%d,%d), want (80000,0)", total, avail)
	}
	// Empty / non-Linux input → both 0, no panic.
	if total, avail := parseMeminfo(""); total != 0 || avail != 0 {
		t.Errorf("empty meminfo = (%d,%d), want (0,0)", total, avail)
	}
}
