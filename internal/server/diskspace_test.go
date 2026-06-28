package server

import (
	"context"
	"testing"
)

func TestDiskVerdict(t *testing.T) {
	cases := []struct {
		avail  uint64
		ok     bool
		status string
	}{
		{0, false, "warn"},       // unknown (off-Linux)
		{1 << 20, true, "fail"},  // 1 MiB — critical
		{2 << 20, true, "fail"},  // 2 MiB — critical
		{5 << 20, true, "warn"},  // 5 MiB — low
		{9 << 20, true, "warn"},  // 9 MiB — low
		{20 << 20, true, "pass"}, // 20 MiB — fine
		{500 << 20, true, "pass"},
	}
	for _, c := range cases {
		got, _, _ := diskVerdict(c.avail, c.ok)
		if got != c.status {
			t.Errorf("diskVerdict(%d MiB, ok=%v) = %q, want %q", c.avail>>20, c.ok, got, c.status)
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
	case "pass", "warn", "fail":
	default:
		t.Fatalf("status=%q, want pass/warn/fail", got.Status)
	}
}
