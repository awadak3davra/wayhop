package main

import (
	"math"
	"testing"
)

func TestSoftMemLimit(t *testing.T) {
	const unset = math.MaxInt64
	cases := []struct {
		name    string
		total   uint64
		current int64
		envSet  bool
		want    int64
	}{
		{"unset-256MB-capped", 256 << 20, unset, false, 64 << 20},        // half=128 → capped to 64 MiB ceiling
		{"unset-64MB", 64 << 20, unset, false, 32 << 20},                 // half=32 < ceiling → unchanged
		{"unset-128MB-at-ceiling", 128 << 20, unset, false, 64 << 20},    // half=64 == ceiling
		{"unset-100MB-below-ceiling", 100 << 20, unset, false, 50 << 20}, // half=50 < ceiling → unchanged
		{"unset-1GB-capped", 1 << 30, unset, false, 64 << 20},            // half=512 → capped to 64 MiB
		{"operator-number-honored", 256 << 20, 200 << 20, false, 0},
		{"operator-off-honored", 256 << 20, unset, true, 0}, // GOMEMLIMIT=off must not be overridden
		{"unknown-ram", 0, unset, false, 0},
	}
	for _, c := range cases {
		if got := softMemLimit(c.total, c.current, c.envSet); got != c.want {
			t.Errorf("%s: softMemLimit(%d, %d, %v) = %d, want %d", c.name, c.total, c.current, c.envSet, got, c.want)
		}
	}
}
