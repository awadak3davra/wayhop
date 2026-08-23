package updater

import "testing"

func TestEnoughSpaceFor(t *testing.T) {
	const mb = 1 << 20
	cases := []struct {
		name       string
		avail      uint64
		known      bool
		binSize    int
		withBackup bool
		want       bool
	}{
		{"unknown free space never blocks", 0, false, 8 * mb, true, true},
		{"plenty for binary+backup", 100 * mb, true, 8 * mb, true, true},
		{"too tight for binary+backup", 10 * mb, true, 8 * mb, true, false}, // need ~18MB
		{"exactly enough for binary+backup", 18*mb + 1, true, 8 * mb, true, true},
		{"install (no backup) fits", 11 * mb, true, 8 * mb, false, true}, // need ~10MB
		{"install too tight (margin counts)", 9 * mb, true, 8 * mb, false, false},
	}
	for _, c := range cases {
		if got := enoughSpaceFor(c.avail, c.known, c.binSize, c.withBackup); got != c.want {
			t.Errorf("%s: enoughSpaceFor(%d, %v, %d, %v) = %v, want %v",
				c.name, c.avail, c.known, c.binSize, c.withBackup, got, c.want)
		}
	}
}
