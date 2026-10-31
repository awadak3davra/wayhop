package server

import (
	"strings"
	"testing"
)

// A core config that does not fit where an Apply writes it is refused before the first byte is
// written: a refilter-sized feed sent to a proxy makes megabytes of config since QA-066, and the
// test router's overlay had 6.1 MB free. Unknown free space skips the guard.
func TestCoreConfigSpaceError(t *testing.T) {
	free := func(n uint64) func(string) (uint64, bool) { return func(string) (uint64, bool) { return n, true } }
	const size = 2_000_000 // ~60k prefixes inline: needs 3 x 2 MB + the reserve
	if err := coreConfigSpaceError("/etc/wayhop", size, free(6_100_000)); err == nil ||
		!strings.Contains(err.Error(), "not enough free space") || !strings.Contains(err.Error(), "/etc/wayhop") {
		t.Fatalf("6.1 MB free for a 2 MB config: err = %v, want a refusal naming the directory", err)
	}
	if err := coreConfigSpaceError("/etc/wayhop", size, free(60_000_000)); err != nil {
		t.Errorf("60 MB free: %v", err)
	}
	if err := coreConfigSpaceError("/etc/wayhop", 8_000, free(2_000_000)); err != nil {
		t.Errorf("an ordinary 8 KB config with 2 MB free was refused: %v", err)
	}
	if err := coreConfigSpaceError("/etc/wayhop", size, func(string) (uint64, bool) { return 0, false }); err != nil {
		t.Errorf("unknown free space must not block: %v", err)
	}
}
