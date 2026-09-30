//go:build linux

package awg

import (
	"syscall"
	"testing"
)

// On the router the number is named from the router's own table, which is not the same on every
// arch: EADDRINUSE is 98 on arm and x86 and 125 on mips, and a fixed table would name one of them
// wrong.
func TestErrnoText_ReadsThisPlatformsTable(t *testing.T) {
	if got := errnoText(-int64(syscall.EADDRINUSE)); got != syscall.EADDRINUSE.Error() {
		t.Errorf("EADDRINUSE named %q", got)
	}
	if got := errnoText(-22); got != "invalid argument" {
		t.Errorf("-22 named %q", got)
	}
	if got := errnoText(0); got != "" {
		t.Errorf("status 0 named %q", got)
	}
}
