package main

import (
	"log"
	"math"
	"os"
	"runtime/debug"
)

// applyMemSoftLimit sets a Go memory soft-limit (GOMEMLIMIT) so a memory spike — a
// bulk subscription import, a large config reload, a runaway list fetch — can't grow
// the heap until the kernel OOM-killer reaps the daemon, which on a low-RAM router
// (256 MB and down) would take routing down with it. GOMEMLIMIT is a SOFT limit: the
// GC works progressively harder as the heap nears it instead of the process failing.
//
// An operator-provided GOMEMLIMIT env (including "off") is honored untouched; a
// default is set only when none was given, derived from detected RAM and held to
// half of physical memory so sing-box, the engine plugins and the kernel keep their
// headroom. No-op on the non-Linux demo build (RAM detection returns 0).
func applyMemSoftLimit() {
	lim := softMemLimit(hostTotalRAM(), debug.SetMemoryLimit(-1), os.Getenv("GOMEMLIMIT") != "")
	if lim <= 0 {
		return
	}
	debug.SetMemoryLimit(lim)
	log.Printf("memory soft-limit: %d MiB (no GOMEMLIMIT set; derived from RAM)", lim>>20)
}

// softMemLimit returns the byte soft-limit to apply, or 0 to leave the limit
// unchanged. current is debug.SetMemoryLimit(-1) (math.MaxInt64 when unset by env);
// total is physical RAM in bytes (0 when unknown, e.g. the non-Linux demo build);
// envSet reports whether the operator set the GOMEMLIMIT env to anything (including
// "off", which the runtime maps to math.MaxInt64 and which we must not override).
func softMemLimit(total uint64, current int64, envSet bool) int64 {
	if envSet || current != math.MaxInt64 {
		return 0 // operator chose a limit (or "off") — honor it
	}
	if total == 0 {
		return 0 // RAM unknown — leave the heap unlimited
	}
	// Half of physical RAM: a soft ceiling on the daemon's own heap that scales with
	// the device (32 MiB on a 64 MB box, 128 MiB on 256 MB) and leaves the other half
	// for sing-box, the engines and the kernel.
	return int64(total / 2)
}
