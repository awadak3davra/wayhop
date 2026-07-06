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
// default is set only when none was given, derived from detected RAM as half of
// physical memory but capped at an absolute ceiling — on a larger router wayhop is
// not the dominant memory consumer, so a half-RAM target would promise a heap it
// could never reach without OOM-killing routing. No-op on the non-Linux demo build
// (RAM detection returns 0).
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
	// Half of physical RAM scales the ceiling with the device (32 MiB on a 64 MB box)
	// and leaves the other half for sing-box, the engines and the kernel.
	lim := total / 2
	// But on a larger router wayhop is NOT the dominant consumer: sing-box, the DNS
	// stack, the kernel conntrack/flowtable and the RAM-backed tmpfs already claim most
	// of physical memory, while wayhop's own steady heap is only ~10-15 MiB. Cap the
	// ceiling so the GC target can't promise a heap the daemon could never reach without
	// OOM-killing routing. 64 MiB is ample headroom for the largest realistic spike — a
	// big multi-country IPTV build or a bulk subscription import.
	const ceiling = 64 << 20
	if lim > ceiling {
		lim = ceiling
	}
	return int64(lim)
}
