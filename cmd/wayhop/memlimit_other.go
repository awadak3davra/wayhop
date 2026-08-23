//go:build !linux

package main

// hostTotalRAM is unavailable off Linux (the daemon's deployment target). The
// Windows demo/dev build skips the memory soft-limit by reporting 0.
func hostTotalRAM() uint64 { return 0 }
