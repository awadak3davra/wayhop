//go:build linux

package main

import "syscall"

// hostTotalRAM returns total physical RAM in bytes via sysinfo(2), or 0 on error.
// Totalram/Unit are uint32 on 32-bit arches (mipsle/mips/arm) and uint64 on 64-bit;
// the uint64 conversions handle both. Unit is the field's byte multiplier (1 on
// modern kernels, but honored for correctness).
func hostTotalRAM() uint64 {
	var si syscall.Sysinfo_t
	if err := syscall.Sysinfo(&si); err != nil {
		return 0
	}
	unit := uint64(si.Unit)
	if unit == 0 {
		unit = 1
	}
	return uint64(si.Totalram) * unit
}
