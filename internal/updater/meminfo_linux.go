//go:build linux

package updater

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// availMemBytes returns the memory available for new allocations WITHOUT swapping, read from
// /proc/meminfo's MemAvailable (kernel 3.14+). ok=false when the field is absent or unparseable,
// so the caller never blocks an install on a number it couldn't take. This is the metric that
// matters for the in-RAM install path: it accounts for reclaimable page cache, so it reflects
// what a fresh download+extract allocation can actually use before the OOM-killer fires.
func availMemBytes() (uint64, bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		fields := strings.Fields(line) // "MemAvailable:   123456 kB"
		if len(fields) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return kb << 10, true // kB -> bytes
	}
	return 0, false
}
