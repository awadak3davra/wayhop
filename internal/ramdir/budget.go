package ramdir

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"sync"
)

// Budget caps the RAM WayHop spends to spare flash: files in the RAM directory (tmpfs pages are RAM)
// and write-behind buffers both reserve from it. Routers can have 256 MB with sing-box alone taking
// 100+ MB, so when a reservation would pass Cap, or the kernel reports less than MinFree available,
// the reservation is refused and the caller writes straight to flash (coalesced) instead of growing
// RAM. Flash wear is the lesser harm than an OOM kill of the router's datapath.
type Budget struct {
	mu      sync.Mutex
	cap     int64
	minFree int64
	used    int64
	peak    int64
	// memAvailable returns MemAvailable in bytes and whether it could be read.
	memAvailable func() (int64, bool)
}

// Defaults: 4 MB total, refuse below 32 MB available.
const (
	DefaultCap     = 4 << 20
	DefaultMinFree = 32 << 20
)

// NewBudget returns a budget; capBytes/minFree <= 0 take the defaults.
func NewBudget(capBytes, minFree int64) *Budget {
	if capBytes <= 0 {
		capBytes = DefaultCap
	}
	if minFree <= 0 {
		minFree = DefaultMinFree
	}
	return &Budget{cap: capBytes, minFree: minFree, memAvailable: readMemAvailable}
}

// Shared is the process-wide budget main configures from config.json.
var Shared = NewBudget(0, 0)

// Configure replaces the limits (bytes; <= 0 keeps the default). Reservations held stay counted.
func (b *Budget) Configure(capBytes, minFree int64) {
	if capBytes <= 0 {
		capBytes = DefaultCap
	}
	if minFree <= 0 {
		minFree = DefaultMinFree
	}
	b.mu.Lock()
	b.cap, b.minFree = capBytes, minFree
	b.mu.Unlock()
}

// Reserve claims n bytes, or reports false (claiming nothing) when the cap would be passed or free
// memory is below the floor.
func (b *Budget) Reserve(n int64) bool {
	if n < 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used+n > b.cap {
		return false
	}
	if avail, ok := b.memAvailable(); ok && avail-n < b.minFree {
		return false
	}
	b.used += n
	if b.used > b.peak {
		b.peak = b.used
	}
	return true
}

// Release returns n bytes reserved earlier.
func (b *Budget) Release(n int64) {
	b.mu.Lock()
	b.used -= n
	if b.used < 0 {
		b.used = 0
	}
	b.mu.Unlock()
}

// Usage reports bytes held now, the peak since start, and the cap.
func (b *Budget) Usage() (used, peak, capBytes int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used, b.peak, b.cap
}

// MemAvailable is MemAvailable from /proc/meminfo in bytes, and false where it cannot be read
// (not Linux, or an error). Other gates that must not start below a floor of free memory use it.
func MemAvailable() (int64, bool) { return readMemAvailable() }

// readMemAvailable reads MemAvailable from /proc/meminfo (Linux); false elsewhere or on error, in
// which case only the cap applies.
func readMemAvailable() (int64, bool) {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	return parseMemAvailable(raw)
}

func parseMemAvailable(raw []byte) (int64, bool) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		f := bytes.Fields(sc.Bytes())
		if len(f) >= 2 && string(f[0]) == "MemAvailable:" {
			kb, err := strconv.ParseInt(string(f[1]), 10, 64)
			if err != nil {
				return 0, false
			}
			return kb * 1024, true
		}
	}
	return 0, false
}
