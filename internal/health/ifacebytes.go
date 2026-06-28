package health

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ifaceBytes returns a network interface's cumulative rx/tx byte counters from sysfs. ok is false
// when the iface (or sysfs) is absent — a tunnel that isn't up, or a non-Linux host — so the caller
// simply skips it. The counters are monotonic while the iface exists and restart at 0 when it is
// recreated, which is exactly what addCumulativeTraffic's delta logic expects.
func ifaceBytes(iface string) (rx, tx int64, ok bool) {
	return ifaceBytesFrom("/sys/class/net", iface)
}

// ifaceBytesFrom is ifaceBytes with an injectable sysfs root, for tests.
func ifaceBytesFrom(root, iface string) (rx, tx int64, ok bool) {
	rb, err1 := os.ReadFile(filepath.Join(root, iface, "statistics", "rx_bytes"))
	tb, err2 := os.ReadFile(filepath.Join(root, iface, "statistics", "tx_bytes"))
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	rx, err1 = strconv.ParseInt(strings.TrimSpace(string(rb)), 10, 64)
	tx, err2 = strconv.ParseInt(strings.TrimSpace(string(tb)), 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return rx, tx, true
}
