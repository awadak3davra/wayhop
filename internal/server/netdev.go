package server

import (
	"os"
	"strconv"
	"strings"
)

// Iface is one network interface's cumulative byte counters + link state, for the
// Dashboard's real-throughput graphs. Rates are computed UI-side from the delta between
// successive /api/system polls (no server-side sampler state needed). Sourced from
// /proc/net/dev (counters) + /sys/class/net (link state) — captures ALL traffic, including
// the kernel fast-path that sing-box/Clash never sees in "fast" mode.
type Iface struct {
	Name      string `json:"name"`
	RxBytes   int64  `json:"rx_bytes"`
	TxBytes   int64  `json:"tx_bytes"`
	SpeedMbps int    `json:"speed_mbps,omitempty"` // /sys speed; 0 = unknown (tunnels report none)
	Up        bool   `json:"up"`                   // operstate == "up"
}

// parseNetDev parses /proc/net/dev into per-interface byte counters. Pure (file-I/O-free)
// so it is unit-tested with a captured sample. Loopback is dropped (never interesting on
// the Dashboard). Field layout: "iface: rxBytes rxPkts ... (8 rx cols) txBytes txPkts ...".
func parseNetDev(s string) []Iface {
	var out []Iface
	for _, line := range strings.Split(s, "\n") {
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue // header rows have no colon
		}
		name := strings.TrimSpace(line[:i])
		if name == "" || name == "lo" {
			continue
		}
		f := strings.Fields(line[i+1:])
		if len(f) < 9 {
			continue
		}
		rx, _ := strconv.ParseInt(f[0], 10, 64) // 1st rx column = bytes
		tx, _ := strconv.ParseInt(f[8], 10, 64) // 9th column = tx bytes
		out = append(out, Iface{Name: name, RxBytes: rx, TxBytes: tx})
	}
	return out
}

// readInterfaces reads /proc/net/dev + enriches each with /sys link state/speed. Returns
// nil off-Linux (no procfs) so the caller degrades to "no interfaces" like system.go.
func readInterfaces() []Iface {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil
	}
	ifs := parseNetDev(string(data))
	for i := range ifs {
		base := "/sys/class/net/" + ifs[i].Name + "/"
		if st, err := os.ReadFile(base + "operstate"); err == nil {
			ifs[i].Up = strings.TrimSpace(string(st)) == "up"
		}
		// speed is only meaningful (and readable) for physical/up links; tunnels error out.
		if sp, err := os.ReadFile(base + "speed"); err == nil {
			if v, err := strconv.Atoi(strings.TrimSpace(string(sp))); err == nil && v > 0 {
				ifs[i].SpeedMbps = v
			}
		}
	}
	return ifs
}

// readTempC reads the first thermal zone (CPU) in °C, or 0 if absent. milli-°C → °C.
func readTempC() float64 {
	b, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp")
	if err != nil {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0
	}
	return float64(v) / 1000
}
