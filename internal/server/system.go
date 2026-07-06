package server

import (
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"wayhop/internal/version"
)

// systemInfo is the host-resource snapshot surfaced on the Dashboard's system strip.
// On a non-Linux host (the Windows dev box) /proc is absent, so Available is false and
// the UI degrades to "unavailable" — the router target always has procfs. Version/Arch
// are build constants (always set) so the Diagnostics "Copy report" can stamp the build.
type systemInfo struct {
	Available  bool    `json:"available"`
	MemTotalKB int64   `json:"mem_total_kb"`
	MemAvailKB int64   `json:"mem_avail_kb"`
	MemUsedPct float64 `json:"mem_used_pct"`
	Load1      float64 `json:"load1"`
	UptimeS    int64   `json:"uptime_s"`
	Version    string  `json:"version,omitempty"`
	Arch       string  `json:"arch,omitempty"`
	TempC      float64 `json:"temp_c,omitempty"`     // CPU temperature, °C (0 = unavailable)
	Interfaces []Iface `json:"interfaces,omitempty"` // real per-iface byte counters (rates computed UI-side)
}

// handleSystem reports host CPU-load / RAM / uptime for the Dashboard. RAM is the #1
// bottleneck on the target router, so a live free-RAM gauge pre-empts OOM.
func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	si := readSystemInfo()
	si.Version, si.Arch = version.Version, runtime.GOARCH
	writeJSON(w, http.StatusOK, si)
}

// readSystemInfo reads procfs; returns an unavailable snapshot off-Linux or on error.
func readSystemInfo() systemInfo {
	mem, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return systemInfo{}
	}
	load, _ := os.ReadFile("/proc/loadavg")
	up, _ := os.ReadFile("/proc/uptime")
	si := parseSystem(string(mem), string(load), string(up))
	si.Interfaces = readInterfaces() // real per-iface throughput (incl. the kernel fast-path)
	si.TempC = readTempC()
	return si
}

// parseSystem is the pure (file-I/O-free) parser, so it is unit-testable with samples.
func parseSystem(meminfo, loadavg, uptime string) systemInfo {
	si := systemInfo{}
	si.MemTotalKB, si.MemAvailKB = parseMeminfo(meminfo)
	if si.MemTotalKB > 0 {
		used := si.MemTotalKB - si.MemAvailKB
		if used < 0 {
			used = 0
		}
		si.MemUsedPct = float64(used) / float64(si.MemTotalKB) * 100
		si.Available = true
	}
	if f := strings.Fields(loadavg); len(f) > 0 {
		si.Load1, _ = strconv.ParseFloat(f[0], 64)
	}
	if f := strings.Fields(uptime); len(f) > 0 {
		if v, err := strconv.ParseFloat(f[0], 64); err == nil {
			si.UptimeS = int64(v)
		}
	}
	return si
}

// parseMeminfo extracts MemTotal and MemAvailable (both kB) from /proc/meminfo in a
// single pass, so the 1 Hz Dashboard poll on a slow A53 doesn't scan the file once per
// key. Returns 0 for a field that's absent; early-exits once both are found.
func parseMeminfo(meminfo string) (total, avail int64) {
	for _, line := range strings.Split(meminfo, "\n") {
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			total = meminfoValue(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			avail = meminfoValue(line)
		}
		if total > 0 && avail > 0 {
			break
		}
	}
	return total, avail
}

// meminfoValue parses the kB number out of a "Key:  N kB" /proc/meminfo line.
func meminfoValue(line string) int64 {
	f := strings.Fields(line) // e.g. ["MemTotal:", "80000", "kB"]
	if len(f) >= 2 {
		v, _ := strconv.ParseInt(f[1], 10, 64)
		return v
	}
	return 0
}
