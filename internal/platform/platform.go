// Package platform identifies the router OS Velinx is running on, so a single universal
// binary picks the right apply backend at runtime (D-PLAT-2: one binary + Detect(), not
// per-platform builds). The OpenWrt backend is today's nft/fw4 + awg-quick path; the
// Keenetic backend (internal/keenetic) drives KeeneticOS-native AmneziaWG/WireGuard + NDM
// routing over RCI. See docs/ARCHITECTURE_NATIVE_FIRST.md (Phase 2.5/3) + memory
// keenetic-backend.md.
package platform

import (
	"os"
	"strings"
)

// Platform is the detected router OS family.
type Platform string

const (
	Keenetic Platform = "keenetic" // KeeneticOS (NDM/RCI, native AWG/WG, ndmc, -ndm- kernel)
	OpenWrt  Platform = "openwrt"  // OpenWrt (fw4/nftables, uci, procd)
	Unknown  Platform = "unknown"  // neither matched (generic Linux / dev host)
)

// probes abstracts the filesystem/proc reads Detect needs, so the decision is unit-testable
// without the real device filesystem.
type probes struct {
	fileExists  func(string) bool
	procVersion func() string
}

// detect is the pure decision: Keenetic markers win (the family device runs Entware ON
// KeeneticOS, so /opt may exist alongside OpenWrt-looking paths — check Keenetic FIRST).
// Signals validated on the live Hopper SE (read-only probe 2026-06-21):
//   - /bin/ndmc (the NDM CLI client) — Keenetic-only;
//   - /proc/version contains "keenetic.com" or a "-ndm-" kernel suffix;
//   - /etc/openwrt_release, /sbin/fw4, /sbin/uci — OpenWrt.
func detect(p probes) Platform {
	pv := strings.ToLower(p.procVersion())
	if p.fileExists("/bin/ndmc") || strings.Contains(pv, "keenetic") || strings.Contains(pv, "-ndm-") {
		return Keenetic
	}
	if p.fileExists("/etc/openwrt_release") || p.fileExists("/sbin/fw4") || p.fileExists("/sbin/uci") {
		return OpenWrt
	}
	return Unknown
}

// Detect identifies the current platform from the live filesystem + /proc/version.
func Detect() Platform {
	return detect(probes{
		fileExists: func(path string) bool { _, err := os.Stat(path); return err == nil },
		procVersion: func() string {
			b, _ := os.ReadFile("/proc/version")
			return string(b)
		},
	})
}
