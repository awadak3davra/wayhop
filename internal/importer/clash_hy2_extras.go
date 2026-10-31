package importer

import (
	"strconv"
	"strings"
)

// clashHysteria2Extras reads mihomo's newer Hysteria2 keys into the params the generator emits for
// sing-box 1.14 (generator/hysteria2_114.go): hop-interval ("30", or "10-30" for a random interval in
// that range, seconds), gecko's obfs-min/max-packet-size, and bbr-profile. A malformed value is left
// out rather than guessed.
func clashHysteria2Extras(p proxyMap, params map[string]any) {
	if hi := strings.TrimSpace(p["hop-interval"]); hi != "" {
		lo, hi2, isRange := strings.Cut(hi, "-")
		a, errA := strconv.Atoi(strings.TrimSpace(lo))
		if errA == nil && a > 0 {
			params["hop_interval"] = strconv.Itoa(a) + "s"
			if b, errB := strconv.Atoi(strings.TrimSpace(hi2)); isRange && errB == nil && b > a {
				params["hop_interval_max"] = strconv.Itoa(b) + "s"
			}
		}
	}
	for clashKey, param := range map[string]string{"obfs-min-packet-size": "obfs_min_packet_size", "obfs-max-packet-size": "obfs_max_packet_size"} {
		if n, err := strconv.Atoi(strings.TrimSpace(p[clashKey])); err == nil && n > 0 {
			params[param] = n
		}
	}
	if b := strings.TrimSpace(p["bbr-profile"]); b == "conservative" || b == "standard" || b == "aggressive" {
		params["bbr_profile"] = b
	}
}
