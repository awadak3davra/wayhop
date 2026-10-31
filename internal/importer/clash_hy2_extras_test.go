package importer

import (
	"strings"
	"testing"
)

// mihomo's hop-interval range, gecko packet sizes and BBR profile reach the params the generator emits.
func TestParseClash_Hysteria2Extras(t *testing.T) {
	yaml := strings.Join([]string{
		"proxies:",
		"  - {name: g, type: hysteria2, server: 192.0.2.4, port: 8443, password: pw, ports: 20000-30000, hop-interval: 10-40, obfs: gecko, obfs-password: o, obfs-min-packet-size: 600, obfs-max-packet-size: 1100, bbr-profile: aggressive}",
		"  - {name: s, type: hysteria2, server: 192.0.2.5, port: 8443, password: pw, hop-interval: 25, bbr-profile: fast}",
	}, "\n")
	eps, errs := ParseClash(yaml)
	if len(eps) != 2 || len(errs) != 0 {
		t.Fatalf("eps %v errs %v", eps, errs)
	}
	g, s := eps[0].Params, eps[1].Params
	if g["obfs"] != "gecko" || g["hop_interval"] != "10s" || g["hop_interval_max"] != "40s" ||
		g["obfs_min_packet_size"] != 600 || g["obfs_max_packet_size"] != 1100 || g["bbr_profile"] != "aggressive" {
		t.Errorf("gecko proxy params = %v", g)
	}
	if s["hop_interval"] != "25s" || s["hop_interval_max"] != nil || s["bbr_profile"] != nil {
		t.Errorf("single interval, unknown profile = %v", s)
	}
}
