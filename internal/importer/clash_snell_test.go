package importer

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// Clash/mihomo Snell entries import as the v4 sing-box speaks (v5 included, since mihomo sends it as
// v4), and the versions and obfuscation sing-box cannot carry are refused by name.
func TestParseClash_Snell(t *testing.T) {
	yaml := strings.Join([]string{
		"proxies:",
		"  - {name: s4, type: snell, server: 192.0.2.1, port: 8443, psk: abcdefghijkl, version: 4, obfs-opts: {mode: http, host: bing.com}}",
		"  - name: s5",
		"    type: snell",
		"    server: snell.example.com",
		"    port: 9443",
		"    psk: abcdefghijkl",
		"    version: 5",
		"    udp: true",
		"    reuse: true",
		"  - {name: s1, type: snell, server: 192.0.2.3, port: 1, psk: x}",
		"  - {name: s3, type: snell, server: 192.0.2.4, port: 2, psk: x, version: 3}",
		"  - {name: stls, type: snell, server: 192.0.2.5, port: 3, psk: x, version: 4, obfs-opts: {mode: tls}}",
	}, "\n")
	eps, errs := ParseClash(yaml)
	if len(eps) != 2 {
		t.Fatalf("imported %d endpoints (%v), want s4 and s5; errors %v", len(eps), eps, errs)
	}
	by := map[string]model.Endpoint{}
	for _, e := range eps {
		by[e.Name] = e
	}
	s4, s5 := by["s4"], by["s5"]
	if s4.Protocol != model.ProtoSnell || s4.Params["version"] != 4 || s4.Params["obfs_mode"] != "http" ||
		s4.Params["obfs_host"] != "bing.com" || s4.Params["network"] != "tcp" {
		t.Errorf("s4 = %+v", s4)
	}
	if s5.Params["version"] != 4 || s5.Params["reuse"] != true || s5.Params["network"] != nil || s5.Port != 9443 {
		t.Errorf("s5 (v5 imports as v4, udp on, reuse) = %+v", s5)
	}
	joined := strings.Join(errs, "\n")
	for _, want := range []string{"s1: version 1", "s3: version 3", `stls: obfs mode "tls"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("errors %q lack %q", joined, want)
		}
	}
}
