package importer

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// QA-013: a Clash / mihomo config reaching Parse (Paste link, or Import file with a .yaml) imports
// its one proxy, says where a config with several goes, and passes on a lone proxy's own error -
// never "malformed share link: invalid control character".
func TestParse_ClashConfigPastedAsALink(t *testing.T) {
	one := "proxies:\n  - {name: s4, type: snell, server: 192.0.2.1, port: 8443, psk: abcdefghijkl, version: 4}\n"
	e, err := Parse(one)
	if err != nil || e.Protocol != model.ProtoSnell || e.Name != "s4" || e.ID == "" {
		t.Fatalf("one proxy: %+v, %v", e, err)
	}
	two := "mixed-port: 7890\nproxies:\n" +
		"  - {name: a, type: trojan, server: 192.0.2.1, port: 443, password: p}\n" +
		"  - {name: b, type: trojan, server: 192.0.2.2, port: 443, password: p}\n"
	if _, err := Parse(two); err == nil || !strings.Contains(err.Error(), "2 proxies") || !strings.Contains(err.Error(), "Subscription") {
		t.Fatalf("two proxies: err = %v, want the Subscription pointer", err)
	}
	bad := "proxies:\n  - {name: old, type: snell, server: 192.0.2.3, port: 1, psk: x, version: 2}\n"
	if _, err := Parse(bad); err == nil || !strings.Contains(err.Error(), "version 2") || strings.Contains(err.Error(), "control character") {
		t.Fatalf("one unsupported proxy: err = %v, want its own reason", err)
	}
}
