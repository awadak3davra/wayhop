package server

import (
	"strings"
	"testing"

	"wakeroute/internal/model"
)

func TestParseSingboxTags(t *testing.T) {
	out := "sing-box version 1.12.17\n\nEnvironment: go1.26.3 linux/arm64\n" +
		"Tags: with_clash_api,with_gvisor,with_quic,with_utls,with_wireguard\nCGO: enabled\n"
	tags := parseSingboxTags(out)
	for _, want := range []string{"with_quic", "with_wireguard", "with_utls", "with_clash_api", "with_gvisor"} {
		if !tags[want] {
			t.Errorf("missing tag %q in %v", want, tags)
		}
	}
	if tags["with_nonexistent"] {
		t.Error("phantom tag parsed")
	}
	if n := len(parseSingboxTags("no Tags line at all")); n != 0 {
		t.Errorf("want 0 tags when no Tags line, got %d", n)
	}
}

// TestUnsupportedSingboxEndpoints: a feature an endpoint needs but the build lacks is flagged;
// core protocols, plugin protocols, native-iface (external) endpoints, and disabled ones are not.
func TestUnsupportedSingboxEndpoints(t *testing.T) {
	p := &model.Profile{Endpoints: []model.Endpoint{
		{ID: "hy", Name: "hy2srv", Protocol: model.ProtoHysteria2, Enabled: true},
		{ID: "wg", Name: "wgsrv", Protocol: model.ProtoWireGuard, Enabled: true},
		{ID: "v", Name: "vlesssrv", Protocol: model.ProtoVLESS, Enabled: true},                                  // core → ok
		{ID: "awg", Name: "awgsrv", Protocol: model.ProtoAmneziaWG, Enabled: true},                              // plugin → skip
		{ID: "ext", Name: "extwg", Protocol: model.ProtoWireGuard, Engine: model.EngineExternal, Enabled: true}, // native → skip
		{ID: "off", Name: "offhy2", Protocol: model.ProtoHysteria2, Enabled: false},                             // disabled → skip
		{ID: "fp", Name: "fpsrv", Protocol: model.ProtoVLESS, Enabled: true, TLS: &model.TLS{Fingerprint: "chrome"}},
	}}
	if bad := unsupportedSingboxEndpoints(p, map[string]bool{"with_quic": true, "with_wireguard": true, "with_utls": true}); len(bad) != 0 {
		t.Fatalf("full build: want 0 unsupported, got %v", bad)
	}
	bad := unsupportedSingboxEndpoints(p, map[string]bool{}) // a bare build
	if len(bad) != 3 {
		t.Fatalf("minimal build: want 3 (hy2/wg/fp), got %d: %v", len(bad), bad)
	}
	j := strings.Join(bad, " | ")
	for _, want := range []string{"hy2srv", "wgsrv", "fpsrv"} {
		if !strings.Contains(j, want) {
			t.Errorf("expected %q flagged, got %v", want, bad)
		}
	}
	for _, skip := range []string{"vlesssrv", "awgsrv", "extwg", "offhy2"} {
		if strings.Contains(j, skip) {
			t.Errorf("%q should not be flagged: %v", skip, bad)
		}
	}
}
