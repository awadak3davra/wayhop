package importer

import (
	"testing"

	"wayhop/internal/model"
)

// TestParse_FragmentNotMisclassified (#14/#15): a proxy share link whose #fragment (node name) contains
// "[Interface]" or olcRTC trigger words must still parse as the proxy — not be routed to the .conf
// parser (#15: import error) or the olcRTC parser (#14: silent data loss → dead stub). The content
// sniffs run only when there is no URI scheme.
func TestParse_FragmentNotMisclassified(t *testing.T) {
	// #15: "[Interface]" in the fragment must NOT route to parseConf.
	e, err := Parse("trojan://secretpass@example.com:443?security=tls&sni=example.com#[Interface]")
	if err != nil {
		t.Fatalf("#15 trojan link with [Interface] in the fragment must import; got error: %v", err)
	}
	if e.Protocol != model.ProtoTrojan || e.Server != "example.com" {
		t.Errorf("#15 expected trojan/example.com, got %s/%s", e.Protocol, e.Server)
	}

	// #14: olcRTC trigger words ("provider:" + "crypto") in the fragment must NOT route to parseOlcRTC.
	e2, err := Parse("vless://11111111-1111-1111-1111-111111111111@cdn.example.com:443?type=tcp&security=tls#provider:crypto")
	if err != nil {
		t.Fatalf("#14 vless link with an olcRTC-ish fragment must import; got error: %v", err)
	}
	if e2.Protocol != model.ProtoVLESS || e2.Server != "cdn.example.com" {
		t.Errorf("#14 expected vless/cdn.example.com, got %s/%s", e2.Protocol, e2.Server)
	}

	// Guard against over-correction: a genuine pasted olcRTC YAML (no scheme) still parses as olcRTC.
	olc, err := Parse("auth:\n  provider: jitsi\n  crypto:\n    key: abc\nroom:\n  id: r1")
	if err != nil {
		t.Fatalf("a real olcRTC YAML blob must still parse: %v", err)
	}
	if olc.Engine != model.EngineOlcRTC {
		t.Errorf("a real olcRTC YAML must parse as the olcRTC engine, got %q", olc.Engine)
	}
}
