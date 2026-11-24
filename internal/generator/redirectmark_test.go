package generator

import (
	"encoding/json"
	"strings"
	"testing"
)

// The daemon's probe sockets carry fwmark 0x2024 to get past the core's transparent
// redirect (first rule of `inet sing-box` `output` on a reference OpenWrt router: `meta mark 0x00002024 return`).
// That value was sing-tun's default and nothing else; the generator now writes it, and the mark of
// the connections the core takes, into the TUN inbound, so the two sides cannot drift apart.
func tunInbound(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(cfg["inbounds"])
	if err != nil {
		t.Fatal(err)
	}
	var inbounds []map[string]any
	if err := json.Unmarshal(raw, &inbounds); err != nil {
		t.Fatal(err)
	}
	for _, in := range inbounds {
		if in["type"] == "tun" {
			return in
		}
	}
	t.Fatalf("no tun inbound in %s", raw)
	return nil
}

func TestTunInboundStatesTheRedirectMarks(t *testing.T) {
	res, err := Generate(probeProfile(), Options{MixedPort: 7890, TunEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	tun := tunInbound(t, res.Config)
	if tun["auto_redirect_output_mark"] != "0x2024" || tun["auto_redirect_input_mark"] != "0x2023" {
		t.Fatalf("tun inbound: %v", tun)
	}
	if AutoRedirectOutputMark != 0x2024 || AutoRedirectInputMark != 0x2023 {
		t.Fatal("the constants are the values sing-box's own table shows on the router")
	}
}

func TestCoreOverrideCannotMoveTheRedirectMarks(t *testing.T) {
	// A patch that replaces the inbounds with a TUN on another output mark: every daemon probe would
	// be redirected into the core and measured over the core's route.
	moved := `{"inbounds":[{"type":"tun","tag":"tun-in","address":["172.31.3.1/30"],"auto_route":true,"auto_redirect":true,"auto_redirect_output_mark":"0x2a"}]}`
	if _, err := Generate(probeProfile(), Options{MixedPort: 7890, TunEnabled: true, CoreOverride: moved}); err == nil ||
		!strings.Contains(err.Error(), "auto_redirect_output_mark") {
		t.Fatalf("an override that moves the output mark was accepted: %v", err)
	}
	// The same mark written as a number is the same mark.
	same := `{"inbounds":[{"type":"tun","tag":"tun-in","address":["172.31.3.1/30"],"auto_route":true,"auto_redirect":true,"auto_redirect_output_mark":8228}]}`
	res, err := Generate(probeProfile(), Options{MixedPort: 7890, TunEnabled: true, CoreOverride: same})
	if err != nil {
		t.Fatalf("the same mark as a number was refused: %v", err)
	}
	// A TUN the override wrote without the marks gets them: no falling back to a default.
	if tun := tunInbound(t, res.Config); tun["auto_redirect_input_mark"] != "0x2023" {
		t.Fatalf("the input mark was not put back: %v", tun)
	}
	// An override that does not touch the inbounds changes nothing here.
	res, err = Generate(probeProfile(), Options{MixedPort: 7890, TunEnabled: true, CoreOverride: `{"log":{"level":"debug"}}`})
	if err != nil {
		t.Fatal(err)
	}
	if tun := tunInbound(t, res.Config); tun["auto_redirect_output_mark"] != "0x2024" {
		t.Fatalf("tun inbound: %v", tun)
	}
}
