package keenetic

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestCompile_NativeFirst: an AmneziaWG endpoint becomes a native interface and a non-native
// VLESS endpoint becomes a sing-box TUN — BOTH are routable interfaces, so IP-CIDR lists
// become `ip route` to whichever, each endpoint's server IP gets an anti-loop ISP route, and
// only the true residue (domain entries) is warned.
func TestCompile_NativeFirst(t *testing.T) {
	awg := awgEndpoint() // AmneziaWG, server 203.0.113.10
	awg.ID, awg.Enabled = "awg-nl", true
	vless := model.Endpoint{ID: "vless-nl", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "1.2.3.4", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u"}}
	p := &model.Profile{
		Endpoints: []model.Endpoint{awg, vless},
		RoutingLists: []model.RoutingList{
			{ID: "ru-banks", Manual: []string{"109.254.0.0/16", "85.21.0.0/16"}, Outbound: "awg-nl", Enabled: true},
			{ID: "mixed", Manual: []string{"10.10.0.0/24", "example.com"}, Outbound: "awg-nl", Enabled: true}, // domain skipped
			{ID: "proxy", Manual: []string{"172.16.0.0/24"}, Outbound: "vless-nl", Enabled: true},             // → fallback TUN
			{ID: "blk", Manual: []string{"192.0.2.0/24"}, Outbound: model.OutboundBlock, Enabled: true},
			{ID: "direct", Manual: []string{"203.0.113.0/24"}, Outbound: model.OutboundDirect, Enabled: true},
			{ID: "disabled", Manual: []string{"198.51.100.0/24"}, Outbound: "awg-nl", Enabled: false},
		},
	}
	plan, err := Compile(p, CompileOptions{BaseIndex: 10})
	if err != nil {
		t.Fatal(err)
	}

	if plan.IfaceFor["awg-nl"] != "Wireguard10" {
		t.Errorf("awg-nl iface = %q, want Wireguard10", plan.IfaceFor["awg-nl"])
	}
	if len(plan.Interfaces) != 1 {
		t.Errorf("want 1 native interface block, got %d", len(plan.Interfaces))
	}
	// Non-native VLESS is now a fallback TUN, not a warning.
	if plan.IfaceFor["vless-nl"] != "wrtun0" {
		t.Errorf("vless-nl iface = %q, want wrtun0", plan.IfaceFor["vless-nl"])
	}
	if plan.Singbox == nil {
		t.Error("Singbox config must be set when there is a non-native endpoint")
	}
	cmds := strings.Join(plan.Commands(), "\n")
	for _, w := range []string{
		"interface Wireguard10",
		"ip route 109.254.0.0 255.255.0.0 Wireguard10", // list → native iface
		"ip route 85.21.0.0 255.255.0.0 Wireguard10",   //
		"ip route 10.10.0.0 255.255.255.0 Wireguard10", // mixed CIDR routed; domain skipped
		"ip route 172.16.0.0 255.255.255.0 wrtun0",     // list → fallback TUN (the integration)
		"ip route 192.0.2.0 255.255.255.0 reject",      // block → reject
		"ip route 203.0.113.0 255.255.255.0 ISP",       // direct → ISP
		"ip route 203.0.113.10 255.255.255.255 ISP",    // anti-loop bypass (native server)
		"ip route 1.2.3.4 255.255.255.255 ISP",         // anti-loop bypass (proxy server)
	} {
		if !strings.Contains(cmds, w) {
			t.Errorf("missing command %q\n--- got ---\n%s", w, cmds)
		}
	}
	if strings.Contains(cmds, "198.51.100.0") {
		t.Error("disabled list must be skipped")
	}

	warns := strings.Join(plan.Warnings, " | ")
	if strings.Contains(warns, "needs sing-box fallback") {
		t.Errorf("VLESS is handled by the fallback now — should not warn: %v", plan.Warnings)
	}
	if !strings.Contains(warns, "domain entries skipped") {
		t.Errorf("missing domain-skipped warning: %v", plan.Warnings)
	}
}

func TestCompile_UnknownOutboundWarned(t *testing.T) {
	p := &model.Profile{
		RoutingLists: []model.RoutingList{
			{ID: "orphan", Manual: []string{"1.2.3.0/24"}, Outbound: "no-such-endpoint", Enabled: true},
		},
	}
	plan, err := Compile(p, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Routes) != 0 {
		t.Errorf("orphan list must produce no routes, got %v", plan.Routes)
	}
	if !strings.Contains(strings.Join(plan.Warnings, " "), "not a native interface") {
		t.Errorf("missing orphan-outbound warning: %v", plan.Warnings)
	}
}

// TestCompile_AdoptInterfaces: an already-live interface (the live cutover case) is recorded
// + routed-to but NEVER (re)created or torn down — so a re-Apply/cutover can't bounce mama's
// existing AmneziaWG tunnels.
func TestCompile_AdoptInterfaces(t *testing.T) {
	awg := awgEndpoint()
	awg.ID, awg.Enabled, awg.Server = "keentest", true, "203.0.113.10"
	p := &model.Profile{
		Endpoints: []model.Endpoint{awg},
		RoutingLists: []model.RoutingList{
			{ID: "blocked", Manual: []string{"149.154.160.0/20"}, Outbound: "keentest", Enabled: true}, // Telegram CIDR
		},
	}
	plan, err := Compile(p, CompileOptions{AdoptInterfaces: map[string]string{"keentest": "nwg3"}})
	if err != nil {
		t.Fatal(err)
	}

	if plan.IfaceFor["keentest"] != "nwg3" {
		t.Errorf("adopted IfaceFor = %q, want nwg3", plan.IfaceFor["keentest"])
	}
	if len(plan.Interfaces) != 0 {
		t.Errorf("adopted endpoint must emit NO interface block, got %d", len(plan.Interfaces))
	}
	cmds := strings.Join(plan.Commands(), "\n")
	if !strings.Contains(cmds, "ip route 149.154.160.0 255.255.240.0 nwg3") {
		t.Errorf("list must route to the adopted iface\n%s", cmds)
	}
	if !strings.Contains(cmds, "ip route 203.0.113.10 255.255.255.255 ISP") {
		t.Error("adopted endpoint server IP must still get an anti-loop bypass")
	}

	td := strings.Join(TeardownCommands(plan), "\n")
	if strings.Contains(td, "no interface") {
		t.Errorf("teardown must NOT remove an adopted interface\n%s", td)
	}
	if !strings.Contains(td, "no ip route 149.154.160.0 255.255.240.0 nwg3") {
		t.Errorf("teardown must still remove WayHop's own route\n%s", td)
	}
}
