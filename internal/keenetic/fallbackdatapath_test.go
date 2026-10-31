package keenetic

import (
	"encoding/json"
	"strings"
	"testing"

	"wayhop/internal/generator"
	"wayhop/internal/model"
)

// overriddenFallback builds the fallback core for two connections, decoded from JSON the way Apply
// carries it, applies a core override to it and re-asserts the datapath.
func overriddenFallback(t *testing.T, override string) (map[string]any, error) {
	t.Helper()
	var endpoints []*model.Endpoint
	for _, e := range []struct{ id, server string }{{"va", "198.51.100.9"}, {"vb", "198.51.100.10"}} {
		endpoints = append(endpoints, &model.Endpoint{ID: e.id, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
			Server: e.server, Port: 443, Enabled: true, Params: map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"}})
	}
	plan, err := SingboxFallback(endpoints, FallbackOptions{ProbePort: 17890, ClashSecret: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(plan.Config)
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	d, err := CaptureFallbackDatapath(cfg, plan.IfaceFor)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if err := generator.ApplyCoreOverride(cfg, override, generator.LeadingProbeRules(cfg)); err != nil {
		t.Fatalf("override: %v", err)
	}
	return cfg, d.Reassert(cfg)
}

func inboundByTag(t *testing.T, cfg map[string]any, tag string) map[string]any {
	t.Helper()
	list, err := objectList(cfg["inbounds"], "inbounds")
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range list {
		if in["tag"] == tag {
			return in
		}
	}
	t.Fatalf("no inbound %q in %v", tag, cfg["inbounds"])
	return nil
}

// The devices NDM routes into survive any override: an override written for the generated config
// restates `inbounds` without them, or restates one with its own device, routing and address, and
// sing-box check would pass either while every route to wrtunN went nowhere.
func TestFallbackDatapath_ReassertedAfterOverride(t *testing.T) {
	// Restated without the connections' inbounds: they come back as built, the operator's stays.
	cfg, err := overriddenFallback(t, `{"inbounds":[{"type":"mixed","tag":"lan","listen":"192.0.2.1","listen_port":7891}]}`)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"va", "vb"} {
		tun := inboundByTag(t, cfg, "tun-"+id)
		if tun["interface_name"] != []string{"wrtun0", "wrtun1"}[i] || tun["auto_route"] != false || tun["strict_route"] != false {
			t.Errorf("tun-%s = %v", id, tun)
		}
		if s := inboundByTag(t, cfg, "socks-"+id); s["listen"] != "127.0.0.1" {
			t.Errorf("socks-%s = %v", id, s)
		}
	}
	inboundByTag(t, cfg, "lan")

	// Restated with the operator's own values: the datapath fields win, the MTU stays theirs.
	cfg, err = overriddenFallback(t, `{"inbounds":[
		{"type":"tun","tag":"tun-va","interface_name":"mine","address":["192.0.2.1/30"],"auto_route":true,
		 "auto_redirect":true,"strict_route":true,"stack":"system","mtu":1280},
		{"type":"socks","tag":"socks-va","listen":"0.0.0.0","listen_port":1080}]}`)
	if err != nil {
		t.Fatal(err)
	}
	tun := inboundByTag(t, cfg, "tun-va")
	b, _ := json.Marshal(tun)
	if string(b) != `{"address":["172.19.8.1/30"],"auto_route":false,"interface_name":"wrtun0","mtu":1280,"stack":"gvisor","strict_route":false,"tag":"tun-va","type":"tun"}` {
		t.Errorf("restated tun-va = %s", b)
	}
	if s := inboundByTag(t, cfg, "socks-va"); s["listen"] != "127.0.0.1" || s["listen_port"] != float64(11800) {
		t.Errorf("restated socks-va = %v", s)
	}

	// route.rules replaced: each connection's rule comes back after the override's own, and a
	// prepended rule goes after the probe rules, not ahead of them.
	cfg, err = overriddenFallback(t, `{"route":{"rules":[{"domain_suffix":["example.net"],"action":"reject"}]}}`)
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := json.Marshal(cfg["route"].(map[string]any)["rules"])
	if string(rules) != `[{"action":"reject","domain_suffix":["example.net"]},{"inbound":["tun-va","socks-va"],"outbound":"va"},{"inbound":["tun-vb","socks-vb"],"outbound":"vb"}]` {
		t.Errorf("route.rules = %s", rules)
	}
	cfg, err = overriddenFallback(t, `{"prepend":{"route.rules":[{"domain_suffix":["example.net"],"action":"reject"}]}}`)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := objectList(cfg["route"].(map[string]any)["rules"], "route.rules")
	probes := generator.LeadingProbeRules(cfg)
	if probes == 0 || len(list) != probes+3 || list[probes]["action"] != "reject" {
		t.Errorf("prepended rule after %d probe rules: %v", probes, list)
	}
}

// What no re-assertion can make right is refused, with what to change.
func TestFallbackDatapath_RefusesWhatCannotBeReasserted(t *testing.T) {
	for _, tc := range []struct{ name, override, want string }{
		{"a TUN of its own that routes",
			`{"inbounds":[{"type":"tun","tag":"tun-in","address":["192.0.2.5/30"],"auto_route":true,"strict_route":true}]}`,
			`"tun-in" is a TUN that routes`},
		{"a TUN on a connection's device",
			`{"inbounds":[{"type":"tun","tag":"mine","interface_name":"wrtun1"}]}`, "takes device wrtun1"},
		{"another inbound on a connection's SOCKS port",
			`{"inbounds":[{"type":"mixed","tag":"lan","listen":"192.0.2.1","listen_port":11801}]}`, "takes port 11801"},
		{"a connection's TUN turned into another type",
			`{"inbounds":[{"type":"mixed","tag":"tun-va","listen_port":7000}]}`, "cannot become mixed"},
		{"a connection's inbound twice",
			`{"inbounds":[{"type":"socks","tag":"socks-va"},{"type":"socks","tag":"socks-va"}]}`, "appears twice"},
		{"inbounds not a list", `{"inbounds":{"type":"tun"}}`, "inbounds is not a list"},
		{"route deleted", `{"route":null}`, "cannot delete or replace route"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := overriddenFallback(t, tc.override); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// The capture holds the core to the plan: a connection's TUN on another device than the one the
// plan's routes name is an inconsistency to stop on, not to re-assert.
func TestCaptureFallbackDatapath_ChecksThePlan(t *testing.T) {
	cfg := map[string]any{"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-va", "interface_name": "wrtun0"}}}
	if _, err := CaptureFallbackDatapath(cfg, map[string]string{"va": "wrtun0", "wg": "Wireguard10"}); err != nil {
		t.Errorf("consistent plan: %v", err)
	}
	if _, err := CaptureFallbackDatapath(cfg, map[string]string{"va": "wrtun3"}); err == nil || !strings.Contains(err.Error(), "routes it to wrtun3") {
		t.Errorf("inconsistent plan: %v", err)
	}
}
