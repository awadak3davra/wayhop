package keenetic

import (
	"strings"
	"testing"

	"wayhop/internal/generator"
	"wayhop/internal/model"
)

func TestSingboxFallback(t *testing.T) {
	vless := &model.Endpoint{ID: "vless-nl", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "1.1.1.1", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u"}}
	hy2 := &model.Endpoint{ID: "hy2-nl", Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2, Server: "2.2.2.2", Port: 8444, Enabled: true, Params: map[string]any{"password": "pw"}}

	plan, err := SingboxFallback([]*model.Endpoint{vless, hy2}, FallbackOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// endpoint → TUN device, sequential.
	if plan.IfaceFor["vless-nl"] != "wrtun0" || plan.IfaceFor["hy2-nl"] != "wrtun1" {
		t.Fatalf("IfaceFor = %v", plan.IfaceFor)
	}

	inb := plan.Config["inbounds"].([]map[string]any)
	if len(inb) != 4 { // 2 tun + 2 socks
		t.Fatalf("want 4 inbounds, got %d", len(inb))
	}
	tun := findByTag(inb, "tun-vless-nl")
	if tun == nil {
		t.Fatal("missing tun-vless-nl inbound")
	}
	if tun["interface_name"] != "wrtun0" {
		t.Errorf("interface_name = %v", tun["interface_name"])
	}
	if tun["mtu"] != 1400 || tun["stack"] != "gvisor" || tun["auto_route"] != false || tun["strict_route"] != false {
		t.Errorf("tun knobs wrong: mtu=%v stack=%v auto_route=%v strict=%v", tun["mtu"], tun["stack"], tun["auto_route"], tun["strict_route"])
	}
	if addr := tun["address"].([]string); len(addr) != 1 || addr[0] != "172.19.8.1/30" {
		t.Errorf("vless tun address = %v, want [172.19.8.1/30]", tun["address"])
	}
	if hy2tun := findByTag(inb, "tun-hy2-nl"); hy2tun == nil || hy2tun["address"].([]string)[0] != "172.19.8.5/30" {
		t.Errorf("hy2 tun address = %v, want 172.19.8.5/30", hy2tun)
	}
	if sk := findByTag(inb, "socks-vless-nl"); sk == nil || sk["listen_port"] != 11800 {
		t.Errorf("socks-vless-nl port = %v, want 11800", sk)
	}

	// outbounds: direct + 2 reused protocol outbounds.
	out := plan.Config["outbounds"].([]map[string]any)
	if len(out) != 3 {
		t.Fatalf("want 3 outbounds, got %d", len(out))
	}
	if findByTag(out, "vless-nl") == nil || findByTag(out, "hy2-nl") == nil || findByTag(out, "direct") == nil {
		t.Errorf("outbound tags = %v", tags(out))
	}

	// route rules: each TUN+SOCKS → its outbound.
	rules := plan.Config["route"].(map[string]any)["rules"].([]map[string]any)
	if len(rules) != 2 {
		t.Fatalf("want 2 route rules, got %d", len(rules))
	}
	if rules[0]["outbound"] != "vless-nl" {
		t.Errorf("rule[0] outbound = %v", rules[0]["outbound"])
	}
	if in := rules[0]["inbound"].([]string); len(in) != 2 || in[0] != "tun-vless-nl" || in[1] != "socks-vless-nl" {
		t.Errorf("rule[0] inbound = %v", rules[0]["inbound"])
	}
}

// The per-exit service check asks a fallback exit through the probe inbound. Without it every exit
// read "Apply once" on KeeneticOS forever: the generator had one, this config never did.
func TestSingboxFallbackCarriesTheProbeInbound(t *testing.T) {
	vless := &model.Endpoint{ID: "vless-nl", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "1.1.1.1", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u"}}
	hy2 := &model.Endpoint{ID: "hy2-nl", Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2, Server: "2.2.2.2", Port: 8444, Enabled: true, Params: map[string]any{"password": "pw"}}

	plan, err := SingboxFallback([]*model.Endpoint{vless, hy2}, FallbackOptions{ProbePort: 17890, ClashSecret: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	probe := findByTag(plan.Config["inbounds"].([]map[string]any), generator.ProbeInboundTag)
	if probe == nil || probe["type"] != "mixed" || probe["listen"] != "127.0.0.1" || probe["listen_port"] != 17890 {
		t.Fatalf("probe inbound = %v", probe)
	}
	users := map[string]string{}
	for _, u := range probe["users"].([]map[string]any) {
		users[u["username"].(string)] = u["password"].(string)
	}
	pw := generator.ProbePassword("s3cret")
	for _, tag := range []string{model.OutboundDirect, "vless-nl", "hy2-nl"} {
		if users[generator.ProbeUser(tag)] != pw {
			t.Errorf("no probe user for %s with the Clash-derived password: %v", tag, users)
		}
	}
	// Each probe user goes to its own exit, ahead of the TUN/SOCKS rules.
	rules := plan.Config["route"].(map[string]any)["rules"].([]map[string]any)
	if len(rules) != 5 {
		t.Fatalf("want 3 probe + 2 endpoint rules, got %v", rules)
	}
	for i, tag := range []string{model.OutboundDirect, "vless-nl", "hy2-nl"} {
		r := rules[i]
		if in := r["inbound"].([]string); len(in) != 1 || in[0] != generator.ProbeInboundTag ||
			r["auth_user"].([]string)[0] != generator.ProbeUser(tag) || r["outbound"] != tag {
			t.Errorf("rule %d = %v, want probe user %s to %s", i, r, generator.ProbeUser(tag), tag)
		}
	}

	// A port inside the SOCKS block would be a second listener on it: no probe inbound then.
	plan, err = SingboxFallback([]*model.Endpoint{vless, hy2}, FallbackOptions{ProbePort: 11801})
	if err != nil {
		t.Fatal(err)
	}
	if findByTag(plan.Config["inbounds"].([]map[string]any), generator.ProbeInboundTag) != nil {
		t.Error("probe inbound on a SOCKS port")
	}
	// ...and said: silently dropped, every exit read "Apply once" however often it was Applied.
	if len(plan.Warnings) != 1 || !strings.Contains(plan.Warnings[0], "probe port 11801") {
		t.Errorf("warnings = %q, want the dropped probe named", plan.Warnings)
	}
}

func TestTunHostAddr(t *testing.T) {
	cases := []struct {
		i    int
		want string
	}{
		{0, "172.19.8.1/30"},
		{1, "172.19.8.5/30"},
		{63, "172.19.8.253/30"}, // 63*4+1 = 253, no octet carry yet
		{64, "172.19.9.1/30"},   // 64*4+1 = 257, carries into the 3rd octet
	}
	for _, c := range cases {
		got, err := tunHostAddr("172.19.8.0", c.i)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("i=%d → %s, want %s", c.i, got, c.want)
		}
	}
}

func findByTag(items []map[string]any, tag string) map[string]any {
	for _, it := range items {
		if it["tag"] == tag {
			return it
		}
	}
	return nil
}

func tags(items []map[string]any) []string {
	var out []string
	for _, it := range items {
		if t, ok := it["tag"].(string); ok {
			out = append(out, t)
		}
	}
	return out
}
