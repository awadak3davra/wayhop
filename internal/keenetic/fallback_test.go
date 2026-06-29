package keenetic

import (
	"testing"

	"velinx/internal/model"
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
