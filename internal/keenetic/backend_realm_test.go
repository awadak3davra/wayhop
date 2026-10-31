package keenetic

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// A Server left beside a Hysteria2 realm is not where the connection goes; the KeeneticOS plan used to
// route it to the ISP as the tunnel's anti-loop bypass, pulling LAN traffic for that address out of the
// tunnel a list chose (QA-060).
func TestCompileRoutesNoBypassForARealmsStaleServer(t *testing.T) {
	hy := model.Endpoint{ID: "hy-realm", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
		Server: "203.0.113.5", Port: 443,
		TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "hy.example.com"},
		Params: map[string]any{"password": "pw", "realm": "realm://tok@rendezvous.example.com/my-cabin-1f3a8c2e9b"}}
	vless := model.Endpoint{ID: "vless-nl", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "1.2.3.4", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u"}}
	p := &model.Profile{
		Endpoints: []model.Endpoint{hy, vless},
		RoutingLists: []model.RoutingList{
			{ID: "vpn", Manual: []string{"203.0.113.0/24"}, Outbound: "vless-nl", Enabled: true},
		},
	}
	plan, err := Compile(p, CompileOptions{Fallback: FallbackOptions{CoreVersion: "1.14.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.CompatibilityRouting {
		t.Fatal("compat routing")
	}
	cmds := strings.Join(plan.Commands(), "\n")
	if strings.Contains(cmds, "ip route 203.0.113.5 255.255.255.255 ISP") {
		t.Errorf("stale Server of a realm connection routed direct via ISP")
	}
}
