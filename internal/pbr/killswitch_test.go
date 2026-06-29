package pbr

import (
	"strings"
	"testing"

	"wakeroute/internal/model"
)

// TestKillSwitchFailClosed: a kernel-routed group with kill_switch makes its tunnel egress
// FailClosed, and RenderIP emits a high-metric `blackhole default` fallback in that egress's table —
// so traffic DROPS instead of leaking to the WAN if the tunnel iface goes down. The live tunnel
// route (metric 0) is rendered too and wins while the iface is up. Without kill_switch, neither the
// FailClosed flag nor the blackhole fallback appears (byte-identical to before).
func TestKillSwitchFailClosed(t *testing.T) {
	build := func(ks bool) (*Plan, string) {
		p := &model.Profile{
			Endpoints: []model.Endpoint{
				{ID: "awg", Engine: model.EngineAmneziaWG, Server: "1.2.3.4", Port: 51820,
					Params: map[string]any{"private_key": "k", "peer_public_key": "k", "local_address": []string{"10.0.0.2/32"}}},
			},
			Groups: []model.Group{{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"awg"}, KillSwitch: ks}},
			Rules: []model.Rule{
				{ID: "r", IPCIDR: []string{"1.2.3.0/24"}, Outbound: "g"},
				{ID: "def", Default: true, Outbound: model.OutboundDirect},
			},
		}
		plan, _, err := Compile(p, Options{})
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		return plan, strings.Join(plan.RenderIP(Options{}), "\n")
	}

	plan, cmds := build(true)
	var ks *Egress
	for i := range plan.Egresses {
		if plan.Egresses[i].Tag == "g" {
			ks = &plan.Egresses[i]
		}
	}
	if ks == nil || !ks.FailClosed {
		t.Fatalf("kill-switched group egress must be FailClosed: %+v", plan.Egresses)
	}
	if !strings.Contains(cmds, "ip route replace default dev") {
		t.Errorf("FailClosed egress must still render its live tunnel route:\n%s", cmds)
	}
	if !strings.Contains(cmds, "blackhole default metric") {
		t.Errorf("FailClosed egress must render a high-metric blackhole fallback:\n%s", cmds)
	}
	// The ipset/Keenetic plane (RenderIPScript) must ALSO render the kill-switch blackhole. This was
	// bug #4: it was missing here, so on the Keenetic kill_switch silently leaked to WAN on tunnel-down.
	ipset := plan.RenderIPScript(Options{})
	if !strings.Contains(ipset, "ip route replace blackhole default metric") {
		t.Errorf("ipset plane must render the kill-switch blackhole for a FailClosed egress:\n%s", ipset)
	}

	planOff, cmdsOff := build(false)
	if strings.Contains(cmdsOff, "blackhole default metric") {
		t.Errorf("a group without kill_switch must not render a blackhole fallback:\n%s", cmdsOff)
	}
	if strings.Contains(planOff.RenderIPScript(Options{}), "blackhole default metric") {
		t.Errorf("ipset plane without kill_switch must not render a blackhole fallback")
	}
}
