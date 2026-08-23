package pbr

import (
	"strings"
	"testing"
)

// When the plan marks v6, RenderIPScript must emit a SYMMETRIC v6 datapath (ip -6 rule +
// route + the v6 LAN-exclusion) so a marked v6 packet routes THROUGH the tunnel instead
// of falling through to the main v6 table (a censorship leak on a v6-default-WAN device,
// the bug-hunt's one high finding). A v4-only plan must emit no `ip -6` at all.
func TestRenderIPScript_V6(t *testing.T) {
	v6 := &Plan{Mask: 0x00ff0000,
		Egresses: []Egress{{Kind: EgressInterface, Iface: "nwg1", Mark: 0x20000, Table: 151}},
		BypassV6: []string{"2001:67c:4e8::1"}, // marks the plan as v6-active
	}
	s := v6.RenderIPScript(Options{})
	for _, w := range []string{
		"ip -6 rule add fwmark 0x00020000/0x00ff0000 table 151 priority 150",
		"ip -6 route add default dev nwg1 table 151",
		"ip -6 rule add to fc00::/7 lookup main priority 148",
		"ip -6 rule add to fe80::/10 lookup main priority 149",
	} {
		if !strings.Contains(s, w) {
			t.Errorf("v6 datapath missing %q in:\n%s", w, s)
		}
	}
	if !strings.Contains(v6.RenderTeardownScript(Options{}, IpsetOptions{}), "ip -6 rule del fwmark 0x00020000") {
		t.Error("v6 teardown must remove the ip -6 fwmark rule")
	}
	// v4-only plan: no ip -6 anywhere (stays inert for v4-only lists).
	v4 := &Plan{Mask: 0x00ff0000, Egresses: []Egress{{Kind: EgressInterface, Iface: "nwg1", Mark: 0x20000, Table: 151}}}
	if strings.Contains(v4.RenderIPScript(Options{}), "ip -6") {
		t.Error("a v4-only plan must not emit any ip -6 rule/route")
	}
}
