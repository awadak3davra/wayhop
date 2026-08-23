package nativedns

import (
	"strings"
	"testing"
)

// TestOpenWrtStrictOrderSurvivesTheRoundTrip (L5): a setting the model carries and one platform
// honours must not be dropped by the other.
//
// strictorder is dnsmasq's strict-order under uci. Keenetic both read and wrote it; OpenWrt did
// neither. So an OpenWrt router with `option strictorder '1'` adopted as StrictOrder:false — the
// panel's pill never appeared — and writing back then omitted the option, turning "try the tunnel
// resolver first" into "ask every upstream at once and keep the first reply". That first reply can be
// the plaintext WAN resolver while an encrypted tunnel one is up, which is the opposite of what the
// tier order the same file advertises is for.
func TestOpenWrtStrictOrderSurvivesTheRoundTrip(t *testing.T) {
	const dhcpOn = "dhcp.@dnsmasq[0].noresolv='1'\ndhcp.@dnsmasq[0].strictorder='1'\n" +
		"dhcp.@dnsmasq[0].server='127.0.0.1#5053'\n"
	nd := ReadUCI("", dhcpOn)
	if !nd.StrictOrder {
		t.Fatalf("an OpenWrt router with strictorder on must adopt as StrictOrder: %+v", nd)
	}
	if !nd.NoResolv {
		t.Errorf("and the neighbouring boolean must still be read: %+v", nd)
	}

	// Written back, the option comes with it.
	cmds := strings.Join(RenderUCI(nd), "\n")
	if !strings.Contains(cmds, "uci set dhcp.@dnsmasq[0].strictorder='1'") {
		t.Errorf("the write-back must carry strict order back to the router:\n%s", cmds)
	}

	// And a router that does NOT have it must be left without it — the delete form, not a stray set.
	off := ReadUCI("", "dhcp.@dnsmasq[0].server='127.0.0.1#5053'\n")
	if off.StrictOrder {
		t.Errorf("absent means absent: %+v", off)
	}
	cmdsOff := strings.Join(RenderUCI(off), "\n")
	if !strings.Contains(cmdsOff, "uci -q delete dhcp.@dnsmasq[0].strictorder") {
		t.Errorf("and the write-back must clear it rather than leave whatever was there:\n%s", cmdsOff)
	}
}
