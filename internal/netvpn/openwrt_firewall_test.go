package netvpn

import (
	"strings"
	"testing"
)

// The zone block as the AX3000T reports it: three anonymous zones, and the tunnels attached to the
// third by a LIST of two interfaces. The indices are the whole point — a writer that remembers "2"
// instead of "vpn" attaches the next tunnel to whatever ends up in that slot.
const liveFirewallShow = `firewall.@defaults[0]=defaults
firewall.@zone[0]=zone
firewall.@zone[0].name='lan'
firewall.@zone[0].network='lan'
firewall.@zone[1]=zone
firewall.@zone[1].name='wan'
firewall.@zone[1].network='wan'
firewall.@rule[0]=rule
firewall.@rule[0].name='Allow-DHCP-Renew'
firewall.@zone[2]=zone
firewall.@zone[2].name='vpn'
firewall.@zone[2].masq='1'
firewall.@zone[2].network='awg0' 'awg1'
`

func TestParseFirewallZones_ReadsTheLiveLayout(t *testing.T) {
	zones := ParseFirewallZones(liveFirewallShow)
	if len(zones) != 3 {
		t.Fatalf("expected 3 zones, got %d: %+v", len(zones), zones)
	}
	// Rules must not be mistaken for zones — both are anonymous sections and both carry a `name`.
	for _, z := range zones {
		if z.Name == "Allow-DHCP-Renew" {
			t.Fatal("a firewall RULE was parsed as a zone")
		}
	}
	vpn, ok := FindZone(zones, "vpn")
	if !ok {
		t.Fatal("the vpn zone was not found by name")
	}
	if vpn.Ref != "@zone[2]" {
		t.Errorf("vpn zone ref: want @zone[2], got %q", vpn.Ref)
	}
	if len(vpn.Networks) != 2 || vpn.Networks[1] != "awg1" {
		t.Errorf("the two-value network list was not split: %v", vpn.Networks)
	}
}

// Attaching must be idempotent. uci add_list appends unconditionally, so re-applying an unchanged
// tunnel would list it twice and fw4 would render duplicate rules.
func TestZoneAttach_IsIdempotent(t *testing.T) {
	vpn, _ := FindZone(ParseFirewallZones(liveFirewallShow), "vpn")

	if cmds := ZoneAttachCmds(vpn, "awg0"); len(cmds) != 0 {
		t.Errorf("awg0 is already attached; attaching again should be a no-op, got %v", cmds)
	}
	cmds := ZoneAttachCmds(vpn, "awg2")
	if len(cmds) != 1 || !strings.Contains(cmds[0], "uci add_list firewall.@zone[2].network='awg2'") {
		t.Errorf("attaching a new interface produced %v", cmds)
	}
}

func TestZoneDetach_OnlyWhenAttached(t *testing.T) {
	vpn, _ := FindZone(ParseFirewallZones(liveFirewallShow), "vpn")

	cmds := ZoneDetachCmds(vpn, "awg1")
	if len(cmds) != 1 || !strings.Contains(cmds[0], "uci del_list firewall.@zone[2].network='awg1'") {
		t.Errorf("detaching an attached interface produced %v", cmds)
	}
	if cmds := ZoneDetachCmds(vpn, "awg9"); len(cmds) != 0 {
		t.Errorf("detaching something that is not attached should be a no-op, got %v", cmds)
	}
}

// A missing zone must be reported, never substituted. On this router the wan zone forwards REJECT,
// so a tunnel quietly landing there would be configured, visible, and dead.
func TestFindZone_AbsentIsNotSilent(t *testing.T) {
	zones := ParseFirewallZones(liveFirewallShow)
	if _, ok := FindZone(zones, "does-not-exist"); ok {
		t.Fatal("FindZone claimed to find a zone that is not there")
	}
}

func TestFirewallCommit_ReloadsRatherThanRestarts(t *testing.T) {
	cmds := strings.Join(FirewallCommitCmds(), " ")
	if !strings.Contains(cmds, "uci commit firewall") || !strings.Contains(cmds, "reload") {
		t.Fatalf("commit tail is wrong: %s", cmds)
	}
	if strings.Contains(cmds, "restart") {
		t.Fatal("restarting fw4 drops every established connection through the router, including this session")
	}
}
