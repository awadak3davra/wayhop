package server

import (
	"context"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// The reference router's `ip rule show` (dump of 02.11) with the line /usr/bin/group-failover.sh adds:
// `ip rule add pref 145 fwmark 0x30000/0xff0000 lookup 153`.
const refrouterRules = `0:	from all lookup local
50:	from all to 198.51.100.48 lookup main
145:	from all fwmark 0x30000/0xff0000 lookup 153
147:	from all to 10.0.0.0/8 lookup main
148:	from all to 172.16.0.0/12 lookup main
149:	from all to 192.168.0.0/16 lookup main
150:	from all fwmark 0x20000/0xff0000 lookup 151
151:	from all fwmark 0x30000/0xff0000 lookup 152
9000:	from all fwmark 0x2024 goto 9002
9001:	from all fwmark 0x2023 lookup 2022
9002:	from all nop
32766:	from all lookup main
32767:	from all lookup default
32768:	from all lookup 2022
`

// The same router's `uci show firewall` and `uci show network`, cut to what the check reads. awg2 is
// taken out of the vpn zone here; on the router all three are in it.
const (
	refrouterFirewall = `firewall.@zone[0]=zone
firewall.@zone[0].name='lan'
firewall.@zone[0].network='lan'
firewall.@zone[1]=zone
firewall.@zone[1].name='wan'
firewall.@zone[1].network='wan' 'wan6'
firewall.@forwarding[0]=forwarding
firewall.@forwarding[0].src='lan'
firewall.@forwarding[0].dest='wan'
firewall.@zone[2]=zone
firewall.@zone[2].name='vpn'
firewall.@zone[2].forward='ACCEPT'
firewall.@zone[2].masq='1'
firewall.@zone[2].network='awg0' 'awg1' 'wr_95bb4df7'
firewall.@zone[2].mtu_fix='1'
firewall.@forwarding[1]=forwarding
firewall.@forwarding[1].src='lan'
firewall.@forwarding[1].dest='vpn'
`
	refrouterNetwork = `network.lan.device='br-lan'
network.wan.device='wan'
network.awg0.proto='amneziawg'
network.awg1.proto='amneziawg'
network.awg2.proto='amneziawg'
`
)

// The operator's own failover script points WayHop's mark 0x30000 at table 153. WayHop
// said nothing, and after a renumbering that mark was another list's.
func TestReviewWarnsAboutAForeignRuleOnWayHopsMarks(t *testing.T) {
	profile := refrouterProfile()
	s, plan := openwrtServer(t, profile, &fakeTables{})
	if egressTable(t, plan, "grp-auto") != 151 || egressTable(t, plan, "ru") != 152 {
		t.Fatalf("setup: the fixture should number as the router does: %+v", plan.Egresses)
	}
	defer func(old func(context.Context) (string, string, error)) { openwrtRuleReader = old }(openwrtRuleReader)
	openwrtRuleReader = func(context.Context) (string, string, error) { return refrouterRules, "", nil }
	s.uciReader = func() (string, string, error) { return refrouterNetwork, refrouterFirewall, nil }

	found := s.openwrtPlaneFindings(context.Background(), *s.cfg, &profile)
	var foreign, forward []PlanFinding
	for _, f := range found {
		switch f.ID {
		case findingForeignRule:
			foreign = append(foreign, f)
		case findingNoForward:
			forward = append(forward, f)
		}
	}
	if len(foreign) != 1 || foreign[0].Item != "ip rule 145: from all fwmark 0x30000/0xff0000 lookup 153" ||
		!strings.Contains(foreign[0].Detail, "matches one of WayHop's marks and looks up one of WayHop's routing tables") {
		t.Fatalf("foreign rule findings: %+v", foreign)
	}
	// Awg2 is one of the group's tunnels and no zone holds it.
	if len(forward) != 1 || forward[0].Item != "awg2" || !strings.Contains(forward[0].Detail, "awg2 is in no firewall zone") ||
		!strings.Contains(forward[0].Detail, "group grp-auto") {
		t.Fatalf("not-forwarded findings: %+v", forward)
	}

	// The router as it is (no script rule, awg2 in the zone): nothing to say.
	openwrtRuleReader = func(context.Context) (string, string, error) {
		return strings.Replace(refrouterRules, "145:\tfrom all fwmark 0x30000/0xff0000 lookup 153\n", "", 1), "", nil
	}
	s.uciReader = func() (string, string, error) {
		return refrouterNetwork, strings.Replace(refrouterFirewall, "'awg0' 'awg1' 'wr_95bb4df7'", "'awg0' 'awg1' 'awg2' 'wr_95bb4df7'", 1), nil
	}
	for _, f := range s.openwrtPlaneFindings(context.Background(), *s.cfg, &profile) {
		if f.ID == findingForeignRule || f.ID == findingNoForward {
			t.Fatalf("a clean router reported %+v", f)
		}
	}
	// A router that cannot be read is not reported on.
	openwrtRuleReader = func(context.Context) (string, string, error) { return "", "", context.DeadlineExceeded }
	s.uciReader = func() (string, string, error) { return "", "", context.DeadlineExceeded }
	if got := s.openwrtPlaneFindings(context.Background(), *s.cfg, &profile); len(got) != 0 {
		t.Fatalf("unreadable router: %+v", got)
	}
}

// Zones by device, a wildcard device, an interface whose device has another name, and a zone
// nothing forwards to.
func TestForwardedDevicesReadsTheFirewall(t *testing.T) {
	firewall := refrouterFirewall +
		"firewall.@zone[3]=zone\nfirewall.@zone[3].name='tun'\nfirewall.@zone[3].device='tun+' 'awg9'\n" +
		"firewall.@forwarding[2]=forwarding\nfirewall.@forwarding[2].src='lan'\nfirewall.@forwarding[2].dest='tun'\n" +
		"firewall.@zone[4]=zone\nfirewall.@zone[4].name='island'\nfirewall.@zone[4].network='vpn_fi'\n"
	network := refrouterNetwork + "network.vpn_fi.device='awg7'\n"
	forwarded, zoned := forwardedDevices(network, firewall)
	for dev, want := range map[string][2]bool{
		"awg0": {true, true}, "awg2": {false, false}, "tun0": {true, true}, "awg9": {true, true},
		"awg7": {false, true}, // in a zone, and nothing forwards to that zone
		"wan":  {true, true},
	} {
		if forwarded(dev) != want[0] || zoned(dev) != want[1] {
			t.Errorf("%s: forwarded %v zoned %v, want %v", dev, forwarded(dev), zoned(dev), want)
		}
	}
	plan := &pbr.Plan{Egresses: []pbr.Egress{
		{Tag: model.ListEgressTag("tg"), Kind: pbr.EgressInterface, Iface: "awg0", Ifaces: []string{"awg0", "awg7"}},
		{Tag: "solo", Kind: pbr.EgressInterface, Iface: "awg2"}, // one tunnel: nothing is elected, not this check's
	}}
	got := notForwardedFindings(plan, network, firewall)
	if len(got) != 1 || got[0].Item != "awg7" || !strings.Contains(got[0].Detail, "is in a firewall zone nothing is forwarded to") ||
		!strings.Contains(got[0].Detail, "list tg") {
		t.Fatalf("findings: %+v", got)
	}
	if len(notForwardedFindings(plan, network, "")) != 0 {
		t.Fatal("an empty firewall dump is unread, not \"no zones\"")
	}
}

// What Review says about a kill switch over names: the hold and its bound in hybrid mode, the gap in
// fast mode, nothing when the kill switch covers addresses only.
func TestReviewStatesTheNamesHold(t *testing.T) {
	profile := refrouterProfile()
	profile.Groups[0].KillSwitch = true
	s, plan := openwrtServer(t, profile, &fakeTables{})
	if got := s.namesHoldFindings(*s.cfg, plan); len(got) != 0 {
		t.Fatalf("addresses only: %+v", got)
	}
	profile.RoutingLists[0].Manual = append(profile.RoutingLists[0].Manual, "telegram.org")
	named, _, err := pbr.Compile(&profile, pbr.Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	got := s.namesHoldFindings(*s.cfg, named) // the fixture runs in fast mode
	if len(got) != 1 || got[0].ID != findingNamesUnheld {
		t.Fatalf("fast mode: %+v", got)
	}
	s.cfg.RoutingMode = "hybrid"
	got = s.namesHoldFindings(*s.cfg, named)
	if len(got) != 1 || got[0].ID != findingNamesHold || !strings.Contains(got[0].Detail, "for at most 600 s") ||
		!strings.Contains(got[0].Detail, "IPv6") {
		t.Fatalf("hybrid mode: %+v", got)
	}
	s.cfg.KillSwitchBootHoldLift = -1
	if got = s.namesHoldFindings(*s.cfg, named); len(got) != 1 || !strings.Contains(got[0].Detail, "never lets go by itself") {
		t.Fatalf("strict: %+v", got)
	}
}

// TestOffloadHWFindings (polish 3): hardware offload in fast mode on OpenWrt, asked for or resolved
// from auto, gets a degraded, non-blocking warning; sw and off get none.
func TestOffloadHWFindings(t *testing.T) {
	got := offloadHWFindings(config.Config{Offload: "hw"}, nil)
	if len(got) != 1 || got[0].ID != findingOffloadHW || got[0].Blocks != platform.BlocksNothing ||
		got[0].Severity != platform.SeverityDegraded || !strings.Contains(got[0].Detail, "MT7981") ||
		!strings.Contains(got[0].Remedy, "sw or off") {
		t.Fatalf("hw: %+v", got)
	}
	if got := offloadHWFindings(config.Config{Offload: "auto"}, &pbr.Plan{Flowtable: &pbr.Flowtable{HW: true}}); len(got) != 1 {
		t.Errorf("auto resolved to hw: %+v", got)
	}
	for _, c := range []struct {
		off  string
		plan *pbr.Plan
	}{{"sw", &pbr.Plan{Flowtable: &pbr.Flowtable{}}}, {"off", nil}, {"auto", &pbr.Plan{}}} {
		if got := offloadHWFindings(config.Config{Offload: c.off}, c.plan); len(got) != 0 {
			t.Errorf("%s: %+v", c.off, got)
		}
	}
}
