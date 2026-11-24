package server

import (
	"reflect"
	"strings"
	"testing"
)

// Which side of the router a device is on, against configurations as routers have them. The first
// is the reason this file exists: on the reference router the LAN zone masquerades, and a rule that read
// masquerading as "the provider's" took the LAN for the provider.

// sidesRouterFirewall is `uci show firewall` of the reference router (OpenWrt 25.12.2), the zones' lines as they
// were measured. Nothing else of that output is known here: no policies, no
// forwardings, and of the fourth zone only its name.
const sidesRouterFirewall = "firewall.@zone[0].name='lan'\nfirewall.@zone[0].masq='1'\nfirewall.@zone[0].network='lan'\n" +
	"firewall.@zone[1].name='wan'\nfirewall.@zone[1].masq='1'\nfirewall.@zone[1].network='wan'\n" +
	"firewall.@zone[2].name='vpn'\nfirewall.@zone[2].masq='1'\nfirewall.@zone[2].network='awg0' 'awg1' 'awg2' 'wr_95bb4df7'\n" +
	"firewall.@zone[3].name='vpn_direct'\n"

// sidesRouterNetwork is NOT measured: the interfaces the zones above name, with the devices the
// router's /proc/net/route showed (br-lan, wan, awg2). The test runs without it as well.
const sidesRouterNetwork = "network.lan=interface\nnetwork.lan.device='br-lan'\nnetwork.lan.proto='static'\n" +
	"network.wan=interface\nnetwork.wan.device='wan'\nnetwork.wan.proto='dhcp'\n" +
	"network.awg0=interface\nnetwork.awg0.proto='amneziawg'\nnetwork.awg1=interface\nnetwork.awg1.proto='amneziawg'\n" +
	"network.awg2=interface\nnetwork.awg2.proto='amneziawg'\nnetwork.wr_95bb4df7=interface\nnetwork.wr_95bb4df7.proto='amneziawg'\n"

// sidesStockFirewall and sidesStockNetwork are the configuration OpenWrt ships (written from its
// /etc/config files as `uci show` prints them, not measured on a router): masquerading on wan only.
const sidesStockFirewall = "firewall.@defaults[0]=defaults\nfirewall.@defaults[0].input='REJECT'\nfirewall.@defaults[0].output='ACCEPT'\n" +
	"firewall.@defaults[0].forward='REJECT'\nfirewall.@defaults[0].synflood_protect='1'\n" +
	"firewall.@zone[0]=zone\nfirewall.@zone[0].name='lan'\nfirewall.@zone[0].network='lan'\nfirewall.@zone[0].input='ACCEPT'\n" +
	"firewall.@zone[0].output='ACCEPT'\nfirewall.@zone[0].forward='ACCEPT'\n" +
	"firewall.@zone[1]=zone\nfirewall.@zone[1].name='wan'\nfirewall.@zone[1].network='wan' 'wan6'\nfirewall.@zone[1].input='REJECT'\n" +
	"firewall.@zone[1].output='ACCEPT'\nfirewall.@zone[1].forward='REJECT'\nfirewall.@zone[1].masq='1'\nfirewall.@zone[1].mtu_fix='1'\n" +
	"firewall.@forwarding[0]=forwarding\nfirewall.@forwarding[0].src='lan'\nfirewall.@forwarding[0].dest='wan'\n" +
	"firewall.@rule[0]=rule\nfirewall.@rule[0].name='Allow-DHCP-Renew'\nfirewall.@rule[0].src='wan'\nfirewall.@rule[0].proto='udp'\n" +
	"firewall.@rule[0].dest_port='68'\nfirewall.@rule[0].target='ACCEPT'\nfirewall.@rule[0].family='ipv4'\n"

const sidesStockNetwork = "network.loopback=interface\nnetwork.loopback.device='lo'\nnetwork.loopback.proto='static'\n" +
	"network.loopback.ipaddr='127.0.0.1'\nnetwork.loopback.netmask='255.0.0.0'\n" +
	"network.globals=globals\nnetwork.globals.ula_prefix='fd12:3456:789a::/48'\n" +
	"network.@device[0]=device\nnetwork.@device[0].name='br-lan'\nnetwork.@device[0].type='bridge'\nnetwork.@device[0].ports='lan1' 'lan2' 'lan3'\n" +
	"network.lan=interface\nnetwork.lan.device='br-lan'\nnetwork.lan.proto='static'\nnetwork.lan.ipaddr='192.168.50.1'\n" +
	"network.lan.netmask='255.255.255.0'\nnetwork.lan.ip6assign='60'\n" +
	"network.wan=interface\nnetwork.wan.device='wan'\nnetwork.wan.proto='dhcp'\n" +
	"network.wan6=interface\nnetwork.wan6.device='wan'\nnetwork.wan6.proto='dhcpv6'\n"

func sidesOf(t *testing.T, sd ksSides, uplink, tunnel []string, want map[string]ksSide) {
	t.Helper()
	set := func(in []string) map[string]bool {
		out := map[string]bool{}
		for _, d := range in {
			out[d] = true
		}
		return out
	}
	j := sd.judge(set(uplink), set(tunnel))
	name := map[ksSide]string{sideUnsure: "not known", sideHouse: "the LAN's", sideProvider: "the provider's", sideTunnel: "a tunnel"}
	for dev, side := range want {
		if got := j.side(dev); got != side {
			t.Errorf("%s is %s, want %s", dev, name[got], name[side])
		}
	}
}

// The reference router: every zone masquerades, the LAN's too. The LAN is the LAN, the uplink the
// provider's, WayHop's tunnels are tunnels.
func TestSidesOnARouterWhoseLANZoneMasquerades(t *testing.T) {
	want := map[string]ksSide{"br-lan": sideHouse, "wan": sideProvider, "awg0": sideTunnel, "awg2": sideTunnel}
	sidesOf(t, parseSides(sidesRouterNetwork, sidesRouterFirewall), []string{"wan"}, []string{"awg0", "awg2"}, want)
	// Without the network configuration the devices are still told apart by netifd's own naming.
	sidesOf(t, parseSides("", sidesRouterFirewall), []string{"wan"}, []string{"awg0", "awg2"}, want)
	// A tunnel of that zone WayHop does not run is the operator's own network, not the provider's.
	// The kernel lists WayHop's default route by a tunnel among the IPv6 routes: it makes no uplink.
	sidesOf(t, parseSides(sidesRouterNetwork, sidesRouterFirewall), []string{"wan", "awg2"}, []string{"awg0", "awg2"},
		map[string]ksSide{"br-lan": sideHouse, "awg1": sideHouse, "wr_95bb4df7": sideHouse, "awg2": sideTunnel, "docker0": sideUnsure})

	// The same router end to end, with the routes its /proc/net/route had: a list that names all of
	// 192.168.0.0/16 keeps the LAN's own segment (requirement B) and holds the uplink's (A).
	route4 := ow4Head + ow4Route("wan", "0.0.0.0/0", "192.168.50.254") + ow4Route("awg2", "1.0.0.1/32", "") +
		ow4Route("br-lan", "192.168.2.0/24", "") + ow4Route("wan", "192.168.1.0/24", "")
	s := ow4Server(t, ow4UCI(sidesRouterNetwork, sidesRouterFirewall), &route4)
	plan := ow4Plan(t, "192.168.0.0/16")
	s.noteGuardTunnels(plan)
	local, partial, _ := s.guardLocalState()
	if want := append(houseRoutes("br-lan", "192.168.2.0/24"), gl("wan", "192.168.1.0/24")...); !reflect.DeepEqual(local, want) || partial {
		t.Fatalf("told %v partial=%v, want %v", local, partial, want)
	}
	program := s.nftGuardProgram(plan)
	lan, jump := strings.Index(program, `oifname "br-lan" ip daddr { 192.168.2.0/24 } accept`), strings.Index(program, "ip daddr { 192.168.0.0/16 } jump ks_routed")
	if lan < 0 || jump < lan || strings.Contains(program, `oifname "wan"`) || strings.Contains(program, "ct direction reply") {
		t.Errorf("the LAN is not accepted ahead of the list's verdict, or the uplink is:\n%s", program)
	}
	if row := ow4Row(s, plan); row.Status != "pass" || !strings.Contains(row.Summary, "1 of the LAN's own networks") {
		t.Errorf("Diagnostics: %+v", row)
	}
}

// The configuration OpenWrt ships.
func TestSidesOnTheStockConfiguration(t *testing.T) {
	sd := parseSides(sidesStockNetwork, sidesStockFirewall)
	sidesOf(t, sd, []string{"wan"}, nil, map[string]ksSide{"br-lan": sideHouse, "wan": sideProvider, "lan1": sideUnsure})
	// The cable is out, or the default route lives in another table: the zone still faces the
	// provider (input refused, forwarded into only, both interfaces clients of another network).
	sidesOf(t, sd, nil, nil, map[string]ksSide{"br-lan": sideHouse, "wan": sideProvider})
	// Masquerading on the LAN's zone, off on wan: nothing changes.
	swapped := strings.Replace(sidesStockFirewall, "firewall.@zone[1].masq='1'\n", "firewall.@zone[0].masq='1'\n", 1)
	sidesOf(t, parseSides(sidesStockNetwork, swapped), []string{"wan"}, nil, map[string]ksSide{"br-lan": sideHouse, "wan": sideProvider})
}

// Dual access: the default route is on the PPPoE session, the provider's own network is routed by
// the port under it, and a second interface on that port takes an address by DHCP.
func TestSidesWithDualAccess(t *testing.T) {
	network := "network.lan=interface\nnetwork.lan.device='br-lan'\nnetwork.lan.proto='static'\n" +
		"network.wan=interface\nnetwork.wan.device='eth1'\nnetwork.wan.proto='pppoe'\nnetwork.wan.username='u'\n" +
		"network.wan6=interface\nnetwork.wan6.device='@wan'\nnetwork.wan6.proto='dhcpv6'\n" +
		"network.isp_lan=interface\nnetwork.isp_lan.device='eth1'\nnetwork.isp_lan.proto='dhcp'\nnetwork.isp_lan.defaultroute='0'\n" +
		"network.iptv=interface\nnetwork.iptv.device='eth1.4'\nnetwork.iptv.proto='dhcp'\nnetwork.iptv.defaultroute='0'\n"
	want := map[string]ksSide{"pppoe-wan": sideProvider, "eth1": sideProvider, "eth1.4": sideProvider, "br-lan": sideHouse}
	for name, fw := range map[string]string{
		"every interface of the provider's in the wan zone": strings.Replace(sidesStockFirewall, "'wan' 'wan6'", "'wan' 'wan6' 'isp_lan' 'iptv'", 1),
		"the same, and the LAN masquerades":                 strings.Replace(sidesStockFirewall, "'wan' 'wan6'\n", "'wan' 'wan6' 'isp_lan' 'iptv'\nfirewall.@zone[0].masq='1'\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			sidesOf(t, parseSides(network, fw), []string{"pppoe-wan"}, nil, want)
		})
	}
	// The second interface is in no zone at all: the port is still the provider's, because it is the
	// port of the interface whose session carries the default route. The VLAN beside it is not known.
	sidesOf(t, parseSides(network, sidesStockFirewall), []string{"pppoe-wan"}, nil,
		map[string]ksSide{"pppoe-wan": sideProvider, "eth1": sideProvider, "eth1.4": sideUnsure, "br-lan": sideHouse})

	route4 := ow4Head + ow4Route("pppoe-wan", "0.0.0.0/0", "") + ow4Route("eth1", "10.0.0.0/8", "10.64.1.1") +
		ow4Route("eth1", "10.64.0.0/18", "") + ow4Route("br-lan", "192.168.2.0/24", "")
	s := ow4Server(t, ow4UCI(network, sidesStockFirewall), &route4)
	program := s.nftGuardProgram(ow4Plan(t, "10.77.0.0/16"))
	if strings.Contains(program, `oifname "eth1"`) || strings.Contains(program, `oifname "pppoe-wan"`) {
		t.Errorf("the office is accepted by the provider's side:\n%s", program)
	}
}

// A WireGuard server for the LAN's own clients, in a zone of its own that masquerades; an IoT
// network the LAN may reach and that may reach nothing; and tunnels put into the LAN's zone.
func TestSidesWithAServerTunnelAndIsolatedZones(t *testing.T) {
	network := sidesStockNetwork +
		"network.wg0=interface\nnetwork.wg0.proto='wireguard'\nnetwork.wg0.listen_port='51820'\nnetwork.wg0.addresses='10.8.0.1/24'\n" +
		"network.iot=interface\nnetwork.iot.device='br-iot'\nnetwork.iot.proto='static'\nnetwork.iot.ipaddr='192.168.50.1'\n" +
		"network.guest=interface\nnetwork.guest.type='bridge'\nnetwork.guest.ifname='eth0.3 eth0.4'\nnetwork.guest.proto='static'\n"
	firewall := sidesStockFirewall +
		"firewall.@zone[2]=zone\nfirewall.@zone[2].name='wgs'\nfirewall.@zone[2].network='wg0'\nfirewall.@zone[2].input='ACCEPT'\nfirewall.@zone[2].masq='1'\n" +
		"firewall.@zone[3]=zone\nfirewall.@zone[3].name='iot'\nfirewall.@zone[3].input='REJECT'\nfirewall.@zone[3].forward='REJECT'\n" +
		"firewall.guests=zone\nfirewall.guests.name='guest'\nfirewall.guests.network='guest'\nfirewall.guests.input='REJECT'\n" +
		"firewall.@forwarding[1]=forwarding\nfirewall.@forwarding[1].src='wgs'\nfirewall.@forwarding[1].dest='lan'\n" +
		"firewall.@forwarding[2]=forwarding\nfirewall.@forwarding[2].src='wgs'\nfirewall.@forwarding[2].dest='wan'\n" +
		"firewall.@forwarding[3]=forwarding\nfirewall.@forwarding[3].src='lan'\nfirewall.@forwarding[3].dest='iot'\n" +
		"firewall.@forwarding[4]=forwarding\nfirewall.@forwarding[4].src='guest'\nfirewall.@forwarding[4].dest='wan'\n"
	sd := parseSides(network, firewall)
	sidesOf(t, sd, []string{"wan"}, nil, map[string]ksSide{
		"wg0": sideHouse, "br-iot": sideHouse, "br-guest": sideHouse, "eth0.3": sideHouse, "br-lan": sideHouse, "wan": sideProvider,
	})
	// The server's clients keep their network when a list names the range it is in.
	route4 := ow4Head + ow4Route("wan", "0.0.0.0/0", "192.168.100.1") + ow4Route("wg0", "10.8.0.0/24", "") + ow4Route("br-lan", "192.168.1.0/24", "")
	s := ow4Server(t, ow4UCI(network, firewall), &route4)
	if program := s.nftGuardProgram(ow4Plan(t, "10.0.0.0/8")); !strings.Contains(program, `oifname "wg0" ip daddr { 10.8.0.0/24 } accept`) {
		t.Errorf("the server tunnel's clients are not accepted:\n%s", program)
	}

	// A tunnel in the LAN's zone. One WayHop runs changes nothing, default route or not. One it does
	// not run, with a default route, leaves the zone saying nothing: the LAN is then on no known
	// side, never the provider's, and keeps its answers.
	inLAN := strings.Replace(firewall, "firewall.@zone[0].network='lan'", "firewall.@zone[0].network='lan' 'awg0' 'wgx'", 1)
	sd = parseSides(network, inLAN)
	sidesOf(t, sd, []string{"wan", "awg0"}, []string{"awg0"}, map[string]ksSide{"br-lan": sideHouse, "awg0": sideTunnel, "wan": sideProvider})
	sidesOf(t, sd, []string{"wan", "wgx"}, []string{"awg0"}, map[string]ksSide{"br-lan": sideUnsure, "wgx": sideProvider, "wan": sideProvider})
	route4 = ow4Head + ow4Route("wan", "0.0.0.0/0", "192.168.100.1") + ow4Route("wgx", "0.0.0.0/0", "") + ow4Route("br-lan", "192.168.1.0/24", "")
	s = ow4Server(t, ow4UCI(network, inLAN), &route4)
	plan := ow4Plan(t, "192.168.0.0/16")
	s.noteGuardTunnels(plan)
	program := s.nftGuardProgram(plan)
	if !strings.Contains(program, `oifname "br-lan" ct direction reply ip daddr { 192.168.1.0/24 } accept`) || strings.Contains(program, `oifname "br-lan" ip daddr`) {
		t.Errorf("a LAN whose zone also holds a way out: answers must pass, new connections to a named network must not:\n%s", program)
	}
	if row := ow4Row(s, plan); row.Status != "warn" || !strings.Contains(row.Summary, "br-lan") {
		t.Errorf("Diagnostics: %+v", row)
	}
	// Zones that were not read say nothing about any device, beyond the default route.
	sidesOf(t, ksSides{}, []string{"wan"}, nil, map[string]ksSide{"br-lan": sideUnsure, "wan": sideProvider})
}

// Review words a route of a device of unknown side differently from the provider's.
func TestReviewSaysWhenADevicesSideIsNotKnown(t *testing.T) {
	sd := parseSides(sidesStockNetwork, sidesStockFirewall)
	routes := gl("br-lan", "192.168.1.0/24", "docker0", "172.17.0.0/16", "wan", "172.20.0.0/24")
	fs := providerSideFindings(ow4Plan(t, "172.16.0.0/12"), sd, routes, map[string]bool{"wan": true})
	if len(fs) != 2 || fs[0].Item != "172.16.0.0/12 on docker0" || !strings.Contains(fs[0].Detail, "no firewall zone holds it") ||
		!strings.Contains(fs[0].Detail, "answers still pass") || !strings.Contains(fs[0].Remedy, "firewall zone") {
		t.Fatalf("a device of unknown side: %+v", fs)
	}
	if fs[1].Item != "172.16.0.0/12 on wan" || !strings.Contains(fs[1].Detail, "is the provider's side") || strings.Contains(fs[1].Detail+fs[1].Remedy, "masquerad") {
		t.Errorf("the provider's side: %+v", fs[1])
	}
}
