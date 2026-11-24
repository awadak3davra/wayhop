package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// Third round of the stage-2 review of the nft kill switch (OW4): which side of the router a route
// is on, the bounds on what the guard is told, and a learn pass against a load of the guard. What the
// rendered program does to a packet is judged in pbr (guard_ow4_test.go) from the same shapes; here
// the shapes are made from the router's own files.

const ow4Head = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"

// ow4Route is one line of /proc/net/route as a little-endian kernel prints it.
func ow4Route(dev, prefix, gateway string) string {
	p := netip.MustParsePrefix(prefix)
	le := func(a netip.Addr) string {
		b := a.As4()
		return fmt.Sprintf("%02X%02X%02X%02X", b[3], b[2], b[1], b[0])
	}
	mask := netip.AddrFrom4([4]byte{})
	if p.Bits() > 0 {
		var m [4]byte
		binary.BigEndian.PutUint32(m[:], ^uint32(0)<<(32-p.Bits()))
		mask = netip.AddrFrom4(m)
	}
	gw, flags := netip.AddrFrom4([4]byte{}), "0001"
	if gateway != "" {
		gw, flags = netip.MustParseAddr(gateway), "0003"
	}
	return fmt.Sprintf("%s\t%s\t%s\t%s\t0\t0\t0\t%s\t0\t0\t0\n", dev, le(p.Addr()), le(gw), flags, le(mask))
}

// ow4Network and ow4Firewall are `uci show` of a router with the stock zones and policies: the LAN
// (lan, a lab bridge, a WireGuard server, any br-seg device), the provider's (wan) and the tunnels'.
// Masquerading is on the tunnels' zone and, by wanMasq, on wan: it decides nothing.
const ow4Network = "network.loopback=interface\nnetwork.loopback.device='lo'\n" +
	"network.lan=interface\nnetwork.lan.device='br-lan'\nnetwork.lan.proto='static'\n" +
	"network.lab=interface\nnetwork.lab.device='br-lab'\n" +
	"network.wgsrv=interface\nnetwork.wgsrv.proto='wireguard'\n" +
	"network.wan=interface\nnetwork.wan.device='wan'\nnetwork.wan.proto='dhcp'\n" +
	"network.wan6=interface\nnetwork.wan6.device='@wan'\nnetwork.wan6.proto='dhcpv6'\n" +
	"network.awg0=interface\nnetwork.awg0.proto='amneziawg'\n"

func ow4FirewallWith(wanMasq bool) string {
	fw := "firewall.@defaults[0]=defaults\nfirewall.@defaults[0].input='REJECT'\nfirewall.@defaults[0].forward='REJECT'\n" +
		"firewall.@zone[0]=zone\nfirewall.@zone[0].name='lan'\nfirewall.@zone[0].network='lan' 'lab' 'wgsrv'\nfirewall.@zone[0].device='br-seg+'\n" +
		"firewall.@zone[0].input='ACCEPT'\n" +
		"firewall.@zone[1]=zone\nfirewall.@zone[1].name='wan'\nfirewall.@zone[1].network='wan' 'wan6'\nfirewall.@zone[1].input='REJECT'\n" +
		"firewall.@zone[2]=zone\nfirewall.@zone[2].name='vpn'\nfirewall.@zone[2].network='awg0' 'awg1' 'awg2'\nfirewall.@zone[2].masq='1'\n" +
		"firewall.@zone[2].input='REJECT'\n" +
		"firewall.@forwarding[0]=forwarding\nfirewall.@forwarding[0].src='lan'\nfirewall.@forwarding[0].dest='wan'\n" +
		"firewall.@forwarding[1]=forwarding\nfirewall.@forwarding[1].src='lan'\nfirewall.@forwarding[1].dest='vpn'\n"
	if wanMasq {
		fw += "firewall.@zone[1].masq='1'\n"
	}
	return fw
}

func ow4UCI(network, firewall string) uciReadFunc {
	return func() (string, string, error) { return network, firewall, nil }
}

// houseUCI is the stock router.
func houseUCI() (string, string, error) { return ow4Network, ow4FirewallWith(true), nil }

// houseRoutes is gl with every route on the LAN side.
func houseRoutes(pairs ...string) []pbr.GuardLocal {
	out := gl(pairs...)
	for i := range out {
		out[i].House = true
	}
	return out
}

func ow4Server(t *testing.T, read uciReadFunc, route4 *string) *Server {
	t.Helper()
	old := ksReadLocalRoutes
	ksReadLocalRoutes = func() ksReading { return localRoutesFrom(*route4, "", binary.LittleEndian) }
	t.Cleanup(func() { ksReadLocalRoutes = old })
	cfg := config.Default()
	cfg.RoutingMode = "hybrid"
	s := &Server{cfg: cfg, uciReader: read}
	s.platformOf = func() platform.Platform { return platform.OpenWrt }
	return s
}

// ow4Plan is one kill-switched list by a group of two tunnels (awg0, awg2).
func ow4Plan(t *testing.T, manual ...string) *pbr.Plan {
	t.Helper()
	ext := func(id, iface, peer string) model.Endpoint {
		return model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineExternal,
			Params: map[string]any{"interface": iface, "endpoint_ip": peer}}
	}
	p := model.Profile{
		Endpoints:    []model.Endpoint{ext("nl", "awg0", "198.51.100.48"), ext("fi", "awg2", "198.51.100.144")},
		Groups:       []model.Group{{ID: "grp", Name: "G", Type: model.GroupFallback, Members: []string{"nl", "fi"}, KillSwitch: true}},
		RoutingLists: []model.RoutingList{{ID: "office", Name: "Office", Outbound: "grp", Enabled: true, Manual: manual}},
	}
	plan, _, err := pbr.Compile(&p, pbr.Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// The guard the daemon loads holds a private network a kill-switched list names, keeps the
// LAN's own segments inside it, follows a new segment, does not pass it by the uplink's segment, and does not change for a route that has nothing to do with the list.
func TestGuardProgramFollowsTheRoutersRoutesInsideAListedNetwork(t *testing.T) {
	routes, out := gl("br-lan", "192.168.2.0/24"), map[string]bool{}
	old := ksReadLocalRoutes
	ksReadLocalRoutes = func() ksReading { return ksReading{Routes: routes, Uplink: out} }
	t.Cleanup(func() { ksReadLocalRoutes = old })
	s := &Server{cfg: config.Default(), uciReader: houseUCI}
	s.platformOf = func() platform.Platform { return platform.OpenWrt }
	plan := officePlan(t)

	first := s.nftGuardProgram(plan)
	for _, want := range []string{"ip daddr { 10.77.0.0/16 } jump ks_routed", "chain ks_routed {\n\t\tip daddr @list_office_4 jump ks_0"} {
		if !strings.Contains(first, want) {
			t.Fatalf("no %q in:\n%s", want, first)
		}
	}
	if strings.Contains(first, "br-lan") || strings.Contains(first, "ct direction reply") {
		t.Errorf("a route outside the listed network, or a rule for routes not told, is in the program:\n%s", first)
	}
	if s.refreshGuardLocal(false) {
		t.Errorf("the same routes read as a change")
	}

	routes = append(routes, gl("wgsrv", "10.8.0.0/24")...)
	if !s.refreshGuardLocal(false) {
		t.Errorf("a new route did not read as a change")
	}
	if got := s.nftGuardProgram(plan); got != first {
		t.Errorf("a route outside the listed network changed the program:\n%s", got)
	}

	routes = append(routes, gl("br-lab", "10.77.5.0/24")...)
	s.refreshGuardLocal(false)
	second := s.nftGuardProgram(plan)
	if !strings.Contains(second, `oifname "br-lab" ip daddr { 10.77.5.0/24 } accept`) {
		t.Errorf("the lab segment is not accepted by its device:\n%s", second)
	}
	if strings.Index(second, `oifname "br-lab"`) > strings.Index(second, "jump ks_routed") {
		t.Errorf("the router's own route comes after the zones' verdict:\n%s", second)
	}

	// The segment goes down: nothing is reloaded and nothing is written, the entry stays (it is
	// bound to its device, so it accepts nothing by the provider).
	routes = gl("br-lan", "192.168.2.0/24")
	if s.refreshGuardLocal(false) {
		t.Errorf("a route that went away read as a change")
	}
	if got := s.nftGuardProgram(plan); got != second {
		t.Errorf("the program changed when a route went away")
	}

	// An uplink's segment inside the network the list names is the provider's, not the office: it is
	// told to the guard as such and accepts nothing. When the uplink is given another
	// segment the old one is forgotten; while the uplink is down nothing changes.
	routes, out = gl("br-lan", "192.168.2.0/24", "wan", "10.77.9.0/24"), map[string]bool{"wan": true}
	s.refreshGuardLocal(false)
	if got := s.nftGuardProgram(plan); got != second {
		t.Errorf("the uplink's segment changed the program for a network the list names:\n%s", got)
	}
	want := append(houseRoutes("br-lab", "10.77.5.0/24", "br-lan", "192.168.2.0/24"),
		append(gl("wan", "10.77.9.0/24"), houseRoutes("wgsrv", "10.8.0.0/24")...)...)
	if got := s.guardLocal(); !reflect.DeepEqual(got, want) {
		t.Errorf("told:\n got %v\nwant %v", got, want)
	}
	routes, out = gl("br-lan", "192.168.2.0/24"), map[string]bool{}
	if s.refreshGuardLocal(false) {
		t.Errorf("an uplink that went down read as a change")
	}
	routes, out = gl("br-lan", "192.168.2.0/24", "wan", "10.77.10.0/24"), map[string]bool{"wan": true}
	if !s.refreshGuardLocal(false) {
		t.Errorf("an uplink's new segment did not read as a change")
	}
	told := fmt.Sprint(s.guardLocal())
	if strings.Contains(told, "10.77.9.0/24") || !strings.Contains(told, "{wan 10.77.10.0/24 false false false}") {
		t.Errorf("the uplink's old segment is still told, or the new one is not: %s", told)
	}
}

// The collision: the office a list names is 192.168.1.0/24, and so is the segment
// between the router and the provider's box.
func TestANamedNetworkIsNotReachedAtTheProvidersSegment(t *testing.T) {
	route4 := ow4Head + ow4Route("wan", "0.0.0.0/0", "192.168.50.254") + ow4Route("br-lan", "192.168.2.0/24", "") + ow4Route("wan", "192.168.1.0/24", "")
	s := ow4Server(t, houseUCI, &route4)
	local, partial, _ := s.guardLocalState()
	if want := append(houseRoutes("br-lan", "192.168.2.0/24"), gl("wan", "192.168.1.0/24")...); !reflect.DeepEqual(local, want) || partial {
		t.Fatalf("told %v partial=%v, want %v", local, partial, want)
	}
	named := s.nftGuardProgram(ow4Plan(t, "192.168.1.0/24"))
	if strings.Contains(named, `oifname "wan"`) || !strings.Contains(named, "ip daddr { 192.168.1.0/24 } jump ks_routed") {
		t.Errorf("a network the list names is accepted by the provider's device, or is not judged:\n%s", named)
	}
	// A list that only sweeps private space keeps the modem's page, after the LAN's own segment.
	swept := s.nftGuardProgram(ow4Plan(t, "0.0.0.0/0"))
	lan, wan := strings.Index(swept, `oifname "br-lan" ip daddr { 192.168.2.0/24 } accept`), strings.Index(swept, `oifname "wan" ip daddr { 192.168.1.0/24 } accept`)
	if lan < 0 || wan < lan || strings.Contains(swept, "ct direction reply ip daddr") {
		t.Errorf("a list that sweeps private space:\n%s", swept)
	}
}

// Dual access: the default route is on the PPPoE session and the provider's own
// network is routed by the physical port, which carries no default route. The port is the
// provider's because the session is its interface's, whether the zone masquerades or not.
func TestThePortUnderAPPPoESessionIsTheProvidersSide(t *testing.T) {
	route4 := ow4Head + ow4Route("pppoe-wan", "0.0.0.0/0", "") + ow4Route("wan", "10.0.0.0/8", "10.64.1.1") +
		ow4Route("wan", "10.64.0.0/18", "") + ow4Route("br-lan", "192.168.2.0/24", "")
	pppoe := strings.Replace(ow4Network, "network.wan.proto='dhcp'", "network.wan.proto='pppoe'", 1)
	want := append(houseRoutes("br-lan", "192.168.2.0/24"), gl("wan", "10.0.0.0/8", "wan", "10.64.0.0/18")...)
	for name, fw := range map[string]string{"a zone that masquerades": ow4FirewallWith(true), "a zone that does not": ow4FirewallWith(false)} {
		s := ow4Server(t, ow4UCI(pppoe, fw), &route4)
		local, partial, _ := s.guardLocalState()
		if !reflect.DeepEqual(local, want) || partial {
			t.Errorf("%s: told %v partial=%v, want %v", name, local, partial, want)
		}
		program := s.nftGuardProgram(ow4Plan(t, "10.77.0.0/16"))
		if strings.Contains(program, `oifname "wan"`) || strings.Contains(program, `oifname "pppoe-wan"`) {
			t.Errorf("%s: the office is accepted by the provider's side:\n%s", name, program)
		}
	}
	// A WAN whose default route lives in another table (mwan3): nothing in main says it is a way out.
	// Its zone does: input refused, forwarded into only, every interface a client of another network.
	route4 = ow4Head + ow4Route("wan", "10.64.0.0/18", "") + ow4Route("br-lan", "192.168.2.0/24", "")
	s := ow4Server(t, houseUCI, &route4)
	if local := s.guardLocal(); !reflect.DeepEqual(local, append(houseRoutes("br-lan", "192.168.2.0/24"), gl("wan", "10.64.0.0/18")...)) {
		t.Errorf("no default route in main: told %v", local)
	}
	// Such a device's routes are told as they are now, not as they once were: given
	// another segment, the old one is forgotten, though main never showed the device as a way out.
	route4 = ow4Head + ow4Route("wan", "10.65.0.0/18", "") + ow4Route("br-lan", "192.168.2.0/24", "")
	if !s.refreshGuardLocal(false) || !reflect.DeepEqual(s.guardLocal(), append(houseRoutes("br-lan", "192.168.2.0/24"), gl("wan", "10.65.0.0/18")...)) {
		t.Errorf("a renumbered segment of the provider's side: told %v", s.guardLocal())
	}
	// A device no zone holds is on no known side: not the LAN's, and told as a candidate, so its
	// answers pass and a new connection to a network a list names does not.
	route4 += ow4Route("docker0", "172.17.0.0/16", "")
	s.refreshGuardLocal(false)
	found := false
	for _, r := range s.guardLocal() {
		if r.Dev == "docker0" {
			found = true
			if r.House || !r.Candidate {
				t.Errorf("a device in no firewall zone: %+v", r)
			}
		} else if r.Candidate {
			t.Errorf("a device of a known side is told as a candidate: %+v", r)
		}
	}
	if !found {
		t.Errorf("the route of a device in no zone is not told")
	}
	plan := ow4Plan(t, "172.17.0.0/16")
	program := s.nftGuardProgram(plan)
	reply, jump := strings.Index(program, `oifname "docker0" ct direction reply ip daddr { 172.17.0.0/16 } accept`), strings.Index(program, "ip daddr { 172.17.0.0/16 } jump ks_routed")
	if reply < 0 || jump < reply || strings.Contains(program, `oifname "docker0" ip daddr`) || strings.Contains(program, "oifname !=") {
		t.Errorf("a device of unknown side inside a named network:\n%s", program)
	}
	if row := ow4Row(s, plan); row.Status != "warn" || !strings.Contains(row.Summary, "the side of docker0 is not known") {
		t.Errorf("Diagnostics: %+v", row)
	}
}

func ow4Row(s *Server, plan *pbr.Plan) healthRow { return s.killSwitchRoutesRow(plan) }

// The bound of 64 must not be filled by a tunnel's public routes in address order: the LAN's own
// segment, which comes last, would never be told and every answer to the LAN would be dropped.
func TestRoutesTheGuardCannotUseDoNotPushTheLANOut(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	var b strings.Builder
	b.WriteString(ow4Head + ow4Route("wan", "0.0.0.0/0", "192.168.50.254"))
	for i := 0; i < 70; i++ {
		b.WriteString(ow4Route("awg2", fmt.Sprintf("5.45.%d.0/24", i), "")) // a tunnel's AllowedIPs in the main table
	}
	b.WriteString(ow4Route("br-lan", "192.168.2.0/24", "") + ow4Route("wan", "192.168.1.0/24", ""))
	route4 := b.String()
	s := ow4Server(t, houseUCI, &route4)
	plan := ow4Plan(t, "0.0.0.0/0")
	s.noteGuardTunnels(plan) // as an Apply and the reconcile tick do
	local, partial, _ := s.guardLocalState()
	if want := append(houseRoutes("br-lan", "192.168.2.0/24"), gl("wan", "192.168.1.0/24")...); !reflect.DeepEqual(local, want) || partial {
		t.Fatalf("told %v partial=%v, want %v", local, partial, want)
	}
	if program := s.nftGuardProgram(plan); !strings.Contains(program, `oifname "br-lan" ip daddr { 192.168.2.0/24 } accept`) {
		t.Fatalf("the LAN is not accepted:\n%s", program)
	}

	// Two hundred private routes on a tunnel are bounded apart from the LAN's.
	for i := 0; i < 200; i++ {
		b.WriteString(ow4Route("awg2", fmt.Sprintf("10.9.%d.0/24", i), ""))
	}
	route4 = b.String()
	if !s.refreshGuardLocal(false) {
		t.Errorf("new routes did not read as a change")
	}
	local, partial, _ = s.guardLocalState()
	if len(local) != 1+ksLocalOtherMax || !local[len(local)-1].House || local[len(local)-1].Dev != "br-lan" || partial {
		t.Fatalf("told %d routes (the last %v) partial=%v", len(local), local[len(local)-1], partial)
	}
	if row := ow4Row(s, plan); row.Status != "warn" || !strings.Contains(row.Summary, "outside the LAN's side") {
		t.Errorf("Diagnostics: %+v", row)
	}
	if !strings.Contains(logged.String(), "are more than the 64 the guard is told") {
		t.Errorf("the bound was reached without a line in the log:\n%s", logged.String())
	}

	// More of the LAN's own networks than the guard is told: a routing daemon's feed behind a LAN
	// router. The connected segments come first, the guard is told it does not know all of the LAN,
	// answers pass, the log says so once and Diagnostics shows it.
	for i := 0; i < 80; i++ {
		b.WriteString(ow4Route("br-lan", fmt.Sprintf("10.50.%d.0/24", i), "192.168.2.2"))
	}
	b.WriteString(ow4Route("br-seg1", "172.20.1.0/24", ""))
	route4 = b.String()
	logged.Reset()
	s.refreshGuardLocal(false)
	local, partial, provider := s.guardLocalState()
	house := map[string]bool{}
	n := 0
	for _, r := range local {
		if r.House {
			n++
			house[r.Dev+" "+r.Prefix.String()] = true
		}
	}
	if n != ksLocalMax || !partial || !house["br-lan 192.168.2.0/24"] || !house["br-seg1 172.20.1.0/24"] {
		t.Fatalf("%d of the LAN's routes told, partial=%v, LAN told=%v, segment told=%v", n, partial, house["br-lan 192.168.2.0/24"], house["br-seg1 172.20.1.0/24"])
	}
	if !reflect.DeepEqual(provider, []string{"wan"}) {
		t.Errorf("the provider's side: %v", provider)
	}
	program := s.nftGuardProgram(plan)
	if !strings.Contains(program, `oifname != { "awg0", "awg2", "wan" } ct direction reply ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept`) {
		t.Errorf("answers to the networks the guard was not told about do not pass:\n%s", program)
	}
	if row := ow4Row(s, plan); row.Status != "warn" || !strings.Contains(row.Summary, "18 more networks") {
		t.Errorf("Diagnostics: %+v", row)
	}
	s.refreshGuardLocal(false)
	if got := strings.Count(logged.String(), "the LAN's side has 18 more routes than the 64 the guard is told"); got != 1 {
		t.Errorf("the log says it %d times:\n%s", got, logged.String())
	}
	if n := len(s.ksLocal.seen); n > ksLocalSeenMax {
		t.Errorf("%d routes remembered, more than %d", n, ksLocalSeenMax)
	}
}

// When the firewall's zones cannot be read no device is the LAN's: a network a list names is held
// on every device but the list's tunnels, answers pass, and Diagnostics says why. A reading that
// fails later leaves the last good one in place.
func TestZonesThatCannotBeReadFailOpenForAnswersOnly(t *testing.T) {
	route4 := ow4Head + ow4Route("wan", "0.0.0.0/0", "192.168.50.254") + ow4Route("br-lan", "192.168.2.0/24", "") + ow4Route("wan", "192.168.1.0/24", "")
	fail := errors.New("uci: not found")
	read := func() (string, string, error) {
		if fail != nil {
			return "", "", fail
		}
		return houseUCI()
	}
	s := ow4Server(t, read, &route4)
	plan := ow4Plan(t, "192.168.0.0/16")
	local, partial, provider := s.guardLocalState()
	if !reflect.DeepEqual(local, gl("br-lan", "192.168.2.0/24", "wan", "192.168.1.0/24")) || !partial || !reflect.DeepEqual(provider, []string{"wan"}) {
		t.Fatalf("told %v partial=%v provider=%v", local, partial, provider)
	}
	program := s.nftGuardProgram(plan)
	if !strings.Contains(program, `oifname != { "awg0", "awg2", "wan" } ct direction reply ip daddr { 192.168.0.0/16 } accept`) || strings.Contains(program, `oifname "br-lan"`) {
		t.Errorf("zones unread:\n%s", program)
	}
	if row := ow4Row(s, plan); row.Status != "warn" || !strings.Contains(row.Detail, "uci: not found") {
		t.Errorf("Diagnostics: %+v", row)
	}
	fail = nil
	if !s.refreshGuardLocal(false) {
		t.Errorf("zones that became readable did not read as a change")
	}
	good := s.nftGuardProgram(plan)
	if !strings.Contains(good, `oifname "br-lan" ip daddr { 192.168.2.0/24 } accept`) || strings.Contains(good, "ct direction reply") || strings.Contains(good, `oifname "wan"`) {
		t.Errorf("zones read:\n%s", good)
	}
	if row := ow4Row(s, plan); row.Status != "pass" {
		t.Errorf("Diagnostics: %+v", row)
	}
	fail = errors.New("uci: busy")
	if s.refreshGuardLocal(true) || s.nftGuardProgram(plan) != good {
		t.Errorf("a reading that failed changed what the guard is told")
	}
}

// Review says which part of a kill-switched list is held at the provider's side, and that a list
// which sweeps private space leaves the provider's box reachable.
func TestReviewNamesWhatTheProvidersSideHasARouteInto(t *testing.T) {
	sd := parseSides(ow4Network, ow4FirewallWith(true))
	routes := gl("br-lan", "192.168.2.0/24", "wan", "192.168.1.0/24", "br-lab", "192.168.5.0/24", "awg2", "192.168.9.0/24", "wgsrv", "192.168.6.0/24")
	up := map[string]bool{"wan": true}
	fs := providerSideFindings(ow4Plan(t, "192.168.0.0/20"), sd, routes, up)
	// A tunnel WayHop does not run, with a route into the named network, is said apart; the LAN's
	// own bridge (br-lab) is not.
	var house []PlanFinding
	for i := 0; i < len(fs); i++ {
		if fs[i].ID == findingNamedOnHouse {
			house, fs = append(house, fs[i]), append(fs[:i], fs[i+1:]...)
			i--
		}
	}
	if len(house) != 1 || house[0].Item != "192.168.0.0/20 on wgsrv" || house[0].Effective != "192.168.6.0/24 reached by wgsrv" ||
		!strings.Contains(house[0].Detail, "a network of this router's own, not by the list's tunnel") {
		t.Fatalf("a named network the LAN has a route into: %+v", house)
	}
	if len(fs) != 1 || fs[0].ID != findingNamedOnProvider || fs[0].Item != "192.168.0.0/20 on wan" ||
		!strings.Contains(fs[0].Detail, `the list "office" names the private network 192.168.0.0/20`) || !strings.Contains(fs[0].Detail, "(192.168.1.0/24) by wan") {
		t.Fatalf("a named network on the provider's segment: %+v", fs)
	}
	fs = providerSideFindings(ow4Plan(t, "0.0.0.0/0"), sd, routes, up)
	if len(fs) != 1 || fs[0].ID != findingSweptUplinkDNS || fs[0].Item != "192.168.1.0/24 on wan" || !strings.Contains(fs[0].Detail, "DNS resolver") {
		t.Fatalf("a swept range with the uplink's segment in it: %+v", fs)
	}
	if fs := providerSideFindings(ow4Plan(t, "10.77.0.0/16"), sd, routes, up); len(fs) != 0 {
		t.Errorf("a network no route of the provider's side overlaps: %+v", fs)
	}
	if fs := providerSideFindings(ow4Plan(t, "203.0.113.0/24"), sd, routes, up); len(fs) != 0 {
		t.Errorf("a list of public addresses: %+v", fs)
	}
}
