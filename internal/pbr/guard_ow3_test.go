package pbr

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// officeProfile is the reviewer's shape: a kill-switched list that names a private
// network behind its tunnel.
func officeProfile() *model.Profile {
	p := guardProfile()
	p.Groups = append(p.Groups, model.Group{ID: "grp-office", Name: "Office", Type: model.GroupFallback, Members: []string{"nl"}, KillSwitch: true})
	p.RoutingLists = append(p.RoutingLists, model.RoutingList{ID: "office", Name: "Office", Outbound: "grp-office", Enabled: true,
		Manual: []string{"10.77.0.0/16", "fd77::/48"}})
	return p
}

func localRoutes(pairs ...string) []GuardLocal {
	var out []GuardLocal
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, GuardLocal{Dev: pairs[i], Prefix: netip.MustParsePrefix(pairs[i+1]), House: true})
	}
	return out
}

// The accept for private destinations came before every zone, so a kill-switched list
// that names an office network behind its tunnel was not guarded at all: with the plane gone (the
// boot, a rollback, a deleted rule) 10.77.0.0/16 left by the main table's default route.
func TestGuardHoldsAPrivateNetworkAKillSwitchedListNames(t *testing.T) {
	plan := compileGuard(t, officeProfile())
	if got := plan.UnpinnedPrivate(); len(got) != 2 {
		t.Fatalf("setup: the plane unpins %v", got)
	}
	program := plan.RenderNftGuard()
	g := parseGuard(t, program)
	g.want("the office by the provider", guardPkt{saddr: "192.168.2.20", daddr: "10.77.1.1", iif: "br-lan", oif: "wan"}, "drop")
	g.want("the office resolver by the provider", guardPkt{saddr: "192.168.2.20", daddr: "10.77.0.53", iif: "br-lan", oif: "wan", proto: "udp"}, "drop")
	g.want("the office by its tunnel", guardPkt{saddr: "192.168.2.20", daddr: "10.77.1.1", iif: "br-lan", oif: "awg0"}, "accept")
	g.want("the office over IPv6 by the provider", guardPkt{v6: true, saddr: "fd00::5", daddr: "fd77::1", iif: "br-lan", oif: "wan"}, "drop")
	g.want("the office over IPv6 by its tunnel", guardPkt{v6: true, saddr: "fd00::5", daddr: "fd77::1", iif: "br-lan", oif: "awg0"}, "accept")
	// Nothing else of private space is judged.
	g.want("the office answers a LAN client", guardPkt{saddr: "10.77.1.1", daddr: "192.168.2.20", iif: "awg0", oif: "br-lan", reply: true}, "accept")
	g.want("the internet answers a LAN client", guardPkt{saddr: "93.184.216.34", daddr: "192.168.2.20", iif: "wan", oif: "br-lan", reply: true}, "accept")
	g.want("LAN to another segment", guardPkt{saddr: "192.168.2.20", daddr: "10.0.5.5", iif: "br-lan", oif: "br-iot"}, "accept")
	g.want("a server's client", guardPkt{saddr: "192.168.2.20", daddr: "10.8.0.2", iif: "br-lan", oif: "wgsrv"}, "accept")
	g.want("ULA inside the LAN", guardPkt{v6: true, saddr: "fd00::5", daddr: "fd00:1::9", iif: "br-lan", oif: "br-guest"}, "accept")
	// The program does not depend on the router's routes when none of them lies inside the office.
	with := plan.RenderNftGuardWith(NamesHold{Local: localRoutes("br-lan", "192.168.2.0/24", "wgsrv", "10.8.0.0/24")})
	if with != program {
		t.Errorf("routes outside the listed network changed the program:\n%s", with)
	}
}

// The router's own routes inside a listed private network stay on the main table on the routing
// plane (`suppress_prefixlength 0`); the guard accepts them by their own device, and by no other.
func TestGuardKeepsTheRoutersOwnRoutesInsideAListedPrivateNetwork(t *testing.T) {
	plan := compileGuard(t, officeProfile())
	local := localRoutes("br-lab", "10.77.5.0/24", "br-lan", "192.168.2.0/24", "wgsrv", "10.77.200.0/24", "br-lab", "fd77:0:0:5::/64",
		"bad dev", "10.77.6.0/24", `x"; drop`, "10.77.7.0/24")
	program := plan.RenderNftGuardWith(NamesHold{Local: local})
	for _, want := range []string{`oifname "br-lab" ip daddr { 10.77.5.0/24 } accept`, `oifname "wgsrv" ip daddr { 10.77.200.0/24 } accept`,
		`oifname "br-lab" ip6 daddr { fd77:0:0:5::/64 } accept`} {
		if !strings.Contains(program, want) {
			t.Errorf("no %q in:\n%s", want, program)
		}
	}
	for _, not := range []string{"192.168.2.0/24", "bad dev", "drop\"", "10.77.6.0/24", "10.77.7.0/24"} {
		if strings.Contains(program, not) {
			t.Errorf("%q is in the program:\n%s", not, program)
		}
	}
	g := parseGuard(t, program)
	g.want("a reply to the lab segment", guardPkt{saddr: "93.184.216.34", daddr: "10.77.5.9", iif: "wan", oif: "br-lab", reply: true}, "accept")
	g.want("LAN to the lab segment", guardPkt{saddr: "192.168.2.20", daddr: "10.77.5.9", iif: "br-lan", oif: "br-lab"}, "accept")
	g.want("a reply to a server's client", guardPkt{saddr: "93.184.216.34", daddr: "10.77.200.2", iif: "wan", oif: "wgsrv", reply: true}, "accept")
	g.want("the lab segment over IPv6", guardPkt{v6: true, saddr: "fd00::5", daddr: "fd77:0:0:5::9", iif: "br-lan", oif: "br-lab"}, "accept")
	// A stale route: the lab bridge is gone and the address is routed by the default route.
	g.want("the lab's address by the provider", guardPkt{saddr: "192.168.2.20", daddr: "10.77.5.9", iif: "br-lan", oif: "wan"}, "drop")
	g.want("the rest of the office by the provider", guardPkt{saddr: "192.168.2.20", daddr: "10.77.9.9", iif: "br-lan", oif: "wan"}, "drop")
}

// A kill-switched rule that matches by source alone is sent, by the plane's unpin rules, to its own
// table for every private network any list names. The guard judges those networks for it too.
func TestGuardHoldsASourceOnlyRuleToAPrivateNetworkAnotherListNames(t *testing.T) {
	p := guardProfile()
	p.RoutingLists = append(p.RoutingLists, model.RoutingList{ID: "lab", Name: "Lab", Outbound: "nl", Enabled: true, Manual: []string{"10.50.0.0/16"}})
	p.Rules = append(p.Rules, model.Rule{ID: "cam", Outbound: "grp-ru", SourceIPCIDR: []string{"192.168.2.77/32"}})
	plan := compileGuard(t, p)
	g := parseGuard(t, plan.RenderNftGuard())
	cam := "192.168.2.77"
	g.want("the camera to the lab by the provider", guardPkt{saddr: cam, daddr: "10.50.1.1", iif: "br-lan", oif: "wan"}, "drop")
	g.want("the camera to the lab by its tunnel", guardPkt{saddr: cam, daddr: "10.50.1.1", iif: "br-lan", oif: "awg1"}, "accept")
	// The lab list has no kill switch: anyone else's packet to it is not the guard's to judge.
	g.want("another device to the lab", guardPkt{saddr: "192.168.2.20", daddr: "10.50.1.1", iif: "br-lan", oif: "wan"}, "accept")
	g.want("the camera answers a server's client", guardPkt{saddr: cam, daddr: "10.8.0.2", iif: "br-lan", oif: "wgsrv", reply: true}, "accept")
}

// The reverse of TestGuardAcceptsWhatThePlaneRoutesByTheMainTable: a packet RenderIP
// sends to a fail-closed table is not accepted when it leaves by a device outside that zone's tunnels.
func TestGuardDropsWhatThePlaneSendsToAFailClosedTableByAnotherDevice(t *testing.T) {
	everything := guardProfile()
	everything.RoutingLists[0].Manual = append(everything.RoutingLists[0].Manual, "0.0.0.0/0", "fc00::/7")
	for name, p := range map[string]*model.Profile{"office": officeProfile(), "everything": everything} {
		plan := compileGuard(t, p)
		closed := map[string][]string{} // table -> the devices its zone may leave by
		byTag := map[string]Egress{}
		for _, e := range plan.Egresses {
			byTag[e.Tag] = e
			if e.Kind == EgressInterface && e.FailClosed {
				closed[strconv.Itoa(e.Table)] = e.Devices()
			}
		}
		g := parseGuard(t, plan.RenderNftGuardWith(NamesHold{Seconds: 600, Pass: []string{"whtun0", "awg0", "awg1", "awg2"}, V6: true,
			Local: localRoutes("br-lan", "192.168.2.0/24")}))
		checked := 0
		for _, line := range plan.RenderIP(Options{}) {
			f := strings.Fields(line)
			// ip [-6] rule add to <cidr> fwmark <m>/<mask> table <n> priority <p>
			n := len(f)
			if n < 10 || f[n-8] != "to" || f[n-6] != "fwmark" || f[n-4] != "table" {
				continue
			}
			allow, ok := closed[f[n-3]]
			if !ok {
				continue
			}
			prefix := netip.MustParsePrefix(f[n-7])
			// The zone that owns this table and names the prefix: its packet is the one the rule routes.
			for _, z := range plan.Zones {
				if e := byTag[z.EgressTag]; strconv.Itoa(e.Table) != f[n-3] {
					continue
				}
				for _, c := range append(append([]string(nil), z.V4...), z.V6...) {
					zp, ok := parseZonePrefix(c)
					if !ok || !zp.Overlaps(prefix) {
						continue
					}
					at := prefix
					if zp.Bits() > prefix.Bits() {
						at = zp
					}
					pk := guardPkt{v6: at.Addr().Is6(), saddr: "192.168.2.20", daddr: at.Addr().Next().String(), iif: "br-lan"}
					if pk.v6 {
						pk.saddr = "fd00::5"
					}
					for _, dev := range []string{"wan", "pppoe-wan", "br-lan", "br-guest"} {
						pk.oif = dev
						g.want(name+": "+line+" by "+dev, pk, "drop")
					}
					for _, dev := range allow {
						pk.oif = dev
						g.want(name+": "+line+" by "+dev, pk, "accept")
					}
					checked++
				}
			}
		}
		if checked == 0 {
			t.Errorf("%s: no unpin rule to a fail-closed table was checked", name)
		}
	}
}
