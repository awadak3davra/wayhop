package pbr

import (
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// guard_ow2_test.go judges the rendered guard by what it does to a packet, not by its text (review
// OW2): a small reader of the forms guard_nft.go renders walks the chain as the kernel would. A form
// it does not know fails the test, so a new kind of rule cannot go unjudged.

// guardPkt is one forwarded packet.
type guardPkt struct {
	v6           bool
	saddr, daddr string
	mac          string
	iif, oif     string
	mark         uint32
	reply        bool
	proto        string // default tcp
}

type guardSim struct {
	t       *testing.T
	addr    map[string][]netip.Prefix
	protos  map[string]map[string]bool
	chains  map[string][]string
	program string
}

func parseGuard(t *testing.T, program string) *guardSim {
	t.Helper()
	g := &guardSim{t: t, addr: map[string][]netip.Prefix{}, protos: map[string]map[string]bool{}, chains: map[string][]string{}, program: program}
	chain := ""
	for _, raw := range strings.Split(program, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "set "):
			f := strings.Fields(line)
			name := f[1]
			_, elems, has := strings.Cut(line, "elements = {")
			var items []string
			if has {
				elems = elems[:strings.Index(elems, "}")]
				for _, e := range strings.Split(elems, ",") {
					if w := strings.Fields(e); len(w) > 0 {
						items = append(items, w[0])
					}
				}
			}
			if strings.Contains(line, "type inet_proto") {
				g.protos[name] = map[string]bool{}
				for _, it := range items {
					g.protos[name][it] = true
				}
			} else {
				g.addr[name] = guardPrefixes(t, items)
			}
		case strings.HasPrefix(line, "chain "):
			chain = strings.Fields(line)[1]
			g.chains[chain] = nil
		case line == "}":
			chain = ""
		case chain != "" && line != "" && !strings.HasPrefix(line, "type "):
			g.chains[chain] = append(g.chains[chain], line)
		case strings.HasPrefix(line, "add rule inet "+GuardTable+" "):
			f := strings.Fields(line)
			g.chains[f[4]] = append(g.chains[f[4]], strings.Join(f[5:], " "))
		}
	}
	if len(g.chains[GuardChain]) == 0 {
		t.Fatalf("no %s chain in:\n%s", GuardChain, program)
	}
	return g
}

func guardPrefixes(t *testing.T, items []string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		if !strings.Contains(it, "/") {
			a, err := netip.ParseAddr(it)
			if err != nil {
				t.Fatalf("set element %q: %v", it, err)
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(it)
		if err != nil {
			t.Fatalf("set element %q: %v", it, err)
		}
		out = append(out, p)
	}
	return out
}

// learn puts an address into a learned set, as the daemon's `add element` would.
func (g *guardSim) learn(set, addr string) {
	g.addr[set] = append(g.addr[set], guardPrefixes(g.t, []string{addr})...)
}

// operand reads `@set` or `{ a, b }` starting at f[i]; it returns the items (for a named set: nil and
// the name) and the index after it.
func (g *guardSim) operand(f []string, i int) (name string, items []string, next int) {
	if strings.HasPrefix(f[i], "@") {
		return f[i][1:], nil, i + 1
	}
	if f[i] != "{" {
		return "", []string{strings.Trim(f[i], `"`)}, i + 1
	}
	for i++; f[i] != "}"; i++ {
		items = append(items, strings.Trim(strings.TrimSuffix(f[i], ","), `"`))
	}
	return "", items, i + 1
}

func (g *guardSim) inAddr(addr, name string, items []string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		g.t.Fatalf("packet address %q: %v", addr, err)
	}
	ps := g.addr[name]
	if name == "" {
		ps = guardPrefixes(g.t, items)
	} else if _, ok := g.addr[name]; !ok {
		g.t.Fatalf("rule names the set %q, which the program does not declare:\n%s", name, g.program)
	}
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func ifaceIn(dev string, items []string) bool {
	for _, it := range items {
		if it == dev || strings.HasSuffix(it, "*") && strings.HasPrefix(dev, strings.TrimSuffix(it, "*")) {
			return true
		}
	}
	return false
}

// verdict walks the base chain: "accept" or "drop".
func (g *guardSim) verdict(p guardPkt) string {
	g.t.Helper()
	if v := g.run(GuardChain, p, 0); v != "" {
		return v
	}
	return "accept" // the chain's policy
}

func (g *guardSim) run(chain string, p guardPkt, depth int) string {
	g.t.Helper()
	if depth > 4 {
		g.t.Fatalf("jump loop at %s", chain)
	}
	if _, ok := g.chains[chain]; !ok {
		g.t.Fatalf("jump to the chain %q, which the program does not have", chain)
	}
	proto := p.proto
	if proto == "" {
		proto = "tcp"
	}
rules:
	for _, rule := range g.chains[chain] {
		f := strings.Fields(rule)
		for i := 0; i < len(f); {
			neg := func() bool {
				if f[i] == "!=" {
					i++
					return true
				}
				return false
			}
			switch {
			case (f[i] == "ip" || f[i] == "ip6") && (f[i+1] == "daddr" || f[i+1] == "saddr"):
				fam6, field := f[i] == "ip6", f[i+1]
				i += 2
				n := neg()
				name, items, next := g.operand(f, i)
				i = next
				if fam6 != p.v6 {
					continue rules
				}
				addr := p.daddr
				if field == "saddr" {
					addr = p.saddr
				}
				if g.inAddr(addr, name, items) == n {
					continue rules
				}
			case f[i] == "ether" && f[i+1] == "saddr":
				i += 2
				n := neg()
				_, items, next := g.operand(f, i)
				i = next
				if ifaceIn(p.mac, items) == n {
					continue rules
				}
			case f[i] == "iifname" || f[i] == "oifname":
				dev := p.iif
				if f[i] == "oifname" {
					dev = p.oif
				}
				i++
				n := neg()
				_, items, next := g.operand(f, i)
				i = next
				if ifaceIn(dev, items) == n {
					continue rules
				}
			case f[i] == "meta" && f[i+1] == "mark" && f[i+2] == "&" && f[i+4] == "==":
				mask, _ := strconv.ParseUint(f[i+3], 0, 32)
				_, items, next := g.operand(f, i+5)
				i = next
				hit := false
				for _, it := range items {
					v, err := strconv.ParseUint(it, 0, 32)
					if err != nil {
						g.t.Fatalf("mark %q in %q", it, rule)
					}
					hit = hit || uint64(p.mark)&mask == v
				}
				if !hit {
					continue rules
				}
			case f[i] == "meta" && f[i+1] == "nfproto":
				if (f[i+2] == "ipv6") != p.v6 {
					continue rules
				}
				i += 3
			case f[i] == "meta" && f[i+1] == "l4proto":
				set, ok := g.protos[strings.TrimPrefix(f[i+2], "@")]
				if !ok {
					g.t.Fatalf("no protocol set for %q", rule)
				}
				if !set[proto] {
					continue rules
				}
				i += 3
			case f[i] == "ct" && f[i+1] == "direction" && f[i+2] == "reply":
				if !p.reply {
					continue rules
				}
				i += 3
			case f[i] == "counter":
				i++
			case f[i] == "comment":
				i += 2
			case f[i] == "accept" || f[i] == "drop":
				return f[i]
			case f[i] == "jump":
				if v := g.run(f[i+1], p, depth+1); v != "" {
					return v
				}
				continue rules
			default:
				g.t.Fatalf("the test's reader does not know %q in the rule %q", f[i], rule)
			}
		}
	}
	return ""
}

func (g *guardSim) want(what string, p guardPkt, verdict string) {
	g.t.Helper()
	if got := g.verdict(p); got != verdict {
		g.t.Errorf("%s: %+v is %s, want %s", what, p, got, verdict)
	}
}

// Replies to the LAN, shape 1. A source-only kill-switched rule (everything FROM the camera goes by the RU
// group) matched every forwarded packet from the camera, and its verdict looked only at the output
// device: the camera's answer to a WireGuard server's client, to another LAN segment or to the LAN
// itself was dropped. The plane never sends those to a tunnel (ip rules 147-149, main table).
func TestGuardLetsASourceOnlyRuleAnswerTheLANAndServerClients(t *testing.T) {
	p := guardProfile()
	p.Rules = append(p.Rules, model.Rule{ID: "cam", Outbound: "grp-ru", SourceIPCIDR: []string{"192.168.2.77/32"}})
	plan := compileGuard(t, p)
	program := plan.RenderNftGuard()
	if !strings.Contains(program, "ip saddr @rule_cam_s4 jump ks_") {
		t.Fatalf("setup: the camera's rule is not in the guard:\n%s", program)
	}
	g := parseGuard(t, program+GuardProofProgram(program))
	cam := "192.168.2.77"
	g.want("the camera answers a WireGuard server's client", guardPkt{saddr: cam, daddr: "10.8.0.2", iif: "br-lan", oif: "wgsrv", reply: true}, "accept")
	g.want("the camera answers another LAN segment", guardPkt{saddr: cam, daddr: "192.168.40.5", iif: "br-lan", oif: "br-guest", reply: true}, "accept")
	g.want("the camera opens a connection to a server client", guardPkt{saddr: cam, daddr: "172.16.9.9", iif: "br-lan", oif: "wgsrv"}, "accept")
	// The kill switch itself: the camera's traffic to the internet, by its tunnel or not at all.
	g.want("the camera by its tunnel", guardPkt{saddr: cam, daddr: "198.51.100.9", iif: "br-lan", oif: "awg1"}, "accept")
	g.want("the camera by the provider", guardPkt{saddr: cam, daddr: "198.51.100.9", iif: "br-lan", oif: "wan"}, "drop")
	g.want("the camera by another list's tunnel", guardPkt{saddr: cam, daddr: "198.51.100.9", iif: "br-lan", oif: "awg0"}, "drop")
}

// Replies to the LAN, shape 2. A block list that holds private space (any bogon feed does) matched every
// forwarded packet TO a LAN client: every reply from the internet and from the tunnels. The whole
// LAN offline with WayHop healthy, and the program was on flash for the next boot.
func TestGuardBlockListWithPrivateSpaceDoesNotDropReplies(t *testing.T) {
	p := guardProfile()
	p.RoutingLists[2].Manual = []string{"0.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "203.0.113.0/24", "fc00::/7", "2001:db8:bad::/48"}
	plan := compileGuard(t, p)
	program := plan.RenderNftGuard()
	if !strings.Contains(program, "192.168.0.0/16") || !strings.Contains(program, "@list_ads_4 counter drop") {
		t.Fatalf("setup: the block list's private prefixes are not in the guard:\n%s", program)
	}
	g := parseGuard(t, program)
	g.want("a reply from the internet to a LAN client", guardPkt{saddr: "93.184.216.34", daddr: "192.168.2.20", iif: "wan", oif: "br-lan", reply: true}, "accept")
	g.want("a reply from a tunnel to a LAN client", guardPkt{saddr: "198.51.100.9", daddr: "192.168.2.20", iif: "awg1", oif: "br-lan", reply: true}, "accept")
	g.want("LAN to LAN", guardPkt{saddr: "192.168.2.20", daddr: "10.0.5.5", iif: "br-lan", oif: "br-iot"}, "accept")
	g.want("a reply to a server client", guardPkt{saddr: "93.184.216.34", daddr: "172.16.0.2", iif: "wan", oif: "wgsrv", reply: true}, "accept")
	g.want("IPv6 inside the LAN", guardPkt{v6: true, saddr: "fd00::5", daddr: "fd00:1::9", iif: "br-lan", oif: "br-guest"}, "accept")
	// What the list is for still holds.
	g.want("a blocked public address", guardPkt{saddr: "192.168.2.20", daddr: "203.0.113.7", iif: "br-lan", oif: "wan"}, "drop")
	g.want("a blocked public IPv6 address", guardPkt{v6: true, saddr: "2001:db8:1::5", daddr: "2001:db8:bad::1", iif: "br-lan", oif: "wan"}, "drop")
}

// Replies to the LAN, shape 3. A kill-switched list over everything (0.0.0.0/0, ::/0) made every reply to a
// LAN client a "kill-switched destination leaving by br-lan". Private destinations are let through
// first; a reply to a host with a public address is known by the tunnel it came in by.
func TestGuardKillSwitchOverEverythingStillDeliversReplies(t *testing.T) {
	p := guardProfile()
	p.Endpoints = append(p.Endpoints, model.Endpoint{ID: "own", Name: "own", Enabled: true, Engine: model.EngineAmneziaWG,
		Server: "198.51.100.200", Params: map[string]any{"local_address": []string{"10.9.0.2/32", "fd00::2/128"}}})
	p.Groups = append(p.Groups, model.Group{ID: "grp-own", Name: "own", Type: model.GroupFallback, Members: []string{"own"}, KillSwitch: true})
	p.RoutingLists = []model.RoutingList{{ID: "all", Name: "all", Outbound: "grp-own", Enabled: true, Manual: []string{"0.0.0.0/0", "::/0"}}}
	plan := compileGuard(t, p)
	var tun string
	for _, e := range plan.Egresses {
		if e.Tag == "grp-own" {
			tun = e.Iface
		}
	}
	// The list names all of private space too, so the LAN's own segments are known by the router's
	// routes to them, as on the routing plane.
	house := NamesHold{Local: localRoutes("br-lan", "192.168.2.0/24")}
	program := plan.RenderNftGuardWith(house)
	if tun == "" || !strings.Contains(program, "ip daddr @list_all_4 jump ks_0") || !strings.Contains(program, "ip6 daddr @list_all_6 jump ks_0") {
		t.Fatalf("setup: tunnel %q, guard:\n%s", tun, program)
	}
	g := parseGuard(t, program)
	g.want("a reply to a LAN client", guardPkt{saddr: "93.184.216.34", daddr: "192.168.2.20", iif: tun, oif: "br-lan", reply: true}, "accept")
	g.want("a reply to a LAN client that came by the provider", guardPkt{saddr: "93.184.216.34", daddr: "192.168.2.20", iif: "wan", oif: "br-lan", reply: true}, "accept")
	g.want("a reply by the tunnel to a host with a public IPv6 address", guardPkt{v6: true, saddr: "2606:4700::1", daddr: "2001:db8:aa::5", iif: tun, oif: "br-lan", reply: true}, "accept")
	g.want("link-local IPv6", guardPkt{v6: true, saddr: "fe80::1", daddr: "fe80::2", iif: "br-lan", oif: "br-guest"}, "accept")
	g.want("the LAN by the tunnel", guardPkt{saddr: "192.168.2.20", daddr: "93.184.216.34", iif: "br-lan", oif: tun}, "accept")
	g.want("a private address the router has no route for, by the provider", guardPkt{saddr: "192.168.2.20", daddr: "10.20.30.40", iif: "br-lan", oif: "wan"}, "drop")
	g.want("the same by the tunnel", guardPkt{saddr: "192.168.2.20", daddr: "10.20.30.40", iif: "br-lan", oif: tun}, "accept")
	g.want("the LAN by the provider", guardPkt{saddr: "192.168.2.20", daddr: "93.184.216.34", iif: "br-lan", oif: "wan"}, "drop")
	g.want("the LAN's IPv6 by the provider", guardPkt{v6: true, saddr: "2001:db8:aa::5", daddr: "2606:4700::1", iif: "br-lan", oif: "wan"}, "drop")

	// The same over a tunnel that cannot carry IPv6: 2000::/3 is "uncarried" and dropped, the LAN's
	// own IPv6 space is not.
	p = guardProfile()
	p.RoutingLists[1].Manual = []string{"0.0.0.0/0", "2000::/3", "fc00::/7"}
	plan = compileGuard(t, p)
	program = plan.RenderNftGuardWith(house)
	if !strings.Contains(program, "ip6 daddr @wh_uncarried6 counter drop") {
		t.Fatalf("setup: no uncarried IPv6 in:\n%s", program)
	}
	g = parseGuard(t, program)
	g.want("ULA to ULA", guardPkt{v6: true, saddr: "fd00::5", daddr: "fd00:1::9", iif: "br-lan", oif: "br-guest"}, "accept")
	g.want("a reply to a LAN client", guardPkt{saddr: "93.184.216.34", daddr: "192.168.2.20", iif: "awg0", oif: "br-lan", reply: true}, "accept")
	g.want("public IPv6 the tunnel cannot carry", guardPkt{v6: true, saddr: "2001:db8:aa::5", daddr: "2606:4700::1", iif: "br-lan", oif: "wan"}, "drop")
}

// The parity the review asked for: whatever the plane sends by `lookup main` ahead of its fwmark
// rules, the guard accepts, for every guarded zone and every kind of source match, hold or no hold.
func TestGuardAcceptsWhatThePlaneRoutesByTheMainTable(t *testing.T) {
	p := guardProfile()
	p.DeviceGroups = []model.DeviceGroup{{ID: "kids", Name: "Kids", Members: []model.DeviceMember{
		{MAC: "aa:bb:cc:dd:ee:01"}, {IP: "192.168.2.50"},
	}}}
	p.RoutingLists[0].ScopeGroups = []string{"kids"}
	p.RoutingLists[0].ScopeMode = "only"
	p.RoutingLists[0].Manual = append(p.RoutingLists[0].Manual, "0.0.0.0/0", "2001:db8:5::/48")
	p.RoutingLists[1].Manual = append(p.RoutingLists[1].Manual, "0.0.0.0/1", "::/0")
	p.RoutingLists[2].Manual = append(p.RoutingLists[2].Manual, "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "fc00::/7", "fe80::/10")
	p.Rules = append(p.Rules, model.Rule{ID: "cam", Outbound: "grp-ru", SourceIPCIDR: []string{"192.168.2.77/32"}})
	plan := compileGuard(t, p)
	var main4, main6 []string
	for _, line := range plan.RenderIP(Options{}) {
		f := strings.Fields(line)
		// ip [-6] rule add to <cidr> lookup main priority <n>
		if n := len(f); n >= 8 && f[n-4] == "lookup" && f[n-3] == "main" && f[n-6] == "to" {
			pref, _ := strconv.Atoi(f[n-1])
			if pref < 144 || pref > 149 {
				t.Fatalf("a main-table rule outside 144-149: %q", line)
			}
			if f[1] == "-6" {
				main6 = append(main6, f[n-5])
			} else {
				main4 = append(main4, f[n-5])
			}
		}
	}
	if len(main4) != 3 || len(main6) != 2 {
		t.Fatalf("the plane's main-table rules: v4 %v v6 %v", main4, main6)
	}
	zones := plan.guardedZones()
	if len(zones) < 5 {
		t.Fatalf("setup: only %d guarded zones", len(zones))
	}
	for _, hold := range []NamesHold{{}, {Seconds: 600, Pass: []string{"tun0", "awg0"}, V6: true}, {Seconds: -1, Pass: []string{"tun0"}}} {
		// Private space is listed here by kill-switched lists, so the plane keeps on the main table only
		// what the main table has a route of its own for: the router's segments.
		hold.Local = localRoutes("br-lan", "10.0.0.0/24", "br-lan", "172.16.0.0/24", "br-lan", "192.168.0.0/25", "br-guest", "fc00::/64")
		g := parseGuard(t, plan.RenderNftGuardWith(hold))
		for _, src := range []guardPkt{
			{saddr: "192.168.2.20"}, {saddr: "192.168.2.77"}, {saddr: "192.168.2.50"},
			{saddr: "192.168.2.60", mac: "aa:bb:cc:dd:ee:01"}, {saddr: "93.184.216.34", iif: "wan", reply: true},
		} {
			for _, cidr := range main4 {
				pk := src
				pk.daddr, pk.oif = netip.MustParsePrefix(cidr).Addr().Next().String(), "br-lan"
				if pk.iif == "" {
					pk.iif = "br-lan"
				}
				g.want("hold "+strconv.Itoa(hold.Seconds)+": to "+cidr, pk, "accept")
			}
		}
		for _, cidr := range main6 {
			g.want("hold "+strconv.Itoa(hold.Seconds)+": to "+cidr,
				guardPkt{v6: true, saddr: "2001:db8:aa::5", daddr: netip.MustParsePrefix(cidr).Addr().Next().String(), iif: "br-lan", oif: "br-guest", mac: "aa:bb:cc:dd:ee:01"}, "accept")
		}
	}
}

// The hold accepted only the direct mark, so a list the operator did NOT kill-switch,
// whose tunnels were all down and whose table was emptied on purpose ("all down: by the provider"),
// was dropped for as long as the core ran. Marks of exits no kill switch covers pass; a kill-switched
// or block mark does not.
func TestGuardHoldPassesListsThatMayFallBackToTheProvider(t *testing.T) {
	p := guardProfile()
	p.RoutingLists = append(p.RoutingLists, model.RoutingList{ID: "open", Name: "Open", Outbound: "fi", Candidates: []string{"fi", "nl"}, Enabled: true,
		Manual: []string{"198.18.0.0/15"}, Fastest: &model.FastestPolicy{Enabled: true, OnAllDown: model.OnAllDownWAN}})
	plan := compileGuard(t, p)
	mark := map[string]uint32{}
	for _, e := range plan.Egresses {
		mark[e.Tag] = e.Mark
	}
	open, plain, ks := mark[model.ListEgressTag("open")], mark["nl"], mark["grp-ru"]
	if open == 0 || plain == 0 || ks == 0 || nftEgress(t, plan, model.ListEgressTag("open")).FailClosed {
		t.Fatalf("setup: marks %v", mark)
	}
	g := parseGuard(t, plan.RenderNftGuardWith(NamesHold{Seconds: 600, Pass: []string{"tun0", "awg0", "awg1", "awg2"}}))
	lan := guardPkt{saddr: "192.168.2.20", iif: "br-lan", oif: "wan"}
	at := func(daddr string, m uint32) guardPkt { pk := lan; pk.daddr, pk.mark = daddr, m; return pk }
	g.want("a fail-open fastest list fallen back to the provider", at("198.18.0.9", open), "accept")
	g.want("a plain tunnel list whose device is gone", at("192.0.2.9", plain), "accept")
	g.want("the direct exit", at("198.51.100.77", plan.markByKind(EgressWAN)), "accept")
	g.want("unmarked traffic while the core is down", at("198.51.100.77", 0), "drop")
	g.want("a kill-switched mark on an address in no list", at("198.51.100.77", ks), "drop")
	g.want("a block mark", at("198.51.100.77", mark[model.OutboundBlock]), "drop")
	g.want("the kill-switched list by the provider, whatever the mark", at("5.45.192.0", open), "drop")
}

// In hybrid mode the core's TUN was IPv4-only, so with the hold renewed (that is, for
// as long as the core ran) every IPv6 packet between the LAN and the provider was dropped, and
// silently. The hold now covers IPv6 only when the core's TUN carries it, which is when the core up
// leaves it nothing to drop; kill-switched IPv6 destinations are held by their own rules either way.
func TestGuardHoldDoesNotDropTheHousesIPv6BesideAnIPv4OnlyCore(t *testing.T) {
	p := guardProfile()
	p.RoutingLists[1].Manual = append(p.RoutingLists[1].Manual, "2001:67c:4e8::/48")
	p.RoutingLists[0].Manual = append(p.RoutingLists[0].Manual, "example.org")
	plan := compileGuard(t, p)
	if len(plan.GuardNameSets) != 1 || plan.GuardNameSets[0].Set != "kn_big_heavy" {
		t.Fatalf("setup: name sets %+v", plan.GuardNameSets)
	}
	pass := []string{"tun0", "awg0", "awg1", "awg2"}
	out6 := guardPkt{v6: true, saddr: "2001:db8:aa::5", daddr: "2606:4700::1", iif: "br-lan", oif: "wan"}
	in6 := guardPkt{v6: true, saddr: "2606:4700::1", daddr: "2001:db8:aa::5", iif: "wan", oif: "br-lan"}
	g := parseGuard(t, plan.RenderNftGuardWith(NamesHold{Seconds: 600, Pass: pass}))
	g.want("IPv4-only core: the LAN's IPv6 to the provider", out6, "accept")
	g.want("IPv4-only core: a connection from outside to a LAN host", in6, "accept")
	g.want("IPv4-only core: IPv4 beside the core is still held", guardPkt{saddr: "192.168.2.20", daddr: "93.184.216.34", iif: "br-lan", oif: "wan"}, "drop")
	// Scoped to the kill-switched destinations: the prefix its tunnel cannot carry, and an address a
	// kill-switched name was reached at.
	g.learn("kn_big_heavy_6", "2a02:6b8::2:242")
	g.want("uncarried kill-switched IPv6", guardPkt{v6: true, saddr: "2001:db8:aa::5", daddr: "2001:67c:4e8::1", iif: "br-lan", oif: "wan"}, "drop")
	g.want("a kill-switched name's IPv6 address by the provider", guardPkt{v6: true, saddr: "2001:db8:aa::5", daddr: "2a02:6b8::2:242", iif: "br-lan", oif: "wan"}, "drop")
	g.want("a kill-switched name's IPv6 address by the core", guardPkt{v6: true, saddr: "2001:db8:aa::5", daddr: "2a02:6b8::2:242", iif: "br-lan", oif: "tun0"}, "accept")

	// A core whose TUN carries IPv6: the hold covers both families, and with the core up nothing
	// reaches it (IPv6 leaves by the TUN like IPv4).
	g = parseGuard(t, plan.RenderNftGuardWith(NamesHold{Seconds: 600, Pass: pass, V6: true}))
	g.want("dual-stack core, core down: IPv6 beside the core", out6, "drop")
	g.want("dual-stack core: IPv6 by the TUN", guardPkt{v6: true, saddr: "2001:db8:aa::5", daddr: "2606:4700::1", iif: "br-lan", oif: "tun0"}, "accept")
	in6.reply = true
	g.want("dual-stack core: replies", in6, "accept")
}

// A kill-switched list's names are held by address: one pair of sets with timeouts per
// list or rule, which the daemon fills. An address in them may leave by the core's TUN or a tunnel
// and never by the provider, with no broad hold armed at all (the hold has lapsed; fast mode).
func TestGuardHoldsLearnedAddressesOfKillSwitchedNames(t *testing.T) {
	p := guardProfile()
	p.RoutingLists[0].Manual = append(p.RoutingLists[0].Manual, "example.org", "*.example.net")
	p.RoutingLists[3].Manual = append(p.RoutingLists[3].Manual, "plain.example") // no kill switch: no set
	p.Rules = append(p.Rules, model.Rule{ID: "r-1", Outbound: "grp-ru", DomainSuffix: []string{"example.com"}})
	plan := compileGuard(t, p)
	want := []GuardNameSet{
		{Set: "kn_big_heavy", Kind: ZoneFromList, ID: "big-heavy", Outbounds: []string{"grp-ru"}},
		{Set: "kn_rule_r_1", Kind: ZoneFromRule, ID: "r-1", Outbounds: []string{"grp-ru"}},
	}
	if !reflect.DeepEqual(plan.GuardNameSets, want) || !plan.GuardNames {
		t.Fatalf("name sets = %+v (GuardNames %v), want %+v", plan.GuardNameSets, plan.GuardNames, want)
	}
	// Fast mode: no hold, no TUN; the tunnels are the only way out.
	program := plan.RenderNftGuardWith(NamesHold{})
	for _, line := range []string{
		"\tset kn_big_heavy_4 { type ipv4_addr; flags timeout; size 8192; }\n",
		"\tset kn_big_heavy_6 { type ipv6_addr; flags timeout; size 8192; }\n",
		"\tset kn_rule_r_1_4 { type ipv4_addr; flags timeout; size 8192; }\n",
		"\t\tip daddr @kn_big_heavy_4 jump ks_names\n",
		"\t\tip6 daddr @kn_rule_r_1_6 jump ks_names\n",
	} {
		if !strings.Contains(program, line) {
			t.Fatalf("guard lacks %q:\n%s", line, program)
		}
	}
	if strings.Contains(program, "wh_hold") {
		t.Fatalf("a guard without a hold carries one:\n%s", program)
	}
	g := parseGuard(t, program)
	lan := guardPkt{saddr: "192.168.2.20", daddr: "93.184.216.34", iif: "br-lan", oif: "wan"}
	g.want("an address nobody learned", lan, "accept")
	g.learn("kn_big_heavy_4", "93.184.216.34")
	g.want("a learned address by the provider", lan, "drop")
	lan.oif = "awg1"
	g.want("a learned address by a tunnel", lan, "accept")
	g.want("a learned address answering through a tunnel", guardPkt{saddr: "93.184.216.34", daddr: "198.51.100.5", iif: "awg1", oif: "br-pub", reply: true}, "accept")
	// Hybrid: the TUN is a way out too, and the learned address is held with the hold lapsed (an
	// empty wh_hold matches nothing).
	g = parseGuard(t, plan.RenderNftGuardWith(NamesHold{Seconds: 600, Pass: []string{"wh-tun", "awg0", "awg1", "awg2"}}))
	g.protos[GuardHoldSet] = map[string]bool{}
	g.learn("kn_rule_r_1_4", "93.184.216.34")
	udp := guardPkt{saddr: "192.168.2.20", daddr: "93.184.216.34", iif: "br-lan", oif: "wh-tun", proto: "udp"}
	g.want("a learned address by the core's TUN", udp, "accept")
	udp.oif = "wan"
	g.want("a learned address by the provider after the hold lapsed", udp, "drop")
	udp.daddr = "198.51.100.77"
	g.want("anything else after the hold lapsed", udp, "accept")

	learn := RenderGuardLearn("kn_big_heavy", map[string]int{"93.184.216.34": 86400, "2a02:6b8::2:242": 3600, "192.0.2.1": 0})
	wantLearn := "add element inet wayhop_ks kn_big_heavy_6 { 2a02:6b8::2:242 timeout 3600s }\n" +
		"delete element inet wayhop_ks kn_big_heavy_6 { 2a02:6b8::2:242 }\n" +
		"add element inet wayhop_ks kn_big_heavy_6 { 2a02:6b8::2:242 timeout 3600s }\n" +
		"add element inet wayhop_ks kn_big_heavy_4 { 93.184.216.34 timeout 86400s }\n" +
		"delete element inet wayhop_ks kn_big_heavy_4 { 93.184.216.34 }\n" +
		"add element inet wayhop_ks kn_big_heavy_4 { 93.184.216.34 timeout 86400s }\n"
	if learn != wantLearn {
		t.Fatalf("learn program:\n%s\nwant:\n%s", learn, wantLearn)
	}
	// A profile without kill-switched names renders no name set, and a plan stored before the field
	// existed renders as it did.
	if g := compileGuard(t, guardProfile()).RenderNftGuard(); strings.Contains(g, "kn_") || strings.Contains(g, "ks_names") {
		t.Fatalf("name sets without kill-switched names:\n%s", g)
	}
}

// The marker was a set beside the chain: `nft flush chain` (or `flush table`) removed
// every rule and left it, and an empty guard read as loaded. It is the chain's last rule now.
func TestGuardMarkerIsInTheChain(t *testing.T) {
	plan := compileGuard(t, guardProfile())
	program := plan.RenderNftGuard()
	proof := GuardProofProgram(program)
	if want := "add rule inet wayhop_ks ks_forward accept comment \"" + GuardProofSet(program) + "\"\n"; proof != want {
		t.Fatalf("marker program %q, want %q", proof, want)
	}
	listing := "table inet wayhop_ks {\n" + "\tchain ks_forward {\n" + nftChainWithHeader(program) + "\n\t\taccept comment \"" + GuardProofSet(program) + "\"\n\t}\n}\n"
	if !GuardProofPresent(listing, program) {
		t.Fatalf("a loaded guard reads as absent:\n%s", listing)
	}
	flushed := "table inet wayhop_ks {\n\tchain ks_forward {\n\t\ttype filter hook forward priority filter - 5; policy accept;\n\t}\n}\n"
	if GuardProofPresent(flushed, program) {
		t.Fatal("a flushed chain reads as the loaded guard")
	}
	onlyMarker := strings.Replace(flushed, "accept;\n", "accept;\n\t\taccept comment \""+GuardProofSet(program)+"\"\n", 1)
	if GuardProofPresent(onlyMarker, program) {
		t.Fatal("a chain holding nothing but the marker reads as the loaded guard")
	}
	if GuardProofPresent(listing, program+"# another plan\n") {
		t.Fatal("another program's marker was accepted")
	}
}

func nftChainWithHeader(program string) string {
	head := "\tchain " + GuardChain + " {\n"
	body := program[strings.Index(program, head)+len(head):]
	return body[:strings.Index(body, "\n\t}\n")]
}

// What the hold has left is read from the set's listing as nft prints it.
func TestGuardHoldRemainingReadsTheSetListing(t *testing.T) {
	const head = "table inet wayhop_ks {\n\tset wh_hold {\n\t\ttype inet_proto\n\t\tflags timeout\n"
	for name, tc := range map[string]struct {
		listing string
		seconds int
		ok      bool
	}{
		"counting down": {head + "\t\telements = { tcp timeout 10m expires 9m58s912ms, udp timeout 10m expires 4m2s,\n\t\t\t     icmp timeout 10m expires 31s }\n\t}\n}\n", 599, true},
		"lapsed":        {head + "\t}\n}\n", 0, true},
		"strict":        {head + "\t\telements = { tcp, udp }\n\t}\n}\n", 0, false},
		"long":          {head + "\t\telements = { tcp timeout 2d expires 1d2h3m4s }\n\t}\n}\n", 93784, true},
		"not the set":   {"Error: No such file or directory\n", 0, false},
		"odd duration":  {head + "\t\telements = { tcp timeout 10m expires soon }\n\t}\n}\n", 0, false},
	} {
		if got, ok := GuardHoldRemaining(tc.listing); got != tc.seconds || ok != tc.ok {
			t.Errorf("%s: %d, %v; want %d, %v", name, got, ok, tc.seconds, tc.ok)
		}
	}
	if n := compileGuard(t, guardProfile()).GuardedElements(); n != 4 {
		t.Fatalf("guarded elements = %d, want the 4 prefixes of the kill-switched and block lists", n)
	}
}
