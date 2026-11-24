package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"wayhop/internal/ctflush"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

func overlapLANProfile() model.Profile {
	return model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "awg31", Engine: model.EngineExternal, Enabled: true, Server: "203.0.113.31", Params: map[string]any{"interface": "nwg5"}},
			{ID: "ru", Engine: model.EngineExternal, Enabled: true, Server: "198.51.100.7", Params: map[string]any{"interface": "nwg7"}},
		},
		Groups: []model.Group{
			{ID: "grp-awg31", Type: model.GroupURLTest, Members: []string{"awg31"}},
			{ID: "grp-list-cascade", Type: model.GroupURLTest, Members: []string{"ru"}},
		},
		RoutingLists: []model.RoutingList{
			{ID: "cidr-refilter", Enabled: true, Outbound: "grp-awg31", Manual: []string{"172.64.0.0/13", "104.16.0.0/13"}},
			{ID: "rl-cascade", Enabled: true, Outbound: "grp-list-cascade", Manual: []string{"104.16.0.1/32"}},
			{ID: "rl-vpn-max-vk", Enabled: true, Outbound: model.OutboundDirect, Manual: []string{"api.ipify.org", "checkip.amazonaws.com", "ifconfig.me"}},
		},
	}
}

// The sing-box half: a TUN, the list's names by its egress's mark, everything else back to the
// kernel, rules ahead of every other one, and outbounds that sing-box does not bind to the WAN.
func TestInjectHandoffCore(t *testing.T) {
	prof := overlapLANProfile()
	plan, _, err := pbr.Compile(&prof, pbr.Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	h := plan.Handoff()
	base := []byte(`{"inbounds":[{"type":"tun","tag":"tun-in","interface_name":"wrtun0"}],"outbounds":[{"type":"direct","tag":"direct"}],` +
		`"route":{"rules":[{"inbound":["probe-in"],"outbound":"direct"}],"final":"direct","auto_detect_interface":true}}`)
	out, err := injectHandoffCore(base, h, "1.12.17")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
		Route     struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	tun := cfg.Inbounds[len(cfg.Inbounds)-1]
	if tun["tag"] != handoffInbound || tun["interface_name"] != pbr.HandoffIfaceDefault || tun["auto_route"] != false {
		t.Fatalf("inbound %v", tun)
	}
	vk := markOfZone(t, plan, "list_rl_vpn_max_vk")
	want := map[string]float64{"wr-handoff-rl_vpn_max_vk": float64(vk), handoffBackTag: float64(pbr.HandoffReturnBit)}
	for _, ob := range cfg.Outbounds {
		if m, ok := want[ob["tag"].(string)]; ok {
			if ob["routing_mark"] != m || ob["inet4_bind_address"] != "0.0.0.0" || ob["inet6_bind_address"] != "::" {
				t.Fatalf("outbound %v", ob)
			}
			delete(want, ob["tag"].(string))
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing outbounds %v", want)
	}
	r := cfg.Route.Rules
	if len(r) != 4 || r[0]["action"] != "sniff" || r[2]["outbound"] != handoffBackTag || r[3]["outbound"] != "direct" {
		t.Fatalf("rules %v", r)
	}
	if ds, _ := r[1]["domain_suffix"].([]any); len(ds) != 3 || r[1]["outbound"] != "wr-handoff-rl_vpn_max_vk" {
		t.Fatalf("names rule %v", r[1])
	}
	if _, err := injectHandoffCore(out, h, "1.12.17"); err == nil {
		t.Fatal("injected twice")
	}
}

func markOfZone(t *testing.T, p *pbr.Plan, name string) uint32 {
	t.Helper()
	for _, z := range p.Zones {
		if z.Name == name {
			return z.Mark
		}
	}
	t.Fatalf("no zone %s", name)
	return 0
}

// Review: the static overlap and who wins, the hand-off, the shared CDN warning from the live set and
// the suggestion of a Russian exit for an address-check list; all advice, none blocking.
func TestKeeneticOverlapPreflight(t *testing.T) {
	prof := overlapLANProfile()
	live := func(set string) []netip.Prefix {
		if set == "wr_list_rl_vpn_max_vk_4" {
			return []netip.Prefix{netip.MustParsePrefix("172.64.41.4/32"), netip.MustParsePrefix("104.16.132.229/32"), netip.MustParsePrefix("198.51.100.3/32")}
		}
		return nil
	}
	if keeneticOverlapPreflight(prof, false, live) != nil {
		t.Fatal("findings off the kernel plane")
	}
	got := map[string]platform.Unsupported{}
	for _, u := range keeneticOverlapPreflight(prof, true, live) {
		got[u.Setting] = u
	}
	for _, want := range []string{
		findingOverlap + ":cidr-refilter:rl-cascade", findingHandoff + ":rl-vpn-max-vk",
		findingSharedCDN + ":rl-vpn-max-vk", findingSharedCDN + ":ipcheck:rl-vpn-max-vk",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if u := got[findingSharedCDN+":rl-vpn-max-vk"]; u.Value != "2" {
		t.Errorf("CDN count %q, want 2", u.Value)
	}
	if u := got[findingOverlap+":cidr-refilter:rl-cascade"]; !strings.Contains(u.Reason, `"rl-cascade" wins`) {
		t.Errorf("winner not named: %s", u.Reason)
	}
	for _, f := range evaluatePlanFindings(platform.CapabilitySet{}, keeneticOverlapPreflight(prof, true, live)) {
		if f.Blocks != platform.BlocksNothing {
			t.Errorf("%s blocks", f.Setting)
		}
	}
}

// The sweep judges domain lists by their live members, is rate-limited, and counts for Review.
func TestLeakSweep(t *testing.T) {
	prof := overlapLANProfile()
	prof.RoutingLists = append(prof.RoutingLists, model.RoutingList{ID: "tg", Enabled: true, Outbound: "grp-awg31", Manual: []string{"t.me"}})
	plan, _, err := pbr.Compile(&prof, pbr.Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	read := func(_ context.Context, set string) ([]netip.Prefix, error) {
		if set == "wr_list_tg_4" {
			return []netip.Prefix{netip.MustParsePrefix("149.154.167.99/32")}, nil
		}
		return nil, nil
	}
	lp := livePlan(context.Background(), plan, read)
	for _, z := range lp.Zones {
		if z.Name == "list_tg" && (len(z.Domains) != 0 || !slices.Contains(z.V4, "149.154.167.99/32")) {
			t.Fatalf("live zone %+v", z)
		}
	}
	tbl := &sweepTable{}
	l := &leakSweeper{open: func() (ctflush.Table, error) { return tbl, nil }}
	l.sweep(context.Background(), plan, read, nil, true, "the Apply")
	l.sweep(context.Background(), plan, read, nil, false, "a firewall rebuild") // within the gap: skipped
	if tbl.dumps != 2 {
		t.Fatalf("dumps %d, want one sweep (two families)", tbl.dumps)
	}
	c := l.counts()
	if c.Found != 0 || leakedFlowsFinding(c) != nil {
		t.Fatalf("counts %+v", c)
	}
	l.mu.Lock()
	l.found, l.flushed, l.lastFound = 3, 3, time.Now()
	l.mu.Unlock()
	if f := leakedFlowsFinding(l.counts()); len(f) != 1 || f[0].Value != "3" {
		t.Fatalf("finding %v", f)
	}
}

type sweepTable struct{ dumps int }

func (s *sweepTable) Dump(uint8, func(ctflush.Entry)) error { s.dumps++; return nil }
func (s *sweepTable) Delete(ctflush.Entry) error            { return nil }
func (s *sweepTable) Close() error                          { return nil }

// The postcheck reads the OUTPUT side the hand-off depends on. A refused or wiped OUTPUT
// jump, an empty return chain or a missing loopback route of the return table fails the Apply.
func TestKeeneticPostcheck_HandoffOutputSide(t *testing.T) {
	prof := overlapLANProfile()
	plan, _, err := pbr.Compile(&prof, pbr.Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	io := keeneticPBROptions("eth3")
	io.LANIfaces, io.HandoffIface = []string{"br0"}, pbr.HandoffIfaceDefault
	art, err := buildKeeneticKernelIpsetArtifact(plan, exactKernelOptions(), io, keeneticPBRTestTools())
	if err != nil {
		t.Fatal(err)
	}
	ch := pbr.HandoffOutputChain(io)
	healthy := func() *handoffRouter {
		r := &handoffRouter{keeneticFakeRouter: healthyKeeneticRouter(art),
			route409: "default dev lo scope link \n"}
		r.mangle4 += "-A OUTPUT -m mark --mark 0x10000000/0x10000000 -j " + ch + "\n" +
			"-A " + ch + " -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000\n"
		return r
	}
	ctx := context.Background()
	if err := keeneticPlanePostcheck(ctx, *art, healthy().run); err != nil {
		t.Fatalf("a healthy hand-off failed its postcheck: %v", err)
	}
	for name, damage := range map[string]func(r *handoffRouter){
		"OUTPUT jump refused": func(r *handoffRouter) {
			r.mangle4 = strings.Replace(r.mangle4, "-A OUTPUT -m mark --mark 0x10000000/0x10000000 -j "+ch+"\n", "", 1)
		},
		"OUTPUT jump into the LAN chain": func(r *handoffRouter) {
			r.mangle4 = strings.Replace(r.mangle4, "-j "+ch+"\n", "-j WR_PREROUTING\n", 1)
		},
		"return chain empty": func(r *handoffRouter) {
			r.mangle4 = strings.Replace(r.mangle4, "-A "+ch+" -j CONNMARK", "-A OTHER -j CONNMARK", 1)
		},
		"return table empty": func(r *handoffRouter) { r.route409 = "" },
	} {
		r := healthy()
		damage(r)
		if err := keeneticPlanePostcheck(ctx, *art, r.run); !errors.Is(err, errExactProductionKernelApply) {
			t.Errorf("%s: postcheck = %v, want the plane reported missing", name, err)
		}
	}
}

type handoffRouter struct {
	*keeneticFakeRouter
	route409 string
}

func (r *handoffRouter) run(ctx context.Context, stdin, name string, args ...string) (string, error) {
	if name+" "+strings.Join(args, " ") == fmt.Sprintf("ip route show table %d", pbr.HandoffReturnTable(pbr.Options{})) {
		return r.route409, nil
	}
	return r.keeneticFakeRouter.run(ctx, stdin, name, args...)
}
