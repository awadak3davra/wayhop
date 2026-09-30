package keenetic

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestCompile_NativeFirst: an AmneziaWG endpoint becomes a native interface and a non-native
// VLESS endpoint becomes a sing-box TUN — BOTH are routable interfaces, so IP-CIDR lists
// become `ip route` to whichever, and each endpoint's server IP gets an anti-loop ISP route.
func TestCompile_NativeFirst(t *testing.T) {
	awg := awgEndpoint() // AmneziaWG, server 203.0.113.10
	awg.ID, awg.Enabled = "awg-example", true
	vless := model.Endpoint{ID: "vless-nl", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "1.2.3.4", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u"}}
	p := &model.Profile{
		Endpoints: []model.Endpoint{awg, vless},
		RoutingLists: []model.RoutingList{
			{ID: "example-list", Manual: []string{"109.254.0.0/16", "85.21.0.0/16"}, Outbound: "awg-example", Enabled: true},
			{ID: "mixed", Manual: []string{"10.10.0.0/24"}, Outbound: "awg-example", Enabled: true},
			{ID: "proxy", Manual: []string{"172.16.0.0/24"}, Outbound: "vless-nl", Enabled: true}, // → fallback TUN
			{ID: "blk", Manual: []string{"192.0.2.0/24"}, Outbound: model.OutboundBlock, Enabled: true},
			{ID: "direct", Manual: []string{"203.0.113.0/24"}, Outbound: model.OutboundDirect, Enabled: true},
			{ID: "disabled", Manual: []string{"198.51.100.0/24"}, Outbound: "awg-example", Enabled: false},
		},
	}
	plan, err := Compile(p, CompileOptions{BaseIndex: 10})
	if err != nil {
		t.Fatal(err)
	}

	if plan.IfaceFor["awg-example"] != "Wireguard10" {
		t.Errorf("awg-example iface = %q, want Wireguard10", plan.IfaceFor["awg-example"])
	}
	if len(plan.Interfaces) != 1 {
		t.Errorf("want 1 native interface block, got %d", len(plan.Interfaces))
	}
	// Non-native VLESS is now a fallback TUN, not a warning.
	if plan.IfaceFor["vless-nl"] != "wrtun0" {
		t.Errorf("vless-nl iface = %q, want wrtun0", plan.IfaceFor["vless-nl"])
	}
	if plan.Singbox == nil {
		t.Error("Singbox config must be set when there is a non-native endpoint")
	}
	cmds := strings.Join(plan.Commands(), "\n")
	for _, w := range []string{
		"interface Wireguard10",
		"ip route 109.254.0.0 255.255.0.0 Wireguard10", // list → native iface
		"ip route 85.21.0.0 255.255.0.0 Wireguard10",   //
		"ip route 10.10.0.0 255.255.255.0 Wireguard10",
		"ip route 172.16.0.0 255.255.255.0 wrtun0",  // list → fallback TUN (the integration)
		"ip route 192.0.2.0 255.255.255.0 reject",   // block → reject
		"ip route 203.0.113.0 255.255.255.0 ISP",    // direct → ISP
		"ip route 203.0.113.10 255.255.255.255 ISP", // anti-loop bypass (native server)
		"ip route 1.2.3.4 255.255.255.255 ISP",      // anti-loop bypass (proxy server)
	} {
		if !strings.Contains(cmds, w) {
			t.Errorf("missing command %q\n--- got ---\n%s", w, cmds)
		}
	}
	if strings.Contains(cmds, "198.51.100.0") {
		t.Error("disabled list must be skipped")
	}
}

func TestCompileSkipsCapturedOccupiedWireguardSlots(t *testing.T) {
	endpoint := awgEndpoint()
	endpoint.ID, endpoint.Enabled = "owned", true
	profile := &model.Profile{Endpoints: []model.Endpoint{endpoint}}
	plan, err := Compile(profile, CompileOptions{
		BaseIndex:          10,
		OccupiedInterfaces: map[string]bool{"Wireguard10": true, "Wireguard11": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.IfaceFor[profile.Endpoints[0].ID]; got != "Wireguard12" {
		t.Fatalf("allocated interface = %q", got)
	}
}

func TestCompile_UnknownOutboundFailsClosed(t *testing.T) {
	p := &model.Profile{
		RoutingLists: []model.RoutingList{
			{ID: "orphan", Manual: []string{"1.2.3.0/24"}, Outbound: "no-such-endpoint", Enabled: true},
		},
	}
	if _, err := Compile(p, CompileOptions{}); err == nil || !strings.Contains(err.Error(), "no-such-endpoint") {
		t.Fatalf("orphan outbound did not refuse the whole plan: %v", err)
	}
}

func TestCompile_GroupOutboundUsesCompatibilityRouting(t *testing.T) {
	p := &model.Profile{
		Groups: []model.Group{{ID: "auto", Name: "Auto", Type: model.GroupFallback, Members: []string{model.OutboundDirect}}},
		RoutingLists: []model.RoutingList{
			{ID: "l", Manual: []string{"example.com"}, Outbound: "auto", Enabled: true},
		},
	}
	plan, err := Compile(p, CompileOptions{})
	if err != nil || !plan.CompatibilityRouting || plan.Singbox == nil || len(plan.Routes) != 0 {
		t.Fatalf("group routing did not select the compatibility TUN: plan=%#v err=%v", plan, err)
	}
}

func TestCompile_StandaloneFailoverGroupUsesCompatibilityRouting(t *testing.T) {
	p := &model.Profile{Groups: []model.Group{{
		ID: "fallback", Type: model.GroupFallback, Members: []string{model.OutboundDirect},
	}}}
	plan, err := Compile(p, CompileOptions{})
	if err != nil || !plan.CompatibilityRouting || plan.Singbox == nil {
		t.Fatalf("standalone failover semantics were not preserved by the compatibility TUN: %#v / %v", plan, err)
	}
}

func TestCompile_DeviceScopeUsesCompatibilityRouting(t *testing.T) {
	p := &model.Profile{
		DeviceGroups: []model.DeviceGroup{{ID: "Kids", Name: "Kids"}},
		RoutingLists: []model.RoutingList{
			{ID: "kids", Manual: []string{"1.2.3.0/24"}, Outbound: model.OutboundDirect, Enabled: true,
				ScopeMode: "only", ScopeGroups: []string{"Kids"}},
		},
	}
	plan, err := Compile(p, CompileOptions{})
	if err != nil || !plan.CompatibilityRouting || len(plan.Routes) != 0 {
		t.Fatalf("device scope was widened or omitted instead of moved to the compatibility TUN: %#v / %v", plan, err)
	}
}

func TestCompile_CompatibilityRoutingKeepsNativeConnectionsAndOneSharedTUN(t *testing.T) {
	awg := awgEndpoint()
	awg.ID, awg.Enabled, awg.Owner = "native-nl", true, model.OwnerExternal
	awg.Engine = model.EngineExternal
	awg.Params["interface"] = "nwg1"
	proxy := model.Endpoint{
		ID: "proxy", Name: "Proxy", Enabled: true,
		Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "198.51.100.20", Port: 443,
		Params: map[string]any{"uuid": "11111111-1111-1111-1111-111111111111"},
	}
	profile := &model.Profile{
		Endpoints: []model.Endpoint{awg, proxy},
		Groups: []model.Group{{
			ID: "fallback", Name: "Fallback", Type: model.GroupFallback,
			Members: []string{awg.ID, proxy.ID, model.OutboundDirect},
		}},
		RoutingLists: []model.RoutingList{{
			ID: "domains", Name: "Domains", Manual: []string{"example.com"},
			Outbound: "fallback", Enabled: true,
		}},
	}
	plan, err := Compile(profile, CompileOptions{AdoptInterfaces: map[string]string{awg.ID: "nwg1"}, AdoptNDMNames: map[string]string{awg.ID: "Wireguard1"}})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.CompatibilityRouting || len(plan.Routes) != 0 || len(plan.Interfaces) != 0 ||
		plan.IfaceFor[awg.ID] != "Wireguard1" || plan.IfaceFor[proxy.ID] != "wrtun0" {
		t.Fatalf("compatibility routing plan = %#v", plan)
	}
	if marker, ok := plan.Singbox["wayhop_compatibility_routing"].(bool); !ok || !marker || len(plan.Singbox) != 1 {
		t.Fatalf("compatibility marker = %#v", plan.Singbox)
	}
	if commands := strings.Join(plan.Commands(), "\n"); commands != "" {
		t.Fatalf("compatibility mode emitted a parallel NDM route plane:\n%s", commands)
	}
}

func TestCompile_RulesUseCompatibilityRouting(t *testing.T) {
	p := &model.Profile{Rules: []model.Rule{{ID: "r1", DomainSuffix: []string{"example.com"}, Outbound: model.OutboundDirect}}}
	plan, err := Compile(p, CompileOptions{})
	if err != nil || !plan.CompatibilityRouting || plan.Singbox == nil || len(plan.Routes) != 0 {
		t.Fatalf("rule semantics were not moved to the compatibility TUN: %#v / %v", plan, err)
	}
}

func TestCompile_DomainAndRemoteListsUseCompatibilityRouting(t *testing.T) {
	for _, list := range []model.RoutingList{
		{ID: "domain", Manual: []string{"example.com"}, Outbound: model.OutboundDirect, Enabled: true},
		{ID: "remote", Source: "https://example.invalid/domains.txt", Outbound: model.OutboundDirect, Enabled: true},
	} {
		p := &model.Profile{RoutingLists: []model.RoutingList{list}}
		plan, err := Compile(p, CompileOptions{})
		if err != nil || !plan.CompatibilityRouting || len(plan.Routes) != 0 {
			t.Fatalf("list %q was not moved intact to compatibility routing: %#v / %v", list.ID, plan, err)
		}
	}
}

func TestCompile_CIDRCacheIsPartOfTheNativeRoutePlan(t *testing.T) {
	p := &model.Profile{RoutingLists: []model.RoutingList{{
		ID: "feed", Enabled: true, Outbound: model.OutboundDirect,
		Manual: []string{"192.0.2.0/24"}, CIDRSource: "asn:64500",
		CIDRCache: []string{"198.51.100.0/24"}, CIDRRefreshed: 1,
	}}}
	plan, err := Compile(p, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(plan.Routes, "\n")
	for _, want := range []string{
		"ip route 192.0.2.0 255.255.255.0 ISP",
		"ip route 198.51.100.0 255.255.255.0 ISP",
	} {
		if !strings.Contains(commands, want) {
			t.Errorf("native route plan omitted %q:\n%s", want, commands)
		}
	}
}

func TestCompile_CIDRSourceWithoutReviewedCacheFailsClosed(t *testing.T) {
	p := &model.Profile{RoutingLists: []model.RoutingList{{
		ID: "feed", Enabled: true, Outbound: model.OutboundDirect,
		Manual: []string{"192.0.2.0/24"}, CIDRSource: "asn:64500",
	}}}
	if _, err := Compile(p, CompileOptions{}); err == nil || !strings.Contains(err.Error(), "no reviewed CIDR cache") {
		t.Fatalf("unmaterialized CIDR source was silently applied: %v", err)
	}
}

// Having a DNS block is not the same as needing a proxy core for it. What needs one is a resolver
// whose own queries must leave through a TUNNEL, a per-name rule (resolver policy the core owns),
// FakeIP — or an ENCRYPTED transport, because dnsmasq speaks plain UDP/TCP and nothing else.
//
// A block that only names direct/local PLAIN resolvers is carried by the router's own dnsmasq, and
// demanding sing-box for it made "manage DNS" mean "install sing-box" on a router that was resolving
// perfectly well, blocking every Apply. That relief is what this test was written for and it stands.
//
// The DoH-going-direct case moved sides, though, and it moved because the router said so: with two
// DoH resolvers configured and the core installed, the plan reported native-only, sing-box never
// started, and dnsmasq answered in plaintext while the panel called the lookups encrypted. "Carried
// natively" was true of the QUERY leaving directly and false of the thing the operator asked for.
func TestCompile_DNSNeedsTheCoreOnlyForWhatTheCoreDoes(t *testing.T) {
	needsCore := []*model.DNSSettings{
		{Enabled: true, FakeIP: true, IndependentCache: true,
			Servers: []model.DNSServer{{Tag: "fake", Type: "fakeip", Enabled: true}}, Final: "fake"},
		{Enabled: true, Final: "doh", Servers: []model.DNSServer{
			{Tag: "doh", Type: "https", Server: "1.1.1.1", Enabled: true, Detour: "nl"}}},
		{Enabled: true, Final: "local",
			Servers: []model.DNSServer{{Tag: "local", Type: "local", Enabled: true}},
			Rules:   []model.DNSRule{{ID: "r", Server: "local", Domain: []string{"example.com"}}}},
		// Encrypted, and going DIRECT: still the core's, because nothing else on the router speaks it.
		{Enabled: true, Final: "doh", Servers: []model.DNSServer{
			{Tag: "doh", Type: "https", Server: "1.1.1.1", Enabled: true, Detour: "direct"}}},
	}
	for i, dns := range needsCore {
		plan, err := Compile(&model.Profile{DNS: dns}, CompileOptions{})
		if err != nil || !plan.CompatibilityRouting {
			t.Fatalf("case %d: DNS semantics the core owns were not moved to compatibility routing: %#v / %v", i, plan, err)
		}
	}

	carriedNatively := []*model.DNSSettings{
		{Enabled: true, Servers: []model.DNSServer{{Tag: "local", Type: "local", Enabled: true}}, Final: "local"},
		// Plain resolvers going direct — exactly what dnsmasq already does.
		{Enabled: true, Final: "isp", Servers: []model.DNSServer{
			{Tag: "isp", Type: "udp", Server: "1.1.1.1", Enabled: true, Detour: "direct"}}},
	}
	for i, dns := range carriedNatively {
		plan, err := Compile(&model.Profile{DNS: dns}, CompileOptions{})
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if plan.CompatibilityRouting {
			t.Fatalf("case %d: a DNS block that asks nothing of the core still demanded one: %#v", i, plan)
		}
	}
}

func TestCompile_InactiveSemanticsDoNotBlock(t *testing.T) {
	p := &model.Profile{
		Rules: []model.Rule{{ID: "off", Disabled: true, Domain: []string{"example.invalid"}, Outbound: model.OutboundBlock}},
		DNS:   &model.DNSSettings{Enabled: false, FakeIP: true},
	}
	if _, err := Compile(p, CompileOptions{}); err != nil {
		t.Fatalf("inactive draft semantics must not block native Apply: %v", err)
	}
}

func TestCompile_InvalidActiveEndpointsFailClosed(t *testing.T) {
	t.Run("native", func(t *testing.T) {
		e := awgEndpoint()
		e.ID, e.Enabled = "bad-awg", true
		delete(e.Params, "private_key")
		if _, err := Compile(&model.Profile{Endpoints: []model.Endpoint{e}}, CompileOptions{}); err == nil ||
			!strings.Contains(err.Error(), "bad-awg") {
			t.Fatalf("invalid native endpoint was skipped: %v", err)
		}
	})
	t.Run("compatibility addon", func(t *testing.T) {
		e := model.Endpoint{
			ID: "bad-vless", Engine: model.EngineSingBox, Protocol: model.Protocol("unsupported-protocol"),
			Server: "192.0.2.1", Port: 443, Enabled: true,
		}
		if _, err := Compile(&model.Profile{Endpoints: []model.Endpoint{e}}, CompileOptions{}); err == nil ||
			!strings.Contains(err.Error(), "bad-vless") {
			t.Fatalf("invalid compatibility endpoint was skipped: %v", err)
		}
	})
}

// TestCompile_AdoptInterfaces: an already-live interface (the live cutover case) is recorded
// + routed-to but NEVER (re)created or torn down — so a re-Apply/cutover can't bounce a live router's
// existing AmneziaWG tunnels.
func TestCompile_AdoptInterfaces(t *testing.T) {
	awg := awgEndpoint()
	awg.ID, awg.Enabled, awg.Server = "wgtest", true, "203.0.113.10"
	p := &model.Profile{
		Endpoints: []model.Endpoint{awg},
		RoutingLists: []model.RoutingList{
			{ID: "blocked", Manual: []string{"149.154.160.0/20"}, Outbound: "wgtest", Enabled: true}, // Telegram CIDR
		},
	}
	plan, err := Compile(p, CompileOptions{AdoptInterfaces: map[string]string{"wgtest": "nwg3"}, AdoptNDMNames: map[string]string{"wgtest": "Wireguard3"}})
	if err != nil {
		t.Fatal(err)
	}

	// IfaceFor is the ROUTE TARGET namespace, so an adopted endpoint records its NDM name here and
	// not the kernel link. Asserting the kernel name is what let `ip route … nwg3` ship: NDM answers
	// that with "argument parse error", so every route to an adopted tunnel failed at Apply.
	if plan.IfaceFor["wgtest"] != "Wireguard3" {
		t.Errorf("adopted IfaceFor = %q, want Wireguard3", plan.IfaceFor["wgtest"])
	}
	if len(plan.Interfaces) != 0 {
		t.Errorf("adopted endpoint must emit NO interface block, got %d", len(plan.Interfaces))
	}
	cmds := strings.Join(plan.Commands(), "\n")
	if !strings.Contains(cmds, "ip route 149.154.160.0 255.255.240.0 Wireguard3") {
		t.Errorf("list must route to the adopted iface\n%s", cmds)
	}
	if !strings.Contains(cmds, "ip route 203.0.113.10 255.255.255.255 ISP") {
		t.Error("adopted endpoint server IP must still get an anti-loop bypass")
	}

	td := strings.Join(TeardownCommands(plan), "\n")
	if strings.Contains(td, "no interface") {
		t.Errorf("teardown must NOT remove an adopted interface\n%s", td)
	}
	if !strings.Contains(td, "no ip route 149.154.160.0 255.255.240.0 Wireguard3") {
		t.Errorf("teardown must still remove WayHop's own route\n%s", td)
	}
}

func TestPlanRequiresCoreMatchesCompiledSingboxPresence(t *testing.T) {
	// The predicate exists so the Apply review can ask exactly what the executor answers, so the
	// test asserts the equivalence itself rather than the predicate in isolation: for each profile,
	// PlanRequiresCore must agree with whether Compile actually populated Plan.Singbox.
	adoptedWG := model.Endpoint{
		ID: "adopted", Enabled: true, Owner: model.OwnerSystem, Engine: model.EngineExternal,
	}
	nativeWG := awgEndpoint()
	nativeWG.ID, nativeWG.Enabled = "native", true
	proxy := model.Endpoint{
		ID: "proxy", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
	}
	cases := []struct {
		name     string
		profile  model.Profile
		adopt    map[string]string
		adoptNDM map[string]string
	}{
		{"empty", model.Profile{}, nil, nil},
		{"disabled proxy only", model.Profile{Endpoints: []model.Endpoint{
			{ID: "proxy", Enabled: false, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS},
		}}, nil, nil},
		{"adopted native tunnel", model.Profile{Endpoints: []model.Endpoint{adoptedWG}},
			map[string]string{"adopted": "nwg0"}, map[string]string{"adopted": "Wireguard0"}},
		{"native amneziawg", model.Profile{Endpoints: []model.Endpoint{nativeWG}}, nil, nil},
		{"enabled proxy", model.Profile{Endpoints: []model.Endpoint{proxy}}, nil, nil},
		{"group forces compatibility", model.Profile{
			Endpoints: []model.Endpoint{adoptedWG},
			Groups:    []model.Group{{ID: "g1"}},
		}, map[string]string{"adopted": "nwg0"}, map[string]string{"adopted": "Wireguard0"}},
	}
	for _, tc := range cases {
		profile := tc.profile
		plan, err := Compile(&profile, CompileOptions{AdoptInterfaces: tc.adopt, AdoptNDMNames: tc.adoptNDM})
		if err != nil {
			t.Fatalf("%s: compile: %v", tc.name, err)
		}
		want := plan.Singbox != nil
		if got := PlanRequiresCore(&profile, RoutePlanes{}); got != want {
			t.Fatalf("%s: PlanRequiresCore = %v, but Compile produced Singbox != nil = %v",
				tc.name, got, want)
		}
	}
	if PlanRequiresCore(nil, RoutePlanes{}) {
		t.Fatal("a nil profile requires a core")
	}
}

// A failover group over native tunnels is not a reason to start a proxy core. At any instant the
// group IS one member, and failing over is re-pointing that member's routes — a decision plus an
// `ip route`, neither of which sing-box owns. Compile pins the member the caller elected, falling
// back to the operator's own order, and reports the choice so the daemon can notice it moved.
func TestCompile_NativeGroupRoutesWithoutCore(t *testing.T) {
	nl := awgEndpoint()
	nl.ID, nl.Enabled, nl.Owner, nl.Engine = "nl", true, model.OwnerExternal, model.EngineExternal
	nl.Params["interface"] = "nwg1"
	cy := awgEndpoint()
	cy.ID, cy.Enabled, cy.Owner, cy.Engine = "cy", true, model.OwnerExternal, model.EngineExternal
	cy.Params["interface"] = "nwg0"
	profile := &model.Profile{
		Endpoints: []model.Endpoint{nl, cy},
		Groups: []model.Group{{
			ID: "grp", Name: "Main", Type: model.GroupFallback, Members: []string{nl.ID, cy.ID},
		}},
		RoutingLists: []model.RoutingList{{
			ID: "list", Name: "L", Manual: []string{"203.0.113.0/24"}, Outbound: "grp", Enabled: true,
		}},
	}
	opt := CompileOptions{
		AdoptInterfaces: map[string]string{nl.ID: "nwg1", cy.ID: "nwg0"},
		AdoptNDMNames:   map[string]string{nl.ID: "Wireguard1", cy.ID: "Wireguard0"},
	}

	plan, err := Compile(profile, opt)
	if err != nil {
		t.Fatal(err)
	}
	if plan.CompatibilityRouting || plan.Singbox != nil {
		t.Fatalf("a group of native tunnels pulled in the compatibility core: routing=%v singbox=%#v",
			plan.CompatibilityRouting, plan.Singbox)
	}
	if plan.GroupMember["grp"] != nl.ID {
		t.Fatalf("with no election the group takes the operator's first member, got %q", plan.GroupMember["grp"])
	}
	if cmds := strings.Join(plan.Routes, "\n"); !strings.Contains(cmds, "ip route 203.0.113.0 255.255.255.0 Wireguard1") {
		t.Fatalf("the group's list did not route to its member's interface:\n%s", cmds)
	}

	// The daemon's election moves those same routes onto another member. Nothing else changes: that
	// is the whole of native failover.
	opt.GroupElection = map[string]string{"grp": cy.ID}
	moved, err := Compile(profile, opt)
	if err != nil {
		t.Fatal(err)
	}
	if moved.GroupMember["grp"] != cy.ID {
		t.Fatalf("election ignored: group compiled onto %q", moved.GroupMember["grp"])
	}
	if cmds := strings.Join(moved.Routes, "\n"); !strings.Contains(cmds, "ip route 203.0.113.0 255.255.255.0 Wireguard0") {
		t.Fatalf("routes did not follow the election:\n%s", cmds)
	}

	// An election naming a member this plan cannot route is stale, not authoritative: obeying it
	// would emit routes to an interface that does not exist.
	opt.GroupElection = map[string]string{"grp": "ghost"}
	stale, err := Compile(profile, opt)
	if err != nil {
		t.Fatal(err)
	}
	if stale.GroupMember["grp"] != nl.ID {
		t.Fatalf("a stale election was obeyed: group compiled onto %q", stale.GroupMember["grp"])
	}
}

// One non-native member is enough to need the core — and it is that MEMBER that needs it, which is
// why the group as a whole still compiles into compatibility routing rather than being refused.
func TestCompile_GroupWithProxyMemberStillNeedsCore(t *testing.T) {
	nl := awgEndpoint()
	nl.ID, nl.Enabled, nl.Owner, nl.Engine = "nl", true, model.OwnerExternal, model.EngineExternal
	nl.Params["interface"] = "nwg1"
	proxy := model.Endpoint{
		ID: "proxy", Name: "Proxy", Enabled: true,
		Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "198.51.100.20", Port: 443,
		Params: map[string]any{"uuid": "11111111-1111-1111-1111-111111111111"},
	}
	profile := &model.Profile{
		Endpoints: []model.Endpoint{nl, proxy},
		Groups: []model.Group{{
			ID: "grp", Name: "Mixed", Type: model.GroupURLTest, Members: []string{nl.ID, proxy.ID},
		}},
	}
	plan, err := Compile(profile, CompileOptions{
		AdoptInterfaces: map[string]string{nl.ID: "nwg1"},
		AdoptNDMNames:   map[string]string{nl.ID: "Wireguard1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.CompatibilityRouting {
		t.Fatal("a group holding a VLESS member compiled without the core")
	}
}

// The live router's own shape: the WAN holds the default route with the HIGHEST ip global, tunnels
// sit below it. Parsing this is what lets a native default route be placed relative to the router's
// numbers instead of numbers we invented.
const liveGlobalsSample = `interface GigabitEthernet1
    description Provider
    ip global 54610
!
interface Wireguard0
    description WgProvider_SiteB
    ip mtu 1280
    ip global 10922
    wireguard peer cGVlci1wdWJsaWMta2V5LTMyLWJ5dGVzLXNjcnViYmQ=
        endpoint cy.example.online:9987
!
interface Wireguard4
    description WgProvider_SiteC
    ip global 2730
!
`

func TestGlobalPriorities_ReadsTheLadder(t *testing.T) {
	got := GlobalPriorities(liveGlobalsSample)
	want := map[string]int{"GigabitEthernet1": 54610, "Wireguard0": 10922, "Wireguard4": 2730}
	if len(got) != len(want) {
		t.Fatalf("priorities = %v, want %v", got, want)
	}
	for iface, prio := range want {
		if got[iface] != prio {
			t.Fatalf("%s = %d, want %d (all: %v)", iface, got[iface], prio, got)
		}
	}
}

// "Send everything through this group" is a default route, and KeeneticOS expresses a default route
// as the top of the global-connection ladder — not as a static 0.0.0.0/0. So a plain default rule
// pointing at a native group needs no proxy core either: it raises the group above the WAN, elected
// member first, and keeps the router's previous numbers for the rollback.
func TestCompile_DefaultRuleRaisesNativeGroupAboveTheWAN(t *testing.T) {
	nl := awgEndpoint()
	nl.ID, nl.Enabled, nl.Owner, nl.Engine = "nl", true, model.OwnerExternal, model.EngineExternal
	nl.Params["interface"] = "nwg1"
	cy := awgEndpoint()
	cy.ID, cy.Enabled, cy.Owner, cy.Engine = "cy", true, model.OwnerExternal, model.EngineExternal
	cy.Params["interface"] = "nwg0"
	profile := &model.Profile{
		Endpoints: []model.Endpoint{nl, cy},
		Groups: []model.Group{{
			ID: "grp", Name: "Main", Type: model.GroupFallback, Members: []string{nl.ID, cy.ID},
		}},
		Rules: []model.Rule{{ID: "default", Default: true, Outbound: "grp"}},
	}
	opt := CompileOptions{
		AdoptInterfaces:   map[string]string{nl.ID: "nwg1", cy.ID: "nwg0"},
		AdoptNDMNames:     map[string]string{nl.ID: "Wireguard1", cy.ID: "Wireguard0"},
		GlobalPriorityNow: GlobalPriorities(liveGlobalsSample),
	}
	plan, err := Compile(profile, opt)
	if err != nil {
		t.Fatal(err)
	}
	if plan.CompatibilityRouting {
		t.Fatal("a default route to a native group still demanded the compatibility core")
	}
	wan := 54610
	if plan.GlobalPriority["Wireguard1"] <= wan || plan.GlobalPriority["Wireguard0"] <= wan {
		t.Fatalf("the group was not raised above the WAN: %v", plan.GlobalPriority)
	}
	if plan.GlobalPriority["Wireguard1"] <= plan.GlobalPriority["Wireguard0"] {
		t.Fatalf("the elected member is not on top: %v", plan.GlobalPriority)
	}
	if plan.GlobalPriorityWas["Wireguard0"] != 10922 {
		t.Fatalf("the router's previous priority was not recorded for rollback: %v", plan.GlobalPriorityWas)
	}
}

// A kill switch says traffic must NOT fall back to the open WAN when every member is down, and a
// ladder cannot say that — the WAN is what sits under it. So that group keeps the core.
func TestCompile_KillSwitchGroupKeepsTheCore(t *testing.T) {
	nl := awgEndpoint()
	nl.ID, nl.Enabled, nl.Owner, nl.Engine = "nl", true, model.OwnerExternal, model.EngineExternal
	nl.Params["interface"] = "nwg1"
	profile := &model.Profile{
		Endpoints: []model.Endpoint{nl},
		Groups: []model.Group{{
			ID: "grp", Name: "Main", Type: model.GroupFallback, Members: []string{nl.ID}, KillSwitch: true,
		}},
		Rules: []model.Rule{{ID: "default", Default: true, Outbound: "grp"}},
	}
	plan, err := Compile(profile, CompileOptions{
		AdoptInterfaces:   map[string]string{nl.ID: "nwg1"},
		AdoptNDMNames:     map[string]string{nl.ID: "Wireguard1"},
		GlobalPriorityNow: GlobalPriorities(liveGlobalsSample),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.CompatibilityRouting {
		t.Fatal("a kill-switch group was compiled onto a ladder that falls back to the open WAN")
	}
}

// Without the router's own numbers there is nothing to be higher than. Compile refuses rather than
// inventing a ladder, because an invented one is an invented default route.
func TestCompile_DefaultRuleRefusesWithoutObservedPriorities(t *testing.T) {
	nl := awgEndpoint()
	nl.ID, nl.Enabled, nl.Owner, nl.Engine = "nl", true, model.OwnerExternal, model.EngineExternal
	nl.Params["interface"] = "nwg1"
	profile := &model.Profile{
		Endpoints: []model.Endpoint{nl},
		Rules:     []model.Rule{{ID: "default", Default: true, Outbound: nl.ID}},
	}
	_, err := Compile(profile, CompileOptions{
		AdoptInterfaces: map[string]string{nl.ID: "nwg1"},
		AdoptNDMNames:   map[string]string{nl.ID: "Wireguard1"},
	})
	if err == nil {
		t.Fatal("a native default route was compiled with no observed global priorities")
	}
}

// A kernel-routed endpoint whose server is a hostname gets NO planned anti-loop bypass - Compile
// is pure and cannot resolve names - and for a long time the adopted branch claimed a nonexistent
// ExtraBypass option covered it. The contract now is a review-visible warning, one per hostname
// endpoint, on BOTH kernel paths (adopted and native); an IP-literal server keeps its bypass and
// warns nothing.
func TestCompile_HostnameServerWarnsMissingBypass(t *testing.T) {
	profile := &model.Profile{Endpoints: []model.Endpoint{
		{ID: "adopted-host", Engine: model.EngineExternal, Server: "vpn.example.com", Enabled: true,
			Params: map[string]any{"interface": "awg1"}},
		{ID: "native-host", Engine: model.EngineAmneziaWG, Server: "peer.example.net", Port: 51820, Enabled: true,
			Params: map[string]any{"private_key": "aGVsbG8td29ybGQtaGVsbG8td29ybGQtaGVsbG8tMTI=",
				"peer_public_key": "aGVsbG8td29ybGQtaGVsbG8td29ybGQtaGVsbG8tMTI=", "address": "10.99.0.2/32"}},
		{ID: "literal", Engine: model.EngineExternal, Server: "198.51.100.7", Enabled: true,
			Params: map[string]any{"interface": "awg2"}},
	}}
	plan, err := Compile(profile, CompileOptions{
		AdoptInterfaces: map[string]string{"adopted-host": "nwg1", "literal": "nwg2"},
		AdoptNDMNames:   map[string]string{"adopted-host": "Wireguard1", "literal": "Wireguard2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	warned := map[string]bool{}
	for _, w := range plan.Warnings {
		for _, id := range []string{"adopted-host", "native-host", "literal"} {
			if strings.Contains(w, id) && strings.Contains(w, "hostname") {
				warned[id] = true
			}
		}
	}
	if !warned["adopted-host"] || !warned["native-host"] {
		t.Fatalf("hostname endpoints must warn about the unplannable bypass; warnings = %q", plan.Warnings)
	}
	if warned["literal"] {
		t.Fatalf("an IP-literal server must not warn; warnings = %q", plan.Warnings)
	}
	found := false
	for _, r := range plan.Routes {
		if strings.Contains(r, "198.51.100.7") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the literal server lost its bypass route; routes = %#v", plan.Routes)
	}
}

// An AmneziaWG endpoint whose obfuscation set is incomplete renders WITHOUT the `wireguard asc`
// line, so the router runs it as plain WireGuard. That is the correct rendering - the line cannot be
// half-written - but it used to happen in silence, and the panel went on showing AmneziaWG. Against
// an AWG peer the tunnel never answers; against a plain-WG peer it works and the operator believes
// they have obfuscation they do not have. A complete set, and a genuine WireGuard endpoint, stay
// quiet.
func TestCompile_PartialAWGObfuscationWarns(t *testing.T) {
	const k = "aGVsbG8td29ybGQtaGVsbG8td29ybGQtaGVsbG8tMTI="
	wgParams := func(extra map[string]any) map[string]any {
		p := map[string]any{"private_key": k, "peer_public_key": k, "address": "10.99.0.2/32"}
		for kk, vv := range extra {
			p[kk] = vv
		}
		return p
	}
	full := map[string]any{"jc": 4, "jmin": 40, "jmax": 70, "s1": 30, "s2": 40,
		"h1": "1148853832", "h2": "1148853833", "h3": "1148853834", "h4": "1148853835"}
	partial := map[string]any{"jc": 4, "jmin": 40, "jmax": 70} // s1/s2/h1-h4 missing

	profile := &model.Profile{Endpoints: []model.Endpoint{
		{ID: "awg-partial", Engine: model.EngineAmneziaWG, Server: "198.51.100.21", Port: 51820, Enabled: true, Params: wgParams(partial)},
		{ID: "awg-full", Engine: model.EngineAmneziaWG, Server: "198.51.100.22", Port: 51820, Enabled: true, Params: wgParams(full)},
		{ID: "plain-wg", Engine: model.EngineSingBox, Protocol: model.ProtoWireGuard, Server: "198.51.100.23", Port: 51820, Enabled: true, Params: wgParams(nil)},
	}}
	plan, err := Compile(profile, CompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	warned := map[string]bool{}
	for _, w := range plan.Warnings {
		for _, id := range []string{"awg-partial", "awg-full", "plain-wg"} {
			if strings.Contains(w, id) && strings.Contains(w, "PLAIN WireGuard") {
				warned[id] = true
			}
		}
	}
	if !warned["awg-partial"] {
		t.Fatalf("a half-filled AmneziaWG set downgraded to plain WireGuard in silence; warnings = %q", plan.Warnings)
	}
	if warned["awg-full"] || warned["plain-wg"] {
		t.Fatalf("a complete AWG set or a genuine WireGuard endpoint must not warn; warnings = %q", plan.Warnings)
	}
}
