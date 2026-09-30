package nativeplan

import (
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
)

func managedAWG() model.Endpoint {
	return model.Endpoint{
		ID: "ep-awg", Name: "AWG", Enabled: true,
		Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
		Server: "198.51.100.8", Port: 51820,
		Params: map[string]any{
			"private_key": "private", "peer_public_key": "public",
			"local_address": []string{"10.10.0.2/32"},
			"allowed_ips":   []string{"0.0.0.0/0"}, "jc": 5,
		},
	}
}

func usableCapabilities(ids ...string) platform.CapabilitySet {
	items := make(map[string]platform.Capability, len(ids))
	for _, id := range ids {
		items[id] = platform.Capability{
			ID: id, State: platform.CapSupported,
			HostSupport: platform.VerdictYes, WayHopSupport: platform.VerdictYes,
			RuntimeState: platform.VerdictYes, Blocks: platform.BlocksNothing,
		}
	}
	return platform.CapabilitySet{Items: items}
}

func openWrtFacts(endpoint model.Endpoint) HostFacts {
	protocol := string(endpoint.Protocol)
	return HostFacts{
		Platform: platform.OpenWrt,
		Capabilities: usableCapabilities(
			platform.NativeOperationCapabilityID(protocol, platform.NativeCreate),
			platform.NativeOperationCapabilityID(protocol, platform.NativeManage),
			platform.NativeOperationCapabilityID(protocol, platform.NativeUpdate),
			platform.NativeOperationCapabilityID(protocol, platform.NativeRemove),
			platform.NativeOperationCapabilityID(protocol, platform.NativeAdopt),
		),
		NetworkUCI:   "network.lan=interface\n",
		FirewallUCI:  "firewall.@zone[0]=zone\nfirewall.@zone[0].name='vpn'\n",
		RouterProtos: netvpn.RouterProtos{"amneziawg": true}, FirewallZone: "vpn",
	}
}

func TestCompileOpenWrtExistingOwnedInterfaceRequiresUpdateAuthority(t *testing.T) {
	endpoint := managedAWG()
	facts := openWrtFacts(endpoint)
	iface := netvpn.InterfaceName(endpoint)
	facts.NetworkUCI = "network." + iface + "=interface\nnetwork." + iface + ".proto='amneziawg'\n"
	facts.OwnedInterfaces = map[string]string{endpoint.ID: iface}
	plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts)
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Decisions[0]; got.Path != PathNativeUpdate ||
		got.Capability != platform.NativeOperationCapabilityID(string(endpoint.Protocol), platform.NativeUpdate) {
		t.Fatalf("existing interface decision = %#v", got)
	}
	delete(facts.Capabilities.Items,
		platform.NativeOperationCapabilityID(string(endpoint.Protocol), platform.NativeUpdate))
	if _, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts); err == nil ||
		!strings.Contains(err.Error(), ".update") {
		t.Fatalf("missing update authority error = %v", err)
	}
}

func TestCompileOpenWrtExistingInterfaceNeedsAuthenticatedOwnership(t *testing.T) {
	endpoint := managedAWG()
	endpoint.Engine = model.EngineSingBox
	facts := openWrtFacts(endpoint)
	iface := netvpn.InterfaceName(endpoint)
	facts.NetworkUCI = "network." + iface + "=interface\nnetwork." + iface + ".proto='amneziawg'\n"
	facts.Capabilities.Items[platform.CapEngineSingbox] = platform.Capability{
		ID: platform.CapEngineSingbox, State: platform.CapSupported,
		HostSupport: platform.VerdictYes, WayHopSupport: platform.VerdictYes,
		RuntimeState: platform.VerdictYes, Blocks: platform.BlocksNothing,
	}
	protocolCap := platform.CapProtocolPrefix + string(endpoint.Protocol)
	facts.Capabilities.Items[protocolCap] = platform.Capability{
		ID: protocolCap, State: platform.CapSupported,
		HostSupport: platform.VerdictYes, WayHopSupport: platform.VerdictYes,
		RuntimeState: platform.VerdictYes, Blocks: platform.BlocksNothing,
	}
	plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Decisions) != 1 || plan.Decisions[0].Path != PathCompatibility || len(plan.OpenWrt) != 0 {
		t.Fatalf("unowned existing interface was mutated: %#v / %#v", plan.Decisions, plan.OpenWrt)
	}
	endpoint.Engine = model.EngineAmneziaWG
	if _, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts); err == nil ||
		!strings.Contains(err.Error(), "authenticated ownership") {
		t.Fatalf("native-only engine claimed unowned interface: %v", err)
	}
}

func TestCompileOpenWrtChoosesNativeBeforeCompatibilityAddon(t *testing.T) {
	endpoint := managedAWG()
	plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, openWrtFacts(endpoint))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Decisions) != 1 || plan.Decisions[0].Path != PathNativeCreate {
		t.Fatalf("decision = %#v", plan.Decisions)
	}
	if len(plan.OpenWrt) != 1 || plan.OpenWrt[0].Iface != netvpn.InterfaceName(endpoint) {
		t.Fatalf("OpenWrt plan = %#v", plan.OpenWrt)
	}
	commands := strings.Join(plan.OpenWrt[0].Commands, "\n")
	if !strings.Contains(commands, ".proto='amneziawg'") {
		t.Fatalf("native plan did not select netifd AmneziaWG:\n%s", commands)
	}
	if plan.Decisions[0].RollbackCap == "" {
		t.Fatal("WayHop took ownership without proving rollback/remove authority")
	}
}

func TestCompileOpenWrtSingBoxWireGuardFallsBackWhenNativeShapeIsUnavailable(t *testing.T) {
	endpoint := managedAWG()
	endpoint.Engine = model.EngineSingBox
	endpoint.Protocol = model.ProtoWireGuard
	delete(endpoint.Params, "local_address") // valid for the addon, not a writable native interface
	facts := openWrtFacts(endpoint)
	facts.Capabilities.Items[platform.CapEngineSingbox] = platform.Capability{
		ID: platform.CapEngineSingbox, State: platform.CapSupported,
		HostSupport: platform.VerdictYes, WayHopSupport: platform.VerdictYes,
		RuntimeState: platform.VerdictYes, Blocks: platform.BlocksNothing,
	}
	protocolCap := platform.CapProtocolPrefix + string(endpoint.Protocol)
	facts.Capabilities.Items[protocolCap] = platform.Capability{
		ID: protocolCap, State: platform.CapSupported,
		HostSupport: platform.VerdictYes, WayHopSupport: platform.VerdictYes,
		RuntimeState: platform.VerdictYes, Blocks: platform.BlocksNothing,
	}

	plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Decisions) != 1 || plan.Decisions[0].Path != PathCompatibility ||
		plan.Decisions[0].Capability != protocolCap || len(plan.OpenWrt) != 0 {
		t.Fatalf("sing-box WireGuard fallback = %#v", plan)
	}
}

func TestCompileOpenWrtNativeEngineDoesNotSilentlyFallBack(t *testing.T) {
	endpoint := managedAWG()
	delete(endpoint.Params, "local_address")
	facts := openWrtFacts(endpoint)
	facts.Capabilities.Items[platform.CapEngineSingbox] = platform.Capability{
		ID: platform.CapEngineSingbox, State: platform.CapSupported,
		HostSupport: platform.VerdictYes, WayHopSupport: platform.VerdictYes,
		RuntimeState: platform.VerdictYes, Blocks: platform.BlocksNothing,
	}
	facts.Capabilities.Items[platform.CapProtocolPrefix+string(endpoint.Protocol)] = platform.Capability{
		ID: platform.CapProtocolPrefix + string(endpoint.Protocol), State: platform.CapSupported,
		HostSupport: platform.VerdictYes, WayHopSupport: platform.VerdictYes,
		RuntimeState: platform.VerdictYes, Blocks: platform.BlocksNothing,
	}
	if _, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts); err == nil ||
		!strings.Contains(err.Error(), "no interface address") {
		t.Fatalf("native engine silently fell back: %v", err)
	}
}

func TestCompileOpenWrtCompatibilityAddonHasNoInventedInterface(t *testing.T) {
	endpoint := model.Endpoint{
		ID: "proxy", Name: "proxy", Enabled: true,
		Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "198.51.100.30", Port: 443,
		Params: map[string]any{"uuid": "11111111-1111-1111-1111-111111111111"},
	}
	facts := HostFacts{
		Platform: platform.OpenWrt,
		Capabilities: usableCapabilities(platform.CapEngineSingbox,
			platform.CapProtocolPrefix+string(model.ProtoVLESS)),
		NetworkUCI: "network.lan=interface\n", FirewallUCI: "firewall.@zone[0]=zone\n",
		RouterProtos: netvpn.RouterProtos{}, FirewallZone: "vpn",
	}
	plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Decisions) != 1 || plan.Decisions[0].Path != PathCompatibility ||
		plan.Decisions[0].Interface != "" || len(plan.OpenWrt) != 0 {
		t.Fatalf("OpenWrt compatibility decision invented a native interface: %#v", plan)
	}
}

func TestCompileOpenWrtExternalInterfaceIsAdoptedWithoutWritePlan(t *testing.T) {
	for _, owner := range []model.Owner{model.OwnerSystem, model.OwnerWayHop} {
		endpoint := managedAWG()
		endpoint.Owner = owner
		endpoint.Engine = model.EngineExternal
		endpoint.Params["interface"] = "wg999"
		facts := openWrtFacts(endpoint)
		facts.AdoptInterfaces = map[string]string{endpoint.ID: "nwg5"}
		plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts)
		if err != nil {
			t.Fatalf("owner %q: %v", owner, err)
		}
		if len(plan.OpenWrt) != 0 {
			t.Fatalf("owner %q: adoption produced %d destructive write plan(s)", owner, len(plan.OpenWrt))
		}
		if got := plan.Decisions[0]; got.Path != PathNativeAdopt || got.Interface != "nwg5" || got.RollbackCap != "" {
			t.Fatalf("owner %q: adoption decision = %#v", owner, got)
		}
	}
}

func TestCompileOpenWrtRefusesManagedExternalInterfaceCollision(t *testing.T) {
	managed := managedAWG()
	iface := netvpn.InterfaceName(managed)
	external := model.Endpoint{
		ID: "external", Name: "external", Enabled: true,
		Engine: model.EngineExternal, Protocol: model.ProtoSOCKS, Owner: model.OwnerExternal,
		Params: map[string]any{"interface": iface},
	}
	for _, endpoints := range [][]model.Endpoint{{managed, external}, {external, managed}} {
		facts := openWrtFacts(managed)
		facts.AdoptInterfaces = map[string]string{external.ID: iface}
		if _, err := Compile(&model.Profile{Endpoints: endpoints}, facts); err == nil ||
			!strings.Contains(err.Error(), "claim the same interface") {
			t.Fatalf("collision order %#v error = %v", endpoints, err)
		}
	}
}

func TestCompileRefusesOwnershipWithoutRollbackAuthority(t *testing.T) {
	endpoint := managedAWG()
	facts := openWrtFacts(endpoint)
	delete(facts.Capabilities.Items,
		platform.NativeOperationCapabilityID(string(endpoint.Protocol), platform.NativeRemove))
	if _, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts); err == nil ||
		!strings.Contains(err.Error(), "rollback authority") {
		t.Fatalf("error = %v, want rollback authority refusal", err)
	}
}

func TestCompileOpenWrtRefusesUnreviewedFirewallZone(t *testing.T) {
	endpoint := managedAWG()
	facts := openWrtFacts(endpoint)
	facts.FirewallZone = ""
	if _, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, facts); err == nil ||
		!strings.Contains(err.Error(), "explicitly reviewed OpenWrt firewall zone") {
		t.Fatalf("error = %v, want explicit firewall-zone refusal", err)
	}
}

func TestCompileRefusesNonsensicalNativeEnginePair(t *testing.T) {
	endpoint := managedAWG()
	endpoint.Engine = model.EngineOlcRTC
	if _, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, openWrtFacts(endpoint)); err == nil ||
		!strings.Contains(err.Error(), "cannot materialize") {
		t.Fatalf("error = %v, want native engine-pair refusal", err)
	}
}

// Until the NDM writer is wired, a native WireGuard endpoint fails closed - no NDM write happens on an
// executor nobody connected. An AmneziaWG endpoint no longer has to: WayHop's own engine runs it,
// which needs no NDM authority at all.
func TestCompileKeeneticFailsClosedUntilNativeWriterCapabilityIsWired(t *testing.T) {
	caps := platform.Capabilities{
		Platform: string(platform.Keenetic), Native: map[string]bool{"amneziawg": true, "wireguard": true},
		Installable: map[string]string{},
	}
	set := platform.Evaluate(caps, platform.RuntimeFacts{})
	wireguard := managedAWG()
	wireguard.Engine, wireguard.Protocol = model.EngineSingBox, model.ProtoWireGuard
	_, err := Compile(&model.Profile{Endpoints: []model.Endpoint{wireguard}}, HostFacts{
		Platform: platform.Keenetic, Capabilities: set,
	})
	if err == nil || !strings.Contains(err.Error(), "native.operation.wireguard.create") {
		t.Fatalf("error = %v, want exact unwired create capability", err)
	}
	plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{managedAWG()}}, HostFacts{
		Platform: platform.Keenetic, Capabilities: set, OccupiedInterfaces: map[string]bool{},
	})
	if err != nil || plan.Decisions[0].Path != PathEnginePlugin {
		t.Fatalf("AmneziaWG endpoint on an unwired NDM writer: plan %+v, err %v", plan, err)
	}
}

func TestCompileKeeneticUsesNativePlanWhenExactAuthoritiesAreProven(t *testing.T) {
	endpoint := managedAWG()
	protocol := string(endpoint.Protocol)
	plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, HostFacts{
		Platform: platform.Keenetic,
		Capabilities: usableCapabilities(
			platform.NativeOperationCapabilityID(protocol, platform.NativeCreate),
			platform.NativeOperationCapabilityID(protocol, platform.NativeRemove),
		),
		OccupiedInterfaces: map[string]bool{"Wireguard10": true, "Wireguard11": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Keenetic == nil || len(plan.Keenetic.Interfaces) != 1 || plan.Keenetic.Singbox != nil {
		t.Fatalf("Keenetic native plan = %#v", plan.Keenetic)
	}
	if plan.Decisions[0].Path != PathNativeCreate || plan.Decisions[0].Interface != "Wireguard12" {
		t.Fatalf("decision = %#v", plan.Decisions[0])
	}
}

func TestCompileKeeneticAdoptsKnownExternalOwnersWithoutWritePlan(t *testing.T) {
	endpoint := managedAWG()
	protocol := string(endpoint.Protocol)
	facts := HostFacts{
		Platform: platform.Keenetic,
		Capabilities: usableCapabilities(
			platform.NativeOperationCapabilityID(protocol, platform.NativeAdopt),
		),
		AdoptInterfaces:    map[string]string{endpoint.ID: "nwg5"},
		AdoptNDMNames:      map[string]string{endpoint.ID: "Wireguard5"},
		OccupiedInterfaces: map[string]bool{},
	}
	owners := []model.Owner{
		model.OwnerExternal, model.OwnerImported, model.OwnerSystem,
		model.OwnerThirdParty, model.OwnerUnknown,
	}
	for _, owner := range owners {
		t.Run(string(owner), func(t *testing.T) {
			candidate := endpoint
			candidate.Owner = owner
			plan, err := Compile(&model.Profile{Endpoints: []model.Endpoint{candidate}}, facts)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Keenetic.Interfaces) != 0 || plan.Decisions[0].Path != PathNativeAdopt ||
				plan.Decisions[0].Interface != "nwg5" {
				t.Fatalf("owner %q produced writable plan: %#v", owner, plan)
			}
		})
	}
}

func TestCompileKeeneticPreservesNativeConnectionsUnderCompatibilityRouting(t *testing.T) {
	native := managedAWG()
	native.ID, native.Name = "native-nl", "Native NL"
	native.Engine, native.Owner = model.EngineExternal, model.OwnerExternal
	native.Params["interface"] = "nwg1"
	proxy := model.Endpoint{
		ID: "proxy", Name: "Proxy", Enabled: true,
		Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "198.51.100.30", Port: 443,
		Params: map[string]any{"uuid": "11111111-1111-1111-1111-111111111111"},
	}
	profile := &model.Profile{
		Endpoints: []model.Endpoint{native, proxy},
		Groups: []model.Group{{
			ID: "fallback", Type: model.GroupFallback,
			Members: []string{native.ID, proxy.ID, model.OutboundDirect},
		}},
		RoutingLists: []model.RoutingList{{
			ID: "domains", Name: "Domains", Manual: []string{"example.com"},
			Outbound: "fallback", Enabled: true,
		}},
	}
	plan, err := Compile(profile, HostFacts{
		Platform: platform.Keenetic,
		Capabilities: usableCapabilities(
			platform.NativeOperationCapabilityID(string(native.Protocol), platform.NativeAdopt),
			platform.CapEngineSingbox,
			platform.CapProtocolPrefix+string(proxy.Protocol),
		),
		AdoptInterfaces:    map[string]string{native.ID: "nwg1"},
		AdoptNDMNames:      map[string]string{native.ID: "Wireguard1"},
		OccupiedInterfaces: map[string]bool{"Wireguard1": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Keenetic == nil || !plan.Keenetic.CompatibilityRouting ||
		len(plan.Keenetic.Routes) != 0 || len(plan.Keenetic.Interfaces) != 0 {
		t.Fatalf("Keenetic compatibility plan = %#v", plan.Keenetic)
	}
	if len(plan.Decisions) != 2 || plan.Decisions[0].Path != PathNativeAdopt ||
		plan.Decisions[0].Interface != "nwg1" || plan.Decisions[1].Path != PathCompatibility ||
		plan.Decisions[1].Interface != "wrtun0" {
		t.Fatalf("native-first decisions = %#v", plan.Decisions)
	}
}

func TestCompileKeeneticRefusesWayHopOwnedEndpointOnAdoptPath(t *testing.T) {
	endpoint := managedAWG()
	endpoint.Engine = model.EngineExternal
	endpoint.Owner = model.OwnerWayHop
	endpoint.Params["interface"] = "nwg5"
	protocol := string(endpoint.Protocol)
	_, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, HostFacts{
		Platform: platform.Keenetic,
		Capabilities: usableCapabilities(
			platform.NativeOperationCapabilityID(protocol, platform.NativeAdopt),
		),
		AdoptInterfaces:    map[string]string{endpoint.ID: "nwg5"},
		AdoptNDMNames:      map[string]string{endpoint.ID: "Wireguard5"},
		OccupiedInterfaces: map[string]bool{"Wireguard5": true},
	})
	if err == nil || !strings.Contains(err.Error(), "external ownership") {
		t.Fatalf("WayHop-owned external endpoint error = %v, want external-ownership refusal", err)
	}
}

func TestCompileKeeneticRefusesUnrecognisedOwner(t *testing.T) {
	endpoint := managedAWG()
	endpoint.Owner = model.Owner("future-owner")
	protocol := string(endpoint.Protocol)
	_, err := Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, HostFacts{
		Platform: platform.Keenetic,
		Capabilities: usableCapabilities(
			platform.NativeOperationCapabilityID(protocol, platform.NativeCreate),
			platform.NativeOperationCapabilityID(protocol, platform.NativeRemove),
		),
		OccupiedInterfaces: map[string]bool{},
	})
	if err == nil || !strings.Contains(err.Error(), "ownership is not writable") {
		t.Fatalf("unrecognised owner error = %v, want fail-closed ownership refusal", err)
	}
}
