// Package nativeplan chooses the router-native connection authority before any compatibility
// engine is considered. It is pure: callers must capture HostFacts and persist the returned secret
// plans inside the strict Apply transaction before an adapter may execute them.
package nativeplan

import (
	"fmt"
	"sort"

	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
)

type Path string

const (
	PathNativeCreate  Path = "native_create"
	PathNativeManage  Path = "native_manage"
	PathNativeUpdate  Path = "native_update"
	PathNativeAdopt   Path = "native_adopt"
	PathCompatibility Path = "compatibility_addon"
	PathExternal      Path = "external_binding"
)

type EndpointDecision struct {
	EndpointID  string
	Protocol    model.Protocol
	Path        Path
	Interface   string
	Capability  string
	RollbackCap string
}

// HostFacts are captured, immutable inputs. OpenWrt snapshots must come from one observation;
// AdoptInterfaces must contain live, ownership-checked bindings rather than desired Params values.
type HostFacts struct {
	Platform        platform.Platform
	Capabilities    platform.CapabilitySet
	NetworkUCI      string
	FirewallUCI     string
	RouterProtos    netvpn.RouterProtos
	FirewallZone    string
	AdoptInterfaces map[string]string
	// AdoptNDMNames is the Keenetic-only companion to AdoptInterfaces: the NDM interface name
	// (`Wireguard0`) for the adopted kernel link (`nwg0`). Routes target the NDM name; the kernel
	// name is what the live-link probe uses. Captured, never derived.
	AdoptNDMNames map[string]string
	// DomainsViaDNSMasq is captured, not assumed: it says this router has both the kernel plane and a
	// resolver able to populate its sets, which is what lets a domain list skip the compatibility core.
	DomainsViaDNSMasq bool
	// OwnedInterfaces comes only from the authenticated previous native plan. A live UCI section
	// or deterministic wr_* name is not ownership evidence and must never authorize an update.
	OwnedInterfaces    map[string]string
	OccupiedInterfaces map[string]bool
	// GlobalPriorities is the router's own `ip global` ladder (Keenetic). A default route is
	// expressed by raising an interface above whatever holds it today, so the plan is compiled
	// against these observed numbers rather than invented ones.
	GlobalPriorities map[string]int
	// ListsViaIpset: the kernel policy plane carries routing lists, so the NDM plane must not also
	// emit their destinations as static routes.
	ListsViaIpset bool
}

// Plan is credential-bearing. It must never be exposed through the public review DTO.
type Plan struct {
	Platform  platform.Platform
	Decisions []EndpointDecision
	OpenWrt   []netvpn.Plan
	Keenetic  *keenetic.Plan
}

func Compile(profile *model.Profile, facts HostFacts) (*Plan, error) {
	if profile == nil {
		return nil, fmt.Errorf("native plan: profile is nil")
	}
	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("native plan: invalid profile: %w", err)
	}
	switch facts.Platform {
	case platform.OpenWrt:
		return compileOpenWrt(profile, facts)
	case platform.Keenetic:
		return compileKeenetic(profile, facts)
	default:
		return nil, fmt.Errorf("native plan: platform %q is not a supported router backend", facts.Platform)
	}
}

func compileOpenWrt(profile *model.Profile, facts HostFacts) (*Plan, error) {
	plan := &Plan{Platform: platform.OpenWrt}
	existing := netvpn.ParseUCIShow(facts.NetworkUCI)
	claimedInterfaces := make(map[string]string)
	for _, endpoint := range profile.Endpoints {
		if !endpoint.Enabled {
			continue
		}
		protocol, native := netvpn.ProtoForModel(endpoint.Protocol)
		if !native {
			decision, err := compatibilityDecision(endpoint, facts.Capabilities)
			if err != nil {
				return nil, err
			}
			if decision.Path == PathExternal {
				decision.Interface = facts.AdoptInterfaces[endpoint.ID]
				if err := reserveInterface(claimedInterfaces, decision.Interface, endpoint.ID); err != nil {
					return nil, err
				}
			}
			plan.Decisions = append(plan.Decisions, decision)
			continue
		}
		if endpoint.IsExternal() || endpoint.Engine == model.EngineExternal {
			decision, err := adoptDecision(endpoint, facts, protocol)
			if err != nil {
				return nil, err
			}
			if err := reserveInterface(claimedInterfaces, decision.Interface, endpoint.ID); err != nil {
				return nil, err
			}
			plan.Decisions = append(plan.Decisions, decision)
			continue
		}
		if endpoint.Engine != model.EngineAmneziaWG && endpoint.Engine != model.EngineSingBox {
			return nil, fmt.Errorf("native plan: endpoint %q uses engine %q, which cannot materialize a native WireGuard-family interface", endpoint.ID, endpoint.Engine)
		}
		decision, devicePlan, err := compileOpenWrtNativeEndpoint(endpoint, protocol, facts, existing)
		if err == nil {
			err = reserveInterface(claimedInterfaces, decision.Interface, endpoint.ID)
		}
		if err != nil {
			// EngineSingBox explicitly authorizes the compatibility addon. Native remains the
			// first choice, but a missing native writer or a profile shape the router cannot
			// represent losslessly (for example a sing-box-only WireGuard endpoint) must stay
			// on that addon instead of making the whole strict review unavailable. An endpoint
			// assigned to a native engine has granted no such fallback and still fails closed.
			if endpoint.Engine != model.EngineSingBox {
				return nil, err
			}
			decision, err = compatibilityDecision(endpoint, facts.Capabilities)
			if err != nil {
				return nil, err
			}
			plan.Decisions = append(plan.Decisions, decision)
			continue
		}
		plan.Decisions = append(plan.Decisions, decision)
		plan.OpenWrt = append(plan.OpenWrt, devicePlan)
	}
	canonicalize(plan)
	return plan, nil
}

func compileOpenWrtNativeEndpoint(
	endpoint model.Endpoint,
	protocol netvpn.Proto,
	facts HostFacts,
	existing map[string]netvpn.AWGInterface,
) (EndpointDecision, netvpn.Plan, error) {
	if !endpoint.OwnsResource() {
		return EndpointDecision{}, netvpn.Plan{},
			fmt.Errorf("native plan: endpoint %q ownership is not writable", endpoint.ID)
	}
	name := netvpn.InterfaceName(endpoint)
	operation := platform.NativeCreate
	path := PathNativeCreate
	if _, found := existing[name]; found {
		if facts.OwnedInterfaces[endpoint.ID] != name {
			return EndpointDecision{}, netvpn.Plan{},
				fmt.Errorf("native plan: endpoint %q cannot update existing interface %q without authenticated ownership", endpoint.ID, name)
		}
		operation = platform.NativeUpdate
		path = PathNativeUpdate
	}
	capability := platform.NativeOperationCapabilityID(string(endpoint.Protocol), operation)
	if err := requireCapability(facts.Capabilities, capability, endpoint.ID); err != nil {
		return EndpointDecision{}, netvpn.Plan{}, err
	}
	removeCapability := platform.NativeOperationCapabilityID(string(endpoint.Protocol), platform.NativeRemove)
	if err := requireCapability(facts.Capabilities, removeCapability, endpoint.ID); err != nil {
		return EndpointDecision{}, netvpn.Plan{}, fmt.Errorf("native plan: rollback authority: %w", err)
	}
	intended, err := netvpn.InterfaceFromEndpoint(endpoint, name, protocol)
	if err != nil {
		return EndpointDecision{}, netvpn.Plan{}, fmt.Errorf("native plan: endpoint %q: %w", endpoint.ID, err)
	}
	if facts.FirewallZone == "" {
		return EndpointDecision{}, netvpn.Plan{},
			fmt.Errorf("native plan: endpoint %q requires an explicitly reviewed OpenWrt firewall zone", endpoint.ID)
	}
	devicePlan, err := netvpn.BuildPlanFor(
		intended, facts.RouterProtos, facts.FirewallZone, facts.NetworkUCI, facts.FirewallUCI,
	)
	if err != nil {
		return EndpointDecision{}, netvpn.Plan{}, fmt.Errorf("native plan: endpoint %q: %w", endpoint.ID, err)
	}
	return EndpointDecision{
		EndpointID: endpoint.ID, Protocol: endpoint.Protocol, Path: path, Interface: name,
		Capability: capability, RollbackCap: removeCapability,
	}, devicePlan, nil
}

func reserveInterface(claimed map[string]string, name, endpointID string) error {
	if err := netvpn.ValidInterfaceName(name); err != nil {
		return fmt.Errorf("native plan: endpoint %q has no safe captured interface: %w", endpointID, err)
	}
	if previous := claimed[name]; previous != "" && previous != endpointID {
		return fmt.Errorf("native plan: endpoints %q and %q claim the same interface %q", previous, endpointID, name)
	}
	claimed[name] = endpointID
	return nil
}

func compileKeenetic(profile *model.Profile, facts HostFacts) (*Plan, error) {
	plan := &Plan{Platform: platform.Keenetic}
	for _, endpoint := range profile.Endpoints {
		if !endpoint.Enabled {
			continue
		}
		_, native := netvpn.ProtoForModel(endpoint.Protocol)
		if !native {
			decision, err := compatibilityDecision(endpoint, facts.Capabilities)
			if err != nil {
				return nil, err
			}
			plan.Decisions = append(plan.Decisions, decision)
			continue
		}
		if endpoint.IsExternal() || endpoint.Engine == model.EngineExternal {
			decision, err := adoptDecision(endpoint, facts, netvpn.Proto(endpoint.Protocol))
			if err != nil {
				return nil, err
			}
			plan.Decisions = append(plan.Decisions, decision)
			continue
		}
		if endpoint.Engine != model.EngineAmneziaWG && endpoint.Engine != model.EngineSingBox {
			return nil, fmt.Errorf("native plan: endpoint %q uses engine %q, which cannot materialize a native WireGuard-family interface", endpoint.ID, endpoint.Engine)
		}
		// Native create/remove is destructive authority. Keep the Keenetic path aligned with
		// OpenWrt: an unrecognised future owner also fails closed because IsExternal only knows
		// ownership classes defined by this build, while OwnsResource is the actual authority gate.
		if !endpoint.OwnsResource() {
			return nil, fmt.Errorf("native plan: endpoint %q ownership is not writable", endpoint.ID)
		}
		capability := platform.NativeOperationCapabilityID(string(endpoint.Protocol), platform.NativeCreate)
		if err := requireCapability(facts.Capabilities, capability, endpoint.ID); err != nil {
			return nil, err
		}
		removeCapability := platform.NativeOperationCapabilityID(string(endpoint.Protocol), platform.NativeRemove)
		if err := requireCapability(facts.Capabilities, removeCapability, endpoint.ID); err != nil {
			return nil, fmt.Errorf("native plan: rollback authority: %w", err)
		}
		plan.Decisions = append(plan.Decisions, EndpointDecision{
			EndpointID: endpoint.ID, Protocol: endpoint.Protocol, Path: PathNativeCreate,
			Capability: capability, RollbackCap: removeCapability,
		})
	}
	compiled, err := keenetic.Compile(profile, keenetic.CompileOptions{
		AdoptInterfaces:    cloneMap(facts.AdoptInterfaces),
		AdoptNDMNames:      cloneMap(facts.AdoptNDMNames),
		DomainsViaDNSMasq:  facts.DomainsViaDNSMasq,
		GlobalPriorityNow:  cloneIntMap(facts.GlobalPriorities),
		ListsViaIpset:      facts.ListsViaIpset,
		OccupiedInterfaces: cloneBoolMap(facts.OccupiedInterfaces),
	})
	if err != nil {
		return nil, fmt.Errorf("native plan: keenetic: %w", err)
	}
	for i := range plan.Decisions {
		decision := &plan.Decisions[i]
		compiledInterface := compiled.IfaceFor[decision.EndpointID]
		// An adopted decision arrives carrying the KERNEL name it was probed by, while Compile
		// assigns the NDM name its routes must use. Comparing the two namespaces would reject every
		// adopted endpoint, so the expectation is translated first; a decision that named a kernel
		// link whose NDM identity does not match is still refused.
		expected := decision.Interface
		if decision.Path == PathNativeAdopt {
			expected = facts.AdoptNDMNames[decision.EndpointID]
		}
		if compiledInterface == "" || (expected != "" && expected != compiledInterface) {
			return nil, fmt.Errorf("native plan: Keenetic endpoint %q has no consistent compiled interface identity", decision.EndpointID)
		}
		// An adopted decision keeps the KERNEL link it was probed by. The NDM name its routes need
		// lives in the compiled plan's IfaceFor, which is where the route builder reads it; copying
		// it here instead would break every consumer that treats Decision.Interface as the live
		// interface — the execution capture compares it against the endpoint's own params, and a
		// namespace mismatch there fails the whole snapshot.
		if decision.Path != PathNativeAdopt {
			decision.Interface = compiledInterface
		}
	}
	plan.Keenetic = compiled
	canonicalize(plan)
	return plan, nil
}

func adoptDecision(endpoint model.Endpoint, facts HostFacts, _ netvpn.Proto) (EndpointDecision, error) {
	legacyOpenWrtExternal := facts.Platform == platform.OpenWrt &&
		endpoint.Engine == model.EngineExternal && endpoint.Owner == model.OwnerWayHop
	if !endpoint.IsExternal() && !legacyOpenWrtExternal {
		return EndpointDecision{}, fmt.Errorf("native plan: endpoint %q requires explicit external ownership before adoption", endpoint.ID)
	}
	name := facts.AdoptInterfaces[endpoint.ID]
	if err := netvpn.ValidInterfaceName(name); err != nil {
		return EndpointDecision{}, fmt.Errorf("native plan: endpoint %q has no captured adoptable interface: %w", endpoint.ID, err)
	}
	capability := platform.NativeOperationCapabilityID(string(endpoint.Protocol), platform.NativeAdopt)
	if err := requireCapability(facts.Capabilities, capability, endpoint.ID); err != nil {
		return EndpointDecision{}, err
	}
	return EndpointDecision{
		EndpointID: endpoint.ID, Protocol: endpoint.Protocol, Path: PathNativeAdopt,
		Interface: name, Capability: capability,
	}, nil
}

func compatibilityDecision(endpoint model.Endpoint, capabilities platform.CapabilitySet) (EndpointDecision, error) {
	if endpoint.Engine == model.EngineExternal || endpoint.IsExternal() {
		return EndpointDecision{EndpointID: endpoint.ID, Protocol: endpoint.Protocol, Path: PathExternal}, nil
	}
	if endpoint.Engine != model.EngineSingBox {
		return EndpointDecision{}, fmt.Errorf("native plan: endpoint %q protocol %q has no native path and engine %q is not a supported addon", endpoint.ID, endpoint.Protocol, endpoint.Engine)
	}
	if err := requireCapability(capabilities, platform.CapEngineSingbox, endpoint.ID); err != nil {
		return EndpointDecision{}, err
	}
	protocolCapability := platform.CapProtocolPrefix + string(endpoint.Protocol)
	if err := requireCapability(capabilities, protocolCapability, endpoint.ID); err != nil {
		return EndpointDecision{}, err
	}
	return EndpointDecision{
		EndpointID: endpoint.ID, Protocol: endpoint.Protocol, Path: PathCompatibility,
		Capability: protocolCapability,
	}, nil
}

func requireCapability(capabilities platform.CapabilitySet, id, endpointID string) error {
	capability := capabilities.Get(id)
	if !capability.State.Usable() {
		return fmt.Errorf("native plan: endpoint %q requires unavailable capability %q (%s)", endpointID, id, capability.Reason)
	}
	return nil
}

func canonicalize(plan *Plan) {
	sort.Slice(plan.Decisions, func(i, j int) bool { return plan.Decisions[i].EndpointID < plan.Decisions[j].EndpointID })
	sort.Slice(plan.OpenWrt, func(i, j int) bool { return plan.OpenWrt[i].Iface < plan.OpenWrt[j].Iface })
}

// cloneIntMap is cloneMap for the observed `ip global` ladder.
func cloneIntMap(source map[string]int) map[string]int {
	if source == nil {
		return nil
	}
	result := make(map[string]int, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneBoolMap(source map[string]bool) map[string]bool {
	if source == nil {
		return nil
	}
	result := make(map[string]bool, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
