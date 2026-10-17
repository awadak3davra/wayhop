// Package nativeplan chooses the router-native connection authority before any compatibility
// engine is considered. It is pure: callers must capture HostFacts and persist the returned secret
// plans inside the strict Apply transaction before an adapter may execute them.
package nativeplan

import (
	"fmt"
	"sort"
	"strings"

	"wayhop/internal/awg"
	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
	"wayhop/internal/util"
)

type Path string

const (
	PathNativeCreate  Path = "native_create"
	PathNativeManage  Path = "native_manage"
	PathNativeUpdate  Path = "native_update"
	PathNativeAdopt   Path = "native_adopt"
	PathCompatibility Path = "compatibility_addon"
	PathExternal      Path = "external_binding"
	// PathEnginePlugin is an endpoint WayHop's own engine plugin runs because the router's native
	// writer cannot carry it (see KeeneticUserspace): no native resource is created, updated or
	// removed for it, so it carries no native authority, and its Interface is the device the plugin
	// creates.
	PathEnginePlugin Path = "engine_plugin"
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
	// PluginDevices comes only from the authenticated previous plan: endpoint -> the device WayHop's
	// AmneziaWG engine ran it on. On OpenWrt that device and the native interface share one name, so
	// an endpoint moving from one to the other is refused (see MoveError).
	PluginDevices map[string]string
	// AWGKernel is the generation of the router's loaded AmneziaWG kernel module, captured with the
	// rest: awg.ProbeHost().Kernel, GenNone when the probe failed or found none, and on OpenWrt no
	// more than the netifd handler passes on (min with netvpn.HandlerAWGGeneration of
	// /lib/netifd/proto/amneziawg.sh). On OpenWrt it is what the UCI writer may write up to
	// (netvpn.AWGWriterGeneration): with a 3.0 or 3.1 module an AmneziaWG 3 connection runs as the
	// router's own interface instead of on WayHop's engine. The zero value keeps the writer at
	// generation 2, as before the module was asked. KeeneticOS ignores it: NDM's writer is
	// generation 2 whatever the module.
	AWGKernel awg.Generation
}

// Plan is credential-bearing. It must never be exposed through the public review DTO.
type Plan struct {
	Platform  platform.Platform
	Decisions []EndpointDecision
	OpenWrt   []netvpn.Plan
	// OpenWrtBindings put each engine-plugin device into the reviewed firewall zone, one per
	// PathEnginePlugin decision on OpenWrt.
	OpenWrtBindings []netvpn.DeviceBinding `json:",omitempty"`
	Keenetic        *keenetic.Plan
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
	userspace := OpenWrtUserspaceFor(profile, facts.Capabilities, facts.AWGKernel)
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
		if lane, ok := userspace[endpoint.ID]; ok {
			decision, binding, err := compileOpenWrtUserspaceEndpoint(endpoint, lane, facts, existing)
			if err == nil {
				err = reserveInterface(claimedInterfaces, decision.Interface, endpoint.ID)
			}
			if err != nil {
				return nil, err
			}
			plan.Decisions = append(plan.Decisions, decision)
			plan.OpenWrtBindings = append(plan.OpenWrtBindings, binding)
			continue
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
	if device := facts.PluginDevices[endpoint.ID]; device != "" {
		return EndpointDecision{}, netvpn.Plan{}, &MoveError{EndpointID: endpoint.ID, Device: device, ToNative: true,
			Why: OpenWrtMoveReason(endpoint, facts.AWGKernel)}
	}
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
	intended, err := netvpn.InterfaceFromEndpointFor(endpoint, name, protocol, facts.AWGKernel)
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
	userspace := UserspaceDevices(KeeneticUserspace(profile, facts.Capabilities))
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
		// NDM cannot carry it, so WayHop's AmneziaWG engine does; this set holds every endpoint with
		// settings beyond NDM's writer, so none reaches the native branch below.
		if device := userspace[endpoint.ID]; device != "" {
			plan.Decisions = append(plan.Decisions, EndpointDecision{
				EndpointID: endpoint.ID, Protocol: endpoint.Protocol, Path: PathEnginePlugin, Interface: device,
			})
			continue
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
		Userspace:          userspace,
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

// MoveError is an OpenWrt endpoint that would change hands within one Apply between the router's own
// AmneziaWG and WayHop's userspace engine. Both run it on a device of the same name (util.AWGIface),
// and the executor starts the plugins after the native prepare and removes native interfaces at the
// commit: netifd's teardown of the old interface would delete the plugin's new TUN by that name, and
// a new native interface cannot be created while the old TUN still holds it. Refused, with the way
// round it: two Applies, one without the connection and one with it.
//
// One such move comes with no change to the profile at all: an AmneziaWG 3 connection the engine ran
// because the router's kernel module was too old, after that module is upgraded to a generation that
// carries it. Why says so, so the refusal names the upgrade rather than leaving the operator to wonder
// what they changed.
type MoveError struct {
	EndpointID string
	Device     string
	ToNative   bool   // the engine ran it and OpenWrt's own AmneziaWG would now; false is the other way
	Why        string // what made the move, when it is not the operator's own change (OpenWrtMoveReason)
}

func (e *MoveError) Error() string {
	from, to := "OpenWrt's own AmneziaWG", "WayHop's userspace AmneziaWG"
	if e.ToNative {
		from, to = to, from
	}
	why := ""
	if e.Why != "" {
		why = " (" + e.Why + ")"
	}
	return fmt.Sprintf("native plan: endpoint %q would move from %s to %s in one Apply%s, and both run it on device %s; "+
		"switch the connection off and apply, then switch it on and apply again - it carries no traffic between the two",
		e.EndpointID, from, to, why, e.Device)
}

// OpenWrtMoveReason says why an OpenWrt AmneziaWG connection that WayHop's engine ran at the last Apply
// would now be the router's own: its settings are beyond the UCI writer's baseline generation, and
// the router's kernel module now carries them. "" when that is not the reason - a connection set back
// to Automatic moves because the operator said so. The planner puts it in MoveError; the review can
// show the same words beside its own account of the move.
func OpenWrtMoveReason(endpoint model.Endpoint, kernel awg.Generation) string {
	if endpoint.Protocol != model.ProtoAmneziaWG || endpoint.AWGUserspace ||
		len(BeyondNative(endpoint, platform.OpenWrt)) == 0 ||
		len(BeyondNativeFor(endpoint, platform.OpenWrt, kernel)) != 0 {
		return ""
	}
	return "the router's AmneziaWG kernel module is generation " + kernel.String() +
		", so OpenWrt's own AmneziaWG now carries its AmneziaWG " + awg.Need(endpoint.Params).String() + " settings"
}

// Userspace is UserspaceFor with no kernel module generation known: the native writers at their
// baselines.
func Userspace(profile *model.Profile, p platform.Platform, capabilities platform.CapabilitySet) map[string]UserspaceEndpoint {
	return UserspaceFor(profile, p, capabilities, awg.GenNone)
}

// UserspaceFor is the userspace-lane set for the platform - KeeneticUserspace or OpenWrtUserspaceFor -
// and empty for a platform with no native plan. kernel is HostFacts.AWGKernel: the review must ask
// with the generation the planner compiles with, or the two disagree about where a connection runs.
func UserspaceFor(profile *model.Profile, p platform.Platform, capabilities platform.CapabilitySet, kernel awg.Generation) map[string]UserspaceEndpoint {
	switch p {
	case platform.Keenetic:
		return KeeneticUserspace(profile, capabilities)
	case platform.OpenWrt:
		return OpenWrtUserspaceFor(profile, capabilities, kernel)
	}
	return map[string]UserspaceEndpoint{}
}

// OpenWrtUserspace is OpenWrtUserspaceFor with no kernel module generation known: the UCI writer at
// generation 2, as before it asked the module.
func OpenWrtUserspace(profile *model.Profile, capabilities platform.CapabilitySet) map[string]UserspaceEndpoint {
	return OpenWrtUserspaceFor(profile, capabilities, awg.GenNone)
}

// OpenWrtUserspaceFor is the set of AmneziaWG endpoints OpenWrt runs on WayHop's own engine next to its
// native tunnels: settings beyond what the UCI writer carries with this kernel module (kernel, see
// HostFacts.AWGKernel), or a connection set to run on amneziawg-go, on a router whose native AmneziaWG
// would otherwise take them. Without a usable native AmneziaWG the endpoint is not in the set - the
// capability refusal hands the whole profile to the generic path, where the plugin runs it anyway (on
// amneziawg-go when it is set to). The planner decides by this set and the review explains by it.
//
// With a 3.1 module nothing but the operator's choice puts a connection here: every setting a
// connection can carry is one the router's own interface carries.
func OpenWrtUserspaceFor(profile *model.Profile, capabilities platform.CapabilitySet, kernel awg.Generation) map[string]UserspaceEndpoint {
	out := map[string]UserspaceEndpoint{}
	if profile == nil {
		return out
	}
	for _, endpoint := range profile.Endpoints {
		if !endpoint.Enabled || endpoint.Engine != model.EngineAmneziaWG || !endpoint.OwnsResource() {
			continue
		}
		if !nativeAWGUsable(endpoint, capabilities) {
			continue
		}
		if endpoint.AWGUserspace {
			out[endpoint.ID] = UserspaceEndpoint{
				Device: util.AWGIface(endpoint.ID), Code: platform.ReasonOperatorChoice,
				Reason: awgChosenReason("OpenWrt's", NativeAWGGenerationFor(platform.OpenWrt, kernel)),
				Remedy: "Set the connection's engine back to Automatic to run it on OpenWrt's own AmneziaWG.",
			}
			continue
		}
		settings := BeyondNativeFor(endpoint, platform.OpenWrt, kernel)
		if len(settings) == 0 {
			continue
		}
		need := awg.Need(endpoint.Params)
		// The module is what is missing, and WayHop ships one: the remedy says which, and what moving
		// a running connection over then takes (MoveError).
		out[endpoint.ID] = UserspaceEndpoint{
			Device: util.AWGIface(endpoint.ID),
			Reason: fmt.Sprintf("it uses AmneziaWG %s settings (%s) that OpenWrt's own AmneziaWG cannot carry: %s",
				need, strings.Join(settings, ", "), netvpn.KernelModuleWords(kernel)),
			Code: platform.ReasonMissingKernelModule,
			Remedy: "Install AmneziaWG " + need.String() + " or newer for OpenWrt (kmod-amneziawg with amneziawg-tools) " +
				"to run it as the router's own interface. Moving it there from WayHop's engine then takes two Applies: " +
				"switch the connection off and apply, then switch it on and apply again.",
		}
	}
	return out
}

// awgChosenReason is the userspace lane's reason for a connection the operator set to run on
// amneziawg-go (Endpoint.AWGUserspace), with the router's own AmneziaWG named - whose it is - and the
// generation it carries: amneziawg-go is the newest only while the router's own is older.
func awgChosenReason(whose string, native awg.Generation) string {
	if native >= awg.UserspaceGeneration {
		return "it is set to run on amneziawg-go rather than on " + whose + " own AmneziaWG, which is generation " +
			native.String() + " too"
	}
	return "it is set to run on amneziawg-go, the newest AmneziaWG, rather than on " + whose + " own AmneziaWG"
}

// NativeAWGAvailable reports whether the router's own AmneziaWG could create and remove an AmneziaWG
// interface at all - what the Components page asks before it names the generation the router carries.
func NativeAWGAvailable(capabilities platform.CapabilitySet) bool {
	return nativeAWGUsable(model.Endpoint{Protocol: model.ProtoAmneziaWG}, capabilities)
}

// nativeAWGUsable reports whether the router's own AmneziaWG could create and remove this endpoint's
// interface - the capabilities the native writer is gated on.
func nativeAWGUsable(endpoint model.Endpoint, capabilities platform.CapabilitySet) bool {
	for _, operation := range []platform.NativeOperation{platform.NativeCreate, platform.NativeRemove} {
		if !capabilities.Get(platform.NativeOperationCapabilityID(string(endpoint.Protocol), operation)).State.Usable() {
			return false
		}
	}
	return true
}

// compileOpenWrtUserspaceEndpoint gives an endpoint in the OpenWrt userspace lane its decision and
// the binding that puts its device into the reviewed firewall zone. An interface of the same name on
// the router - WayHop's own from a previous Apply, or anyone's - is a move this Apply cannot make.
func compileOpenWrtUserspaceEndpoint(
	endpoint model.Endpoint,
	lane UserspaceEndpoint,
	facts HostFacts,
	existing map[string]netvpn.AWGInterface,
) (EndpointDecision, netvpn.DeviceBinding, error) {
	if _, found := existing[lane.Device]; found || facts.OwnedInterfaces[endpoint.ID] != "" {
		return EndpointDecision{}, netvpn.DeviceBinding{}, &MoveError{EndpointID: endpoint.ID, Device: lane.Device}
	}
	if facts.FirewallZone == "" {
		return EndpointDecision{}, netvpn.DeviceBinding{},
			fmt.Errorf("native plan: endpoint %q requires an explicitly reviewed OpenWrt firewall zone", endpoint.ID)
	}
	binding, err := netvpn.BuildDeviceBinding(lane.Device, facts.FirewallZone, facts.FirewallUCI)
	if err != nil {
		return EndpointDecision{}, netvpn.DeviceBinding{}, fmt.Errorf("native plan: endpoint %q: %w", endpoint.ID, err)
	}
	return EndpointDecision{
		EndpointID: endpoint.ID, Protocol: endpoint.Protocol, Path: PathEnginePlugin, Interface: lane.Device,
	}, binding, nil
}

// UserspaceEndpoint is an AmneziaWG endpoint WayHop runs on its own engine instead of the router's
// AmneziaWG.
type UserspaceEndpoint struct {
	Device string              // the device WayHop's AmneziaWG engine creates for it
	Reason string              // why the router's own AmneziaWG does not carry it, in words for the review
	Code   platform.ReasonCode // the same, as a stable code
	Remedy string              // what would let the router carry it natively, when anything would
}

// KeeneticUserspace is the set of AmneziaWG endpoints KeeneticOS runs on WayHop's own AmneziaWG
// engine rather than on NDM: an endpoint whose settings NDM's writer cannot carry, or one NDM cannot
// create at all - no AmneziaWG in this firmware, its WireGuard component not installed. Either way
// the plugin runs it on amneziawg-go, so the connection comes up instead of being refused or written
// without the settings its server requires. The native planner decides by this set and the Apply
// review explains by it, so the two cannot disagree.
//
// Only WayHop's own AmneziaWG endpoints qualify: an adopted tunnel stays the router's, and a
// sing-box WireGuard endpoint has no userspace engine here. A previously native endpoint that lands
// in the set is torn down natively by the reconcile, whose remove authority it still needs - a
// capability probe that merely failed cannot move a working tunnel.
func KeeneticUserspace(profile *model.Profile, capabilities platform.CapabilitySet) map[string]UserspaceEndpoint {
	out := map[string]UserspaceEndpoint{}
	if profile == nil {
		return out
	}
	for _, endpoint := range profile.Endpoints {
		if u, ok := keeneticUserspaceReason(endpoint, capabilities); ok {
			u.Device = util.AWGIface(endpoint.ID)
			out[endpoint.ID] = u
		}
	}
	return out
}

// UserspaceDevices is the endpoint → device view that keenetic.CompileOptions.Userspace and
// keenetic.RoutePlanes take.
func UserspaceDevices(set map[string]UserspaceEndpoint) map[string]string {
	out := make(map[string]string, len(set))
	for id, endpoint := range set {
		out[id] = endpoint.Device
	}
	return out
}

func keeneticUserspaceReason(endpoint model.Endpoint, capabilities platform.CapabilitySet) (UserspaceEndpoint, bool) {
	// OwnsResource is the ownership gate: an adopted or imported tunnel stays the router's.
	if !endpoint.Enabled || endpoint.Engine != model.EngineAmneziaWG || !endpoint.OwnsResource() {
		return UserspaceEndpoint{}, false
	}
	if _, native := netvpn.ProtoForModel(endpoint.Protocol); !native {
		return UserspaceEndpoint{}, false
	}
	// The operator's choice moves it whatever NDM could carry. Unlike a failed probe below, the
	// choice is a definite answer, so a native tunnel it names is torn down by the reconcile.
	if endpoint.AWGUserspace {
		return UserspaceEndpoint{
			Reason: awgChosenReason("KeeneticOS's", keenetic.AWGGeneration), Code: platform.ReasonOperatorChoice,
			Remedy: "Set the connection's engine back to Automatic to run it on KeeneticOS's own AmneziaWG.",
		}, true
	}
	if settings := BeyondNative(endpoint, platform.Keenetic); len(settings) != 0 {
		return UserspaceEndpoint{
			Reason: fmt.Sprintf("it uses AmneziaWG %s settings (%s) that KeeneticOS's own AmneziaWG cannot carry",
				awg.Need(endpoint.Params), strings.Join(settings, ", ")),
			Code: platform.ReasonPlatformUnsupported,
		}, true
	}
	for _, operation := range []platform.NativeOperation{platform.NativeCreate, platform.NativeRemove} {
		capability := capabilities.Get(platform.NativeOperationCapabilityID(string(endpoint.Protocol), operation))
		if capability.State.Usable() {
			continue
		}
		// Only a definite answer moves the endpoint: this firmware has no AmneziaWG, its component is
		// not installed, or this build does not drive NDM for it. A probe that failed is not an answer;
		// the endpoint stays on the native path, which then refuses for want of the capability.
		switch capability.Reason {
		case platform.ReasonPlatformUnsupported, platform.ReasonMissingFirmwareComp, platform.ReasonBackendNotWired:
			why := capability.Detail
			if why == "" {
				why = string(capability.Reason)
			}
			return UserspaceEndpoint{
				Reason: "KeeneticOS cannot run it natively (" + why + ")",
				Code:   capability.Reason, Remedy: capability.Remedy,
			}, true
		}
		return UserspaceEndpoint{}, false
	}
	return UserspaceEndpoint{}, false
}

// NativeAWGGeneration is NativeAWGGenerationFor with no kernel module generation known: each writer's
// baseline, the generation it expresses on any router.
func NativeAWGGeneration(p platform.Platform) awg.Generation {
	return NativeAWGGenerationFor(p, awg.GenNone)
}

// NativeAWGGenerationFor is the newest AmneziaWG generation the platform's native writer expresses on
// a router whose loaded kernel module is kernel: NDM's `wireguard asc` on KeeneticOS, which stays at
// its own whatever the module; the UCI interface on OpenWrt, which writes up to what the module
// carries (netvpn.AWGWriterGeneration). Each writer states its own, next to the settings it writes and
// held to them by its tests; GenNone is a platform with no writer.
func NativeAWGGenerationFor(p platform.Platform, kernel awg.Generation) awg.Generation {
	switch p {
	case platform.Keenetic:
		return keenetic.AWGGeneration
	case platform.OpenWrt:
		return netvpn.AWGWriterGeneration(kernel)
	}
	return awg.GenNone
}

// BeyondNative is BeyondNativeFor with no kernel module generation known.
func BeyondNative(endpoint model.Endpoint, p platform.Platform) []string {
	return BeyondNativeFor(endpoint, p, awg.GenNone)
}

// BeyondNativeFor lists, sorted, the endpoint's AmneziaWG settings that the platform's native writer
// cannot express with this kernel module, or nil when a native tunnel carries the endpoint as
// configured. The review asks it before Apply and Compile refuses on it, so the two cannot disagree -
// as long as both ask with the same kernel generation. Only an AmneziaWG endpoint is asked: a
// WireGuard one has no such settings to lose.
func BeyondNativeFor(endpoint model.Endpoint, p platform.Platform, kernel awg.Generation) []string {
	if endpoint.Protocol != model.ProtoAmneziaWG {
		return nil
	}
	return awg.Beyond(endpoint.Params, NativeAWGGenerationFor(p, kernel))
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
	sort.Slice(plan.OpenWrtBindings, func(i, j int) bool { return plan.OpenWrtBindings[i].Device < plan.OpenWrtBindings[j].Device })
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
