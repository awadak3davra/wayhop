package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/netvpn"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

const (
	executionNativeArtifactSchemaV1 = 1
	executionNativeDeltaSchemaV1    = 1
)

var errExecutionNativeArtifact = errors.New("native execution artifact is invalid")

// executionNativeCaptureV1 contains read-only router evidence captured in the same host pass as the
// Apply. Desired endpoint Params never substitute for these ownership and device facts.
type executionNativeCaptureV1 struct {
	NetworkUCI        string              `json:"network_uci,omitempty"`
	FirewallUCI       string              `json:"firewall_uci,omitempty"`
	KeeneticConfigRev string              `json:"keenetic_config_rev,omitempty"`
	RouterProtos      netvpn.RouterProtos `json:"router_protos,omitempty"`
	FirewallZone      string              `json:"firewall_zone,omitempty"`
	AdoptInterfaces   map[string]string   `json:"adopt_interfaces,omitempty"`
	// AdoptNDMNames is Keenetic-only: endpoint ID → the NDM interface name that owns the adopted
	// kernel link. omitempty keeps an OpenWrt capture encoding byte-identically.
	AdoptNDMNames map[string]string `json:"adopt_ndm_names,omitempty"`
	// AdoptForeign is Keenetic-only: endpoint ID → the kernel device of an adopted tunnel run outside
	// KeeneticOS, proven to be no NDM interface's link (validKeeneticAdoptEvidence). omitempty keeps
	// every capture without one encoding byte-identically.
	AdoptForeign map[string]string `json:"adopt_foreign,omitempty"`
	// DomainsViaDNSMasq records that the resolver-backed domain path was available when this was
	// captured, so a replay compiles the same plan that was reviewed rather than one that quietly
	// needs a proxy core because the resolver went missing in between.
	DomainsViaDNSMasq  bool            `json:"domains_via_dnsmasq,omitempty"`
	OccupiedInterfaces map[string]bool `json:"occupied_interfaces,omitempty"`
	// GlobalPriorities is Keenetic-only: each interface's `ip global` priority as the running config
	// read it. A native default route is expressed by raising one above the rest, so the plan has to
	// be compiled against the router's own numbers — and captured, like everything else here, so a
	// replay produces the ladder that was reviewed rather than one built from numbers that moved.
	GlobalPriorities map[string]int `json:"global_priorities,omitempty"`
	// ListsViaIpset records that the kernel policy plane was carrying routing lists when this was
	// captured, so a replay compiles the same plan that was reviewed rather than one that suddenly
	// wants thousands of static routes because ipset went missing in between.
	ListsViaIpset bool `json:"lists_via_ipset,omitempty"`
	// NDMPolicies is Keenetic-only: the access policies by name → mark as `show ip policy` read them,
	// captured only when a routing list points at one. The kernel plane and the core are compiled
	// against these numbers, so they are recorded with the plan rather than re-read later: NDM may
	// renumber its policies, and a replay must route by the marks that were reviewed. omitempty keeps
	// every other capture encoding byte-identically.
	NDMPolicies map[string]uint32 `json:"ndm_policies,omitempty"`
	// AWGKernel is OpenWrt's HostFacts.AWGKernel with the evidence it was decided on (awgkernel.go), so
	// a replay compiles the UCI interfaces at the generation that was reviewed, and a later capture whose
	// probe fails can tell whether that generation still holds. nil on KeeneticOS, which keeps its
	// capture encoding byte-identically.
	AWGKernel *awgKernelCaptureV1 `json:"awg_kernel,omitempty"`
	// ndmPresent is Keenetic-only: the interface headers and route identities the running config
	// carried, for ownershipBaseline. Unexported, so never recorded with the artifact.
	ndmPresent map[string]bool
}

// executionNativeArtifactV1 is the compiled native plan plus the capture it was compiled from. It is
// credential-bearing (the plan carries interface keys) and lives only inside the apply-state record.
type executionNativeArtifactV1 struct {
	SchemaVersion int                      `json:"schema_version"`
	Capture       executionNativeCaptureV1 `json:"capture"`
	Plan          nativeplan.Plan          `json:"plan"`
}

// executionNativeDeltaV1 is the one replayable native program the adapter receives: the exact target
// plus the ownership-filtered removals derived from the previous applied plan.
type executionNativeDeltaV1 struct {
	SchemaVersion int                       `json:"schema_version"`
	Reconcile     nativeplan.Reconciliation `json:"reconcile"`
}

// buildExecutionNativeArtifactV1 compiles the native plan for desired against the captured router
// facts. previous is the last applied native plan (nil on a first Apply); only interfaces it created
// count as WayHop-owned, so an existing UCI section or NDM block that WayHop did not create is never
// updated or deleted.
func buildExecutionNativeArtifactV1(
	desired DesiredSnapshot,
	host HostSnapshotV1,
	capture executionNativeCaptureV1,
	previous *nativeplan.Plan,
) (executionNativeArtifactV1, error) {
	return buildExecutionNativeArtifactFrom(desired, host, capture, previous, nil)
}

// buildExecutionNativeArtifactFrom is buildExecutionNativeArtifactV1 with the AmneziaWG devices a
// previous materialization WITHOUT a native plan ran on WayHop's own engine (genericPluginDevices),
// which previous cannot carry: it is nil then.
func buildExecutionNativeArtifactFrom(
	desired DesiredSnapshot,
	host HostSnapshotV1,
	capture executionNativeCaptureV1,
	previous *nativeplan.Plan,
	genericPlugins map[string]string,
) (executionNativeArtifactV1, error) {
	if desired.SchemaVersion != DesiredSnapshotSchemaV1 || host.SchemaVersion != HostSnapshotSchemaV1 ||
		(host.Platform == string(platform.OpenWrt) && capture.FirewallZone != desired.Config.NativeFirewallZone) ||
		(host.Platform == string(platform.Keenetic) &&
			(capture.FirewallZone != "" || capture.OccupiedInterfaces == nil ||
				!isLowerHexRevision(capture.KeeneticConfigRev, reviewSHA256HexLen))) {
		return executionNativeArtifactV1{}, errExecutionNativeArtifact
	}
	facts := nativeplan.HostFacts{
		Platform: platform.Platform(host.Platform), Capabilities: host.CapabilitySet,
		NetworkUCI: capture.NetworkUCI, FirewallUCI: capture.FirewallUCI,
		RouterProtos: cloneRouterProtos(capture.RouterProtos), FirewallZone: capture.FirewallZone,
		AdoptInterfaces:     cloneNativeInterfaces(capture.AdoptInterfaces),
		AdoptNDMNames:       cloneNativeInterfaces(capture.AdoptNDMNames),
		AdoptForeign:        cloneNativeInterfaces(capture.AdoptForeign),
		DomainsViaDNSMasq:   capture.DomainsViaDNSMasq,
		OwnedInterfaces:     nativeOwnershipFrom(previous),
		KeeneticOwnedBlocks: nativeplan.KeeneticOwnedBlocks(previous),
		PluginDevices:       mergeNativeInterfaces(nativePluginDevicesFrom(previous), genericPlugins),
		OccupiedInterfaces:  cloneNativeInterfaceSet(capture.OccupiedInterfaces),
		GlobalPriorities:    cloneNativePriorities(capture.GlobalPriorities),
		ListsViaIpset:       capture.ListsViaIpset,
		AWGKernel:           capture.AWGKernel.generation(),
		ProbePort:           desired.Config.Ports.Probe(),
		ClashSecret:         desired.Config.Clash.Secret,
		CoreVersion:         executionCoreVersion(host),
	}
	compiled, err := nativeplan.Compile(&desired.Profile, facts)
	if err != nil {
		// Both wrapped: the caller branches on the planner's typed refusals (MoveError), which a %v
		// would flatten into text.
		return executionNativeArtifactV1{}, fmt.Errorf("%w: %w", errExecutionNativeArtifact, err)
	}
	if compiled == nil {
		return executionNativeArtifactV1{}, fmt.Errorf("%w: the native planner returned no plan", errExecutionNativeArtifact)
	}
	artifact := executionNativeArtifactV1{
		SchemaVersion: executionNativeArtifactSchemaV1,
		Capture: executionNativeCaptureV1{
			NetworkUCI: capture.NetworkUCI, FirewallUCI: capture.FirewallUCI,
			KeeneticConfigRev: capture.KeeneticConfigRev,
			RouterProtos:      cloneRouterProtos(capture.RouterProtos), FirewallZone: capture.FirewallZone,
			AdoptInterfaces:    cloneNativeInterfaces(capture.AdoptInterfaces),
			AdoptNDMNames:      cloneNativeInterfaces(capture.AdoptNDMNames),
			AdoptForeign:       cloneNativeInterfaces(capture.AdoptForeign),
			DomainsViaDNSMasq:  capture.DomainsViaDNSMasq,
			OccupiedInterfaces: cloneNativeInterfaceSet(capture.OccupiedInterfaces),
			GlobalPriorities:   cloneNativePriorities(capture.GlobalPriorities),
			ListsViaIpset:      capture.ListsViaIpset,
			NDMPolicies:        cloneNDMPolicyMarks(capture.NDMPolicies),
			AWGKernel:          cloneAWGKernelCapture(capture.AWGKernel),
		},
		Plan: *compiled,
	}
	if artifact.Plan.Keenetic != nil {
		artifact.Plan.Keenetic.RunningConfigRev = capture.KeeneticConfigRev
	}
	return artifact, nil
}

// nativePluginDevicesFrom lists the devices WayHop's AmneziaWG engine ran endpoints on under the
// previous applied plan, which is what lets the planner see a move between that engine and the
// router's own AmneziaWG (nativeplan.MoveError).
func nativePluginDevicesFrom(previous *nativeplan.Plan) map[string]string {
	devices := make(map[string]string)
	if previous == nil {
		return devices
	}
	for _, decision := range previous.Decisions {
		if decision.Path == nativeplan.PathEnginePlugin && decision.EndpointID != "" && decision.Interface != "" {
			devices[decision.EndpointID] = decision.Interface
		}
	}
	return devices
}

// genericPluginDevices lists the AmneziaWG devices WayHop's own engine ran under a previous
// materialization that carried no native plan - the generic path, where an OpenWrt router lands when
// its native plan could not be compiled (QA-043: one ByeDPI connection did that). The router's own
// AmneziaWG creates the same device name, so taking such an endpoint native is the move the planner
// refuses within one Apply (nativeplan.MoveError); with no native previous it went unseen, and the
// new interface came up while the old plugin still held the link.
func genericPluginDevices(m *executionMaterializationV1) map[string]string {
	devices := make(map[string]string)
	if m == nil || !m.known() || m.nativeTarget() != nil {
		return devices
	}
	for i := range m.Plugins {
		e := &m.Plugins[i].Endpoint
		if e.Engine != model.EngineAmneziaWG || e.ID == "" {
			continue
		}
		if iface := pbr.KernelIface(e); iface != "" {
			devices[e.ID] = iface
		}
	}
	return devices
}

func mergeNativeInterfaces(a, b map[string]string) map[string]string {
	for k, v := range b {
		if _, ok := a[k]; !ok {
			a[k] = v
		}
	}
	return a
}

// nativeOwnershipFrom lists the interfaces the previous applied plan created or managed. Only those
// may be updated or removed by a later Apply.
func nativeOwnershipFrom(previous *nativeplan.Plan) map[string]string {
	owned := make(map[string]string)
	if previous == nil {
		return owned
	}
	for _, decision := range previous.Decisions {
		switch decision.Path {
		case nativeplan.PathNativeCreate, nativeplan.PathNativeManage, nativeplan.PathNativeUpdate:
			if decision.EndpointID != "" && decision.Interface != "" {
				owned[decision.EndpointID] = decision.Interface
			}
		}
	}
	return owned
}

// buildExecutionNativeDeltaV1 reconciles the previous applied native plan (nil = WayHop owns no
// native state yet) with the freshly compiled target.
func buildExecutionNativeDeltaV1(
	previousPlan *nativeplan.Plan,
	target executionNativeArtifactV1,
	capabilities platform.CapabilitySet,
) (executionNativeDeltaV1, error) {
	if target.SchemaVersion != executionNativeArtifactSchemaV1 ||
		(target.Plan.Platform != platform.OpenWrt && target.Plan.Platform != platform.Keenetic) {
		return executionNativeDeltaV1{}, errExecutionNativeArtifact
	}
	delta, err := nativeplan.Reconcile(previousPlan, &target.Plan, capabilities,
		target.Capture.NetworkUCI, target.Capture.FirewallUCI)
	if err != nil {
		return executionNativeDeltaV1{}, fmt.Errorf("%w: %v", errExecutionNativeArtifact, err)
	}
	return executionNativeDeltaV1{
		SchemaVersion: executionNativeDeltaSchemaV1,
		Reconcile:     *delta,
	}, nil
}

// nativeBaselineFromMaterialization returns an owned copy of the native plan a materialization
// installed, or nil when it carried no native program.
func nativeBaselineFromMaterialization(materialization *executionMaterializationV1) *nativeplan.Plan {
	target := materialization.nativeTarget()
	if target == nil {
		return nil
	}
	encoded, err := json.Marshal(target)
	if err != nil {
		return nil
	}
	var owned nativeplan.Plan
	if err := json.Unmarshal(encoded, &owned); err != nil {
		return nil
	}
	return &owned
}

// keeneticPresentIdentities is the interface headers and route identities a running config carries.
func keeneticPresentIdentities(running string) map[string]bool {
	present := make(map[string]bool)
	for _, line := range normalizedNDMConfigLines(running) {
		switch {
		case strings.HasPrefix(line, "interface "):
			present[line] = true
		case strings.HasPrefix(line, "ip route "), strings.HasPrefix(line, "ipv6 route "):
			present[keenetic.RouteKey(line)] = true
		}
	}
	return present
}

// ownershipBaseline is what an Apply compiles its native removals against while a rollback is
// outstanding: the live revision's materialization, plus the committed revision's router-native
// objects that this Apply's capture still finds on the router. The live revision alone left out the
// committed interfaces, routes and ladder a failed Apply never retired (it stopped before its native
// commit) or that a failed rollback had already put back, and the next Apply left them on the router
// for good. Only what is present is added, so no removal is sent for something already gone. The
// kernel plane and the plugins stay the live revision's.
func ownershipBaseline(live, committed *executionMaterializationV1, capture *executionNativeCaptureV1) *executionMaterializationV1 {
	if !live.known() || !committed.known() || committed.nativeTarget() == nil || capture == nil {
		return live
	}
	theirs := committed.nativeTarget()
	union := nativeBaselineFromMaterialization(live) // a copy; nil when live has no native plan
	if union == nil {
		union = &nativeplan.Plan{Platform: theirs.Platform}
	}
	var present func(identity string) bool
	switch {
	case union.Platform != theirs.Platform:
		return live
	case theirs.Platform == platform.OpenWrt:
		uci := netvpn.ParseUCIShow(capture.NetworkUCI)
		present = func(identity string) bool { _, ok := uci[strings.TrimPrefix(identity, "interface ")]; return ok }
	case theirs.Platform == platform.Keenetic:
		present = func(identity string) bool { return capture.ndmPresent[identity] }
	default:
		return live
	}
	added := false
	decided := make(map[string]bool, 2*len(union.Decisions))
	for _, d := range union.Decisions {
		decided["endpoint "+d.EndpointID], decided["interface "+d.Interface] = true, true
	}
	for _, d := range theirs.Decisions {
		managed := d.Path == nativeplan.PathNativeCreate || d.Path == nativeplan.PathNativeManage || d.Path == nativeplan.PathNativeUpdate
		if managed && d.Interface != "" && !decided["endpoint "+d.EndpointID] && !decided["interface "+d.Interface] &&
			present("interface "+d.Interface) {
			union.Decisions = append(union.Decisions, d)
			added = true
		}
	}
	if k := theirs.Keenetic; k != nil {
		if union.Keenetic == nil {
			union.Keenetic = &keenetic.Plan{}
		}
		u := union.Keenetic
		blocks := make(map[string]bool, len(u.Interfaces))
		for _, block := range u.Interfaces {
			if len(block) != 0 {
				blocks[block[0]] = true
			}
		}
		theirBlocks := make(map[string]bool)
		for _, block := range k.Interfaces {
			if len(block) != 0 && !blocks[block[0]] && present(block[0]) {
				u.Interfaces = append(u.Interfaces, append([]string(nil), block...))
				theirBlocks[block[0]] = true
				added = true
			}
		}
		routes := make(map[string]bool, len(u.Routes))
		for _, route := range u.Routes {
			routes[keenetic.RouteKey(route)] = true
		}
		for _, route := range k.Routes {
			if key := keenetic.RouteKey(route); !routes[key] && present(key) {
				u.Routes = append(u.Routes, route)
				added = true
			}
		}
		for iface, priority := range k.GlobalPriority {
			if _, ours := u.GlobalPriority[iface]; ours || !present("interface "+iface) {
				continue
			}
			if u.GlobalPriority == nil {
				u.GlobalPriority = map[string]int{}
			}
			u.GlobalPriority[iface] = priority
			if was, known := k.GlobalPriorityWas[iface]; known {
				if u.GlobalPriorityWas == nil {
					u.GlobalPriorityWas = map[string]int{}
				}
				u.GlobalPriorityWas[iface] = was
			}
			added = true
		}
		for endpoint, iface := range k.IfaceFor {
			if _, ours := u.IfaceFor[endpoint]; !ours && theirBlocks["interface "+iface] {
				if u.IfaceFor == nil {
					u.IfaceFor = map[string]string{}
				}
				u.IfaceFor[endpoint] = iface
			}
		}
	}
	if !added {
		return live
	}
	out := *live
	native := executionNativeMaterializationV1{Delta: executionNativeDeltaV1{SchemaVersion: executionNativeDeltaSchemaV1}}
	if live.Native != nil {
		native = *live.Native
	}
	native.Delta.Reconcile = nativeplan.Reconciliation{Platform: union.Platform, Target: union}
	out.Native = &native
	return &out
}

func cloneRouterProtos(source netvpn.RouterProtos) netvpn.RouterProtos {
	if source == nil {
		return nil
	}
	result := make(netvpn.RouterProtos, len(source))
	for protocol, available := range source {
		result[protocol] = available
	}
	return result
}

func cloneNativeInterfaces(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for endpoint, iface := range source {
		result[endpoint] = iface
	}
	return result
}

// cloneNativePriorities copies the observed `ip global` ladder, keeping nil as nil so a capture from
// a platform that has no such thing still encodes byte-identically.
func cloneNativePriorities(source map[string]int) map[string]int {
	if source == nil {
		return nil
	}
	result := make(map[string]int, len(source))
	for name, priority := range source {
		result[name] = priority
	}
	return result
}

// cloneNDMPolicyMarks copies the captured access-policy marks, keeping nil as nil.
func cloneNDMPolicyMarks(source map[string]uint32) map[string]uint32 {
	if source == nil {
		return nil
	}
	result := make(map[string]uint32, len(source))
	for name, mark := range source {
		result[name] = mark
	}
	return result
}

func cloneNativeInterfaceSet(source map[string]bool) map[string]bool {
	if source == nil {
		return nil
	}
	result := make(map[string]bool, len(source))
	for name, present := range source {
		result[name] = present
	}
	return result
}
