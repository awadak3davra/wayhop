package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"

	"wayhop/internal/awg"
	"wayhop/internal/generator"
	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// materializeInput is everything one Apply captured before it decides what to install: the desired
// snapshot, the host facts (captured once, inside applyMu), the native capture (nil when the router
// has no native plane WayHop drives, or in demo), the previous applied materialization (ownership
// and retire baseline) and the server's pbr options when the routing mode has a kernel plane (nil
// otherwise). The kernel plan itself is compiled here, after the native plan: on KeeneticOS that plan
// is what knows the device each NDM-created tunnel lives on.
type materializeInput struct {
	desired       DesiredSnapshot
	host          ExecutionHostFactsV1
	native        *executionNativeCaptureV1
	previous      *executionMaterializationV1
	kernelOptions *pbr.Options
	generate      executionGenerator
	// ndmPolicies is KeeneticOS's access policies by name → mark as this Apply captured them (the demo's
	// in demo): the core routes a list sent to one by a `direct` outbound carrying that mark.
	ndmPolicies map[string]uint32
}

// materializeError names a materialization failure for the operator: what could not be built and,
// where known, what to do about it. It is never a router mutation.
type materializeError struct {
	Stage  string // "profile" | "native" | "core" | "kernel" | "plugins"
	Detail string
	Remedy string
}

func (e *materializeError) Error() string { return e.Stage + ": " + e.Detail }

// withoutKernelCarriedFeeds drops the fetched IP feed of every list whose zone the KeeneticOS ipset
// plane builds. Those destinations are marked and policy-routed before they reach wrtun0, so the
// compatibility core's copy is never consulted - and on the live router it was 45.6k prefixes, about
// 1.4 MB of config and parse memory (QA-066 review). A list without its own unscoped zone keeps its
// feed: then the core is what routes it. Names stay too: sniffing backs up clients that bypass the
// router's resolver.
func withoutKernelCarriedFeeds(lists []model.RoutingList, plan *pbr.Plan) []model.RoutingList {
	if plan == nil || len(plan.Zones) == 0 {
		return lists
	}
	carried := make(map[string]bool, len(plan.Zones))
	for _, z := range plan.Zones {
		if !z.SrcScoped {
			carried[z.Name] = true
		}
	}
	out := make([]model.RoutingList, len(lists))
	copy(out, lists)
	for i := range out {
		if len(out[i].CIDRCache) > 0 && carried[pbr.ListZoneName(out[i].ID)] {
			out[i].CIDRCache = nil
		}
	}
	return out
}

func newMaterializeError(stage, detail, remedy string) *materializeError {
	return &materializeError{Stage: stage, Detail: detail, Remedy: remedy}
}

// materialize turns the desired snapshot into the exact artifacts an Apply installs. It is pure over
// its inputs (no host reads) apart from the injected generator: the same decisions the previous
// executor made — core present/absent, Keenetic compatibility TUN vs native singbox map, kernel action
// per platform/mode, ipset artifact on Keenetic, nft/ip render on OpenWrt, plugin specs — without
// review or HMAC binding. It returns non-fatal warnings the response should carry.
func materialize(in materializeInput) (executionMaterializationV1, []string, error) {
	var warnings []string
	if in.generate == nil {
		in.generate = generator.Generate
	}
	desired := in.desired
	host := in.host
	profile, err := cloneExecutionProfile(desired.Profile)
	if err != nil {
		return executionMaterializationV1{}, nil, newMaterializeError("profile", "the profile could not be copied: "+err.Error(), "")
	}
	bindings, err := applyCapturedExternalBindings(&profile, host.ExternalBindings)
	if err != nil {
		return executionMaterializationV1{}, nil, newMaterializeError("profile",
			"an enabled connection routes through an external interface that is not up on this router",
			"Bring the interface up (or fix its name in the connection), or disable the connection.")
	}
	gotPlatform := platform.Platform(host.Host.Platform)
	backend := executionBackendGeneric
	var nativeMaterialization *executionNativeMaterializationV1
	var previousNative *nativeplan.Plan
	if in.previous.known() {
		previousNative = nativeBaselineFromMaterialization(in.previous)
	}
	if in.native != nil && !desired.Config.Demo && (gotPlatform == platform.OpenWrt || gotPlatform == platform.Keenetic) {
		artifact, nativeErr := buildExecutionNativeArtifactV1(desired, host.Host, *in.native, previousNative)
		var move *nativeplan.MoveError
		switch {
		case nativeErr == nil:
			// The planner refuses moving a connection WayHop's engine ran to OpenWrt's own AmneziaWG
			// (nativeplan.MoveError), but it sees the engine only through the previous NATIVE plan's
			// engine-plugin decisions. A generic baseline has no native plan, yet its engine plugins ran
			// AmneziaWG connections on the very device names the native writer gives them
			// (util.AWGIface): the router applied while its own AmneziaWG was missing, now installed
			// (QA-043: or while one ByeDPI connection kept the native plan from compiling). Checked
			// here, on a plan that compiled, rather than fed to the planner: there it would refuse even
			// when another connection fails the native plan anyway, and that Apply goes to the generic
			// path again, where the plugin simply keeps running.
			if gotPlatform == platform.OpenWrt {
				if moved := enginePluginMoves(in.previous, &artifact.Plan, desired.Profile,
					artifact.Capture.AWGKernel.generation()); len(moved) != 0 {
					return executionMaterializationV1{}, nil, newMaterializeError("native",
						"connections WayHop's AmneziaWG engine ran under the previous Apply would move to OpenWrt's own "+
							"AmneziaWG in one Apply, on the same device names: "+strings.Join(moved, ", ")+
							"; the native interface cannot be created while the engine's link holds the name, and retiring "+
							"the engine afterwards deletes the link by that name, so switch the connection off and apply, "+
							"then switch it on and apply again, one at a time or all together",
						"Switch these connections off and apply, then switch them on and apply again.")
				}
			}
			delta, deltaErr := buildExecutionNativeDeltaV1(previousNative, artifact, host.Host.CapabilitySet)
			if deltaErr != nil {
				return executionMaterializationV1{}, nil, newMaterializeError("native",
					"the router-native plan could not be reconciled with what WayHop applied before: "+deltaErr.Error(),
					"Review the affected connections; an interface WayHop did not create is never replaced.")
			}
			if err := applyNativeConnectionBindings(&profile, delta.Reconcile.Target); err != nil {
				return executionMaterializationV1{}, nil, newMaterializeError("native",
					"the router-native plan does not cover every enabled connection", "")
			}
			backend = executionBackendNativeFirst
			nativeMaterialization = &executionNativeMaterializationV1{Delta: delta,
				AWGKernel: cloneAWGKernelCapture(artifact.Capture.AWGKernel)}
		case errors.As(nativeErr, &move):
			// Not handed to the generic path below. That path takes the whole profile: every other
			// tunnel would leave the router's own AmneziaWG with it, and the interfaces a previous
			// native Apply created would stay configured while the plugin creates links under the same
			// names - the very collision the move refusal names.
			return executionMaterializationV1{}, nil, newMaterializeError("native", move.Error(),
				"Switch this connection off and apply, then switch it on and apply again.")
		case gotPlatform == platform.OpenWrt:
			// OpenWrt has a complete generic path (sing-box + engine plugins) that predates the
			// native one; a profile the native planner cannot express still works through it, but
			// only while WayHop holds no native interface of its own.
			//
			// Refused, not handed to that path, while the authenticated baseline holds interfaces a
			// native Apply created. The generic path runs no native prepare or commit, so nothing
			// would reconcile them: they stay in /etc/config/network and their firewall zone; an
			// AmneziaWG connection's engine plugin deletes and re-creates its link under the same
			// wr_ name netifd runs (and netifd's next reload deletes the plugin's); and the record
			// this Apply writes carries no native plan, so the next Apply no longer counts them as
			// WayHop's - it can neither update nor remove them, and lands here again. Reconciling
			// first instead (removing them through the RemovalPlan before the plugins start) would
			// turn the executor's make-before-break order around for this one case: a gap with no
			// tunnel, a rollback that has to re-create the interfaces, and an ordering between
			// netifd's teardown and the plugin's `ip link add` that only a router can prove. The
			// refusal is the move refusal's (above), with the same way round: with the named
			// connections switched off, a native Apply removes their interfaces through the
			// reconcile that already runs, and the generic path then starts from nothing native.
			if held := heldNativeInterfaces(previousNative, desired.Profile); len(held) != 0 {
				return executionMaterializationV1{}, nil, newMaterializeError("native",
					"router-native tunnels cannot carry this configuration ("+nativeErr.Error()+
						"), and sing-box cannot take over while OpenWrt still runs the interfaces an earlier Apply created: "+
						strings.Join(held, ", "),
					"Fix what the detail names to keep these connections native. To run them through sing-box instead, "+
						"switch off the connections the detail names and apply, which removes their interfaces, "+
						"then switch them on and apply again.")
			}
			warnings = append(warnings, "router-native tunnels are not used for this configuration ("+
				nativeErr.Error()+"); the connections run through sing-box and the engine plugins instead")
		default:
			return executionMaterializationV1{}, nil, newMaterializeError("native",
				"KeeneticOS cannot carry this configuration natively: "+nativeErr.Error(),
				"Fix or disable the named connection; the Review plan lists what the router cannot run.")
		}
	}

	expectedPlugins := make(map[string]model.Endpoint)
	coreEndpoint := false
	for i := range profile.Endpoints {
		endpoint := profile.Endpoints[i]
		if !endpoint.Enabled {
			continue
		}
		switch classifyExecutionEndpoint(endpoint.Engine, endpoint.Protocol) {
		case executionEndpointCore:
			coreEndpoint = true
		case executionEndpointPlugin:
			// The plugin manager starts/stops a process and, for AWG, creates and deletes a kernel
			// interface. Route-through/imported resources must use EngineExternal; ownership
			// uncertainty never grants destructive authority.
			if !endpoint.OwnsResource() {
				return executionMaterializationV1{}, nil, newMaterializeError("plugins",
					"connection "+endpointLabel(endpoint)+" is not owned by WayHop, so its engine cannot be started",
					"Mark the connection as external (route through its existing interface) or re-import it.")
			}
			expectedPlugins[endpoint.ID] = endpoint
		case executionEndpointExternal:
			// The captured binding was installed above; there is no managed artifact.
		default:
			return executionMaterializationV1{}, nil, newMaterializeError("profile",
				"connection "+endpointLabel(endpoint)+" uses engine "+string(endpoint.Engine)+" with protocol "+
					string(endpoint.Protocol)+", which this build cannot run",
				"Use sing-box or AmneziaWG for this connection, or disable it.")
		}
	}

	mode := desiredRoutingMode(desired.Config)
	coreAction := ExecutionEnsurePresent
	var coreConfig []byte
	var plugins []executionPluginSpecV1
	keeneticNative := nativeMaterialization != nil && nativeMaterialization.Delta.Reconcile.Target != nil &&
		nativeMaterialization.Delta.Reconcile.Target.Platform == platform.Keenetic

	// The kernel plan routes each list into a table seeded with a device. Compiled from the desired
	// profile, not the bound one: binding rewrites an NDM-created endpoint as an external interface,
	// which would change its IPv6 posture along with its name. The native plan supplies only the
	// device NDM put each of its tunnels on.
	var kernelPlan *pbr.Plan
	if in.kernelOptions != nil {
		options := *in.kernelOptions
		if keeneticNative {
			devices, devicesErr := keeneticKernelDevices(nativeMaterialization.Delta.Reconcile.Target)
			if devicesErr != nil {
				return executionMaterializationV1{}, nil, newMaterializeError("kernel",
					"the kernel routing plan cannot name the device of an interface NDM creates: "+devicesErr.Error(), "")
			}
			options.Devices = devices
		}
		compiled, _, compileErr := pbr.Compile(&desired.Profile, options)
		if compileErr != nil {
			return executionMaterializationV1{}, nil, newMaterializeError("kernel",
				"the kernel routing plan could not be compiled: "+compileErr.Error(),
				"Fix the routing lists named in the detail, or switch to tun or mixed mode.")
		}
		kernelPlan = compiled
	}

	if keeneticNative {
		target := nativeMaterialization.Delta.Reconcile.Target
		if target.Keenetic == nil || len(target.OpenWrt) != 0 {
			return executionMaterializationV1{}, nil, newMaterializeError("native", "the Keenetic native plan is incomplete", "")
		}
		// The engine plugins KeeneticOS runs are exactly the endpoints the native plan handed to
		// WayHop's own AmneziaWG engine. Any other plugin would be a tunnel NDM also believes it owns.
		pluginRun := make(map[string]bool)
		for _, decision := range target.Decisions {
			if decision.Path == nativeplan.PathEnginePlugin {
				pluginRun[decision.EndpointID] = true
			}
		}
		agree := len(pluginRun) == len(expectedPlugins)
		for id := range expectedPlugins {
			agree = agree && pluginRun[id]
		}
		if !agree {
			return executionMaterializationV1{}, nil, newMaterializeError("native",
				"the KeeneticOS native plan and the engine plugins disagree about which connections WayHop runs itself", "")
		}
		// Native NDM interfaces remain the connection authority. When NDM cannot represent the
		// complete routing policy, generate one full compatibility TUN from the already-bound
		// profile instead of applying a partial native route plan or recreating native tunnels.
		switch {
		case target.Keenetic.CompatibilityRouting:
			if target.Keenetic.Singbox == nil {
				return executionMaterializationV1{}, nil, newMaterializeError("native", "the Keenetic compatibility plan carries no core config", "")
			}
			compat := executionKeeneticCompatibilityOptions(desired)
			compat.CoreVersion = executionCoreVersion(host.Host)
			compat.NDMPolicies = in.ndmPolicies
			genProfile := profile
			if mode == "hybrid" || mode == "fast" {
				genProfile.RoutingLists = withoutKernelCarriedFeeds(profile.RoutingLists, kernelPlan)
			}
			result, generateErr := in.generate(&genProfile, compat)
			if generateErr != nil {
				return executionMaterializationV1{}, nil, newMaterializeError("core", "the sing-box config could not be generated: "+generateErr.Error(), "")
			}
			if result == nil || result.Config == nil {
				return executionMaterializationV1{}, nil, newMaterializeError("core", "the sing-box config could not be generated for the compatibility TUN", "")
			}
			// The core egresses through the userspace devices, so their plugins are the ones it names.
			plugins, err = captureExecutionPlugins(result.Plugins, expectedPlugins, executionExternalInterfaces(bindings))
			if err != nil {
				return executionMaterializationV1{}, nil, newMaterializeError("plugins",
					"the engine plugins for this configuration could not be prepared (an interface name collides or an endpoint is not WayHop-owned)",
					"Check the AmneziaWG connections' names and ownership.")
			}
			if err := bindKeeneticCompatibilityTUN(result.Config); err != nil {
				return executionMaterializationV1{}, nil, newMaterializeError("core", "the generated config has no TUN inbound to bind to wrtun0", "")
			}
			generator.FitTUNToCore(result.Config, compat.CoreVersion) // the bind above set gvisor again
			coreConfig, err = json.MarshalIndent(result.Config, "", "  ")
			if err != nil {
				return executionMaterializationV1{}, nil, newMaterializeError("core", "the sing-box config could not be encoded: "+err.Error(), "")
			}
		case target.Keenetic.Singbox == nil:
			coreAction = ExecutionEnsureAbsent
			coreConfig = []byte{}
		default:
			coreConfig, err = json.MarshalIndent(target.Keenetic.Singbox, "", "  ")
			if err == nil {
				coreConfig, err = fitFallbackCore(coreConfig, executionCoreVersion(host.Host), desired.Config.CoreOverride, target.Keenetic.IfaceFor)
			}
			if err != nil {
				return executionMaterializationV1{}, nil, newMaterializeError("core", "the sing-box config could not be prepared: "+err.Error(), "")
			}
		}
		if !target.Keenetic.CompatibilityRouting {
			plugins, err = keeneticEnginePlugins(expectedPlugins, bindings)
			if err != nil {
				return executionMaterializationV1{}, nil, newMaterializeError("plugins",
					"the engine plugins for this configuration could not be prepared (an interface name collides or an endpoint is not WayHop-owned)",
					"Check the AmneziaWG connections' names and ownership.")
			}
		}
	} else {
		opts, optionsErr := executionGeneratorOptions(desired, kernelPlan)
		if optionsErr != nil {
			return executionMaterializationV1{}, nil, newMaterializeError("kernel",
				"routing mode "+mode+" needs a kernel routing plan and none could be compiled",
				"Add routing lists with IP/CIDR sources, or switch to tun or mixed mode.")
		}
		opts.CoreVersion = executionCoreVersion(host.Host)
		opts.NDMPolicies = in.ndmPolicies
		result, generateErr := in.generate(&profile, opts)
		if generateErr != nil {
			return executionMaterializationV1{}, nil, newMaterializeError("core", "the sing-box config could not be generated: "+generateErr.Error(), "")
		}
		if result == nil || result.Config == nil {
			return executionMaterializationV1{}, nil, newMaterializeError("core", "the sing-box config could not be generated", "")
		}
		coreConfig, err = json.MarshalIndent(result.Config, "", "  ")
		if err != nil {
			return executionMaterializationV1{}, nil, newMaterializeError("core", "the sing-box config could not be encoded: "+err.Error(), "")
		}
		plugins, err = captureExecutionPlugins(result.Plugins, expectedPlugins, executionExternalInterfaces(bindings))
		if err != nil {
			return executionMaterializationV1{}, nil, newMaterializeError("plugins",
				"the engine plugins for this configuration could not be prepared (an interface name collides or an endpoint is not WayHop-owned)",
				"Check the AmneziaWG connections' names and ownership.")
		}
	}

	if desired.Config.Demo {
		coreAction = ExecutionDemoNoop
	} else if !keeneticNative && !coreEndpoint && generator.DatapathNativeOnly(&profile, mode) {
		coreAction = ExecutionEnsureAbsent
	}

	kernelAction := ExecutionEnsureAbsent
	kernelMode := mode == "hybrid" || mode == "fast"
	// Keenetic never executes the OpenWrt nft/ip kernel plane — it has no nftables — but it does
	// carry the ipset/iptables one, which rides alongside the native NDM plane rather than replacing
	// it: NDM owns the interfaces, the kernel plane owns which destinations reach them.
	keeneticKernel := gotPlatform == platform.Keenetic && kernelMode && kernelPlan != nil && len(kernelPlan.Zones) != 0
	if !keeneticNative && gotPlatform == platform.OpenWrt && kernelMode {
		kernelAction = ExecutionEnsurePresent
	} else if keeneticKernel {
		kernelAction = ExecutionEnsurePresent
	}
	if desired.Config.Demo {
		kernelAction = ExecutionDemoNoop
	}
	pluginAction := ExecutionEnsureAbsent
	if len(plugins) != 0 {
		pluginAction = ExecutionEnsurePresent
	}
	if desired.Config.Demo {
		pluginAction = ExecutionDemoNoop
	}

	kernelArtifact := executionKernelArtifactV1{
		Action:   kernelAction,
		Plan:     kernelPlan,
		IP:       []string{},
		Teardown: []string{},
		Retire:   []string{},
	}
	if kernelAction == ExecutionEnsurePresent && !keeneticKernel {
		if !validExecutionToolIdentity(host.KernelNFT, executionToolNFT) ||
			!validExecutionToolIdentity(host.KernelIP, executionToolIP) {
			return executionMaterializationV1{}, nil, newMaterializeError("kernel",
				"the nft and ip tools this routing mode needs were not found on the router",
				"Install nftables and iproute2, or switch to tun or mixed mode.")
		}
		kernelArtifact.NFTTool = host.KernelNFT
		kernelArtifact.IPTool = host.KernelIP
	}
	if kernelAction == ExecutionEnsurePresent && keeneticKernel {
		if !validWANInterfaceName(host.KernelWANIface) {
			log.Printf("apply: Keenetic kernel artifact: WAN uplink %q is not a usable interface name", host.KernelWANIface)
			return executionMaterializationV1{}, nil, newMaterializeError("kernel",
				"the WAN uplink interface could not be determined, so the policy plane cannot be rendered", "")
		}
		ipsetOptions := keeneticPBROptionsFor(host.KernelWANIface, &in.desired.Profile)
		ipsetOptions.MasqDevices = keeneticUserspaceDevices(nativeMaterialization)
		ipsetArtifact, err := buildKeeneticKernelIpsetArtifact(
			kernelPlan, exactKernelOptions(), ipsetOptions,
			executionKernelIpsetArtifactV1{
				IpsetTool: host.KernelIpset, IptablesTool: host.KernelIptables,
				IP6Tool: host.KernelIp6tables, IPTool: host.KernelIP,
				DnsmasqTool: host.KernelDnsmasq, ShellTool: host.KernelShell,
			},
		)
		if err != nil {
			log.Printf("apply: Keenetic kernel artifact could not be rendered: %v", err)
			return executionMaterializationV1{}, nil, newMaterializeError("kernel",
				"the KeeneticOS policy plane could not be rendered: "+err.Error(),
				"Install ipset, iptables and (for domain lists) dnsmasq from Entware.")
		}
		kernelArtifact.Ipset = ipsetArtifact
	}
	// The nft rendering is the OpenWrt plane. Keenetic carries the same compiled plan through the
	// ipset program built above; an artifact holding both would leave the executor free to pick.
	if kernelPlan != nil && !keeneticKernel {
		kernelArtifact.Nft = []byte(kernelPlan.RenderNft())
		kernelArtifact.IP = append([]string(nil), kernelPlan.RenderIP(pbr.Options{})...)
		kernelArtifact.Offload = []byte(kernelPlan.RenderOffload())
		kernelArtifact.Teardown = append([]string(nil), kernelPlan.RenderTeardown(pbr.Options{})...)
	}
	if kernelAction != ExecutionEnsurePresent {
		// An absent plane carries no program; only the retire list below may name commands.
		kernelArtifact.Plan, kernelArtifact.Nft, kernelArtifact.IP = nil, []byte{}, []string{}
		kernelArtifact.Offload, kernelArtifact.Teardown = []byte{}, []string{}
	}
	if kernelArtifact.Nft == nil {
		kernelArtifact.Nft = []byte{}
	}
	if kernelArtifact.Offload == nil {
		kernelArtifact.Offload = []byte{}
	}
	if kernelAction != ExecutionDemoNoop {
		bindKernelRetire(&kernelArtifact, in.previous)
	}

	m := executionMaterializationV1{
		SchemaVersion: ExecutionSnapshotSchemaV1,
		Backend:       backend,
		Core: executionCoreArtifactV1{
			Action: coreAction, BinaryPath: desired.Config.SingBox.Bin,
			ConfigPath: desired.Config.SingBox.Config, HostIdentity: host.Host.Core,
			Config: append([]byte(nil), coreConfig...),
		},
		Kernel:           kernelArtifact,
		PluginAction:     pluginAction,
		Plugins:          plugins,
		ExternalBindings: append([]ExecutionExternalBindingV1{}, bindings...),
		Native:           nativeMaterialization,
	}
	if m.Plugins == nil {
		m.Plugins = []executionPluginSpecV1{}
	}
	return m, warnings, nil
}

// keeneticEnginePlugins is the plugin set for the endpoints KeeneticOS hands to WayHop's AmneziaWG
// engine when no core is generated to name them: the same specs and the same checks (engine, owner,
// device collisions with the external bindings) the generator's plugin list goes through.
func keeneticEnginePlugins(expected map[string]model.Endpoint, bindings []ExecutionExternalBindingV1) ([]executionPluginSpecV1, error) {
	generated := make([]generator.Plugin, 0, len(expected))
	for _, endpoint := range expected {
		generated = append(generated, generator.Plugin{Endpoint: endpoint})
	}
	return captureExecutionPlugins(generated, expected, executionExternalInterfaces(bindings))
}

// keeneticUserspaceDevices lists, sorted, the devices of the endpoints the native plan handed to
// WayHop's AmneziaWG engine.
func keeneticUserspaceDevices(native *executionNativeMaterializationV1) []string {
	var out []string
	if native == nil || native.Delta.Reconcile.Target == nil {
		return out
	}
	for _, decision := range native.Delta.Reconcile.Target.Decisions {
		if decision.Path == nativeplan.PathEnginePlugin {
			out = append(out, decision.Interface)
		}
	}
	sort.Strings(out)
	return out
}

// bindKernelRetire adds the previous plane's teardown commands the new plane does not already cover
// (a shrinking plan no longer uses some ip rules/routes; an absent plane removes the whole table).
// Only what WayHop itself installed is ever retired; nothing is inferred from the router.
func bindKernelRetire(target *executionKernelArtifactV1, previous *executionMaterializationV1) {
	target.Retire = []string{}
	if !previous.known() || previous.Kernel.Action != ExecutionEnsurePresent {
		return
	}
	if previous.Kernel.Ipset != nil {
		// The Keenetic plane tears itself down through its own script (see rollback); the nft/ip
		// retire list is an OpenWrt concept.
		return
	}
	covered := make(map[string]bool, len(target.Teardown))
	for _, command := range target.Teardown {
		covered[command] = true
	}
	for _, command := range previous.Kernel.Teardown {
		if !covered[command] {
			target.Retire = append(target.Retire, command)
		}
	}
	if len(target.Retire) != 0 && target.Action == ExecutionEnsureAbsent {
		target.NFTTool = previous.Kernel.NFTTool
		target.IPTool = previous.Kernel.IPTool
	}
}

// heldNativeInterfaces names, sorted by interface, the interfaces the authenticated previous native
// plan created or manages (nativeOwnershipFrom: the ones only the native reconcile may update or
// remove), each with the connection it was created for.
func heldNativeInterfaces(previous *nativeplan.Plan, profile model.Profile) []string {
	owned := nativeOwnershipFrom(previous)
	ids := make([]string, 0, len(owned))
	for id := range owned {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if owned[ids[i]] != owned[ids[j]] {
			return owned[ids[i]] < owned[ids[j]]
		}
		return ids[i] < ids[j]
	})
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, profileEndpointLabel(profile, id)+" on "+owned[id])
	}
	return out
}

// enginePluginMoves names, sorted by interface, the connections the target native plan creates or
// manages under a device name an AmneziaWG engine plugin of the previous materialization ran on: the
// name the plugin manager gives its link (util.AWGIface), which is the one the native writer gives
// the interface. Only a previous without a native plan is read here (genericPluginDevices): the engine
// plugins of a native one are its engine-plugin decisions, whose move the planner already refuses
// (nativeplan.MoveError). A connection that moves because the router's kernel module now carries its
// settings says so, as the planner's refusal does (nativeplan.OpenWrtMoveReason).
func enginePluginMoves(previous *executionMaterializationV1, target *nativeplan.Plan, profile model.Profile,
	kernel awg.Generation) []string {
	ran := make(map[string]bool)
	for _, device := range genericPluginDevices(previous) {
		ran[device] = true
	}
	var moved []nativeplan.EndpointDecision
	for _, decision := range target.Decisions {
		switch decision.Path {
		case nativeplan.PathNativeCreate, nativeplan.PathNativeManage, nativeplan.PathNativeUpdate:
			if ran[decision.Interface] {
				moved = append(moved, decision)
			}
		}
	}
	sort.Slice(moved, func(i, j int) bool { return moved[i].Interface < moved[j].Interface })
	out := make([]string, 0, len(moved))
	for _, decision := range moved {
		label := profileEndpointLabel(profile, decision.EndpointID) + " on " + decision.Interface
		if e := profile.EndpointByID(decision.EndpointID); e != nil {
			if why := nativeplan.OpenWrtMoveReason(*e, kernel); why != "" {
				label += " (" + why + ")"
			}
		}
		out = append(out, label)
	}
	return out
}

// profileEndpointLabel names connection id for an operator-facing message: by name where the profile
// still has it, else by id, marked as gone.
func profileEndpointLabel(profile model.Profile, id string) string {
	for _, endpoint := range profile.Endpoints {
		if endpoint.ID == id {
			return endpointLabel(endpoint)
		}
	}
	return id + " (no longer configured)"
}

// endpointLabel names an endpoint for an operator-facing message.
func endpointLabel(e model.Endpoint) string {
	if e.Name != "" && e.Name != e.ID {
		return fmt.Sprintf("%q (%s)", e.Name, e.ID)
	}
	return e.ID
}

// materializeFailure extracts the operator-facing parts of a materialization error.
func materializeFailure(err error) (stage, detail, remedy string) {
	var me *materializeError
	if errors.As(err, &me) {
		return me.Stage, me.Detail, me.Remedy
	}
	return "materialize", err.Error(), ""
}

// fitFallbackCore is what Generate does last, for the KeeneticOS fallback core, which the native plan
// assembles and carries already encoded: generator.FitTUNToCore, then the operator's core override.
// The override is applied here too because it is the operator's word on the core WayHop runs, and on
// a KeeneticOS router whose connections NDM carries natively this is that core; leaving it out would
// make the override silently mean nothing there. An override written against the full generated
// config can name tags this per-connection core does not have (its groups, say): `sing-box check`
// passes a rule to a missing outbound, so ApplyCoreOverride refuses one of the override's own rules
// that does, and Apply stops here, before anything is written.
//
// What NDM routes into is not the override's to change: each connection's wrtunN TUN (the device
// ifaceFor, the plan's, names), its SOCKS inbound and its route rule are captured before the override
// and re-asserted after it (keenetic.FallbackDatapath), and an override that cannot keep them is
// refused here the same way. The compatibility core gets the same from bindKeeneticCompatibilityTUN.
// The override's prepended route rules go after this core's guards, its probe rules.
//
// Untouched, byte for byte, without an override and for every core that still accepts the TUN `stack`
// option; otherwise the config is decoded and re-encoded.
func fitFallbackCore(config []byte, coreVersion, override string, ifaceFor map[string]string) ([]byte, error) {
	if generator.TUNStackAccepted(coreVersion) && strings.TrimSpace(override) == "" {
		return config, nil
	}
	var decoded map[string]any
	if err := json.Unmarshal(config, &decoded); err != nil {
		return nil, err
	}
	generator.FitTUNToCore(decoded, coreVersion)
	if strings.TrimSpace(override) == "" {
		return json.MarshalIndent(decoded, "", "  ")
	}
	datapath, err := keenetic.CaptureFallbackDatapath(decoded, ifaceFor)
	if err != nil {
		return nil, err
	}
	if err := generator.ApplyCoreOverride(decoded, override, generator.LeadingProbeRules(decoded)); err != nil {
		return nil, err
	}
	if err := datapath.Reassert(decoded); err != nil {
		return nil, err
	}
	return json.MarshalIndent(decoded, "", "  ")
}
