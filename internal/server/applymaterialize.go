package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"wayhop/internal/generator"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// materializeInput is everything one Apply captured before it decides what to install: the desired
// snapshot, the host facts (captured once, inside applyMu), the native capture (nil when the router
// has no native plane WayHop drives, or in demo), the previous applied materialization (ownership
// and retire baseline) and the kernel plan compiled with the server's pbr options.
type materializeInput struct {
	desired    DesiredSnapshot
	host       ExecutionHostFactsV1
	native     *executionNativeCaptureV1
	previous   *executionMaterializationV1
	kernelPlan *pbr.Plan
	generate   executionGenerator
}

// materializeError names a materialization failure for the operator: what could not be built and,
// where known, what to do about it. It is never a router mutation.
type materializeError struct {
	Stage  string // "profile" | "native" | "core" | "kernel" | "plugins"
	Detail string
	Remedy string
}

func (e *materializeError) Error() string { return e.Stage + ": " + e.Detail }

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
		switch {
		case nativeErr == nil:
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
			nativeMaterialization = &executionNativeMaterializationV1{Delta: delta}
		case gotPlatform == platform.OpenWrt:
			// OpenWrt has a complete generic path (sing-box + engine plugins) that predates the
			// native one; a profile the native planner cannot express still works through it.
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
				"Use sing-box, AmneziaWG or olcRTC for this connection, or disable it.")
		}
	}

	mode := desiredRoutingMode(desired.Config)
	coreAction := ExecutionEnsurePresent
	var coreConfig []byte
	var plugins []executionPluginSpecV1
	keeneticNative := nativeMaterialization != nil && nativeMaterialization.Delta.Reconcile.Target != nil &&
		nativeMaterialization.Delta.Reconcile.Target.Platform == platform.Keenetic
	if keeneticNative {
		target := nativeMaterialization.Delta.Reconcile.Target
		if target.Keenetic == nil || len(target.OpenWrt) != 0 {
			return executionMaterializationV1{}, nil, newMaterializeError("native", "the Keenetic native plan is incomplete", "")
		}
		if len(expectedPlugins) != 0 {
			return executionMaterializationV1{}, nil, newMaterializeError("native",
				"KeeneticOS runs AmneziaWG/WireGuard tunnels natively; an engine plugin cannot be combined with the native plan",
				"Let KeeneticOS own the tunnel (default) or disable the connection.")
		}
		// Native NDM interfaces remain the connection authority. When NDM cannot represent the
		// complete routing policy, generate one full compatibility TUN from the already-bound
		// profile instead of applying a partial native route plan or recreating native tunnels.
		switch {
		case target.Keenetic.CompatibilityRouting:
			if target.Keenetic.Singbox == nil {
				return executionMaterializationV1{}, nil, newMaterializeError("native", "the Keenetic compatibility plan carries no core config", "")
			}
			result, generateErr := in.generate(&profile, executionKeeneticCompatibilityOptions(desired))
			if generateErr != nil {
				return executionMaterializationV1{}, nil, newMaterializeError("core", "the sing-box config could not be generated: "+generateErr.Error(), "")
			}
			if result == nil || result.Config == nil || len(result.Plugins) != 0 {
				return executionMaterializationV1{}, nil, newMaterializeError("core", "the sing-box config could not be generated for the compatibility TUN", "")
			}
			if err := bindKeeneticCompatibilityTUN(result.Config); err != nil {
				return executionMaterializationV1{}, nil, newMaterializeError("core", "the generated config has no TUN inbound to bind to wrtun0", "")
			}
			coreConfig, err = json.MarshalIndent(result.Config, "", "  ")
			if err != nil {
				return executionMaterializationV1{}, nil, newMaterializeError("core", "the sing-box config could not be encoded: "+err.Error(), "")
			}
		case target.Keenetic.Singbox == nil:
			coreAction = ExecutionEnsureAbsent
			coreConfig = []byte{}
		default:
			coreConfig, err = json.MarshalIndent(target.Keenetic.Singbox, "", "  ")
			if err != nil {
				return executionMaterializationV1{}, nil, newMaterializeError("core", "the sing-box config could not be encoded: "+err.Error(), "")
			}
		}
		plugins = []executionPluginSpecV1{}
	} else {
		opts, optionsErr := executionGeneratorOptions(desired, in.kernelPlan)
		if optionsErr != nil {
			return executionMaterializationV1{}, nil, newMaterializeError("kernel",
				"routing mode "+mode+" needs a kernel routing plan and none could be compiled",
				"Add routing lists with IP/CIDR sources, or switch to tun or mixed mode.")
		}
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
	keeneticKernel := gotPlatform == platform.Keenetic && kernelMode && in.kernelPlan != nil && len(in.kernelPlan.Zones) != 0
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
		Plan:     in.kernelPlan,
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
		ipsetArtifact, err := buildKeeneticKernelIpsetArtifact(
			in.kernelPlan, exactKernelOptions(), keeneticPBROptionsFor(host.KernelWANIface, &in.desired.Profile),
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
	if in.kernelPlan != nil && !keeneticKernel {
		kernelArtifact.Nft = []byte(in.kernelPlan.RenderNft())
		kernelArtifact.IP = append([]string(nil), in.kernelPlan.RenderIP(pbr.Options{})...)
		kernelArtifact.Offload = []byte(in.kernelPlan.RenderOffload())
		kernelArtifact.Teardown = append([]string(nil), in.kernelPlan.RenderTeardown(pbr.Options{})...)
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
