package server

import (
	"encoding/json"
	"errors"
	"path"
	"sort"
	"strings"

	"wayhop/internal/generator"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// ExecutionSnapshotSchemaV1 is the materialization schema carried in the apply-state record.
const ExecutionSnapshotSchemaV1 = 1

const (
	executionBackendGeneric     = "generic"
	executionBackendNativeFirst = "native_first"
)

// ExecutionActionV1 is an explicit reconciliation instruction for one plane. demo_noop keeps the
// materialized artifacts in the record while forbidding the executor from touching the router.
type ExecutionActionV1 string

const (
	ExecutionEnsurePresent ExecutionActionV1 = "ensure_present"
	ExecutionEnsureAbsent  ExecutionActionV1 = "ensure_absent"
	ExecutionDemoNoop      ExecutionActionV1 = "demo_noop"
)

var (
	errExecutionInvalidCapture  = errors.New("execution requires a valid captured host state")
	errExecutionGeneration      = errors.New("execution core artifact could not be generated")
	errExecutionPluginArtifact  = errors.New("execution plugin artifact could not be generated")
	errExecutionExternalBinding = errors.New("execution external binding is unavailable")
)

// ExecutionExternalBindingV1 is an observed host fact for an OS-owned interface. The builder never
// trusts DesiredSnapshot.Profile.Params["interface"] as live host truth; it replaces that value in
// its private working profile with this captured binding before generation. Interface is the stable
// external-resource identity. IfIndex records the capture observation for review/audit only: Linux
// assigns it afresh at boot, so using it as durable identity would reject the same netifd/NDM-owned
// interface whenever independent tunnels finish starting in a different order.
type ExecutionExternalBindingV1 struct {
	EndpointID string `json:"endpoint_id"`
	Interface  string `json:"interface"`
	IfIndex    int    `json:"ifindex"`
	AdminUp    bool   `json:"admin_up"`
	Ready      bool   `json:"ready"`
}

// ExecutionToolIdentityV1 is a content-addressed runnable used by the generic plugin backend. A
// broad platform capability is insufficient: OpenWrt netifd or Keenetic firmware support does not
// prove that the generic process manager can invoke these exact tools.
type ExecutionToolIdentityV1 struct {
	Tool          string `json:"tool"`
	ResolvedPath  string `json:"resolved_path"`
	ContentSHA256 string `json:"content_sha256"`
	Version       string `json:"version"`
	Runnable      bool   `json:"runnable"`
}

type executionCoreArtifactV1 struct {
	Action       ExecutionActionV1      `json:"action"`
	BinaryPath   string                 `json:"binary_path"`
	ConfigPath   string                 `json:"config_path"`
	HostIdentity CoreRunnableIdentityV1 `json:"host_identity"`
	Config       []byte                 `json:"config"`
}

type executionKernelArtifactV1 struct {
	Action   ExecutionActionV1       `json:"action"`
	NFTTool  ExecutionToolIdentityV1 `json:"nft_tool"`
	IPTool   ExecutionToolIdentityV1 `json:"ip_tool"`
	Plan     *pbr.Plan               `json:"plan"`
	Nft      []byte                  `json:"nft"`
	IP       []string                `json:"ip"`
	Offload  []byte                  `json:"offload"`
	Teardown []string                `json:"teardown"`
	Retire   []string                `json:"retire"`
	// Ipset carries the KeeneticOS kernel plane. Pointer + omitempty so an OpenWrt artifact
	// serializes byte-identically to before this field existed: these blobs are content-addressed
	// and hashed into the ledger, so a changed encoding would make every already-applied plan read
	// as drift on the next startup.
	Ipset *executionKernelIpsetArtifactV1 `json:"ipset,omitempty"`
}

// executionKernelIpsetArtifactV1 is the KeeneticOS policy plane: ipset sets, iptables mangle marks,
// ip rule/route, and the dnsmasq config that populates domain sets at query time. KeeneticOS has no
// nftables, so this is the only kernel plane the platform can carry.
//
// Unlike the nft path this is authenticated *shell text*, not a list of argv vectors, because shell
// is unavoidable here: NDM rebuilds its firewall periodically and drops foreign rules, so the same
// program has to be re-asserted from an /opt/etc/ndm/netfilter.d hook, which NDM invokes as a
// script. Executing one content-addressed script in both places is what keeps Apply and re-assert
// from diverging. Script and Teardown are rendered with a preamble that pins every tool name to the
// absolute path of the binary whose identity was probed, so "only the exact verified binary runs"
// survives the move from argv to shell.
type executionKernelIpsetArtifactV1 struct {
	IpsetTool    ExecutionToolIdentityV1 `json:"ipset_tool"`
	IptablesTool ExecutionToolIdentityV1 `json:"iptables_tool"`
	IP6Tool      ExecutionToolIdentityV1 `json:"ip6tables_tool"`
	IPTool       ExecutionToolIdentityV1 `json:"ip_tool"`
	DnsmasqTool  ExecutionToolIdentityV1 `json:"dnsmasq_tool"`
	ShellTool    ExecutionToolIdentityV1 `json:"shell_tool"`
	// Restore is the `ipset restore` payload, fed on stdin in one invocation. It is separate from
	// Script because it is data, not commands: rendering thousands of set members into shell would
	// be both slow and unreviewable.
	Restore []byte `json:"restore"`
	// Script installs the chain, marks and routes. Idempotent by construction — it is re-run by the
	// netfilter.d hook after every NDM firewall rebuild.
	Script []byte `json:"script"`
	// DnsmasqConf holds the `ipset=` directives that let dnsmasq fill domain sets from answers.
	// Empty when the plan carries no domain zone.
	DnsmasqConf []byte `json:"dnsmasq_conf"`
	// SetNames is every set the plan owns, so postcheck can prove they exist without re-deriving
	// names from the plan and drifting from what RenderIpsetRestore actually created.
	SetNames []string `json:"set_names"`
	Teardown []byte   `json:"teardown"`
	// WANIface is the uplink the MASQUERADE rule was rendered against. Stored because validation
	// re-renders the program from the plan and compares it byte for byte; without it that render
	// would fall back to a default and every artifact would fail its own integrity check.
	WANIface string `json:"wan_iface"`
}

type executionPluginSpecV1 struct {
	ID        string         `json:"id"`
	Endpoint  model.Endpoint `json:"endpoint"`
	SOCKSPort int            `json:"socks_port"`
}

const (
	executionToolIP  = "ip"
	executionToolAWG = "awg"
	executionToolNFT = "nft"

	executionMaxToolVersionBytes  = 256
	executionMaxResolvedPathBytes = 4096
	executionMaxAWGAddresses      = 16
	executionMinAWGMTU            = 576
	executionMaxAWGMTU            = 9200
)

// ExecutionHostFactsV1 is everything one Apply captured from the router before materializing:
// the host snapshot, the kernel tool identities the rendered kernel program pins, the WAN uplink
// and the live external interface bindings. It is captured once per Apply and never persisted.
type ExecutionHostFactsV1 struct {
	Host      HostSnapshotV1          `json:"-"`
	KernelNFT ExecutionToolIdentityV1 `json:"-"`
	KernelIP  ExecutionToolIdentityV1 `json:"-"`
	// KeeneticOS carries its policy plane on ipset + iptables instead of nftables.
	KernelIpset     ExecutionToolIdentityV1 `json:"-"`
	KernelIptables  ExecutionToolIdentityV1 `json:"-"`
	KernelIp6tables ExecutionToolIdentityV1 `json:"-"`
	KernelDnsmasq   ExecutionToolIdentityV1 `json:"-"`
	KernelShell     ExecutionToolIdentityV1 `json:"-"`
	// KernelWANIface is the uplink the plane MASQUERADEs through. Captured rather than defaulted:
	// the rendering default in render_ipset.go is one developer's router, and a wrong value breaks
	// return traffic while the installed rules still look correct.
	KernelWANIface   string                       `json:"-"`
	ExternalBindings []ExecutionExternalBindingV1 `json:"-"`
}

// executionMaterializationV1 is what one Apply installs: the exact core config bytes, the rendered
// kernel program, the plugin specs and the native (UCI/NDM) reconciliation. It is stored in the
// apply-state record so boot converge, fail-safe rollback and the reconcile loop re-execute exactly
// what was applied instead of recompiling from a profile that may have moved on since.
type executionMaterializationV1 struct {
	SchemaVersion    int                               `json:"schema_version"`
	Backend          string                            `json:"backend"`
	Core             executionCoreArtifactV1           `json:"core"`
	Kernel           executionKernelArtifactV1         `json:"kernel"`
	PluginAction     ExecutionActionV1                 `json:"plugin_action"`
	Plugins          []executionPluginSpecV1           `json:"plugins"`
	ExternalBindings []ExecutionExternalBindingV1      `json:"external_bindings"`
	Native           *executionNativeMaterializationV1 `json:"native,omitempty"`
}

type executionNativeMaterializationV1 struct {
	Delta executionNativeDeltaV1 `json:"delta"`
}

// nativeTarget returns the native plan this materialization installs, or nil when it has none.
func (m *executionMaterializationV1) nativeTarget() *nativeplan.Plan {
	if m == nil || m.Native == nil {
		return nil
	}
	return m.Native.Delta.Reconcile.Target
}

// kernelPlan returns the kernel plan this materialization keeps installed, or nil.
func (m *executionMaterializationV1) kernelPlan() *pbr.Plan {
	if m == nil || m.Kernel.Action != ExecutionEnsurePresent {
		return nil
	}
	return m.Kernel.Plan
}

// pluginSpecs converts the recorded plugin specs into what plugin.Manager.Sync consumes.
func (m *executionMaterializationV1) pluginSpecs() []executionPluginSpecV1 {
	if m == nil || m.PluginAction != ExecutionEnsurePresent {
		return nil
	}
	return m.Plugins
}

type executionGenerator func(*model.Profile, generator.Options) (*generator.Result, error)

func cloneExecutionProfile(profile model.Profile) (model.Profile, error) {
	encoded, err := json.Marshal(profile)
	if err != nil {
		return model.Profile{}, err
	}
	var owned model.Profile
	if err := json.Unmarshal(encoded, &owned); err != nil {
		return model.Profile{}, err
	}
	return owned, nil
}

func applyCapturedExternalBindings(
	profile *model.Profile,
	captured []ExecutionExternalBindingV1,
) ([]ExecutionExternalBindingV1, error) {
	if profile == nil {
		return nil, errExecutionExternalBinding
	}
	expected := make(map[string]*model.Endpoint)
	for i := range profile.Endpoints {
		endpoint := &profile.Endpoints[i]
		if endpoint.Enabled && endpoint.Engine == model.EngineExternal {
			expected[endpoint.ID] = endpoint
		}
	}
	bindings := make(map[string]string, len(captured))
	for _, binding := range captured {
		if binding.EndpointID == "" || binding.Interface == "" ||
			strings.TrimSpace(binding.EndpointID) != binding.EndpointID ||
			strings.TrimSpace(binding.Interface) != binding.Interface ||
			binding.IfIndex <= 0 || !binding.AdminUp || !binding.Ready {
			return nil, errExecutionExternalBinding
		}
		if _, duplicate := bindings[binding.EndpointID]; duplicate {
			return nil, errExecutionExternalBinding
		}
		if _, wanted := expected[binding.EndpointID]; !wanted {
			return nil, errExecutionExternalBinding
		}
		desiredInterface, _ := expected[binding.EndpointID].Params["interface"].(string)
		if binding.Interface != desiredInterface {
			// Host observation confirms a configured interface; it never rewrites Desired truth.
			return nil, errExecutionExternalBinding
		}
		bindings[binding.EndpointID] = binding.Interface
	}
	if len(bindings) != len(expected) {
		return nil, errExecutionExternalBinding
	}
	ids := make([]string, 0, len(expected))
	for id := range expected {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]ExecutionExternalBindingV1, 0, len(ids))
	for _, id := range ids {
		endpoint := expected[id]
		params := make(map[string]any, len(endpoint.Params)+1)
		for key, value := range endpoint.Params {
			params[key] = value
		}
		params["interface"] = bindings[id]
		endpoint.Params = params
		for _, observed := range captured {
			if observed.EndpointID == id {
				out = append(out, observed)
				break
			}
		}
	}
	return out, nil
}

func applyNativeConnectionBindings(profile *model.Profile, plan *nativeplan.Plan) error {
	if profile == nil || plan == nil {
		return errExecutionInvalidCapture
	}
	decisions := make(map[string]nativeplan.EndpointDecision, len(plan.Decisions))
	for _, decision := range plan.Decisions {
		if decision.EndpointID == "" {
			return errExecutionInvalidCapture
		}
		if _, duplicate := decisions[decision.EndpointID]; duplicate {
			return errExecutionInvalidCapture
		}
		decisions[decision.EndpointID] = decision
	}
	seen := 0
	for i := range profile.Endpoints {
		endpoint := &profile.Endpoints[i]
		if !endpoint.Enabled {
			continue
		}
		decision, ok := decisions[endpoint.ID]
		if !ok || decision.Protocol != endpoint.Protocol {
			return errExecutionInvalidCapture
		}
		seen++
		switch decision.Path {
		case nativeplan.PathNativeCreate, nativeplan.PathNativeManage, nativeplan.PathNativeUpdate:
			if decision.Interface == "" || strings.TrimSpace(decision.Interface) != decision.Interface {
				return errExecutionInvalidCapture
			}
			params := make(map[string]any, len(endpoint.Params)+1)
			for key, value := range endpoint.Params {
				params[key] = value
			}
			params["interface"] = decision.Interface
			endpoint.Engine = model.EngineExternal
			endpoint.Params = params
		case nativeplan.PathNativeAdopt:
			iface, _ := endpoint.Params["interface"].(string)
			if endpoint.Engine != model.EngineExternal || iface == "" || iface != decision.Interface {
				return errExecutionInvalidCapture
			}
		case nativeplan.PathExternal:
			if endpoint.Engine != model.EngineExternal && !endpoint.IsExternal() {
				return errExecutionInvalidCapture
			}
		case nativeplan.PathEnginePlugin:
			// WayHop's AmneziaWG engine runs it, so the endpoint keeps its engine; the decision's device
			// must be the one the plugin and the kernel plane both derive for it.
			if endpoint.Engine != model.EngineAmneziaWG || decision.Interface == "" ||
				decision.Interface != pbr.KernelIface(endpoint) {
				return errExecutionInvalidCapture
			}
		case nativeplan.PathCompatibility:
			if endpoint.Engine != model.EngineSingBox {
				return errExecutionInvalidCapture
			}
			// OpenWrt carries compatibility endpoints directly as sing-box outbounds and therefore
			// has no per-endpoint kernel interface. Keenetic deliberately allocates one wrtunN device
			// per compatibility endpoint so NDM can route into it. Requiring an interface on both
			// platforms made every proxy-only OpenWrt execution artifact impossible to materialize.
			switch plan.Platform {
			case platform.OpenWrt:
				if decision.Interface != "" {
					return errExecutionInvalidCapture
				}
			case platform.Keenetic:
				if decision.Interface == "" || strings.TrimSpace(decision.Interface) != decision.Interface {
					return errExecutionInvalidCapture
				}
			default:
				return errExecutionInvalidCapture
			}
		default:
			return errExecutionInvalidCapture
		}
	}
	if seen != len(decisions) {
		return errExecutionInvalidCapture
	}
	return nil
}

func validExecutionToolIdentity(identity ExecutionToolIdentityV1, expectedTool string) bool {
	return identity.Tool == expectedTool && identity.Runnable &&
		validExecutionRouterPath(identity.ResolvedPath) &&
		isLowerHexRevision(identity.ContentSHA256, reviewSHA256HexLen) &&
		validExecutionIdentityText(identity.Version, executionMaxToolVersionBytes)
}

func validExecutionRouterPath(value string) bool {
	return value != "" && len(value) <= executionMaxResolvedPathBytes &&
		strings.TrimSpace(value) == value && path.IsAbs(value) && path.Clean(value) == value &&
		validExecutionIdentityText(value, executionMaxResolvedPathBytes)
}

func validExecutionIdentityText(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func executionExternalInterfaces(bindings []ExecutionExternalBindingV1) map[string]bool {
	out := make(map[string]bool, len(bindings))
	for _, binding := range bindings {
		out[binding.Interface] = true
	}
	return out
}

func executionGeneratorOptions(
	desired DesiredSnapshot,
	reviewedPlan *pbr.Plan,
) (generator.Options, error) {
	mode := desiredRoutingMode(desired.Config)
	opts := generator.Options{
		MixedPort: desired.Config.Ports.Mixed,
		ClashAddr: desired.Inputs.ClashAddr, ClashSecret: desired.Config.Clash.Secret,
		TunEnabled: mode == "tun" || mode == "hybrid",
		TunMTU:     desired.Config.GatewayMTU, TunAddr: desired.Config.GatewayAddr,
		CacheFile:     path.Join(path.Dir(desired.Config.SingBox.Config), "cache.db"),
		RuleSetDetour: desired.Config.RuleSetDetour,
	}
	switch mode {
	case "tun", "mixed":
		if reviewedPlan != nil {
			return generator.Options{}, errExecutionInvalidCapture
		}
		return opts, nil
	case "hybrid", "fast":
		if reviewedPlan == nil {
			return generator.Options{}, errExecutionInvalidCapture
		}
	default:
		return generator.Options{}, errExecutionInvalidCapture
	}
	opts.Hybrid = true
	if mode == "fast" {
		opts.TunEnabled = false
		return opts, nil
	}
	blackhole := make(map[string]bool)
	for _, egress := range reviewedPlan.Egresses {
		if egress.Kind == pbr.EgressBlackhole {
			blackhole[egress.Tag] = true
		}
	}
	for _, zone := range reviewedPlan.Zones {
		if blackhole[zone.EgressTag] || zone.SrcScoped {
			continue
		}
		opts.KernelExcludeV4 = append(opts.KernelExcludeV4, zone.V4...)
		opts.KernelExcludeV6 = append(opts.KernelExcludeV6, zone.V6...)
	}
	opts.KernelExcludeV4 = append(opts.KernelExcludeV4, reviewedPlan.BypassV4...)
	opts.KernelExcludeV6 = append(opts.KernelExcludeV6, reviewedPlan.BypassV6...)
	return opts, nil
}

func executionKeeneticCompatibilityOptions(desired DesiredSnapshot) generator.Options {
	return generator.Options{
		MixedPort: desired.Config.Ports.Mixed,
		ClashAddr: desired.Inputs.ClashAddr, ClashSecret: desired.Config.Clash.Secret,
		TunEnabled: true,
		TunMTU:     desired.Config.GatewayMTU, TunAddr: desired.Config.GatewayAddr,
		CacheFile:     path.Join(path.Dir(desired.Config.SingBox.Config), "cache.db"),
		RuleSetDetour: desired.Config.RuleSetDetour,
	}
}

// dropTUNIPv6WithoutAutoRoute removes the TUN's IPv6 ULA when auto_route is off.
//
// The generator adds fdfe:dcba:9876::1/126 for one stated reason: so auto_route ALSO installs the
// IPv6 defaults, because a v4-only TUN would let a dual-stack client's v6 leak straight past it.
// Here auto_route is OFF by design - NDM installs the route into wrtun0 - so the address cannot buy
// that benefit, and it is not free.
//
// Measured on a live Keenetic: the address puts "fdfe:dcba:9876::/126 dev wrtun0" in the
// kernel, NDM's IPv6 route enumeration cannot map wrtun0 to an interface it manages, and it answers
// every enumeration with a ~24-frame backtrace. 165 of 165 "unable to resolve" records named wrtun0,
// about 4000 log lines in 9.5 minutes, which cut the router's bounded native log to under ten
// minutes of retention - and S99wayhop deliberately routes this daemon's own log into exactly that
// buffer, so WayHop's startup and failure lines were evicted before anyone could read them.
//
// v6 connectivity is unaffected: on that router the IPv6 defaults are nwg0, nwg1, nwg3 and nwg4, and
// none of them ever pointed at the TUN.
func dropTUNIPv6WithoutAutoRoute(inbound map[string]any) {
	if auto, _ := inbound["auto_route"].(bool); auto {
		return
	}
	isV6 := func(a string) bool { return strings.Contains(a, ":") }
	switch addrs := inbound["address"].(type) {
	case []string:
		kept := make([]string, 0, len(addrs))
		for _, a := range addrs {
			if !isV6(a) {
				kept = append(kept, a)
			}
		}
		inbound["address"] = kept
	case []any:
		kept := make([]any, 0, len(addrs))
		for _, a := range addrs {
			if str, ok := a.(string); ok && isV6(str) {
				continue
			}
			kept = append(kept, a)
		}
		inbound["address"] = kept
	}
}

func bindKeeneticCompatibilityTUN(config map[string]any) error {
	inbounds, ok := config["inbounds"].([]map[string]any)
	if !ok {
		return errExecutionGeneration
	}
	count := 0
	for _, inbound := range inbounds {
		if inbound["type"] != "tun" || inbound["tag"] != "tun-in" {
			continue
		}
		count++
		inbound["interface_name"] = "wrtun0"
		inbound["auto_route"] = false
		inbound["auto_redirect"] = false
		inbound["strict_route"] = false
		inbound["stack"] = "gvisor"
		dropTUNIPv6WithoutAutoRoute(inbound)
	}
	if count != 1 {
		return errExecutionGeneration
	}
	config["inbounds"] = inbounds
	return nil
}

type executionEndpointKind uint8

const (
	executionEndpointUnsupported executionEndpointKind = iota
	executionEndpointCore
	executionEndpointPlugin
	executionEndpointExternal
)

// classifyExecutionEndpoint is intentionally exhaustive over the model's current engines and
// protocols. It does not inherit generator.Generate's broad "any other engine is a SOCKS plugin"
// fallback: OpenVPN/Xray/Mihomo have no plugin implementation and nfqws is a packet modifier
// rather than an egress, so an enabled endpoint on one of them cannot be materialized.
func classifyExecutionEndpoint(engine model.Engine, protocol model.Protocol) executionEndpointKind {
	switch engine {
	case model.EngineExternal:
		// Protocol is non-semantic for an OS-owned interface endpoint.
		return executionEndpointExternal
	case model.EngineAmneziaWG:
		if protocol == model.ProtoAmneziaWG || protocol == model.ProtoWireGuard {
			return executionEndpointPlugin
		}
	case model.EngineOlcRTC:
		return executionEndpointPlugin
	case model.EngineSingBox:
		switch protocol {
		case model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan,
			model.ProtoShadowsocks, model.ProtoHysteria2, model.ProtoTUIC,
			model.ProtoAnyTLS, model.ProtoWireGuard, model.ProtoSOCKS, model.ProtoHTTP:
			return executionEndpointCore
		}
	case model.EngineOpenVPN, model.EngineXray, model.EngineMihomo, model.EngineNfqws:
		return executionEndpointUnsupported
	default:
		return executionEndpointUnsupported
	}
	return executionEndpointUnsupported
}

// captureExecutionPlugins turns the generator's plugin list into the specs the plugin manager
// runs. Every plugin must be an expected, WayHop-owned endpoint (an adopted or external tunnel is
// never started or torn down by the plugin manager) and its interface must not collide with an
// external binding or another plugin.
func captureExecutionPlugins(
	generated []generator.Plugin,
	expected map[string]model.Endpoint,
	externalInterfaces map[string]bool,
) ([]executionPluginSpecV1, error) {
	if len(generated) != len(expected) {
		return nil, errExecutionPluginArtifact
	}
	seen := make(map[string]bool, len(generated))
	awgIfaces := make(map[string]bool, len(generated))
	specs := make([]executionPluginSpecV1, 0, len(generated))
	for _, generatedPlugin := range generated {
		id := generatedPlugin.Endpoint.ID
		expectedEndpoint, ok := expected[id]
		if !ok || seen[id] || classifyExecutionEndpoint(
			generatedPlugin.Endpoint.Engine, generatedPlugin.Endpoint.Protocol,
		) != executionEndpointPlugin {
			return nil, errExecutionPluginArtifact
		}
		seen[id] = true
		owned, err := cloneExecutionEndpoint(generatedPlugin.Endpoint)
		if err != nil || !sameExecutionEndpoint(owned, expectedEndpoint) {
			return nil, errExecutionPluginArtifact
		}
		if owned.Engine == model.EngineAmneziaWG {
			iface := pbr.KernelIface(&owned)
			if iface == "" || awgIfaces[iface] || externalInterfaces[iface] {
				return nil, errExecutionPluginArtifact
			}
			awgIfaces[iface] = true
		}
		specs = append(specs, executionPluginSpecV1{
			ID: id, Endpoint: owned, SOCKSPort: generatedPlugin.SOCKSPort,
		})
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].ID < specs[j].ID })
	return specs, nil
}

func cloneExecutionEndpoint(endpoint model.Endpoint) (model.Endpoint, error) {
	encoded, err := json.Marshal(endpoint)
	if err != nil {
		return model.Endpoint{}, err
	}
	var owned model.Endpoint
	if err := json.Unmarshal(encoded, &owned); err != nil {
		return model.Endpoint{}, err
	}
	return owned, nil
}

func sameExecutionEndpoint(left, right model.Endpoint) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}
