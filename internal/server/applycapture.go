package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
)

var errExecutionCaptureUnavailable = errors.New("exact execution host capture is unavailable")

const (
	keeneticRunningConfigTimeout = 5 * time.Second
	keeneticRunningConfigLimit   = 1 << 20
)

type executionInterfaceObservationV1 struct {
	Index   int
	AdminUp bool
}

type executionInterfaceProbe func(context.Context, string) (executionInterfaceObservationV1, error)
type keeneticConfigReadFunc func(context.Context) (string, error)

func readKeeneticRunningConfig(ctx context.Context) (string, error) {
	return readKeeneticRunningConfigWith(ctx, runHostCommandBounded)
}

func readKeeneticRunningConfigWith(
	ctx context.Context,
	run func(context.Context, time.Duration, int, time.Duration, string, ...string) (string, error),
) (string, error) {
	if ctx == nil || run == nil {
		return "", errExecutionCaptureUnavailable
	}
	output, err := run(ctx, keeneticRunningConfigTimeout, keeneticRunningConfigLimit,
		applyHostCommandWaitDelay, exactKeeneticNDMCPath, "-c", "show running-config")
	if err != nil || strings.TrimSpace(output) == "" {
		return "", errExecutionCaptureUnavailable
	}
	return output, nil
}

// hostSnapshotMatchesDesired reports whether host was captured against desired: the two are only
// ever combined inside one Apply, so a mismatch is a programming error caught here rather than a
// mixed observation reaching the materializer.
func hostSnapshotMatchesDesired(desired DesiredSnapshot, host HostSnapshotV1) bool {
	return desired.SchemaVersion == DesiredSnapshotSchemaV1 && desired.DesiredRev != "" &&
		host.SchemaVersion == HostSnapshotSchemaV1 && host.DesiredRev == desired.DesiredRev
}

func probeExecutionInterface(_ context.Context, name string) (executionInterfaceObservationV1, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return executionInterfaceObservationV1{}, err
	}
	return executionInterfaceObservationV1{
		Index: iface.Index, AdminUp: iface.Flags&net.FlagUp != 0,
	}, nil
}

func (s *Server) captureExecutionHostFacts(
	ctx context.Context,
	desired DesiredSnapshot,
) (ExecutionHostFactsV1, error) {
	host, err := s.captureHostSnapshot(ctx, desired)
	if err != nil {
		return ExecutionHostFactsV1{}, fmt.Errorf("%w: host snapshot", errExecutionCaptureUnavailable)
	}
	facts, err := captureExecutionHostFactsFrom(ctx, desired, host, probeExecutionInterface)
	if err != nil {
		return ExecutionHostFactsV1{}, fmt.Errorf("%w: external interface evidence", errExecutionCaptureUnavailable)
	}
	mode := desiredRoutingMode(desired.Config)
	kernelMode := mode == "hybrid" || mode == "fast"
	switch {
	case platform.Platform(host.Platform) == platform.OpenWrt && kernelMode:
		facts.KernelNFT, err = probeExecutionToolIdentity(ctx, executionToolNFT)
		if err != nil {
			return ExecutionHostFactsV1{}, fmt.Errorf("%w: nft identity", errExecutionCaptureUnavailable)
		}
		facts.KernelIP, err = probeExecutionToolIdentity(ctx, executionToolIP)
		if err != nil {
			return ExecutionHostFactsV1{}, fmt.Errorf("%w: ip identity", errExecutionCaptureUnavailable)
		}
	case platform.Platform(host.Platform) == platform.Keenetic && kernelMode:
		// KeeneticOS has no nftables; its policy plane is ipset + iptables mangle + ip rule/route,
		// executed as one authenticated script because NDM re-invokes the same program from a
		// netfilter.d hook after every firewall rebuild.
		for _, probe := range []struct {
			tool string
			into *ExecutionToolIdentityV1
		}{
			{executionToolIpset, &facts.KernelIpset},
			{executionToolIptables, &facts.KernelIptables},
			{executionToolIp6tables, &facts.KernelIp6tables},
			{executionToolIP, &facts.KernelIP},
			{executionToolShell, &facts.KernelShell},
		} {
			identity, probeErr := probeExecutionToolIdentity(ctx, probe.tool)
			if probeErr != nil {
				// The API answer for a failed capture is deliberately vague, which leaves an
				// operator with "router state could not be verified" and no way to learn that one
				// tool of five was at fault. The name is not sensitive and the log is the only
				// place it can be recovered from afterwards.
				log.Printf("apply: Keenetic kernel capture: %s identity unavailable: %v", probe.tool, probeErr)
				return ExecutionHostFactsV1{}, fmt.Errorf("%w: %s identity", errExecutionCaptureUnavailable, probe.tool)
			}
			*probe.into = identity
		}
		// dnsmasq participates only when the plan carries domain zones, and a router routing plain
		// IP-CIDR lists has no reason to require it. Absence is recorded as an empty identity; the
		// artifact builder refuses a domain config that has no authenticated resolver behind it.
		if identity, probeErr := probeExecutionToolIdentity(ctx, executionToolDnsmasq); probeErr == nil {
			facts.KernelDnsmasq = identity
		}
		facts.KernelWANIface, err = probeWANInterface()
		if err != nil {
			return ExecutionHostFactsV1{}, fmt.Errorf("%w: WAN uplink", errExecutionCaptureUnavailable)
		}
	}
	return facts, nil
}

func captureExecutionHostFactsFrom(
	ctx context.Context,
	desired DesiredSnapshot,
	host HostSnapshotV1,
	probe executionInterfaceProbe,
) (ExecutionHostFactsV1, error) {
	if ctx == nil || probe == nil || !hostSnapshotMatchesDesired(desired, host) {
		return ExecutionHostFactsV1{}, errExecutionCaptureUnavailable
	}
	if err := context.Cause(ctx); err != nil {
		return ExecutionHostFactsV1{}, err
	}
	facts := ExecutionHostFactsV1{Host: host, ExternalBindings: []ExecutionExternalBindingV1{}}
	for _, endpoint := range desired.Profile.Endpoints {
		if !endpoint.Enabled || endpoint.Engine != model.EngineExternal {
			continue
		}
		legacyOpenWrtExternal := platform.Platform(host.Platform) == platform.OpenWrt &&
			endpoint.Engine == model.EngineExternal && endpoint.Owner == model.OwnerWayHop
		// Old Keenetic profiles predate ownership/ndm_name capture. Observe their exact live kernel
		// interface so the public review can explain the repair; the review blocks materialization
		// until a user-initiated re-adoption records OwnerExternal + the authoritative NDM name.
		legacyKeeneticExternal := platform.Platform(host.Platform) == platform.Keenetic &&
			endpoint.Engine == model.EngineExternal && endpoint.Owner == model.OwnerWayHop
		if !endpoint.IsExternal() && !legacyOpenWrtExternal && !legacyKeeneticExternal {
			return ExecutionHostFactsV1{}, errExecutionCaptureUnavailable
		}
		iface, _ := endpoint.Params["interface"].(string)
		if strings.TrimSpace(iface) != iface || netvpn.ValidInterfaceName(iface) != nil {
			return ExecutionHostFactsV1{}, errExecutionCaptureUnavailable
		}
		observation, err := probe(ctx, iface)
		if err != nil || observation.Index <= 0 {
			return ExecutionHostFactsV1{}, errExecutionCaptureUnavailable
		}
		facts.ExternalBindings = append(facts.ExternalBindings, ExecutionExternalBindingV1{
			EndpointID: endpoint.ID, Interface: iface, IfIndex: observation.Index,
			AdminUp: observation.AdminUp, Ready: observation.AdminUp,
		})
	}
	return facts, nil
}

func (s *Server) captureExecutionNative(
	ctx context.Context,
	desired DesiredSnapshot,
	host ExecutionHostFactsV1,
) (executionNativeCaptureV1, error) {
	read := readUCI
	if s != nil && s.uciReader != nil {
		read = s.uciReader
	}
	var readKeenetic keeneticConfigReadFunc
	if s != nil {
		readKeenetic = s.keeneticConfigReader
	}
	capture, err := captureExecutionNativeFrom(ctx, desired, host, read, readKeenetic)
	if err == nil && s != nil && platform.Platform(host.Host.Platform) == platform.OpenWrt {
		// In the same host pass: the UCI writer's generation is part of what the plan is compiled
		// against, like the UCI itself.
		awgKernel := s.awgKernelCaptureFor(platform.OpenWrt, s.awgHostProbe())
		switch {
		case awgKernel.Kept:
			log.Printf("apply: the AmneziaWG module probe failed (%s); keeping generation %s from the last Apply - the module and the netifd handler are unchanged",
				awgKernel.ProbeError, awgKernel.Generation)
		case awgKernel.ProbeError != "":
			log.Printf("apply: the AmneziaWG module probe failed (%s) and nothing proves the last Apply's generation still holds; OpenWrt's own AmneziaWG is written at its baseline",
				awgKernel.ProbeError)
		}
		capture.AWGKernel = &awgKernel
	}
	return capture, err
}

func captureExecutionNativeFrom(
	ctx context.Context,
	desired DesiredSnapshot,
	host ExecutionHostFactsV1,
	read uciReadFunc,
	readKeenetic keeneticConfigReadFunc,
) (executionNativeCaptureV1, error) {
	if ctx == nil || !hostSnapshotMatchesDesired(desired, host.Host) {
		return executionNativeCaptureV1{}, errExecutionCaptureUnavailable
	}
	if err := context.Cause(ctx); err != nil {
		return executionNativeCaptureV1{}, err
	}
	adopt := make(map[string]string, len(host.ExternalBindings))
	for _, binding := range host.ExternalBindings {
		if binding.EndpointID == "" || binding.Interface == "" || !binding.Ready ||
			adopt[binding.EndpointID] != "" {
			return executionNativeCaptureV1{}, errExecutionCaptureUnavailable
		}
		adopt[binding.EndpointID] = binding.Interface
	}
	switch platform.Platform(host.Host.Platform) {
	case platform.OpenWrt:
		if read == nil || host.Host.RawCapabilities.NetifdProtos == nil {
			return executionNativeCaptureV1{}, errExecutionCaptureUnavailable
		}
		network, firewall, err := read()
		if err != nil {
			return executionNativeCaptureV1{}, errExecutionCaptureUnavailable
		}
		return executionNativeCaptureV1{
			NetworkUCI: network, FirewallUCI: firewall,
			RouterProtos:    cloneRouterProtos(netvpn.RouterProtos(host.Host.RawCapabilities.NetifdProtos)),
			FirewallZone:    desired.Config.NativeFirewallZone,
			AdoptInterfaces: adopt,
		}, nil
	case platform.Keenetic:
		if readKeenetic == nil {
			return executionNativeCaptureV1{}, errExecutionCaptureUnavailable
		}
		runningConfig, err := readKeenetic(ctx)
		if err != nil || strings.TrimSpace(runningConfig) == "" {
			return executionNativeCaptureV1{}, errExecutionCaptureUnavailable
		}
		occupied := keenetic.OccupiedWireguardInterfaces(runningConfig)
		ndmNames, ok := validKeeneticAdoptEvidence(desired.Profile, adopt, occupied)
		if !ok {
			return executionNativeCaptureV1{}, errExecutionCaptureUnavailable
		}
		return executionNativeCaptureV1{
			AdoptInterfaces:    adopt,
			AdoptNDMNames:      ndmNames,
			DomainsViaDNSMasq:  keeneticDomainsViaDNSMasq(),
			ListsViaIpset:      keeneticKernelPBRPresent(),
			OccupiedInterfaces: occupied,
			GlobalPriorities:   keenetic.GlobalPriorities(runningConfig),
			KeeneticConfigRev:  keeneticRunningConfigRevision(runningConfig),
		}, nil
	default:
		return executionNativeCaptureV1{}, errExecutionCaptureUnavailable
	}
}

// validKeeneticAdoptEvidence binds every enabled external endpoint to both views captured for the
// same strict review: the live kernel link (ExternalBindings) and the exact NDM identity present in
// show running-config. A desired interface name alone is never ownership evidence.
// validKeeneticAdoptEvidence proves every adopted kernel link against the NDM interface that owns
// it, and returns that proven mapping.
//
// It used to return only a boolean, so the NDM names it had just authenticated were discarded and
// the plan had nothing but kernel names to route with — which NDM rejects. Returning them keeps the
// single place that establishes the correspondence as the single place it comes from.
func validKeeneticAdoptEvidence(
	profile model.Profile,
	adopt map[string]string,
	occupied map[string]bool,
) (map[string]string, bool) {
	endpoints := make(map[string]model.Endpoint, len(profile.Endpoints))
	for _, endpoint := range profile.Endpoints {
		if endpoint.Enabled && endpoint.Engine == model.EngineExternal {
			if endpoint.ID == "" || !endpoint.IsExternal() || endpoints[endpoint.ID].ID != "" {
				return nil, false
			}
			endpoints[endpoint.ID] = endpoint
		}
	}
	if len(endpoints) != len(adopt) {
		return nil, false
	}
	ndmNames := make(map[string]string, len(adopt))
	for endpointID, kernelName := range adopt {
		endpoint, ok := endpoints[endpointID]
		if !ok {
			return nil, false
		}
		ndmName, known := keenetic.ResolveNDMName(endpoint)
		if !known || !occupied[ndmName] || keeneticKernelName(ndmName) != kernelName {
			return nil, false
		}
		ndmNames[endpointID] = ndmName
	}
	return ndmNames, true
}

func keeneticKernelName(ndmName string) string {
	if !strings.HasPrefix(ndmName, "Wireguard") {
		return ""
	}
	suffix := strings.TrimPrefix(ndmName, "Wireguard")
	if suffix == "" {
		return ""
	}
	for _, digit := range suffix {
		if digit < '0' || digit > '9' {
			return ""
		}
	}
	return "nwg" + suffix
}

func keeneticRunningConfigRevision(running string) string {
	sum := sha256.Sum256([]byte(running))
	return hex.EncodeToString(sum[:])
}
