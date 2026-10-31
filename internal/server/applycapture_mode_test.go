package server

import (
	"context"
	"testing"

	"wayhop/internal/platform"
)

// A Keenetic with Entware's ipset and iptables installed has the kernel plane's tools, but the plane
// is built only in hybrid and fast. In tun and mixed the capture said the lists rode it anyway, so no
// NDM route and no compatibility core carried them: every list left by the WAN behind a clean review
// (QA-061). The capture now says so only where the plane exists.
func TestCaptureKeeneticListsViaIpsetFollowsTheRoutingMode(t *testing.T) {
	orig := keeneticKernelPBRPresent
	t.Cleanup(func() { keeneticKernelPBRPresent = orig })
	keeneticKernelPBRPresent = func() bool { return true }

	for mode, want := range map[string]bool{"mixed": false, "tun": false, "hybrid": true, "fast": true} {
		desired, _ := executionCaptureExternalTuple(t)
		profile := desired.Profile
		profile.Endpoints[0].Params = map[string]any{"interface": "nwg10", "ndm_name": "Wireguard10"}
		cfg := desired.Config
		cfg.RoutingMode = mode
		var err error
		desired, err = newDesiredSnapshot(cfg, profile, 4)
		if err != nil {
			t.Fatal(err)
		}
		probe := hostTestProbe(desired)
		probe.Platform = string(platform.Keenetic)
		probe.RawCapabilities.Platform = string(platform.Keenetic)
		probe.RawCapabilities.NetifdProtos = nil
		host, err := newHostSnapshot(desired, probe, nil)
		if err != nil {
			t.Fatal(err)
		}
		facts := ExecutionHostFactsV1{Host: host, ExternalBindings: []ExecutionExternalBindingV1{{
			EndpointID: "external", Interface: "nwg10", IfIndex: 17, AdminUp: true, Ready: true,
		}}}
		capture, err := captureExecutionNativeFrom(context.Background(), desired, facts,
			func() (string, string, error) { return "", "", nil },
			func(context.Context) (string, error) { return "interface Wireguard10\n!\n", nil })
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if capture.ListsViaIpset != want {
			t.Errorf("%s: ListsViaIpset = %v, want %v", mode, capture.ListsViaIpset, want)
		}
		if !want && capture.DomainsViaDNSMasq {
			t.Errorf("%s: domains said to reach a kernel plane that is not built", mode)
		}
	}
}
