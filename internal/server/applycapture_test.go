package server

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

func executionCaptureExternalTuple(t *testing.T) (DesiredSnapshot, HostSnapshotV1) {
	t.Helper()
	cfg := *config.Default()
	cfg.RoutingMode = "mixed"
	cfg.NativeFirewallZone = "vpn"
	profile := model.Profile{Endpoints: []model.Endpoint{{
		ID: "external", Name: "external", Enabled: true,
		Engine: model.EngineExternal, Protocol: model.ProtoWireGuard, Owner: model.OwnerExternal,
		Params: map[string]any{"interface": "wg_existing"},
	}}}
	desired, err := newDesiredSnapshot(cfg, profile, 4)
	if err != nil {
		t.Fatal(err)
	}
	host, err := newHostSnapshot(desired, hostTestProbe(desired), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hostSnapshotMatchesDesired(desired, host) {
		t.Fatalf("invalid desired/host fixture: desired=%#v host=%#v", desired, host)
	}
	return desired, host
}

func TestCaptureExecutionHostFactsUsesObservedExternalInterface(t *testing.T) {
	desired, host := executionCaptureExternalTuple(t)
	calls := 0
	facts, err := captureExecutionHostFactsFrom(context.Background(), desired, host,
		func(_ context.Context, name string) (executionInterfaceObservationV1, error) {
			calls++
			if name != "wg_existing" {
				t.Fatalf("interface probe = %q", name)
			}
			return executionInterfaceObservationV1{Index: 17, AdminUp: true}, nil
		})
	if err != nil || calls != 1 || len(facts.ExternalBindings) != 1 {
		t.Fatalf("capture = %#v, calls=%d, err=%v", facts, calls, err)
	}
	if binding := facts.ExternalBindings[0]; binding.EndpointID != "external" ||
		binding.Interface != "wg_existing" || binding.IfIndex != 17 || !binding.Ready {
		t.Fatalf("external binding = %#v", binding)
	}

	_, err = captureExecutionHostFactsFrom(context.Background(), desired, host,
		func(context.Context, string) (executionInterfaceObservationV1, error) {
			return executionInterfaceObservationV1{}, errors.New("link disappeared")
		})
	if !errors.Is(err, errExecutionCaptureUnavailable) {
		t.Fatalf("missing external interface error = %v", err)
	}
}

func TestCaptureExecutionHostFactsAllowsLegacyExternalForReviewOnly(t *testing.T) {
	desired, _ := executionCaptureExternalTuple(t)
	profile := desired.Profile
	profile.Endpoints = append([]model.Endpoint(nil), profile.Endpoints...)
	profile.Endpoints[0].Owner = model.OwnerWayHop
	var err error
	desired, err = newDesiredSnapshot(desired.Config, profile, 4)
	if err != nil {
		t.Fatal(err)
	}
	host, err := newHostSnapshot(desired, hostTestProbe(desired), nil)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := captureExecutionHostFactsFrom(context.Background(), desired, host,
		func(context.Context, string) (executionInterfaceObservationV1, error) {
			return executionInterfaceObservationV1{Index: 17, AdminUp: true}, nil
		})
	if err != nil || len(facts.ExternalBindings) != 1 ||
		facts.ExternalBindings[0].Interface != "wg_existing" {
		t.Fatalf("legacy OpenWrt external capture=%#v error=%v", facts, err)
	}

	keeneticProbe := hostTestProbe(desired)
	keeneticProbe.Platform = string(platform.Keenetic)
	keeneticProbe.RawCapabilities.Platform = string(platform.Keenetic)
	keeneticHost, err := newHostSnapshot(desired, keeneticProbe, nil)
	if err != nil {
		t.Fatal(err)
	}
	keeneticFacts, err := captureExecutionHostFactsFrom(context.Background(), desired, keeneticHost,
		func(context.Context, string) (executionInterfaceObservationV1, error) {
			return executionInterfaceObservationV1{Index: 17, AdminUp: true}, nil
		})
	if err != nil || len(keeneticFacts.ExternalBindings) != 1 {
		t.Fatalf("legacy Keenetic interface must be observable for a repair review: facts=%#v err=%v", keeneticFacts, err)
	}
	// The plan refuses to materialize a legacy Keenetic external endpoint until it is re-adopted.
	keeneticServer := &Server{cfg: &desired.Config, platformOf: func() platform.Platform { return platform.Keenetic }}
	findings := keeneticServer.endpointFindings(desired.Profile, keeneticHost.CapabilitySet)
	if len(findings) != 1 || findings[0].ID != "endpoint.external.keenetic_identity" ||
		findings[0].Blocks != platform.BlocksApply {
		t.Fatalf("legacy Keenetic endpoint plan findings = %#v", findings)
	}
	if code, _, _, _ := findingTemplate(findings[0]); code != "NATIVE_ADOPTION_INCOMPLETE" {
		t.Fatalf("legacy Keenetic public review code = %q", code)
	}

	repairedProfile := desired.Profile
	repairedProfile.Endpoints = append([]model.Endpoint(nil), repairedProfile.Endpoints...)
	repairedProfile.Endpoints[0].Owner = model.OwnerExternal
	repairedProfile.Endpoints[0].Params = map[string]any{"interface": "wg_existing", "ndm_name": "Wireguard17"}
	repairedDesired, err := newDesiredSnapshot(desired.Config, repairedProfile, 5)
	if err != nil {
		t.Fatal(err)
	}
	repairedHost, err := newHostSnapshot(repairedDesired, func() hostProbeV1 {
		probe := hostTestProbe(repairedDesired)
		probe.Platform = string(platform.Keenetic)
		probe.RawCapabilities.Platform = string(platform.Keenetic)
		return probe
	}(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if findings := keeneticServer.endpointFindings(repairedDesired.Profile, repairedHost.CapabilitySet); len(findings) != 0 {
		t.Fatalf("repaired Keenetic endpoint findings = %#v, want none", findings)
	}
}

func TestCaptureExecutionHostFactsHonorsCanceledContextBeforeProbe(t *testing.T) {
	desired, host := executionCaptureExternalTuple(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	_, err := captureExecutionHostFactsFrom(ctx, desired, host,
		func(context.Context, string) (executionInterfaceObservationV1, error) {
			calls++
			return executionInterfaceObservationV1{Index: 17, AdminUp: true}, nil
		})
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("capture error = %v, calls=%d; want canceled before probe", err, calls)
	}
}

func TestCaptureExecutionNativeBindsHostProtocolsZoneAndAdoption(t *testing.T) {
	desired, host := executionCaptureExternalTuple(t)
	hostFacts := ExecutionHostFactsV1{Host: host, ExternalBindings: []ExecutionExternalBindingV1{{
		EndpointID: "external", Interface: "wg_existing", IfIndex: 17, AdminUp: true, Ready: true,
	}}}
	reads := 0
	capture, err := captureExecutionNativeFrom(context.Background(), desired, hostFacts,
		func() (string, string, error) {
			reads++
			return "network.lan=interface\n", "firewall.@zone[0]=zone\nfirewall.@zone[0].name='vpn'\n", nil
		}, nil)
	if err != nil || reads != 1 || capture.FirewallZone != "vpn" ||
		capture.AdoptInterfaces["external"] != "wg_existing" || capture.RouterProtos == nil ||
		!capture.RouterProtos["wireguard"] {
		t.Fatalf("native capture = %#v, reads=%d, err=%v", capture, reads, err)
	}

	_, err = captureExecutionNativeFrom(context.Background(), desired, hostFacts,
		func() (string, string, error) { return "", "", errors.New("uci failed") }, nil)
	if !errors.Is(err, errExecutionCaptureUnavailable) {
		t.Fatalf("UCI failure = %v", err)
	}
}

func TestCaptureExecutionNativeKeeneticNeverReadsUCI(t *testing.T) {
	desired, _ := executionCaptureExternalTuple(t)
	profile := desired.Profile
	profile.Endpoints[0].Params = map[string]any{
		"interface": "nwg10", "ndm_name": "Wireguard10",
	}
	var err error
	desired, err = newDesiredSnapshot(desired.Config, profile, 4)
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
	hostFacts := ExecutionHostFactsV1{Host: host, ExternalBindings: []ExecutionExternalBindingV1{{
		EndpointID: "external", Interface: "nwg10", IfIndex: 17, AdminUp: true, Ready: true,
	}}}
	reads := 0
	runningConfig := "interface Wireguard10\n description occupied\n!\n"
	capture, err := captureExecutionNativeFrom(context.Background(), desired, hostFacts,
		func() (string, string, error) { reads++; return "", "", nil },
		func(context.Context) (string, error) {
			return runningConfig, nil
		})
	if err != nil || reads != 0 || capture.AdoptInterfaces["external"] != "nwg10" ||
		!capture.OccupiedInterfaces["Wireguard10"] ||
		capture.KeeneticConfigRev != keeneticRunningConfigRevision(runningConfig) {
		t.Fatalf("Keenetic capture = %#v, reads=%d, err=%v", capture, reads, err)
	}
	if capture.FirewallZone != "" {
		t.Fatalf("Keenetic capture inherited OpenWrt firewall zone %q", capture.FirewallZone)
	}
}

func TestCaptureExecutionNativeKeeneticRequiresExactExternalNDMEvidence(t *testing.T) {
	desired, _ := executionCaptureExternalTuple(t)
	profile := desired.Profile
	profile.Endpoints[0].Params = map[string]any{
		"interface": "nwg5", "ndm_name": "Wireguard5",
	}
	var err error
	desired, err = newDesiredSnapshot(desired.Config, profile, 4)
	if err != nil {
		t.Fatal(err)
	}
	probe := hostTestProbe(desired)
	probe.Platform = string(platform.Keenetic)
	probe.RawCapabilities.Platform = string(platform.Keenetic)
	host, err := newHostSnapshot(desired, probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostFacts := ExecutionHostFactsV1{Host: host, ExternalBindings: []ExecutionExternalBindingV1{{
		EndpointID: "external", Interface: "nwg5", IfIndex: 17, AdminUp: true, Ready: true,
	}}}
	for name, mutate := range map[string]func(*model.Endpoint){
		"missing NDM identity": func(endpoint *model.Endpoint) { delete(endpoint.Params, "ndm_name") },
		"WayHop ownership":     func(endpoint *model.Endpoint) { endpoint.Owner = model.OwnerWayHop },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := desired
			candidate.Profile = desired.Profile
			candidate.Profile.Endpoints = append([]model.Endpoint(nil), desired.Profile.Endpoints...)
			candidate.Profile.Endpoints[0].Params = map[string]any{
				"interface": "nwg5", "ndm_name": "Wireguard5",
			}
			mutate(&candidate.Profile.Endpoints[0])
			candidate, err = newDesiredSnapshot(candidate.Config, candidate.Profile, 4)
			if err != nil {
				t.Fatal(err)
			}
			candidateHost := hostFacts
			candidateHost.Host, err = newHostSnapshot(candidate, probe, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := captureExecutionNativeFrom(context.Background(), candidate, candidateHost, nil,
				func(context.Context) (string, error) {
					return "interface Wireguard5\n description external\n!\n", nil
				}); !errors.Is(err, errExecutionCaptureUnavailable) {
				t.Fatalf("error = %v, want exact external NDM evidence refusal", err)
			}
		})
	}
	if _, err := captureExecutionNativeFrom(context.Background(), desired, hostFacts, nil,
		func(context.Context) (string, error) {
			return "interface Wireguard7\n description different\n!\n", nil
		}); !errors.Is(err, errExecutionCaptureUnavailable) {
		t.Fatalf("mismatched running-config error = %v", err)
	}
}

// keeneticForeignTuple is the live shape that Apply refused: an AmneziaWG 3.1 tunnel run from
// Entware (`awg1`), seen by discovery's runtime dump only, adopted with no NDM name.
func keeneticForeignTuple(t *testing.T, params map[string]any) (DesiredSnapshot, ExecutionHostFactsV1) {
	t.Helper()
	desired, _ := executionCaptureExternalTuple(t)
	profile := desired.Profile
	profile.Endpoints = append([]model.Endpoint(nil), profile.Endpoints...)
	profile.Endpoints[0].Protocol = model.ProtoAmneziaWG
	profile.Endpoints[0].Params = params
	var err error
	desired, err = newDesiredSnapshot(desired.Config, profile, 4)
	if err != nil {
		t.Fatal(err)
	}
	probe := hostTestProbe(desired)
	probe.Platform = string(platform.Keenetic)
	probe.RawCapabilities.Platform = string(platform.Keenetic)
	host, err := newHostSnapshot(desired, probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	iface, _ := params["interface"].(string)
	return desired, ExecutionHostFactsV1{Host: host, ExternalBindings: []ExecutionExternalBindingV1{{
		EndpointID: "external", Interface: iface, IfIndex: 21, AdminUp: true, Ready: true,
	}}}
}

func TestCaptureExecutionNativeKeeneticProvesForeignTunnel(t *testing.T) {
	runningConfig := func(context.Context) (string, error) {
		return "interface Wireguard0\n description provider-tunnel\n!\n", nil
	}
	desired, hostFacts := keeneticForeignTuple(t, map[string]any{"interface": "awg1", "source": "runtime"})
	capture, err := captureExecutionNativeFrom(context.Background(), desired, hostFacts, nil, runningConfig)
	if err != nil {
		t.Fatalf("a tunnel run outside KeeneticOS was refused at capture: %v", err)
	}
	if capture.AdoptForeign["external"] != "awg1" || len(capture.AdoptNDMNames) != 0 ||
		capture.AdoptInterfaces["external"] != "awg1" {
		t.Fatalf("foreign capture = adopt %#v ndm %#v foreign %#v",
			capture.AdoptInterfaces, capture.AdoptNDMNames, capture.AdoptForeign)
	}

	for name, params := range map[string]map[string]any{
		// A legacy NDM tunnel that only lacks its captured name keeps the re-adoption path.
		"NDM namespace":      {"interface": "nwg5", "source": "runtime"},
		"not runtime-seen":   {"interface": "awg1", "source": "ndm"},
		"no discovery proof": {"interface": "awg1"},
	} {
		t.Run(name, func(t *testing.T) {
			desired, hostFacts := keeneticForeignTuple(t, params)
			if _, err := captureExecutionNativeFrom(context.Background(), desired, hostFacts, nil,
				runningConfig); !errors.Is(err, errExecutionCaptureUnavailable) {
				t.Fatalf("error = %v, want the NDM evidence refusal", err)
			}
		})
	}

	// The live link must be the device the endpoint names: a binding to anything else is not proof.
	desired, hostFacts = keeneticForeignTuple(t, map[string]any{"interface": "awg1", "source": "runtime"})
	hostFacts.ExternalBindings[0].Interface = "awg2"
	if _, err := captureExecutionNativeFrom(context.Background(), desired, hostFacts, nil,
		runningConfig); !errors.Is(err, errExecutionCaptureUnavailable) {
		t.Fatalf("mismatched foreign link error = %v", err)
	}
}

func TestEndpointFindingsAcceptForeignKeeneticTunnel(t *testing.T) {
	desired, hostFacts := keeneticForeignTuple(t, map[string]any{"interface": "awg1", "source": "runtime"})
	s := &Server{cfg: &desired.Config, platformOf: func() platform.Platform { return platform.Keenetic }}
	for _, f := range s.endpointFindings(desired.Profile, hostFacts.Host.CapabilitySet) {
		if f.ID == "endpoint.external.keenetic_identity" {
			t.Fatalf("a tunnel run outside KeeneticOS was sent to an NDM re-adoption that cannot exist: %#v", f)
		}
	}
	if got := keeneticForeignDevices(desired.Profile); got["external"] != "awg1" || len(got) != 1 {
		t.Fatalf("review foreign devices = %#v", got)
	}

	legacy, legacyHost := keeneticForeignTuple(t, map[string]any{"interface": "nwg5", "source": "runtime"})
	found := false
	for _, f := range s.endpointFindings(legacy.Profile, legacyHost.Host.CapabilitySet) {
		found = found || f.ID == "endpoint.external.keenetic_identity"
	}
	if !found {
		t.Fatal("an NDM tunnel without its captured name lost its re-adoption finding")
	}
}

func TestCaptureExecutionNativeKeeneticRequiresRunningConfigEvidence(t *testing.T) {
	desired, _ := executionCaptureExternalTuple(t)
	probe := hostTestProbe(desired)
	probe.Platform = string(platform.Keenetic)
	probe.RawCapabilities.Platform = string(platform.Keenetic)
	host, err := newHostSnapshot(desired, probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, read := range map[string]keeneticConfigReadFunc{
		"missing": nil,
		"empty":   func(context.Context) (string, error) { return "", nil },
		"failed":  func(context.Context) (string, error) { return "", errors.New("ndmc failed") },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := captureExecutionNativeFrom(context.Background(), desired,
				ExecutionHostFactsV1{Host: host}, nil, read); !errors.Is(err, errExecutionCaptureUnavailable) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestReadKeeneticRunningConfigUsesOnlyBoundedReadOnlyCommand(t *testing.T) {
	calls := 0
	got, err := readKeeneticRunningConfigWith(context.Background(),
		func(_ context.Context, timeout time.Duration, limit int, wait time.Duration,
			name string, args ...string) (string, error) {
			calls++
			if timeout != keeneticRunningConfigTimeout || limit != keeneticRunningConfigLimit ||
				wait != applyHostCommandWaitDelay || name != exactKeeneticNDMCPath ||
				!reflect.DeepEqual(args, []string{"-c", "show running-config"}) {
				t.Fatalf("unsafe command: timeout=%s limit=%d wait=%s %s %#v",
					timeout, limit, wait, name, args)
			}
			return "interface Wireguard0\n!\n", nil
		})
	if err != nil || calls != 1 || !strings.Contains(got, "Wireguard0") {
		t.Fatalf("read result=%q calls=%d error=%v", got, calls, err)
	}
	_, err = readKeeneticRunningConfigWith(context.Background(),
		func(context.Context, time.Duration, int, time.Duration, string, ...string) (string, error) {
			return "sensitive stderr", errors.New("sensitive ndmc failure")
		})
	if !errors.Is(err, errExecutionCaptureUnavailable) || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("error = %v", err)
	}
}
