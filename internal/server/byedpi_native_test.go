package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
)

func byedpiEndpoint() model.Endpoint {
	return model.Endpoint{ID: "bye", Name: "ByeDPI", Engine: model.EngineByeDPI, Protocol: model.ProtoSOCKS, Enabled: true}
}

// QA-043: one ByeDPI connection next to a native AmneziaWG tunnel made the OpenWrt planner refuse the
// whole profile, and every native tunnel moved to sing-box and the engine plugins with the warning
// "router-native tunnels are not used". The native plan now stays: the tunnel is still the router's
// own interface, and ByeDPI is the core's SOCKS outbound to the ciadpi the plugin manager runs.
func TestMaterializeOpenWrtKeepsTheNativePlanWithByeDPI(t *testing.T) {
	desired, _, capture := executionNativeTestTuple(t)
	desired.Profile.Endpoints = append(desired.Profile.Endpoints, byedpiEndpoint())
	desired.Profile.RoutingLists = []model.RoutingList{{
		ID: "yt", Name: "YouTube", Manual: []string{"youtube.com"}, Outbound: "bye", Enabled: true,
	}}
	probe := hostTestProbe(desired)
	probe.RawCapabilities.Native["amneziawg"] = true
	delete(probe.RawCapabilities.Installable, "amneziawg")
	probe.RawCapabilities.NetifdProtos["amneziawg"] = true
	probe.RawCapabilities.SingboxRequired = append(probe.RawCapabilities.SingboxRequired, "socks")
	host, err := newHostSnapshot(desired, probe, nil)
	if err != nil {
		t.Fatal(err)
	}

	m, warnings, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}, native: &capture})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if m.Native == nil || strings.Contains(strings.Join(warnings, "\n"), "router-native tunnels are not used") {
		t.Fatalf("the native plan was dropped: native=%v warnings=%q", m.Native != nil, warnings)
	}
	target := m.Native.Delta.Reconcile.Target
	paths, ifaces := map[string]nativeplan.Path{}, map[string]string{}
	for _, d := range target.Decisions {
		paths[d.EndpointID], ifaces[d.EndpointID] = d.Path, d.Interface
	}
	if paths["ep-native"] != nativeplan.PathNativeCreate || len(target.OpenWrt) != 1 ||
		paths["bye"] != nativeplan.PathCompatibility {
		t.Fatalf("decisions %+v, %d UCI plans", target.Decisions, len(target.OpenWrt))
	}

	if len(m.Plugins) != 1 || m.Plugins[0].ID != "bye" || m.Plugins[0].Endpoint.Engine != model.EngineByeDPI ||
		m.Plugins[0].SOCKSPort == 0 || m.PluginAction != ExecutionEnsurePresent {
		t.Fatalf("plugins %+v, action %v: want the ciadpi spec alone", m.Plugins, m.PluginAction)
	}
	if m.Core.Action != ExecutionEnsurePresent {
		t.Fatalf("core %v: the core carries the SOCKS outbound to ciadpi", m.Core.Action)
	}
	var core struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(m.Core.Config, &core); err != nil {
		t.Fatal(err)
	}
	var socks, awg map[string]any
	for _, o := range core.Outbounds {
		switch o["tag"] {
		case "bye":
			socks = o
		case "ep-native":
			awg = o
		}
	}
	if socks == nil || socks["type"] != "socks" || socks["server"] != "127.0.0.1" ||
		socks["server_port"] != float64(m.Plugins[0].SOCKSPort) {
		t.Errorf("ByeDPI outbound = %v, want SOCKS to 127.0.0.1:%d", socks, m.Plugins[0].SOCKSPort)
	}
	// The tunnel reaches the core as the router's interface, not as a userspace AmneziaWG of its own.
	if awg == nil || awg["type"] != "direct" || ifaces["ep-native"] == "" || awg["bind_interface"] != ifaces["ep-native"] {
		t.Errorf("AmneziaWG outbound = %v, want a direct bind to the native interface", awg)
	}
}

// KeeneticOS cannot run ByeDPI: an Apply with one enabled is refused by name, with the way out.
func TestMaterializeKeeneticRefusesByeDPIByName(t *testing.T) {
	desired, host, capture := keeneticUserspaceTuple(t)
	desired.Profile.Endpoints = append(desired.Profile.Endpoints, byedpiEndpoint())
	_, _, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}, native: &capture})
	stage, detail, _ := materializeFailure(err)
	if err == nil || stage != "native" || !strings.Contains(detail, nativeplan.ByeDPIOnKeenetic) ||
		!strings.Contains(detail, `"bye"`) || !strings.Contains(detail, "disable the connection") {
		t.Fatalf("err %v, stage %q, detail %q", err, stage, detail)
	}
}

// The save gate refuses ENABLING a ByeDPI connection on KeeneticOS, though the core and its SOCKS
// client it otherwise asks for are there; a draft still saves, and OpenWrt still takes one.
func TestGateEndpointRefusesByeDPIOnKeenetic(t *testing.T) {
	gate := func(p platform.Platform, enabled bool) (int, string) {
		s := gateProxyServer(t, string(model.ProtoSOCKS), platform.CapSupported, platform.CapSupported)
		s.cfg.Demo = false
		s.platformOf = func() platform.Platform { return p }
		e := byedpiEndpoint()
		e.Enabled = enabled
		return s.gateEndpoint(context.Background(), e)
	}
	if code, msg := gate(platform.Keenetic, true); code != http.StatusUnprocessableEntity ||
		!strings.Contains(msg, "KeeneticOS") || !strings.Contains(msg, "Save it disabled") {
		t.Errorf("KeeneticOS, enabled: %d %q", code, msg)
	}
	if code, msg := gate(platform.Keenetic, false); code != 0 {
		t.Errorf("KeeneticOS, disabled draft: %d %q", code, msg)
	}
	if code, msg := gate(platform.OpenWrt, true); code != 0 {
		t.Errorf("OpenWrt, enabled: %d %q", code, msg)
	}
}

// One already stored enabled on KeeneticOS is a review blocker that names it, before any Apply.
func TestReviewBlocksByeDPIOnKeenetic(t *testing.T) {
	findings := func(p platform.Platform) map[string]PlanFinding {
		cfg := *config.Default()
		s := &Server{cfg: &cfg, platformOf: func() platform.Platform { return p },
			binaryPresentOf: func(name string) bool { return name == "ciadpi" }}
		s.applyState.loaded = true
		out := map[string]PlanFinding{}
		for _, f := range s.endpointFindings(model.Profile{Endpoints: []model.Endpoint{byedpiEndpoint()}}, platform.CapabilitySet{}) {
			out[f.ID] = f
		}
		return out
	}
	f, ok := findings(platform.Keenetic)["endpoint.engine.byedpi.keenetic"]
	if !ok || f.Blocks != platform.BlocksApply || f.Item != "ByeDPI" || !strings.Contains(f.Detail, "KeeneticOS") ||
		!strings.Contains(f.Remedy, "Disable") {
		t.Errorf("KeeneticOS finding: %+v (present %v)", f, ok)
	}
	if got := findings(platform.OpenWrt); len(got) != 0 {
		t.Errorf("OpenWrt with ciadpi installed: %+v", got)
	}
}

// A router QA-043 already hit ran its AmneziaWG on WayHop's engine (the generic path, no native plan).
// The first Apply after the fix takes it native on the SAME device name - the move the planner refuses
// within one Apply, because the new interface comes up while the old plugin still holds the link. A
// generic previous carries no native plan, so it went unseen; now it is refused with the two-Apply way.
func TestMaterializeRefusesTheMoveFromAGenericPrevious(t *testing.T) {
	desired, _, capture := executionNativeTestTuple(t)
	desired.Profile.Endpoints = append(desired.Profile.Endpoints, byedpiEndpoint())
	desired.Profile.RoutingLists = []model.RoutingList{{
		ID: "yt", Name: "YouTube", Manual: []string{"youtube.com"}, Outbound: "bye", Enabled: true,
	}}
	probe := hostTestProbe(desired)
	probe.RawCapabilities.Native["amneziawg"] = true
	delete(probe.RawCapabilities.Installable, "amneziawg")
	probe.RawCapabilities.NetifdProtos["amneziawg"] = true
	probe.RawCapabilities.SingboxRequired = append(probe.RawCapabilities.SingboxRequired, "socks")
	host, err := newHostSnapshot(desired, probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	generic, _, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}})
	if err != nil {
		t.Fatalf("generic materialize: %v", err)
	}
	if len(genericPluginDevices(&generic)) == 0 {
		t.Fatal("test setup: the generic previous must run an AmneziaWG plugin")
	}
	_, _, err = materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}, native: &capture, previous: &generic})
	if err == nil || !strings.Contains(err.Error(), "would move") || !strings.Contains(err.Error(), "switch the connection off and apply") {
		t.Fatalf("err = %v, want the move refused with the two-Apply remedy", err)
	}
}
