package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wayhop/internal/binstore"
	"wayhop/internal/config"
	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// OpenWrt, whose own AmneziaWG would take an AmneziaWG 3 connection but cannot carry it, runs it on
// the engine plugin next to the native plan: the plugin is materialized, the device is bound to the
// reviewed zone, and the generic path is not taken.
func TestMaterializeOpenWrtRunsAWG3OnTheUserspaceEngine(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	in := func(d DesiredSnapshot, previous *executionMaterializationV1) materializeInput {
		return materializeInput{desired: d, host: ExecutionHostFactsV1{Host: host}, native: &capture, previous: previous}
	}
	native, _, err := materialize(in(desired, nil))
	if err != nil || native.Native == nil || len(native.Plugins) != 0 {
		t.Fatalf("the generation-1 fixture must materialize native-first with no plugin: native=%v plugins=%d err=%v",
			native.Native != nil, len(native.Plugins), err)
	}

	gen3 := desired
	gen3.Profile.Endpoints = append([]model.Endpoint(nil), desired.Profile.Endpoints...)
	params := map[string]any{}
	for k, v := range desired.Profile.Endpoints[0].Params {
		params[k] = v
	}
	params["header_protection_key"], params["disable_cookies"] = "k", true
	gen3.Profile.Endpoints[0].Params = params
	m, warnings, err := materialize(in(gen3, nil))
	if err != nil || m.Native == nil {
		t.Fatalf("materialize: native=%v err=%v warnings=%q", m.Native != nil, err, warnings)
	}
	target := m.Native.Delta.Reconcile.Target
	if len(target.OpenWrt) != 0 || len(target.OpenWrtBindings) != 1 || target.Decisions[0].Path != nativeplan.PathEnginePlugin {
		t.Fatalf("target: %d UCI plans, bindings %+v, decisions %+v", len(target.OpenWrt), target.OpenWrtBindings, target.Decisions)
	}
	if len(m.Plugins) != 1 || m.Plugins[0].Endpoint.Engine != model.EngineAmneziaWG ||
		pbr.KernelIface(&m.Plugins[0].Endpoint) != target.OpenWrtBindings[0].Device {
		t.Errorf("plugins %+v, binding %+v", m.Plugins, target.OpenWrtBindings)
	}

	// The same connection after an Apply that ran it natively: a move, refused by name rather than
	// handed to the generic path.
	_, _, err = materialize(in(gen3, &native))
	if err == nil {
		t.Fatal("a move from the native interface to the engine was materialized")
	}
	stage, detail, remedy := materializeFailure(err)
	if stage != "native" || !strings.Contains(detail, "would move") || !strings.Contains(remedy, "apply again") {
		t.Errorf("move refusal = %q / %q / %q", stage, detail, remedy)
	}

	// And back: after an Apply that ran it on the engine, the generation-1 connection would go to the
	// native writer - the same collision the other way round.
	_, _, err = materialize(in(desired, &m))
	if stage, detail, _ := materializeFailure(err); err == nil || stage != "native" ||
		!strings.Contains(detail, "from WayHop's userspace AmneziaWG to OpenWrt's own AmneziaWG") {
		t.Errorf("move back: err %v, stage %q, detail %q", err, stage, detail)
	}
}

// Every other native refusal on OpenWrt still hands the profile to the generic path: the typed case
// must not swallow them. A WARP client id is one the UCI writer has no option for.
func TestMaterializeOpenWrtOtherNativeRefusalsStillFallBack(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	desired.Profile.Endpoints[0].Params["reserved"] = []any{1.0, 2.0, 3.0}
	m, warnings, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}, native: &capture})
	if err != nil {
		t.Fatalf("the generic path must take a profile the native writer cannot express: %v", err)
	}
	if m.Native != nil || len(warnings) == 0 || !strings.Contains(strings.Join(warnings, "\n"), "router-native tunnels are not used") {
		t.Errorf("native=%v warnings=%q, want the generic path and its warning", m.Native != nil, warnings)
	}
}

// On OpenWrt the review tells the same story as on KeeneticOS for a connection the lane takes - what it
// needs, and that it is not native - and says nothing where the lane does not take it.
func TestReviewOpenWrtRunsAWG3OnTheUserspaceEngine(t *testing.T) {
	endpoint := awg3Endpoint("a3")
	protocol := string(endpoint.Protocol)
	native := platform.CapabilitySet{Items: map[string]platform.Capability{}}
	for _, op := range []platform.NativeOperation{platform.NativeCreate, platform.NativeRemove} {
		id := platform.NativeOperationCapabilityID(protocol, op)
		native.Items[id] = platform.Capability{ID: id, State: platform.CapSupported}
	}
	findings := func(demo bool, capset platform.CapabilitySet, installed bool) map[string]PlanFinding {
		cfg := *config.Default()
		cfg.Demo = demo
		s := &Server{cfg: &cfg, platformOf: func() platform.Platform { return platform.OpenWrt },
			binaryPresentOf: func(name string) bool { return installed && name == "amneziawg-go" }}
		s.applyState.loaded = true
		out := map[string]PlanFinding{}
		for _, f := range s.endpointFindings(model.Profile{Endpoints: []model.Endpoint{endpoint}}, capset) {
			out[f.ID] = f
		}
		return out
	}
	if f := findings(false, native, false)["endpoint.engine.amneziawg_go"]; f.Blocks != platform.BlocksFeature {
		t.Errorf("amneziawg-go missing: %+v", f)
	}
	if f := findings(false, native, true)["endpoint.amneziawg.userspace"]; f.Blocks != platform.BlocksNothing ||
		!strings.Contains(f.Detail, "OpenWrt's own AmneziaWG cannot carry") {
		t.Errorf("userspace note: %+v", f)
	}
	for name, got := range map[string]map[string]PlanFinding{
		"no native AmneziaWG (the generic path runs it)": findings(false, platform.CapabilitySet{}, true),
		"the demo": findings(true, native, true),
	} {
		for id := range got {
			if id == "endpoint.amneziawg.userspace" || id == "endpoint.amneziawg.move" {
				t.Errorf("%s: unexpected %s", name, id)
			}
		}
	}
}

// A move between the router's own AmneziaWG and the engine is a blocker in the review, read from the
// applied plan, in both directions.
func TestReviewOpenWrtBlocksAMove(t *testing.T) {
	protocol := string(model.ProtoAmneziaWG)
	native := platform.CapabilitySet{Items: map[string]platform.Capability{}}
	for _, op := range []platform.NativeOperation{platform.NativeCreate, platform.NativeRemove} {
		id := platform.NativeOperationCapabilityID(protocol, op)
		native.Items[id] = platform.Capability{ID: id, State: platform.CapSupported}
	}
	review := func(e model.Endpoint, was nativeplan.Path) *PlanFinding {
		cfg := *config.Default()
		s := &Server{cfg: &cfg, platformOf: func() platform.Platform { return platform.OpenWrt },
			binaryPresentOf: func(string) bool { return true }}
		s.applyState.rec = applyStateRecord{Committed: &appliedRevision{Rev: "r1",
			Materialization: executionMaterializationV1{SchemaVersion: ExecutionSnapshotSchemaV1,
				Native: &executionNativeMaterializationV1{Delta: executionNativeDeltaV1{Reconcile: nativeplan.Reconciliation{
					Platform: platform.OpenWrt,
					Target: &nativeplan.Plan{Platform: platform.OpenWrt, Decisions: []nativeplan.EndpointDecision{{
						EndpointID: e.ID, Protocol: model.ProtoAmneziaWG, Path: was, Interface: pbr.KernelIface(&e)}}},
				}}}}}}
		s.applyState.loaded = true
		for _, f := range s.endpointFindings(model.Profile{Endpoints: []model.Endpoint{e}}, native) {
			if f.ID == "endpoint.amneziawg.move" {
				return &f
			}
		}
		return nil
	}
	if f := review(awg3Endpoint("m"), nativeplan.PathNativeCreate); f == nil || f.Blocks != platform.BlocksApply ||
		f.Requested != "WayHop's userspace AmneziaWG" {
		t.Errorf("native to userspace: %+v", f)
	}
	if f := review(executionAWGEndpoint("m"), nativeplan.PathEnginePlugin); f == nil || f.Requested != "OpenWrt's own AmneziaWG" {
		t.Errorf("userspace to native: %+v", f)
	}
	if f := review(awg3Endpoint("m"), nativeplan.PathEnginePlugin); f != nil {
		t.Errorf("staying on the engine is not a move: %+v", f)
	}
	if f := review(executionAWGEndpoint("m"), nativeplan.PathNativeCreate); f != nil {
		t.Errorf("staying native is not a move: %+v", f)
	}
}

// keeneticAWGCapabilities is KeeneticOS whose NDM can create and remove AmneziaWG interfaces.
func keeneticAWGCapabilities() platform.CapabilitySet {
	return platform.Evaluate(platform.Capabilities{
		Platform: string(platform.Keenetic), Native: map[string]bool{"amneziawg": true, "wireguard": true},
		Installable: map[string]string{},
	}, platform.RuntimeFacts{NativeOperations: keeneticProductionNativeOperations()})
}

func awg3Endpoint(id string) model.Endpoint {
	e := executionAWGEndpoint(id)
	e.Params["s1"], e.Params["s2"], e.Params["s3"], e.Params["s4"] = 20, 30, 40, 50
	e.Params["header_protection_key"] = e.Params["pre_shared_key"]
	return e
}

// KeeneticOS hands an AmneziaWG 3 connection to WayHop's userspace engine, and the review says what
// that needs (amneziawg-go) and what it costs (it is not native); a connection NDM carries gets
// neither note.
func TestReviewKeeneticRunsAWG3OnTheUserspaceEngine(t *testing.T) {
	capset := keeneticAWGCapabilities()
	findings := func(installed bool, e model.Endpoint) map[string]PlanFinding {
		cfg := *config.Default()
		s := &Server{cfg: &cfg, platformOf: func() platform.Platform { return platform.Keenetic },
			binaryPresentOf: func(name string) bool { return installed && name == "amneziawg-go" }}
		out := map[string]PlanFinding{}
		for _, f := range s.endpointFindings(model.Profile{Endpoints: []model.Endpoint{e}}, capset) {
			out[f.ID] = f
		}
		return out
	}
	missing := findings(false, awg3Endpoint("a3"))["endpoint.engine.amneziawg_go"]
	if missing.Blocks != platform.BlocksFeature || missing.Reason != platform.ReasonMissingBinary ||
		!strings.Contains(missing.Detail, "header_protection_key") {
		t.Errorf("amneziawg-go missing: %+v", missing)
	}
	got := findings(true, awg3Endpoint("a3"))
	if _, refused := got["endpoint.amneziawg.generation"]; refused {
		t.Error("KeeneticOS still refuses the connection it now runs")
	}
	userspace := got["endpoint.amneziawg.userspace"]
	if userspace.Blocks != platform.BlocksNothing || userspace.Severity != platform.SeverityDegraded ||
		userspace.Reason != platform.ReasonPlatformUnsupported {
		t.Errorf("userspace note: %+v", userspace)
	}
	for id := range findings(true, executionAWGEndpoint("a1")) {
		if id == "endpoint.amneziawg.userspace" || id == "endpoint.engine.amneziawg_go" {
			t.Errorf("a connection NDM carries got %s", id)
		}
	}
}

// keeneticUserspaceTuple is a KeeneticOS native-first fixture: one AmneziaWG endpoint NDM creates and
// one AmneziaWG 3 endpoint WayHop's userspace engine runs.
func keeneticUserspaceTuple(t *testing.T) (DesiredSnapshot, HostSnapshotV1, executionNativeCaptureV1) {
	t.Helper()
	cfg := *config.Default()
	cfg.RoutingMode = "mixed"
	cfg.Offload = "auto" // what hostTestProbe measured; a mismatch poisons the capability set
	native, gen3 := executionAWGEndpoint("native"), awg3Endpoint("gen3")
	gen3.Server = "198.51.100.33"
	desired, err := newDesiredSnapshot(cfg, model.Profile{Endpoints: []model.Endpoint{native, gen3}}, 9)
	if err != nil {
		t.Fatal(err)
	}
	probe := hostTestProbe(desired)
	probe.Platform = string(platform.Keenetic)
	probe.RawCapabilities.Platform = string(platform.Keenetic)
	probe.RawCapabilities.Native = map[string]bool{"amneziawg": true, "wireguard": true}
	probe.RawCapabilities.NetifdProtos = nil
	probe.NativeOperations = keeneticProductionNativeOperations()
	host, err := newHostSnapshot(desired, probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	capture := executionNativeCaptureV1{
		OccupiedInterfaces: map[string]bool{},
		GlobalPriorities:   map[string]int{"ISP": 1000},
		KeeneticConfigRev:  strings.Repeat("a", 64),
	}
	return desired, host, capture
}

// Materialized, the userspace endpoint is one engine plugin next to the native plan, which creates an
// NDM interface only for the endpoint NDM carries - and no core is needed for either.
func TestMaterializeKeeneticRunsTheUserspaceEndpointAsAPlugin(t *testing.T) {
	desired, host, capture := keeneticUserspaceTuple(t)
	m, _, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}, native: &capture})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if m.Native == nil || len(m.Plugins) != 1 || m.Plugins[0].ID != "gen3" || m.PluginAction != ExecutionEnsurePresent {
		t.Fatalf("native %v, plugins %+v, action %v", m.Native != nil, m.Plugins, m.PluginAction)
	}
	if m.Plugins[0].Endpoint.Engine != model.EngineAmneziaWG {
		t.Errorf("the plugin endpoint lost its engine: %+v", m.Plugins[0].Endpoint)
	}
	target := m.Native.Delta.Reconcile.Target
	if len(target.Keenetic.Interfaces) != 1 || m.Core.Action != ExecutionEnsureAbsent {
		t.Errorf("NDM blocks %d, core %v", len(target.Keenetic.Interfaces), m.Core.Action)
	}
	if got := keeneticUserspaceDevices(m.Native); len(got) != 1 || got[0] != pbr.KernelIface(&m.Plugins[0].Endpoint) {
		t.Errorf("userspace devices for the kernel plane = %v", got)
	}
}

// The execution side of the new path: the binding keeps the endpoint's engine and holds the decision
// to the device the plugin derives, and the exact Keenetic target refuses any NDM route or ladder
// rung naming that device.
func TestKeeneticEnginePluginDecisionIsHeldToItsDevice(t *testing.T) {
	desired, host, capture := keeneticUserspaceTuple(t)
	// Only the userspace endpoint: the exact validator is judged on the device alone here.
	desired.Profile.Endpoints = desired.Profile.Endpoints[1:]
	artifact, err := buildExecutionNativeArtifactV1(desired, host, capture, nil)
	if err != nil {
		t.Fatal(err)
	}
	target := artifact.Plan
	target.Keenetic.RunningConfigRev = strings.Repeat("a", 64)
	if !validExactKeeneticTarget(target) {
		t.Fatalf("a compiled plan with an engine-plugin decision was refused: %+v", target.Decisions)
	}
	device := ""
	for _, d := range target.Decisions {
		if d.Path == nativeplan.PathEnginePlugin {
			device = d.Interface
		}
	}
	if device == "" {
		t.Fatalf("no engine-plugin decision in %+v", target.Decisions)
	}
	routed := target
	routed.Keenetic = withRoutesCopied(target.Keenetic)
	routed.Keenetic.Routes = append(routed.Keenetic.Routes, "ip route 203.0.113.0 255.255.255.0 "+device)
	if validExactKeeneticTarget(routed) {
		t.Error("an NDM route naming the userspace device was accepted")
	}
	laddered := target
	laddered.Keenetic = withRoutesCopied(target.Keenetic)
	laddered.Keenetic.GlobalPriority = map[string]int{device: 2000}
	if validExactKeeneticTarget(laddered) {
		t.Error("a ladder rung naming the userspace device was accepted")
	}

	profile := desired.Profile
	if err := applyNativeConnectionBindings(&profile, &target); err != nil {
		t.Fatalf("bindings: %v", err)
	}
	for _, e := range profile.Endpoints {
		if e.ID == "gen3" && (e.Engine != model.EngineAmneziaWG || e.Params["interface"] != nil) {
			t.Errorf("the plugin endpoint was rebound: %+v", e)
		}
	}
	wrong := target
	wrong.Decisions = append([]nativeplan.EndpointDecision(nil), target.Decisions...)
	for i := range wrong.Decisions {
		if wrong.Decisions[i].Path == nativeplan.PathEnginePlugin {
			wrong.Decisions[i].Interface = "wr_other"
		}
	}
	profile = desired.Profile
	if err := applyNativeConnectionBindings(&profile, &wrong); err == nil {
		t.Error("a decision naming another device was bound")
	}
}

// withRoutesCopied copies a plan with its own Routes slice and everything else as it was - a nil
// Singbox stays nil, so a refusal below is about the device and nothing else.
func withRoutesCopied(p *keenetic.Plan) *keenetic.Plan {
	out := *p
	out.Routes = append([]string(nil), p.Routes...)
	return &out
}

// On a flash too small for the binary the updater keeps amneziawg-go as its gzip; the plugin unpacks it
// into RAM at start, so the review must count it as installed.
func TestAWGUserspaceInstalledSeesTheCompressedStore(t *testing.T) {
	dir := t.TempDir()
	cfg := *config.Default()
	cfg.SingBox.Bin = filepath.Join(dir, "sing-box")
	s := &Server{cfg: &cfg}
	if s.awgUserspaceInstalled() {
		t.Fatal("amneziawg-go counted as installed with nothing stored")
	}
	if err := os.WriteFile(binstore.Stored(dir, "amneziawg-go", true), []byte("gzip bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := binstore.Write(dir, "amneziawg-go", "v3.1.20260828", true); err != nil {
		t.Fatal(err)
	}
	if !s.awgUserspaceInstalled() {
		t.Error("the compressed store was not counted as installed")
	}
}

// The review's core question on KeeneticOS asks with the same userspace set the planner uses: a
// default route into the userspace device needs the core, the device alone does not.
func TestDatapathRequiresCoreSeesTheUserspaceEndpoints(t *testing.T) {
	cfg := *config.Default()
	s := &Server{cfg: &cfg, platformOf: func() platform.Platform { return platform.Keenetic }}
	s.caps.set = keeneticAWGCapabilities()
	s.caps.set.ProbedAt = time.Now()
	profile := model.Profile{Endpoints: []model.Endpoint{awg3Endpoint("a3")}}
	if s.datapathRequiresCore(cfg, profile) {
		t.Error("an AmneziaWG 3 endpoint nothing routes into pulled in the core")
	}
	profile.Rules = []model.Rule{{ID: "all", Default: true, Outbound: "a3"}}
	if !s.datapathRequiresCore(cfg, profile) {
		t.Error("a default route into the userspace device did not pull in the core")
	}
	if reasons := s.datapathCoreReasons(cfg, profile); len(reasons) == 0 {
		t.Error("the core is required and no reason names why")
	}
}

// A default route into the userspace device is something NDM cannot express, so the compatibility
// core takes the policy - and egresses through the device, whose plugin it therefore names.
func TestMaterializeKeeneticCompatibilityCoreCarriesTheUserspaceEndpoint(t *testing.T) {
	desired, host, capture := keeneticUserspaceTuple(t)
	desired.Profile.Rules = []model.Rule{{ID: "all", Default: true, Outbound: "gen3"}}
	m, _, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}, native: &capture})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	target := m.Native.Delta.Reconcile.Target
	if !target.Keenetic.CompatibilityRouting || m.Core.Action != ExecutionEnsurePresent {
		t.Fatalf("compatibility routing %v, core %v", target.Keenetic.CompatibilityRouting, m.Core.Action)
	}
	if len(m.Plugins) != 1 || m.Plugins[0].ID != "gen3" {
		t.Fatalf("plugins %+v", m.Plugins)
	}
	if device := pbr.KernelIface(&m.Plugins[0].Endpoint); !strings.Contains(string(m.Core.Config), `"bind_interface": "`+device+`"`) {
		t.Errorf("the core does not egress through %s:\n%s", device, m.Core.Config)
	}
}
