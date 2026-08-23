package server

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/core"
	"wayhop/internal/failsafe"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
	"wayhop/internal/plugin"
	"wayhop/internal/store"
)

// Fixtures for the Apply pipeline tests: a Server whose host probe and execution adapters are fakes,
// so an Apply is deterministic, offline, and can be driven onto any platform.

// applytest_ops records every adapter call in order and lets each one be failed on demand.
type applytest_ops struct {
	mu    sync.Mutex
	calls []string

	prepareNativeErr error
	commitNativeErr  error
	persistNativeErr error
	coreErr          error
	checkErr         error
	kernelErr        error
	kernelCheckErr   error
	// failOnce clears the error field after it has fired once, so a rollback that re-executes the
	// baseline through the same adapters can succeed where the failed apply did not.
	failOnce bool
	// coreRunningAfter is what the fake core reports once an ensure_present core step has run; the
	// postcheck reads it, so a test can simulate a core that came up and then died.
	coreRunning bool
	problems    []map[string]any
	// nativeTargets / pluginSyncs record what the adapters were handed, so a rollback can be shown
	// to re-execute the BASELINE rather than the failed target.
	nativeTargets []string
	pluginSyncs   [][]string
	kernelActions []ExecutionActionV1
}

// take returns the pending error for one adapter, clearing it when failOnce is set.
func (f *applytest_ops) take(field *error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	err := *field
	if err != nil && f.failOnce {
		*field = nil
	}
	return err
}

func (f *applytest_ops) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
}

func (f *applytest_ops) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *applytest_ops) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls, f.nativeTargets, f.pluginSyncs, f.kernelActions = nil, nil, nil, nil
}

// ops builds the applyExecOps the Server will use.
func (f *applytest_ops) ops() applyExecOps {
	return applyExecOps{
		prepareNative: func(_ context.Context, target nativeplan.Plan) error {
			f.record("prepareNative")
			f.mu.Lock()
			f.nativeTargets = append(f.nativeTargets, string(target.Platform))
			f.mu.Unlock()
			return f.prepareNativeErr
		},
		commitNative: func(context.Context, nativeplan.Reconciliation) error {
			f.record("commitNative")
			return f.commitNativeErr
		},
		abortNative: func(context.Context, nativeplan.Plan) error {
			f.record("abortNative")
			return nil
		},
		persistNative: func(context.Context, nativeplan.Reconciliation) error {
			f.record("persistNative")
			return f.persistNativeErr
		},
		postcheckNative: func(context.Context, nativeplan.Reconciliation) error {
			f.record("postcheckNative")
			return nil
		},
		core: func(_ context.Context, artifact executionCoreArtifactV1) error {
			f.record("core:" + string(artifact.Action))
			if err := f.take(&f.coreErr); err != nil {
				return err
			}
			f.mu.Lock()
			f.coreRunning = artifact.Action == ExecutionEnsurePresent
			f.mu.Unlock()
			return nil
		},
		coreRunning: func() bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.coreRunning
		},
		checkCore: func(context.Context, []byte) error {
			f.record("checkCore")
			return f.checkErr
		},
		kernel: func(_ context.Context, target executionKernelArtifactV1, _ *executionKernelArtifactV1) error {
			f.record("kernel:" + string(target.Action))
			f.mu.Lock()
			f.kernelActions = append(f.kernelActions, target.Action)
			f.mu.Unlock()
			return f.take(&f.kernelErr)
		},
		kernelTeardown: func(context.Context, executionKernelArtifactV1) error {
			f.record("kernelTeardown")
			return nil
		},
		kernelPostcheck: func(context.Context, executionKernelArtifactV1) error {
			f.record("kernelPostcheck")
			return f.take(&f.kernelCheckErr)
		},
		plugins: func(_ context.Context, specs []executionPluginSpecV1) []map[string]any {
			f.record("plugins")
			ids := []string{}
			for _, spec := range specs {
				ids = append(ids, spec.ID)
			}
			f.mu.Lock()
			f.pluginSyncs = append(f.pluginSyncs, ids)
			f.mu.Unlock()
			return f.problems
		},
	}
}

// applytest_server builds a non-demo Server with fake adapters, a fake host probe and a capability
// set that supports the sing-box core and the usual protocols — the shape a healthy router has.
func applytest_server(t *testing.T) (*Server, *applytest_ops) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Demo = false
	cfg.RoutingMode = "mixed"
	cfg.DataDir = dir
	cfg.SingBox.Bin = filepath.Join(dir, "sing-box")
	cfg.SingBox.Config = filepath.Join(dir, "singbox.json")
	st, err := store.Open(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	fake := &applytest_ops{problems: []map[string]any{}}
	ops := fake.ops()
	s := &Server{
		cfg: cfg, store: st, applyStateDir: dir,
		singbox:  core.New(cfg.SingBox.Bin, cfg.SingBox.Config),
		failsafe: failsafe.New(failsafe.DefaultDurations()),
		plugins:  plugin.New(filepath.Join(dir, "plugins"), dir),
		execOps:  &ops,
		// The developer host is not a router: probe it and every capability reads unknown, so nothing
		// below could be exercised. platformOf keeps the plan's platform view consistent with it.
		hostProbeOf: func(_ context.Context, desired DesiredSnapshot) (hostProbeV1, error) {
			return applytest_hostProbe(desired, platform.Unknown), nil
		},
		platformOf: func() platform.Platform { return platform.Unknown },
	}
	s.caps.set = applytest_caps(nil)
	t.Cleanup(func() { s.failsafe.Confirm() }) // stop the armed window's background goroutine
	return s, fake
}

// applytest_caps is a capability set where everything an Apply needs is supported, minus the ids in
// `unusable` (which become hard-blocked, as a router that cannot carry them reports).
func applytest_caps(unusable []string) platform.CapabilitySet {
	blocked := make(map[string]bool, len(unusable))
	for _, id := range unusable {
		blocked[id] = true
	}
	items := map[string]platform.Capability{}
	add := func(id, blocks string) {
		c := platform.Capability{
			ID: id, State: platform.CapSupported, HostSupport: platform.VerdictYes,
			WayHopSupport: platform.VerdictYes, RuntimeState: platform.VerdictYes,
			Blocks: platform.BlocksNothing,
		}
		if blocked[id] {
			c.State, c.RuntimeState = platform.CapUnsupportedPlatform, platform.VerdictNo
			c.Reason, c.Blocks = platform.ReasonMissingBinary, blocks
			c.Detail = id + " is not available on this router"
		}
		items[id] = c
	}
	add(platform.CapEngineSingbox, platform.BlocksFeature)
	add(platform.CapEngineAmneziaWG, platform.BlocksFeature)
	add(platform.CapEngineOlcRTC, platform.BlocksFeature)
	add(platform.CapPBRKernel, platform.BlocksApply)
	for _, protocol := range []string{"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "anytls", "wireguard", "amneziawg", "socks", "http"} {
		add(platform.CapProtocolPrefix+protocol, platform.BlocksFeature)
	}
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, operation := range []platform.NativeOperation{platform.NativeAdopt, platform.NativeCreate, platform.NativeRemove} {
			add(platform.NativeOperationCapabilityID(protocol, operation), platform.BlocksFeature)
		}
	}
	for _, mode := range []string{"mixed", "tun", "fast", "hybrid"} {
		add("routing.mode."+mode, platform.BlocksApply)
	}
	return platform.CapabilitySet{Items: items, ProbedAt: time.Now()}
}

// applytest_hostProbe is a complete, ready host observation for desired on the given platform. It
// matches the desired snapshot field for field (the snapshot builder records a probe error when the
// two disagree), so the resulting capability set is clean.
func applytest_hostProbe(desired DesiredSnapshot, got platform.Platform) hostProbeV1 {
	caps := platform.Capabilities{
		Platform:        string(got),
		Native:          map[string]bool{"wireguard": true, "amneziawg": true},
		Installable:     map[string]string{},
		SingboxRequired: []string{"vless", "trojan", "vmess", "shadowsocks", "hysteria2", "tuic", "anytls", "socks", "http"},
		SingboxPresent:  true,
		NetifdProtos:    map[string]bool{"wireguard": true, "amneziawg": true},
		Accel:           platform.Accel{Kind: "nft-flowtable", HW: true},
	}
	if got == platform.Keenetic {
		caps.NetifdProtos = nil
		caps.Accel = platform.Accel{Kind: "ppe", HW: true}
	}
	return hostProbeV1{
		Platform: string(got), RawCapabilities: caps,
		Core: CoreRunnableIdentityV1{
			ConfiguredPath: strings.TrimSpace(desired.Config.SingBox.Bin),
			ResolvedPath:   "/opt/sbin/sing-box", ContentSHA256: strings.Repeat("a", 64),
			Version: "sing-box version 1.12.17", Present: true, Runnable: true, State: coreStateReady,
		},
		KernelPBRAvailable: got != platform.Keenetic,
		Accel:              caps.Accel,
		OffloadState:       platform.OffloadState{Requested: desired.Config.Offload, Configured: "off", Effective: "off"},
		ResolvedOffload:    "off",
		NativeDNSRead:      got == platform.OpenWrt || got == platform.Keenetic,
		NativeOperations:   keeneticProductionNativeOperations(),
		IPv6Routable:       false,
		ProbedAt:           time.Now(),
	}
}

// applytest_keenetic points the server at a Keenetic router: the host probe reports the platform and
// the NDM running-config reader is a fixture, so the native (NDM) plane is materialized and executed
// through the fakes.
func applytest_keenetic(s *Server) {
	s.hostProbeOf = func(_ context.Context, desired DesiredSnapshot) (hostProbeV1, error) {
		return applytest_hostProbe(desired, platform.Keenetic), nil
	}
	s.platformOf = func() platform.Platform { return platform.Keenetic }
	s.keeneticConfigReader = func(context.Context) (string, error) { return exactKeeneticBaselineConfig, nil }
}

// applytest_wireguardEndpoint is a WayHop-owned native WireGuard endpoint: KeeneticOS carries it as
// an NDM interface, so it drives the native path.
func applytest_wireguardEndpoint(id string) model.Endpoint {
	return model.Endpoint{
		ID: id, Name: id, Engine: model.EngineSingBox, Protocol: model.ProtoWireGuard,
		Server: "198.51.100.30", Port: 51820, Enabled: true,
		Params: map[string]any{
			"private_key":     "cHJpdmF0ZS1rZXktMzItYnl0ZXMtZm9yLXRlc3Rpbmc=",
			"peer_public_key": "cHVibGljLWtleS0zMi1ieXRlcy1mb3ItdGVzdGluZ3M=",
			"local_address":   []string{"10.9.0.2/32"},
		},
	}
}

// applytest_materialization is a hand-built materialization for the executor tests: every plane's
// action is explicit, so the step program can be asserted without going through the generator.
func applytest_materialization(core, kernel, plugins ExecutionActionV1, native bool) *executionMaterializationV1 {
	m := &executionMaterializationV1{
		SchemaVersion: ExecutionSnapshotSchemaV1, Backend: executionBackendGeneric,
		Core:         executionCoreArtifactV1{Action: core, Config: []byte(`{"log":{}}`)},
		Kernel:       executionKernelArtifactV1{Action: kernel},
		PluginAction: plugins, Plugins: []executionPluginSpecV1{},
	}
	if plugins == ExecutionEnsurePresent {
		m.Plugins = []executionPluginSpecV1{{ID: "awg1", Endpoint: executionAWGEndpoint("awg1")}}
	}
	if native {
		m.Backend = executionBackendNativeFirst
		target := &nativeplan.Plan{Platform: platform.OpenWrt}
		m.Native = &executionNativeMaterializationV1{Delta: executionNativeDeltaV1{
			SchemaVersion: executionNativeDeltaSchemaV1,
			Reconcile:     nativeplan.Reconciliation{Platform: platform.OpenWrt, Target: target},
		}}
	}
	return m
}
