package server

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/keenetic"
	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
)

type exactKeeneticRecordRunner struct {
	batches [][]string
	failAt  int
}

const exactKeeneticBaselineConfig = "interface Existing\n    up\n!"

func TestExactKeeneticNDMCRunnerSendsOneCommandPerInvocationAndFlattensBlocks(t *testing.T) {
	// Interactive ndmc needs a terminal: fed on stdin by a daemon it reports "unable to update a
	// window line size", closes the NDM connection and exits 0 having run nothing — a whole batch
	// silently skipped while the process reported success. `-c` takes exactly one command, so a
	// block is flattened to the full path KeeneticOS accepts on one line.
	var sent []string
	var gotStdin string
	runner := &exactKeeneticNDMCRunner{run: func(_ context.Context, stdin, name string, args ...string) (string, error) {
		gotStdin = stdin
		if name != exactKeeneticNDMCPath || len(args) != 2 || args[0] != "-c" {
			t.Fatalf("unexpected ndmc invocation: name=%q args=%#v", name, args)
		}
		sent = append(sent, args[1])
		return "ok", nil
	}}
	commands := []string{"interface Wireguard10", "description wayhop", "up"}
	if _, err := runner.ParseBatch(context.Background(), commands); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"interface Wireguard10",
		"interface Wireguard10 description wayhop",
		"interface Wireguard10 up",
	}
	if !reflect.DeepEqual(sent, want) {
		t.Fatalf("sent = %#v, want %#v", sent, want)
	}
	if gotStdin != "" {
		t.Fatalf("stdin must stay empty, got %q", gotStdin)
	}

	// A batch with no block prefix is sent verbatim, one command at a time.
	sent = nil
	if _, err := runner.ParseBatch(context.Background(), []string{"ip route 10.0.0.0 255.0.0.0 ISP"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sent, []string{"ip route 10.0.0.0 255.0.0.0 ISP"}) {
		t.Fatalf("flat batch sent = %#v", sent)
	}

	if _, err := runner.ParseBatch(context.Background(), []string{"up\nno interface ISP"}); !errors.Is(err, errExactKeeneticPlan) {
		t.Fatalf("unsafe command error = %v", err)
	}
}

func TestExactKeeneticNDMCRunnerRedactsTransportFailure(t *testing.T) {
	runner := &exactKeeneticNDMCRunner{run: func(context.Context, string, string, ...string) (string, error) {
		return "private output", errors.New("private ndmc error")
	}}
	_, err := runner.ParseBatch(context.Background(), []string{"system configuration save"})
	if !errors.Is(err, errExactKeeneticApply) || strings.Contains(err.Error(), "private") {
		t.Fatalf("error = %v", err)
	}
}

func TestExactKeeneticNDMCRunnerRejectsSemanticCommandFailure(t *testing.T) {
	for name, response := range map[string]string{
		"rci status": `{"status":[{"status":"error","code":"7405600","message":"PRIVATE rejection"}]}`,
		"ndmc text":  `(config)> no such command: PRIVATE-rejected-command`,
	} {
		t.Run(name, func(t *testing.T) {
			runner := &exactKeeneticNDMCRunner{run: func(context.Context, string, string, ...string) (string, error) {
				return response, nil
			}}
			_, err := runner.ParseBatch(context.Background(), []string{"system configuration save"})
			if !errors.Is(err, errExactKeeneticApply) || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("semantic rejection error = %v", err)
			}
		})
	}
}

func (runner *exactKeeneticRecordRunner) ParseBatch(_ context.Context, commands []string) ([]byte, error) {
	runner.batches = append(runner.batches, append([]string(nil), commands...))
	if runner.failAt > 0 && len(runner.batches) == runner.failAt {
		return nil, errors.New("sensitive NDM failure")
	}
	return []byte(`[]`), nil
}

func exactKeeneticTestTarget() nativeplan.Plan {
	return nativeplan.Plan{
		Platform: platform.Keenetic,
		Decisions: []nativeplan.EndpointDecision{{
			EndpointID: "native", Path: nativeplan.PathNativeCreate, Interface: "Wireguard10",
		}},
		Keenetic: &keenetic.Plan{
			Interfaces:       [][]string{{"interface Wireguard10", "description wayhop", "up"}},
			Routes:           []string{"ip route 203.0.113.0 255.255.255.0 Wireguard10 auto"},
			IfaceFor:         map[string]string{"native": "Wireguard10"},
			RunningConfigRev: keeneticRunningConfigRevision(exactKeeneticBaselineConfig),
		},
	}
}

func exactKeeneticCompatibilityTarget() nativeplan.Plan {
	return nativeplan.Plan{
		Platform: platform.Keenetic,
		Decisions: []nativeplan.EndpointDecision{
			{EndpointID: "proxy-a", Path: nativeplan.PathCompatibility, Interface: "wrtun0"},
			{EndpointID: "proxy-b", Path: nativeplan.PathCompatibility, Interface: "wrtun0"},
		},
		Keenetic: &keenetic.Plan{
			IfaceFor:             map[string]string{"proxy-a": "wrtun0", "proxy-b": "wrtun0"},
			Singbox:              map[string]any{"wayhop_compatibility_routing": true},
			CompatibilityRouting: true,
			RunningConfigRev:     strings.Repeat("a", reviewSHA256HexLen),
		},
	}
}

func TestValidExactKeeneticTargetAllowsOnlySharedCompatibilityTUN(t *testing.T) {
	target := exactKeeneticCompatibilityTarget()
	if !validExactKeeneticTarget(target) {
		t.Fatal("one authenticated compatibility TUN was rejected")
	}

	withoutMode := target
	withoutMode.Keenetic = cloneKeeneticPlanForTest(target.Keenetic)
	withoutMode.Keenetic.CompatibilityRouting = false
	if validExactKeeneticTarget(withoutMode) {
		t.Fatal("duplicate per-endpoint interface was accepted outside compatibility-routing mode")
	}

	wrongIface := target
	wrongIface.Keenetic = cloneKeeneticPlanForTest(target.Keenetic)
	wrongIface.Decisions = append([]nativeplan.EndpointDecision(nil), target.Decisions...)
	wrongIface.Decisions[1].Interface = "wrtun1"
	wrongIface.Keenetic.IfaceFor["proxy-b"] = "wrtun1"
	if validExactKeeneticTarget(wrongIface) {
		t.Fatal("compatibility-routing endpoint escaped the one reviewed TUN")
	}

	collision := target
	collision.Keenetic = cloneKeeneticPlanForTest(target.Keenetic)
	collision.Decisions = append([]nativeplan.EndpointDecision(nil), target.Decisions...)
	collision.Decisions = append(collision.Decisions, nativeplan.EndpointDecision{
		EndpointID: "native", Path: nativeplan.PathNativeAdopt, Interface: "wrtun0",
	})
	collision.Keenetic.IfaceFor["native"] = "wrtun0"
	if validExactKeeneticTarget(collision) {
		t.Fatal("compatibility TUN collided with an adopted native interface")
	}
}

func cloneKeeneticPlanForTest(source *keenetic.Plan) *keenetic.Plan {
	clone := *source
	clone.IfaceFor = make(map[string]string, len(source.IfaceFor))
	for key, value := range source.IfaceFor {
		clone.IfaceFor[key] = value
	}
	clone.Singbox = make(map[string]any, len(source.Singbox))
	for key, value := range source.Singbox {
		clone.Singbox[key] = value
	}
	return &clone
}

func exactKeeneticReconciliation(target nativeplan.Plan, teardown []string) nativeplan.Reconciliation {
	return nativeplan.Reconciliation{
		Platform: platform.Keenetic, Target: &target,
		KeeneticTeardown: append([]string(nil), teardown...),
	}
}

func exactKeeneticConfigReader(configs ...string) keeneticConfigReadFunc {
	index := 0
	return func(context.Context) (string, error) {
		if index >= len(configs) {
			return "", errors.New("unexpected config read")
		}
		result := configs[index]
		index++
		return result, nil
	}
}

func exactKeeneticTargetRunningConfig(target nativeplan.Plan) string {
	lines := []string{}
	for _, block := range target.Keenetic.Interfaces {
		lines = append(lines, block...)
	}
	lines = append(lines, target.Keenetic.Routes...)
	return strings.Join(lines, "\n")
}

func TestExactKeeneticAdapterRequiresConfigSnapshotBeforeMutation(t *testing.T) {
	runner := &exactKeeneticRecordRunner{}
	adapter, _ := newExactKeeneticNativeAdapter(runner)
	adapter.readConfig = func(context.Context) (string, error) { return "", errors.New("PRIVATE snapshot failure") }
	err := adapter.prepare(context.Background(), exactKeeneticTestTarget())
	if !errors.Is(err, errExactKeeneticApply) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("snapshot error = %v", err)
	}
	if len(runner.batches) != 0 {
		t.Fatalf("snapshot failure crossed mutation boundary: %#v", runner.batches)
	}
}

func TestExactKeeneticAdapterPrepareAdoptedOnlyDoesNotReadOrMutate(t *testing.T) {
	runner := &exactKeeneticRecordRunner{failAt: 1}
	adapter, _ := newExactKeeneticNativeAdapter(runner)
	adapter.readConfig = func(context.Context) (string, error) {
		t.Fatal("adopted-only prepare read NDM running config")
		return "", nil
	}
	if err := adapter.prepare(context.Background(), exactKeeneticCompatibilityTarget()); err != nil {
		t.Fatal(err)
	}
	if len(runner.batches) != 0 {
		t.Fatalf("adopted-only prepare mutated NDM: %#v", runner.batches)
	}
}

func TestExactKeeneticAdapterPreparesUnsavedThenCommitsAndSaves(t *testing.T) {
	runner := &exactKeeneticRecordRunner{}
	adapter, err := newExactKeeneticNativeAdapter(runner)
	if err != nil {
		t.Fatal(err)
	}
	target := exactKeeneticTestTarget()
	adapter.readConfig = exactKeeneticConfigReader(
		exactKeeneticBaselineConfig,
		strings.Join(target.Keenetic.Interfaces[0], "\n"),
		exactKeeneticTargetRunningConfig(target),
		exactKeeneticTargetRunningConfig(target),
	)
	if err := adapter.prepare(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if len(runner.batches) != 1 || !reflect.DeepEqual(runner.batches[0], target.Keenetic.Interfaces[0]) {
		t.Fatalf("prepare activated routes before the compatibility/core phase: %#v", runner.batches)
	}
	teardown := []string{"no ip route 198.51.100.0 255.255.255.0 Wireguard11", "no interface Wireguard11"}
	if err := adapter.commit(context.Background(), exactKeeneticReconciliation(target, teardown)); err != nil {
		t.Fatal(err)
	}
	if err := adapter.persist(context.Background(), exactKeeneticReconciliation(target, teardown)); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		target.Keenetic.Interfaces[0], target.Keenetic.Routes, teardown, {exactKeeneticSaveCommand},
	}
	if !reflect.DeepEqual(runner.batches, want) {
		t.Fatalf("batches = %#v\nwant = %#v", runner.batches, want)
	}
}

func TestExactKeeneticAdapterPrepareSkipsExactSavedInterfaceAtColdBoot(t *testing.T) {
	runner := &exactKeeneticRecordRunner{failAt: 1}
	adapter, _ := newExactKeeneticNativeAdapter(runner)
	target := exactKeeneticTestTarget()
	running := exactKeeneticTargetRunningConfig(target)
	adapter.readConfig = exactKeeneticConfigReader(running, running)
	if err := adapter.prepare(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if len(runner.batches) != 0 {
		t.Fatalf("already materialized interface was resent: %#v", runner.batches)
	}
}

func TestExactKeeneticAdapterPrepareCreatesOnlyMissingColdBootInterface(t *testing.T) {
	runner := &exactKeeneticRecordRunner{}
	adapter, _ := newExactKeeneticNativeAdapter(runner)
	target := exactKeeneticTestTarget()
	existing := append([]string(nil), target.Keenetic.Interfaces[0]...)
	missing := []string{"interface Wireguard11", "description second", "up"}
	target.Keenetic.Interfaces = append(target.Keenetic.Interfaces, missing)
	target.Keenetic.IfaceFor["second"] = "Wireguard11"
	target.Decisions = append(target.Decisions, nativeplan.EndpointDecision{
		EndpointID: "second", Path: nativeplan.PathNativeCreate, Interface: "Wireguard11",
	})
	adapter.readConfig = exactKeeneticConfigReader(
		strings.Join(existing, "\n"), exactKeeneticTargetRunningConfig(target))
	if err := adapter.prepare(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if len(runner.batches) != 1 || !reflect.DeepEqual(runner.batches[0], missing) {
		t.Fatalf("prepare batches = %#v; want only missing interface %#v", runner.batches, missing)
	}
}

func TestExactKeeneticAdapterApplyOnlyNeverSaves(t *testing.T) {
	runner := &exactKeeneticRecordRunner{}
	adapter, _ := newExactKeeneticNativeAdapter(runner)
	target := exactKeeneticTestTarget()
	adapter.readConfig = exactKeeneticConfigReader(exactKeeneticTargetRunningConfig(target))
	if err := adapter.commit(context.Background(), exactKeeneticReconciliation(target, nil)); err != nil {
		t.Fatal(err)
	}
	if len(runner.batches) != 1 || !reflect.DeepEqual(runner.batches[0], target.Keenetic.Routes) {
		t.Fatalf("apply-only batches = %#v", runner.batches)
	}
}

func TestExactKeeneticAdapterSaveFailureIsRedacted(t *testing.T) {
	runner := &exactKeeneticRecordRunner{failAt: 2}
	adapter, _ := newExactKeeneticNativeAdapter(runner)
	target := exactKeeneticTestTarget()
	adapter.readConfig = exactKeeneticConfigReader(
		exactKeeneticTargetRunningConfig(target), exactKeeneticTargetRunningConfig(target))
	if err := adapter.commit(context.Background(), exactKeeneticReconciliation(target, nil)); err != nil {
		t.Fatal(err)
	}
	err := adapter.persist(context.Background(), exactKeeneticReconciliation(target, nil))
	if !errors.Is(err, errExactKeeneticApply) || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("error = %v", err)
	}
	// This test used to demand a teardown here, and that demand encoded the bug: persist runs only
	// after the postcheck proved the datapath, its caller keeps the revision as a live unsaved
	// window with "use Keep to retry", and Keep retries persist - which cannot succeed against a
	// target the previous attempt tore down. A failed `system configuration save` means flash
	// failed, not the datapath: the target must SURVIVE so the promised retry can work.
	if len(runner.batches) != 2 {
		t.Fatalf("save failure batches = %#v; want commit+save only, target left running", runner.batches)
	}
	wantCleanup := keenetic.TeardownCommands(target.Keenetic)
	for _, batch := range runner.batches {
		if reflect.DeepEqual(batch, wantCleanup) {
			t.Fatal("a failed save tore down the verified live target")
		}
	}
}

// The read that guards the save is plumbing, not drift: when it fails, nothing is known to be
// wrong with the running datapath, so nothing may be torn down and no save may be attempted.
func TestExactKeeneticAdapterPersistReadFailureLeavesTargetRunning(t *testing.T) {
	runner := &exactKeeneticRecordRunner{}
	adapter, _ := newExactKeeneticNativeAdapter(runner)
	target := exactKeeneticTestTarget()
	adapter.readConfig = func(context.Context) (string, error) {
		return "", errors.New("PRIVATE transient read failure")
	}
	err := adapter.persist(context.Background(), exactKeeneticReconciliation(target, nil))
	if !errors.Is(err, errExactKeeneticApply) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("error = %v", err)
	}
	if len(runner.batches) != 0 {
		t.Fatalf("a transient pre-save read failure mutated the router: %#v", runner.batches)
	}
}

func TestExactKeeneticAdapterCleansPreparedTargetOnFailureWithoutLeakingError(t *testing.T) {
	runner := &exactKeeneticRecordRunner{failAt: 2}
	adapter, _ := newExactKeeneticNativeAdapter(runner)
	target := exactKeeneticTestTarget()
	target.Decisions = append(target.Decisions, nativeplan.EndpointDecision{
		EndpointID: "second", Path: nativeplan.PathNativeCreate, Interface: "Wireguard11",
	})
	target.Keenetic.Interfaces = append(target.Keenetic.Interfaces,
		[]string{"interface Wireguard11", "description second", "up"})
	target.Keenetic.IfaceFor["second"] = "Wireguard11"
	adapter.readConfig = exactKeeneticConfigReader(exactKeeneticBaselineConfig)
	err := adapter.prepare(context.Background(), target)
	if !errors.Is(err, errExactKeeneticApply) || err.Error() != errExactKeeneticApply.Error() {
		t.Fatalf("error = %v", err)
	}
	wantCleanup := keenetic.TeardownCommands(&keenetic.Plan{Interfaces: target.Keenetic.Interfaces})
	if len(runner.batches) != 3 || !reflect.DeepEqual(runner.batches[2], wantCleanup) {
		t.Fatalf("batches = %#v; want cleanup %#v", runner.batches, wantCleanup)
	}
}

func TestExactKeeneticAdapterCleansSilentlyIncompleteInterfaceBatch(t *testing.T) {
	runner := &exactKeeneticRecordRunner{}
	adapter, _ := newExactKeeneticNativeAdapter(runner)
	target := exactKeeneticTestTarget()
	adapter.readConfig = exactKeeneticConfigReader(exactKeeneticBaselineConfig, exactKeeneticBaselineConfig)
	err := adapter.prepare(context.Background(), target)
	if !errors.Is(err, errExactKeeneticApply) {
		t.Fatalf("silent partial error = %v", err)
	}
	wantCleanup := keenetic.TeardownCommands(&keenetic.Plan{Interfaces: target.Keenetic.Interfaces})
	if len(runner.batches) != 2 || !reflect.DeepEqual(runner.batches[1], wantCleanup) {
		t.Fatalf("batches = %#v; want cleanup %#v", runner.batches, wantCleanup)
	}
}

func TestExactKeeneticAdapterVerifiesLiveStateBeforeSave(t *testing.T) {
	runner := &exactKeeneticRecordRunner{}
	adapter, _ := newExactKeeneticNativeAdapter(runner)
	target := exactKeeneticTestTarget()
	adapter.readConfig = exactKeeneticConfigReader(strings.Join(target.Keenetic.Interfaces[0], "\n"))
	err := adapter.commit(context.Background(), exactKeeneticReconciliation(target, nil))
	if !errors.Is(err, errExactKeeneticApply) {
		t.Fatalf("pre-save verification error = %v", err)
	}
	wantCleanup := keenetic.TeardownCommands(target.Keenetic)
	if len(runner.batches) != 2 || !reflect.DeepEqual(runner.batches[0], target.Keenetic.Routes) ||
		!reflect.DeepEqual(runner.batches[1], wantCleanup) {
		t.Fatalf("batches = %#v; want route then cleanup %#v", runner.batches, wantCleanup)
	}
	for _, batch := range runner.batches {
		if len(batch) == 1 && batch[0] == exactKeeneticSaveCommand {
			t.Fatal("unverified NDM state was persisted")
		}
	}
}

func TestExactKeeneticAdapterPostcheckProvesTargetAndRetirement(t *testing.T) {
	target := exactKeeneticTestTarget()
	teardown := []string{
		"no ip route 198.51.100.0 255.255.255.0 Wireguard11",
		"no interface Wireguard11",
	}
	running := strings.Join([]string{
		"interface Wireguard10", " description wayhop", " up",
		"ip route 203.0.113.0 255.255.255.0 Wireguard10 auto",
	}, "\n")
	adapter, _ := newExactKeeneticNativeAdapter(&exactKeeneticRecordRunner{})
	adapter.readConfig = func(context.Context) (string, error) { return running, nil }
	if err := adapter.postcheck(context.Background(), target, teardown, nil); err != nil {
		t.Fatal(err)
	}

	for name, bad := range map[string]string{
		"target route missing": strings.ReplaceAll(running,
			"ip route 203.0.113.0 255.255.255.0 Wireguard10 auto", ""),
		"obsolete interface remains": running + "\ninterface Wireguard11\n up",
		"obsolete route remains":     running + "\nip route 198.51.100.0 255.255.255.0 Wireguard11",
		"interface block reordered": strings.Join([]string{
			"interface Wireguard10", " up", " description wayhop",
			"ip route 203.0.113.0 255.255.255.0 Wireguard10 auto",
		}, "\n"),
	} {
		t.Run(name, func(t *testing.T) {
			adapter.readConfig = func(context.Context) (string, error) { return bad, nil }
			if err := adapter.postcheck(context.Background(), target, teardown, nil); !errors.Is(err, errExactKeeneticApply) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestExactKeeneticAdapterPostcheckRedactsReadFailure(t *testing.T) {
	adapter, _ := newExactKeeneticNativeAdapter(&exactKeeneticRecordRunner{})
	adapter.readConfig = func(context.Context) (string, error) {
		return "PRIVATE running config", errors.New("PRIVATE ndmc failure")
	}
	err := adapter.postcheck(context.Background(), exactKeeneticTestTarget(), nil, nil)
	if !errors.Is(err, errExactKeeneticApply) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("error=%v", err)
	}
}

func TestVerifyExactKeeneticRunningConfigIgnoresNDMContextSeparators(t *testing.T) {
	target := exactKeeneticTestTarget()
	target.Keenetic.Interfaces[0] = []string{
		"interface Wireguard10", "description wayhop", "wireguard peer AAAA=",
		"endpoint 192.0.2.10:443", "allow-ips 0.0.0.0 0.0.0.0", "connect", "up",
	}
	running := `interface Wireguard10
    description wayhop
    wireguard peer AAAA=
        endpoint 192.0.2.10:443
        allow-ips 0.0.0.0 0.0.0.0
        connect
    !
    up
!
ip route 203.0.113.0 255.255.255.0 Wireguard10 auto`
	if !verifyExactKeeneticRunningConfig(target, nil, nil, running) {
		t.Fatal("valid Keenetic running-config with NDM context separators was rejected")
	}
}

func TestExactKeeneticAdapterAcceptsBoundCompatibilityAddon(t *testing.T) {
	target := nativeplan.Plan{
		Platform: platform.Keenetic,
		Decisions: []nativeplan.EndpointDecision{{
			EndpointID: "compat", Path: nativeplan.PathCompatibility, Interface: "wrtun0",
		}},
		Keenetic: &keenetic.Plan{
			IfaceFor:         map[string]string{"compat": "wrtun0"},
			Singbox:          map[string]any{"inbounds": []any{}},
			RunningConfigRev: keeneticRunningConfigRevision(exactKeeneticBaselineConfig),
		},
	}
	adapter, _ := newExactKeeneticNativeAdapter(&exactKeeneticRecordRunner{})
	adapter.readConfig = exactKeeneticConfigReader(exactKeeneticBaselineConfig)
	if !validExactKeeneticTarget(target) {
		t.Fatal("exact compatibility target was rejected")
	}
	if err := adapter.prepare(context.Background(), target); err != nil {
		t.Fatal(err)
	}
}

func TestExactKeeneticAdoptedOnlyPhasesDoNotRequireNDM(t *testing.T) {
	target := exactKeeneticCompatibilityTarget()
	target.Keenetic.Interfaces = nil
	target.Keenetic.Routes = nil
	runner := &exactKeeneticRecordRunner{failAt: 1}
	adapter, err := newExactKeeneticNativeAdapter(runner)
	if err != nil {
		t.Fatal(err)
	}
	adapter.readConfig = func(context.Context) (string, error) {
		t.Fatal("adopted-only phase read NDM configuration")
		return "", errors.New("unreachable")
	}
	reconcile := exactKeeneticReconciliation(target, nil)
	if err := adapter.prepare(context.Background(), target); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := adapter.commit(context.Background(), reconcile); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := adapter.postcheck(context.Background(), target, nil, nil); err != nil {
		t.Fatalf("postcheck: %v", err)
	}
	if err := adapter.persist(context.Background(), reconcile); err != nil {
		t.Fatalf("persist: %v", err)
	}
	if len(runner.batches) != 0 {
		t.Fatalf("adopted-only phase mutated NDM: %#v", runner.batches)
	}
}

func TestExactKeeneticAdapterRejectsUnboundAddonAndCrossPlatformArtifacts(t *testing.T) {
	for name, mutate := range map[string]func(*nativeplan.Plan){
		"unbound addon": func(plan *nativeplan.Plan) { plan.Keenetic.Singbox = map[string]any{"secret": true} },
		"openwrt":       func(plan *nativeplan.Plan) { plan.Platform = platform.OpenWrt },
		"missing iface": func(plan *nativeplan.Plan) { plan.Decisions[0].Interface = "Wireguard12" },
		"duplicate": func(plan *nativeplan.Plan) {
			plan.Keenetic.Routes = append(plan.Keenetic.Routes, plan.Keenetic.Routes[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			target := exactKeeneticTestTarget()
			mutate(&target)
			runner := &exactKeeneticRecordRunner{}
			adapter, _ := newExactKeeneticNativeAdapter(runner)
			if err := adapter.prepare(context.Background(), target); !errors.Is(err, errExactKeeneticPlan) {
				t.Fatalf("error = %v", err)
			}
			if len(runner.batches) != 0 {
				t.Fatalf("invalid plan mutated Keenetic: %#v", runner.batches)
			}
		})
	}
}
