package server

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The executor's job is the make-before-break order: bring up what the next plane will consume
// before switching it, and retire what nothing references only afterwards.

func applyexec_run(t *testing.T, m, previous *executionMaterializationV1, fake *applytest_ops) (applyExecResult, error) {
	t.Helper()
	ops := fake.ops()
	return executeMaterialization(context.Background(), ops, m, previous, nil)
}

func TestExecuteMaterialization_StepOrder(t *testing.T) {
	cases := []struct {
		name string
		m    *executionMaterializationV1
		want []string
	}{
		{
			name: "native, core and kernel all present",
			m:    applytest_materialization(ExecutionEnsurePresent, ExecutionEnsurePresent, ExecutionEnsurePresent, true),
			// Interfaces and engines first, then the consumers (core, kernel), then the retirements,
			// then the native commit, then the proof.
			want: []string{"prepareNative", "plugins", "core:ensure_present", "kernel:ensure_present",
				"plugins", "commitNative", "postcheckNative", "kernelPostcheck"},
		},
		{
			name: "native-only: the kernel plane goes up before the core is retired",
			m:    applytest_materialization(ExecutionEnsureAbsent, ExecutionEnsurePresent, ExecutionEnsureAbsent, false),
			want: []string{"kernel:ensure_present", "core:ensure_absent", "kernelPostcheck"},
		},
		{
			name: "no kernel plane: the core carries everything",
			m:    applytest_materialization(ExecutionEnsurePresent, ExecutionEnsureAbsent, ExecutionEnsureAbsent, false),
			want: []string{"core:ensure_present", "kernel:ensure_absent"},
		},
		{
			name: "demo touches nothing",
			m:    applytest_materialization(ExecutionDemoNoop, ExecutionDemoNoop, ExecutionDemoNoop, false),
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &applytest_ops{}
			res, err := applyexec_run(t, tc.m, nil, fake)
			if err != nil {
				t.Fatalf("execute: %v", err)
			}
			if got := strings.Join(fake.snapshot(), ","); got != strings.Join(tc.want, ",") {
				t.Errorf("ops = %v\nwant  %v", fake.snapshot(), tc.want)
			}
			if tc.want == nil && res.Mutated {
				t.Error("a demo program must not report a mutation")
			}
			if tc.want != nil && !res.Mutated {
				t.Error("a program that ran steps must report a mutation")
			}
		})
	}
}

// Make-before-break for the engine plugins: the union of old and new runs while the consumer planes
// switch, and only then is the set narrowed to the target — so a restored outbound never binds to an
// interface that was already torn down.
func TestExecuteMaterialization_PluginUnionThenRetire(t *testing.T) {
	target := applytest_materialization(ExecutionEnsurePresent, ExecutionEnsureAbsent, ExecutionEnsurePresent, false)
	target.Plugins = []executionPluginSpecV1{{ID: "awgB", Endpoint: executionAWGEndpoint("awgB")}}
	previous := applytest_materialization(ExecutionEnsurePresent, ExecutionEnsureAbsent, ExecutionEnsurePresent, false)
	previous.Plugins = []executionPluginSpecV1{{ID: "awgA", Endpoint: executionAWGEndpoint("awgA")}}

	fake := &applytest_ops{}
	if _, err := applyexec_run(t, target, previous, fake); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(fake.pluginSyncs) != 2 {
		t.Fatalf("plugin syncs = %v, want the union then the target", fake.pluginSyncs)
	}
	if got := strings.Join(fake.pluginSyncs[0], ","); got != "awgB,awgA" {
		t.Errorf("first sync = %v, want both the new and the still-running set", fake.pluginSyncs[0])
	}
	if got := strings.Join(fake.pluginSyncs[1], ","); got != "awgB" {
		t.Errorf("second sync = %v, want only the target set", fake.pluginSyncs[1])
	}
	// The retire pass is what reports which engines are down.
	steps := strings.Join(fake.snapshot(), ",")
	if !strings.Contains(steps, "plugins,core:ensure_present") || !strings.Contains(steps, "kernel:ensure_absent,plugins") {
		t.Errorf("ops = %v, want prepare before the core and retire after the planes", fake.snapshot())
	}
}

func TestExecuteMaterialization_FailureStopsAndNamesTheStep(t *testing.T) {
	m := applytest_materialization(ExecutionEnsurePresent, ExecutionEnsurePresent, ExecutionEnsureAbsent, true)
	fake := &applytest_ops{kernelErr: errors.New("nft: permission denied")}

	res, err := applyexec_run(t, m, nil, fake)
	if err == nil {
		t.Fatal("a failing plane must fail the program")
	}
	var stepErr *applyExecError
	if !errors.As(err, &stepErr) {
		t.Fatalf("error = %v, want an applyExecError naming the step", err)
	}
	if stepErr.Step != stepKernel {
		t.Errorf("step = %q, want %q", stepErr.Step, stepKernel)
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("the adapter's cause must survive: %v", err)
	}
	if !res.Mutated {
		t.Error("a failure after the first step must report the mutation, else nothing is rolled back")
	}
	// Everything after the failing step is skipped: the native commit never runs.
	if got := strings.Join(fake.snapshot(), ","); strings.Contains(got, "commitNative") {
		t.Errorf("the program continued past a failure: %v", fake.snapshot())
	}
	if last := res.Steps; len(last) != 0 && last[len(last)-1] == stepKernel {
		t.Error("a failed step must not be recorded as completed")
	}
}

// The postcheck is the difference between "we ran the commands" and "the router is in that state".
func TestPostcheckMaterialization_CoreMustMatchTheIntent(t *testing.T) {
	cases := []struct {
		name    string
		action  ExecutionActionV1
		running bool
		wantErr string
	}{
		{name: "core wanted and up", action: ExecutionEnsurePresent, running: true},
		{name: "core wanted and dead", action: ExecutionEnsurePresent, running: false, wantErr: "not running"},
		{name: "core retired and gone", action: ExecutionEnsureAbsent, running: false},
		{name: "core retired and still up", action: ExecutionEnsureAbsent, running: true, wantErr: "still running"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := applytest_materialization(tc.action, ExecutionEnsureAbsent, ExecutionEnsureAbsent, false)
			fake := &applytest_ops{coreRunning: tc.running}
			ops := fake.ops()
			// coreRunning is fixed for this check: the core step is not part of a postcheck.
			ops.core = func(context.Context, executionCoreArtifactV1) error { return nil }
			err := postcheckMaterialization(context.Background(), ops, m)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("postcheck: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("postcheck error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// A materialization the record cannot describe (an imported pre-ledger baseline) must be refused
// rather than half-executed.
func TestExecuteMaterialization_RefusesAnUnknownProgram(t *testing.T) {
	fake := &applytest_ops{}
	if _, err := applyexec_run(t, &executionMaterializationV1{}, nil, fake); err == nil {
		t.Fatal("an unknown materialization must not be executed")
	}
	if got := fake.snapshot(); len(got) != 0 {
		t.Errorf("an unknown materialization reached the adapters: %v", got)
	}
	// So must a plane whose action is not executable.
	m := applytest_materialization(ExecutionDemoNoop, ExecutionEnsurePresent, ExecutionEnsureAbsent, false)
	if _, err := applyexec_run(t, m, nil, fake); err == nil {
		t.Fatal("a half-demo program must be refused")
	}
}

// Teardown is the rollback path when there is no baseline to return to: everything WayHop installed
// comes back out.
func TestTeardownMaterialization_RemovesEveryPlane(t *testing.T) {
	m := applytest_materialization(ExecutionEnsurePresent, ExecutionEnsurePresent, ExecutionEnsurePresent, true)
	fake := &applytest_ops{}
	ops := fake.ops()
	if err := teardownMaterialization(context.Background(), ops, m); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	got := strings.Join(fake.snapshot(), ",")
	for _, want := range []string{"core:ensure_absent", "kernelTeardown", "abortNative", "plugins"} {
		if !strings.Contains(got, want) {
			t.Errorf("teardown did not %s: %v", want, fake.snapshot())
		}
	}
	if len(fake.pluginSyncs) != 1 || len(fake.pluginSyncs[0]) != 0 {
		t.Errorf("the plugins must be synced to nothing, got %v", fake.pluginSyncs)
	}
	// A demo program installed nothing, so there is nothing to remove.
	fake.reset()
	demo := applytest_materialization(ExecutionDemoNoop, ExecutionDemoNoop, ExecutionDemoNoop, false)
	if err := teardownMaterialization(context.Background(), ops, demo); err != nil {
		t.Fatalf("demo teardown: %v", err)
	}
	if got := fake.snapshot(); len(got) != 0 {
		t.Errorf("a demo teardown touched the router: %v", got)
	}
}
