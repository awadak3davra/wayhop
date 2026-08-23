package server

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

type exactKernelRecordRunner struct {
	calls       []string
	stdin       []string
	causes      []error
	fail        map[string]error
	cancel      context.CancelFunc
	cancelAfter int
}

type exactKernelRunnerFunc func(context.Context, string, string, ...string) (string, error)

func (fn exactKernelRunnerFunc) Run(
	ctx context.Context,
	stdin string,
	name string,
	args ...string,
) (string, error) {
	return fn(ctx, stdin, name, args...)
}

func (runner *exactKernelRecordRunner) Run(
	ctx context.Context,
	stdin string,
	name string,
	args ...string,
) (string, error) {
	command := strings.TrimSpace(name + " " + strings.Join(args, " "))
	runner.calls = append(runner.calls, command)
	runner.stdin = append(runner.stdin, stdin)
	runner.causes = append(runner.causes, context.Cause(ctx))
	if runner.cancel != nil && runner.cancelAfter == len(runner.calls) {
		runner.cancel()
	}
	for fragment, err := range runner.fail {
		if strings.Contains(command, fragment) {
			return "", err
		}
	}
	return "", nil
}

func exactKernelTestArtifact() executionKernelArtifactV1 {
	plan := &pbr.Plan{
		Table: "wayhop_pbr", Mask: 0x00ff0000,
		Egresses: []pbr.Egress{
			{Tag: model.OutboundDirect, Kind: pbr.EgressWAN, Table: 254},
			{Tag: "native", Kind: pbr.EgressInterface, Iface: "awg0", Mark: 0x00010000, Table: 100},
		},
		Zones: []pbr.Zone{{
			Name: "native", EgressTag: "native", Mark: 0x00010000,
			V4: []string{"203.0.113.0/24"},
		}},
	}
	nftTool, ipTool := executionTestKernelTools()
	return executionKernelArtifactV1{
		Action: ExecutionEnsurePresent, Plan: plan,
		NFTTool: nftTool, IPTool: ipTool,
		Nft: []byte(plan.RenderNft()), IP: plan.RenderIP(pbr.Options{}),
		Offload: []byte(plan.RenderOffload()), Teardown: plan.RenderTeardown(pbr.Options{}),
	}
}

func TestExactKernelAdapterConsumesCapturedArtifactInOrder(t *testing.T) {
	artifact := exactKernelTestArtifact()
	runner := &exactKernelRecordRunner{}
	adapter, err := newExactKernelAdapter(runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.apply(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	want := []string{"nft -f -"}
	want = append(want, artifact.Teardown[1:]...)
	want = append(want, artifact.IP...)
	if len(artifact.Offload) != 0 {
		want = append(want, "nft -f -")
	}
	want = append(want, "nft -f -")
	proof, err := exactKernelProofProgram(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runner.calls, want) || runner.stdin[0] != string(artifact.Nft) ||
		runner.stdin[len(runner.stdin)-1] != proof {
		t.Fatalf("calls = %#v\nstdin[0] = %q\nwant calls = %#v", runner.calls, runner.stdin[0], want)
	}
}

func TestExactKernelAdapterPostcheckRequiresArtifactProof(t *testing.T) {
	artifact := exactKernelTestArtifact()
	proof, err := exactKernelProofSet(artifact)
	if err != nil {
		t.Fatal(err)
	}
	runner := &exactKernelRecordRunner{}
	adapter, _ := newExactKernelAdapter(runner)
	if err := adapter.postcheck(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	want := "nft list set inet " + artifact.Plan.Table + " " + proof
	if !reflect.DeepEqual(runner.calls, []string{want}) {
		t.Fatalf("postcheck calls = %#v; want %q", runner.calls, want)
	}

	runner = &exactKernelRecordRunner{fail: map[string]error{"list set": errors.New("set missing")}}
	adapter, _ = newExactKernelAdapter(runner)
	if err := adapter.postcheck(context.Background(), artifact); !errors.Is(err, errExactKernelArtifact) {
		t.Fatalf("missing proof postcheck = %v", err)
	}
}

func TestExactKernelAdapterPostcheckProvesAuthenticatedRetirement(t *testing.T) {
	previous := exactKernelTestArtifact()
	artifact := executionKernelArtifactV1{
		Action: ExecutionEnsureAbsent, NFTTool: previous.NFTTool, IPTool: previous.IPTool,
		Nft: []byte{}, IP: []string{}, Offload: []byte{}, Teardown: []string{},
		Retire: append([]string(nil), previous.Teardown...),
	}
	runner := &exactKernelRecordRunner{fail: map[string]error{
		"list table": errors.New("No such file or directory"),
	}}
	adapter, _ := newExactKernelAdapter(runner)
	if err := adapter.postcheck(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	runner.fail = nil
	if err := adapter.postcheck(context.Background(), artifact); !errors.Is(err, errExactKernelArtifact) {
		t.Fatalf("live retired table postcheck = %v", err)
	}
}

func TestExactKernelAdapterRejectsDriftAndUnprovenTeardownBeforeMutation(t *testing.T) {
	for name, mutate := range map[string]func(*executionKernelArtifactV1){
		"nft": func(a *executionKernelArtifactV1) { a.Nft = append(a.Nft, []byte("\n# drift")...) },
		"ip":  func(a *executionKernelArtifactV1) { a.IP[0] += " drift" },
		"nft identity": func(a *executionKernelArtifactV1) {
			a.NFTTool.ContentSHA256 = strings.Repeat("f", 63)
		},
		"swapped tool": func(a *executionKernelArtifactV1) {
			a.NFTTool.Tool, a.IPTool.Tool = a.IPTool.Tool, a.NFTTool.Tool
		},
		"teardown": func(a *executionKernelArtifactV1) { a.Teardown[0] = "nft delete table inet other" },
		"absent": func(a *executionKernelArtifactV1) {
			a.Action, a.Plan, a.Nft, a.IP, a.Offload, a.Teardown = ExecutionEnsureAbsent, nil, nil, nil, nil, nil
			a.Retire = []string{"rm -rf /"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			artifact := exactKernelTestArtifact()
			mutate(&artifact)
			runner := &exactKernelRecordRunner{}
			adapter, _ := newExactKernelAdapter(runner)
			if err := adapter.apply(context.Background(), artifact); !errors.Is(err, errExactKernelArtifact) {
				t.Fatalf("error = %v", err)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("invalid artifact mutated kernel: %#v", runner.calls)
			}
		})
	}
}

func TestExactKernelAdapterRemovesOnlyAuthenticatedBaseline(t *testing.T) {
	previous := exactKernelTestArtifact()
	artifact := executionKernelArtifactV1{
		Action:  ExecutionEnsureAbsent,
		NFTTool: previous.NFTTool, IPTool: previous.IPTool,
		Nft: []byte{}, IP: []string{}, Offload: []byte{}, Teardown: []string{},
		Retire: append([]string(nil), previous.Teardown...),
	}
	runner := &exactKernelRecordRunner{}
	adapter, _ := newExactKernelAdapter(runner)
	if err := adapter.apply(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runner.calls, previous.Teardown) {
		t.Fatalf("calls = %#v; want authenticated teardown %#v", runner.calls, previous.Teardown)
	}
	if artifact.NFTTool != previous.NFTTool || artifact.IPTool != previous.IPTool {
		t.Fatal("authenticated teardown lost the captured kernel tool identities")
	}
}

func TestExactKernelAdapterRollsBackPartialInstall(t *testing.T) {
	artifact := exactKernelTestArtifact()
	if len(artifact.IP) == 0 {
		t.Fatal("fixture has no IP command")
	}
	failed := strings.Join(strings.Fields(artifact.IP[0])[:3], " ")
	runner := &exactKernelRecordRunner{fail: map[string]error{failed: errors.New("route failed")}}
	adapter, _ := newExactKernelAdapter(runner)
	if err := adapter.apply(context.Background(), artifact); err == nil {
		t.Fatal("partial install unexpectedly succeeded")
	}
	rollbackStart := len(runner.calls) - len(artifact.Teardown)
	if rollbackStart < 0 || !reflect.DeepEqual(runner.calls[rollbackStart:], artifact.Teardown) {
		t.Fatalf("calls = %#v; want final rollback %#v", runner.calls, artifact.Teardown)
	}
}

func TestExactKernelAdapterRollsBackWhenProofCannotBeInstalled(t *testing.T) {
	artifact := exactKernelTestArtifact()
	runner := &exactKernelRecordRunner{}
	// Fail only the final nft transaction, not the initial ruleset or optional offload load.
	calls := 0
	baseRun := runner.Run
	adapter, _ := newExactKernelAdapter(exactKernelRunnerFunc(func(
		ctx context.Context, stdin, name string, args ...string,
	) (string, error) {
		calls++
		if strings.HasPrefix(stdin, "add set inet ") {
			_, _ = baseRun(ctx, stdin, name, args...)
			return "", errors.New("injected proof failure")
		}
		return baseRun(ctx, stdin, name, args...)
	}))
	if err := adapter.apply(context.Background(), artifact); err == nil {
		t.Fatal("proof failure unexpectedly succeeded")
	}
	if calls == 0 || len(runner.calls) < len(artifact.Teardown) ||
		!reflect.DeepEqual(runner.calls[len(runner.calls)-len(artifact.Teardown):], artifact.Teardown) {
		t.Fatalf("proof failure did not roll back: %#v", runner.calls)
	}
}

func TestExactKernelAdapterHonorsCancellationBeforeMutation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &exactKernelRecordRunner{}
	adapter, _ := newExactKernelAdapter(runner)
	if err := adapter.apply(ctx, exactKernelTestArtifact()); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("canceled adapter mutated kernel: %#v", runner.calls)
	}
}

func TestExactKernelAdapterCancellationAfterMutationUsesBoundedCleanupContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &exactKernelRecordRunner{cancel: cancel, cancelAfter: 1}
	adapter, _ := newExactKernelAdapter(runner)
	artifact := exactKernelTestArtifact()
	if err := adapter.apply(ctx, artifact); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if len(runner.calls) != 1+len(artifact.Teardown) {
		t.Fatalf("calls = %#v; want nft load plus rollback", runner.calls)
	}
	for i, cause := range runner.causes[1:] {
		if cause != nil {
			t.Fatalf("rollback call %d inherited canceled request context: %v", i, cause)
		}
	}
}

func TestExactKernelAlreadyAbsentNeverHidesMissingExecutable(t *testing.T) {
	if exactKernelAlreadyAbsent("nft delete table inet wayhop_pbr", errors.New("table does not exist")) != true {
		t.Fatal("absent nft table was not treated as idempotent cleanup")
	}
	if exactKernelAlreadyAbsent("ip rule del fwmark 0x1", errors.New("RTNETLINK: No such process")) != true {
		t.Fatal("absent ip rule was not treated as idempotent cleanup")
	}
	if exactKernelAlreadyAbsent("ip rule del fwmark 0x1", errors.New("exec: ip: executable file not found")) {
		t.Fatal("missing ip executable was hidden as an already-absent route")
	}
	busyBoxMissing := errors.New("exit status 2: ip: RTNETLINK answers: No such file or directory")
	if !exactKernelAlreadyAbsent("ip rule del fwmark 0x1", busyBoxMissing) {
		t.Fatal("BusyBox absent-rule spelling was treated as fatal")
	}
	if exactKernelAlreadyAbsent("ip rule add fwmark 0x1", busyBoxMissing) {
		t.Fatal("an add failure was treated as an idempotent cleanup miss")
	}
}
