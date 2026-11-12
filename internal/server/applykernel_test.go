package server

import (
	"context"
	"errors"
	"reflect"
	"slices"
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
	// Rules and routes, then the nft program, then the deletions; nothing of the running plane is
	// removed before the new one is complete (RT-01).
	var want, cleanups []string
	for _, command := range artifact.IP {
		if exactKernelIPCleanupCommand(command) {
			cleanups = append(cleanups, command)
		} else {
			want = append(want, command)
		}
	}
	if len(cleanups) == 0 {
		t.Fatal("fixture has no in-place cleanup command")
	}
	want = append(want, "nft -f -")
	want = append(want, cleanups...)
	if len(artifact.Offload) != 0 {
		want = append(want, "nft -f -")
	}
	want = append(want, "nft -f -")
	proof, err := exactKernelProofProgram(artifact)
	if err != nil {
		t.Fatal(err)
	}
	nftAt := slices.Index(runner.calls, "nft -f -")
	if !reflect.DeepEqual(runner.calls, want) || nftAt < 0 || runner.stdin[nftAt] != string(artifact.Nft) ||
		runner.stdin[len(runner.stdin)-1] != proof {
		t.Fatalf("calls = %#v\nwant calls = %#v", runner.calls, want)
	}
}

// RT-01: a re-apply over the running plane converges in place. The kernel answers every rule the
// plane already holds with "File exists" and every stale-state delete with "No such process"; the
// apply must accept both, and must never delete a rule or flush a table it keeps, the kill-switch
// blackhole above all, so no marked packet can fall through to the main table (the WAN) meanwhile.
func TestExactKernelAdapterReapplyConvergesInPlace(t *testing.T) {
	artifact := exactKernelTestArtifact()
	artifact.Plan.Egresses[1].FailClosed = true
	artifact.Plan.Zones[0].V4 = append(artifact.Plan.Zones[0].V4, "10.77.0.0/16") // a listed private range (RT-09 rules)
	artifact.Nft = []byte(artifact.Plan.RenderNft())
	artifact.IP = artifact.Plan.RenderIP(pbr.Options{})
	artifact.Offload = []byte(artifact.Plan.RenderOffload())
	artifact.Teardown = artifact.Plan.RenderTeardown(pbr.Options{})
	exists := errors.New("exit status 2: RTNETLINK answers: File exists")
	runner := &exactKernelRecordRunner{fail: map[string]error{" rule add ": exists}}
	adapter, _ := newExactKernelAdapter(runner)
	if err := adapter.apply(context.Background(), artifact); err != nil {
		t.Fatalf("re-apply over the installed plane failed: %v\ncalls = %#v", err, runner.calls)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, " del ") || strings.Contains(call, " flush ") || strings.HasPrefix(call, "nft delete") {
			t.Fatalf("re-apply removed part of the running plane: %q\ncalls = %#v", call, runner.calls)
		}
	}
	blackhole := "ip route replace blackhole default metric 1000 table 100"
	if b, n := slices.Index(runner.calls, blackhole), slices.Index(runner.calls, "nft -f -"); b < 0 || n < 0 || b > n {
		t.Fatalf("the kill-switch blackhole must be in place before the nft load (blackhole %d, nft %d): %#v", b, n, runner.calls)
	}

	// Turning the kill switch off: the blackhole is removed by its own delete, after the nft load, and
	// "already gone" is the normal answer.
	off := exactKernelTestArtifact()
	del := "ip route del blackhole default metric 1000 table 100"
	if !slices.Contains(off.IP, del) {
		t.Fatalf("fixture without kill switch renders no stale-blackhole delete: %#v", off.IP)
	}
	runner = &exactKernelRecordRunner{fail: map[string]error{
		" rule add ": exists, del: errors.New("exit status 2: RTNETLINK answers: No such process"),
	}}
	adapter, _ = newExactKernelAdapter(runner)
	if err := adapter.apply(context.Background(), off); err != nil {
		t.Fatalf("an absent stale blackhole failed the apply: %v", err)
	}
	if d, n := slices.Index(runner.calls, del), slices.Index(runner.calls, "nft -f -"); d < 0 || d < n {
		t.Fatalf("the stale-blackhole delete must run after the nft load (del %d, nft %d): %#v", d, n, runner.calls)
	}

	// "File exists" is accepted only for a rule add; on a route it is still a fault.
	if !exactKernelRuleAlreadyPresent("ip -6 rule add fwmark 0x1/0xff table 100 priority 150", exists) ||
		exactKernelRuleAlreadyPresent("ip route add default dev awg0 table 100", exists) ||
		exactKernelRuleAlreadyPresent("ip rule add fwmark 0x1/0xff table 100 priority 150", errors.New("Operation not permitted")) {
		t.Fatal("exactKernelRuleAlreadyPresent accepts the wrong command or error")
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

// SRV-01: a tunnel device that does not exist yet (boot before the endpoint resolves, amneziawg-go
// being relaunched) fails only its own `default dev` route. The adapter used to answer that with the
// full teardown, deleting the nft table and the kill-switch blackhole of the same table: marked
// traffic then left by the WAN until the device came up.
func TestExactKernelAdapterKeepsThePlaneWhenATunnelDeviceIsMissing(t *testing.T) {
	artifact := exactKernelTestArtifact()
	artifact.Plan.Egresses[1].FailClosed = true
	artifact.Nft = []byte(artifact.Plan.RenderNft())
	artifact.IP = artifact.Plan.RenderIP(pbr.Options{})
	artifact.Offload = []byte(artifact.Plan.RenderOffload())
	artifact.Teardown = artifact.Plan.RenderTeardown(pbr.Options{})
	const route = "ip route replace default dev awg0 table 100"
	blackhole := ""
	for _, command := range artifact.IP {
		if strings.Contains(command, "route replace blackhole default") && strings.HasSuffix(command, "table 100") {
			blackhole = command
		}
	}
	if !slices.Contains(artifact.IP, route) || blackhole == "" {
		t.Fatalf("fixture has no device route with a kill-switch blackhole: %#v", artifact.IP)
	}

	runner := &exactKernelRecordRunner{fail: map[string]error{
		route: errors.New(`exit status 1: Cannot find device "awg0"`),
	}}
	adapter, _ := newExactKernelAdapter(runner)
	if err := adapter.apply(context.Background(), artifact); err != nil {
		t.Fatalf("a missing tunnel device failed the whole plane: %v", err)
	}
	if slices.Contains(runner.calls, artifact.Teardown[0]) {
		t.Fatalf("the nft table was deleted for one missing device: %#v", runner.calls)
	}
	if !slices.Contains(runner.calls, blackhole) {
		t.Fatalf("the kill-switch blackhole was not installed: %#v", runner.calls)
	}
	proof, err := exactKernelProofProgram(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if runner.stdin[len(runner.stdin)-1] != proof {
		t.Fatal("the plane was not completed with its proof marker")
	}

	// Any other failure of that line, and that failure on any other line, is still a fault.
	for command, failure := range map[string]error{
		route:     errors.New("exit status 2: RTNETLINK answers: Operation not permitted"),
		blackhole: errors.New(`exit status 1: Cannot find device "awg0"`),
	} {
		runner := &exactKernelRecordRunner{fail: map[string]error{command: failure}}
		adapter, _ := newExactKernelAdapter(runner)
		if err := adapter.apply(context.Background(), artifact); err == nil {
			t.Fatalf("%q failing with %v was tolerated", command, failure)
		}
		if !slices.Contains(runner.calls, artifact.Teardown[0]) {
			t.Fatalf("%q failing with %v did not roll the plane back", command, failure)
		}
	}
}
