package server

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

type exactKernelRecordRunner struct {
	calls  []string
	stdin  []string
	causes []error
	fail   map[string]error
	// out answers a command by its exact text: the rule and route dumps postcheck reads.
	out         map[string]string
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
	return runner.out[command], nil
}

// kernelStateOf is what the router's ip prints once an artifact is installed, in the kernel's own
// shapes (an OpenWrt router's `ip rule show` and `ip route show table all`): a rule as
// "150:	from all fwmark 0x20000/0xff0000 lookup 151", a kill-switch route as "blackhole default table
// 151 metric 1000" (IPv6: "blackhole default dev lo table 151 metric 2048 pref medium"). The map is
// keyed by the command postcheck runs.
// guardChainCommand is what the adapter runs to see whether a guard is loaded, and
// guardChainListing what nft answers for a loaded guard: its chain, the marker rule last.
const guardChainCommand = "nft list chain inet wayhop_ks ks_forward"

func guardChainListing(guard string) string {
	head := "\tchain " + pbr.GuardChain + " {\n"
	body := guard[strings.Index(guard, head):]
	body = body[:strings.Index(body, "\n\t}\n")]
	return "table inet wayhop_ks {\n" + body + "\n\t\taccept comment \"" + pbr.GuardProofSet(guard) + "\"\n\t}\n}\n"
}

// guardChainFlushed is the same listing after `nft flush chain inet wayhop_ks ks_forward`.
const guardChainFlushed = "table inet wayhop_ks {\n\tchain ks_forward {\n\t\ttype filter hook forward priority filter - 5; policy accept;\n\t}\n}\n"

func kernelStateOf(artifact executionKernelArtifactV1) map[string]string {
	out := map[string]string{
		"ip rule show": "0:\tfrom all lookup local\n", "ip -6 rule show": "0:\tfrom all lookup local\n",
		"ip route show table all":    "default via 192.0.2.1 dev wan proto static src 192.0.2.138\n",
		"ip -6 route show table all": "",
	}
	if guard := artifact.Plan.RenderNftGuard(); guard != "" {
		out[guardChainCommand] = guardChainListing(guard)
	}
	for _, command := range artifact.IP {
		f := strings.Fields(command)[1:]
		fam := "ip "
		if f[0] == "-6" {
			fam, f = "ip -6 ", f[1:]
		}
		switch {
		case len(f) > 2 && f[0] == "rule" && f[1] == "add":
			var spec []string
			pref := ""
			for i := 2; i < len(f); i++ {
				switch f[i] {
				case "priority":
					pref = f[i+1]
					i++
				case "table":
					spec = append(spec, "lookup", f[i+1])
					i++
				case "fwmark":
					mark, mask, _ := strings.Cut(f[i+1], "/")
					m, _ := strconv.ParseUint(mark, 0, 32)
					k, _ := strconv.ParseUint(mask, 0, 32)
					spec = append(spec, "fwmark", fmt.Sprintf("%#x/%#x", m, k))
					i++
				default:
					spec = append(spec, f[i])
				}
			}
			out[fam+"rule show"] += pref + ":\tfrom all " + strings.Join(spec, " ") + "\n"
		case len(f) > 4 && f[0] == "route" && f[1] == "replace" && f[2] == "blackhole":
			table, metric := f[len(f)-1], ""
			if f[4] == "metric" {
				metric = " metric " + f[5]
			}
			if fam == "ip " {
				out["ip route show table all"] += "blackhole default table " + table + metric + "\n"
			} else {
				out["ip -6 route show table all"] += "blackhole default dev lo table " + table + metric + " pref medium\n"
			}
		}
	}
	return out
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
		Renderer: kernelRendererID(),
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
	// Nothing of this plan is kill-switched: a guard an earlier plane left is removed, last.
	want = append(want, "nft delete table inet wayhop_ks")
	proof, err := exactKernelProofProgram(artifact)
	if err != nil {
		t.Fatal(err)
	}
	nftAt := slices.Index(runner.calls, "nft -f -")
	if !reflect.DeepEqual(runner.calls, want) || nftAt < 0 || runner.stdin[nftAt] != string(artifact.Nft) ||
		runner.stdin[len(runner.stdin)-2] != proof {
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
	if b, n := slices.Index(runner.calls, blackhole), slices.Index(runner.stdin, string(artifact.Nft)); b < 0 || n < 0 || b > n {
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
	runner := &exactKernelRecordRunner{out: kernelStateOf(artifact)}
	adapter, _ := newExactKernelAdapter(runner)
	if err := adapter.postcheck(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	// The marker first, then the rules. No kill switch in this plan: no route is read.
	want := []string{"nft list set inet " + artifact.Plan.Table + " " + proof, "ip rule show"}
	if !reflect.DeepEqual(runner.calls, want) {
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
	// The plane's own teardown, then the kill-switch guard: it has no plane left to guard.
	want := append(append([]string(nil), previous.Teardown...), "nft delete table inet wayhop_ks")
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls = %#v; want authenticated teardown %#v", runner.calls, want)
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

// TestExactKernelAdapterRerendersAnOlderBuildsArtifact (live 22.11): after a binary upgrade the stored
// artifact, rendered by the previous build, no longer equals this build's rendering of the same plan.
// It is re-rendered from its plan and installed, not refused; tools that are not authenticated are
// still refused, and the postcheck reads the re-rendered form.
func TestExactKernelAdapterRerendersAnOlderBuildsArtifact(t *testing.T) {
	old := exactKernelTestArtifact()
	old.Renderer = "" // stored before the field, or by another build
	old.Nft = append(old.Nft, []byte("\n# what the previous build rendered")...)
	old.IP = append(append([]string(nil), old.IP...), "ip rule add fwmark 0x00010000/0x00ff0000 table 100 priority 999")
	runner := &exactKernelRecordRunner{}
	adapter, _ := newExactKernelAdapter(runner)
	if err := adapter.apply(context.Background(), old); err != nil {
		t.Fatalf("an older build's artifact was refused: %v", err)
	}
	deleted := false
	for _, c := range runner.calls {
		if strings.Contains(c, "rule add") && strings.Contains(c, "priority 999") || strings.Contains(c, "previous build") {
			t.Fatalf("the stale rendering was run: %q", c)
		}
		// What the old rendering added and the new one does not is taken out.
		deleted = deleted || strings.Contains(c, "rule del fwmark 0x00010000/0x00ff0000 table 100 priority 999")
	}
	if !deleted {
		t.Errorf("the superseded rule was left: %q", runner.calls)
	}
	bad := old
	bad.NFTTool.ContentSHA256 = strings.Repeat("f", 63)
	runner = &exactKernelRecordRunner{}
	adapter, _ = newExactKernelAdapter(runner)
	if err := adapter.apply(context.Background(), bad); !errors.Is(err, errExactKernelArtifact) || len(runner.calls) != 0 {
		t.Fatalf("an unauthenticated tool was re-rendered and run: %v %q", err, runner.calls)
	}
}

// TestRerenderNeedsAMatchingRendering: a stored plan changed beside an older build's
// rendering (a prefix the old bytes never held, an egress device they never named) is not re-rendered
// into an executable plane; it stays refused until a fresh Review and Apply.
func TestRerenderNeedsAMatchingRendering(t *testing.T) {
	for name, mutate := range map[string]func(*executionKernelArtifactV1){
		"prefix": func(a *executionKernelArtifactV1) { a.Plan.Zones[0].V4 = []string{"0.0.0.0/0"} },
		"device": func(a *executionKernelArtifactV1) { a.Plan.Egresses[1].Iface = "evil0" },
	} {
		t.Run(name, func(t *testing.T) {
			a := exactKernelTestArtifact()
			a.Renderer = ""
			plan := *a.Plan
			plan.Zones = append([]pbr.Zone(nil), a.Plan.Zones...)
			plan.Egresses = append([]pbr.Egress(nil), a.Plan.Egresses...)
			a.Plan = &plan
			mutate(&a)
			runner := &exactKernelRecordRunner{}
			adapter, _ := newExactKernelAdapter(runner)
			if err := adapter.apply(context.Background(), a); !errors.Is(err, errExactKernelArtifact) || len(runner.calls) != 0 {
				t.Fatalf("a plan the old rendering does not account for ran: %v %q", err, runner.calls)
			}
		})
	}
}

// TestNoRerenderOfAnotherBuildsFastPlan: a fast-mode plan with the resolver plane, or
// one carrying routed tables, from another build is not re-rendered (it would keep that build's choice
// of what leaves nft); the same plan rendered by this build still runs. Superseded cleanup treats a
// route added by the old rendering as the one the new rendering replaces.
func TestNoRerenderOfAnotherBuildsFastPlan(t *testing.T) {
	for name, mutate := range map[string]func(*pbr.Plan){
		"fast dns": func(p *pbr.Plan) { p.FastDNS = true },
		"routed":   func(p *pbr.Plan) { p.Zones[0].Routed, p.Zones[0].RouteV4 = true, []string{"0.0.0.0/0"} },
	} {
		t.Run(name, func(t *testing.T) {
			a := exactKernelTestArtifact()
			plan := *a.Plan
			plan.Zones = append([]pbr.Zone(nil), a.Plan.Zones...)
			mutate(&plan)
			a.Plan = &plan
			a.Renderer = ""
			a.Nft = append(append([]byte(nil), a.Nft...), []byte("\n# the other build's rendering")...)
			runner := &exactKernelRecordRunner{}
			adapter, _ := newExactKernelAdapter(runner)
			if err := adapter.apply(context.Background(), a); !errors.Is(err, errExactKernelArtifact) || len(runner.calls) != 0 {
				t.Fatalf("another build's fast plan ran: %v %q", err, runner.calls)
			}
		})
	}
	old := []string{"ip -6 route add blackhole default table 151", "ip rule add fwmark 0x1/0xff table 151 priority 150"}
	now := []string{"ip -6 route replace blackhole default table 151", "ip rule add fwmark 0x1/0xff table 151 priority 150"}
	if got := supersededKernelCommands(old, now); len(got) != 0 {
		t.Errorf("a route the new rendering replaces was deleted: %q", got)
	}
}

// TestKernelTeardownOfAnOlderBuild: an older build's stored plane is taken down with this
// build's teardown of its plan too (a table an older teardown does not name).
func TestKernelTeardownOfAnOlderBuild(t *testing.T) {
	a := exactKernelTestArtifact()
	a.Renderer = ""
	a.Teardown = a.Teardown[:1] // the older teardown deleted only the table
	got := strings.Join(kernelTeardownOf(a), "\n")
	for _, c := range exactKernelTestArtifact().Teardown {
		if !strings.Contains(got, c) {
			t.Errorf("teardown lacks %q:\n%s", c, got)
		}
	}
}
