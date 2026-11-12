package server

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
)

// compiledKeeneticNativeTarget is a plan the real compiler produced for an interface WayHop creates on
// KeeneticOS, with every optional peer line the writer can emit (keepalive, preshared key, the IPv6
// allow-ips) and the obfuscation line. The exact-adapter tests used to run on hand-written blocks
// only, which is how a writer/validator disagreement over the peer lines stayed invisible.
func compiledKeeneticNativeTarget(t *testing.T) nativeplan.Plan {
	t.Helper()
	endpoint := executionAWGEndpoint("native")
	endpoint.Params["persistent_keepalive"] = 25
	endpoint.Params["local_address"] = []string{"10.8.0.2/32", "fd00::2/128"}
	for key, value := range map[string]int{
		"jc": 3, "jmin": 10, "jmax": 50, "s1": 15, "s2": 25, "h1": 101, "h2": 202, "h3": 303, "h4": 404,
	} {
		endpoint.Params[key] = value
	}
	plan, err := nativeplan.Compile(&model.Profile{Endpoints: []model.Endpoint{endpoint}}, nativeplan.HostFacts{
		Platform:           platform.Keenetic,
		Capabilities:       keeneticAWGCapabilities(),
		OccupiedInterfaces: map[string]bool{},
		GlobalPriorities:   map[string]int{"ISP": 1000},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(plan.Decisions) != 1 || plan.Decisions[0].Path != nativeplan.PathNativeCreate ||
		plan.Keenetic == nil || len(plan.Keenetic.Interfaces) != 1 || len(plan.Keenetic.GlobalPriority) != 0 {
		t.Fatalf("not a plain native-create plan: %+v", plan)
	}
	// What applynative.go stamps on the artifact from the capture.
	plan.Keenetic.RunningConfigRev = keeneticRunningConfigRevision(exactKeeneticBaselineConfig)
	block := plan.Keenetic.Interfaces[0]
	peer, nested := false, 0
	for _, command := range block {
		peer = peer || strings.HasPrefix(command, exactKeeneticPeerCommand)
		if strings.HasPrefix(command, exactKeeneticPeerIndent) {
			nested++
		}
	}
	// The point of the fixture: without a peer and its nested lines it no longer tests anything.
	if !peer || nested != 6 {
		t.Fatalf("compiled block lost its peer lines: %q", block)
	}
	return *plan
}

func peerLineIndex(t *testing.T, block []string) int {
	t.Helper()
	for i, command := range block {
		if strings.HasPrefix(command, exactKeeneticPeerCommand) {
			return i
		}
	}
	t.Fatalf("no peer line in %q", block)
	return -1
}

func TestValidExactKeeneticTargetAcceptsACompiledNativeBlock(t *testing.T) {
	target := compiledKeeneticNativeTarget(t)
	if !validExactKeeneticTarget(target) {
		t.Fatalf("the exact validator refused the block the Keenetic writer produced: %q",
			target.Keenetic.Interfaces[0])
	}
}

// The same block reached through the execution artifact the strict transaction builds, next to an
// endpoint WayHop's userspace engine runs.
func TestValidExactKeeneticTargetAcceptsTheNativeBlockOfAnExecutionArtifact(t *testing.T) {
	desired, host, capture := keeneticUserspaceTuple(t)
	artifact, err := buildExecutionNativeArtifactV1(desired, host, capture, nil)
	if err != nil {
		t.Fatal(err)
	}
	target := artifact.Plan
	if target.Keenetic == nil || len(target.Keenetic.Interfaces) != 1 {
		t.Fatalf("artifact carries no NDM block: %+v", target.Keenetic)
	}
	peerLineIndex(t, target.Keenetic.Interfaces[0])
	if !validExactKeeneticTarget(target) {
		t.Fatalf("the exact validator refused the artifact's NDM block: %q", target.Keenetic.Interfaces[0])
	}
}

// Every line of a compiled block reaches ndmc as one full-path command, and the peer's lines reach it
// under the peer: `interface X endpoint …` is not an NDM command. The whole create, commit, verify and
// save sequence then accepts the block against a running-config printed the KeeneticOS way.
func TestExactKeeneticAdapterAppliesACompiledNativeBlockThroughNDMC(t *testing.T) {
	target := compiledKeeneticNativeTarget(t)
	block := target.Keenetic.Interfaces[0]
	var sent []string
	runner := &exactKeeneticNDMCRunner{run: func(_ context.Context, stdin, name string, args ...string) (string, error) {
		if stdin != "" || name != exactKeeneticNDMCPath || len(args) != 2 || args[0] != "-c" {
			t.Fatalf("unexpected ndmc invocation: stdin=%q name=%q args=%#v", stdin, name, args)
		}
		sent = append(sent, args[1])
		return "", nil
	}}
	adapter, err := newExactKeeneticNativeAdapter(runner)
	if err != nil {
		t.Fatal(err)
	}
	// Printed the KeeneticOS way, so without the private key and the preshared key the block sent.
	running := exactKeeneticTargetRunningConfig(target)
	adapter.readConfig = exactKeeneticConfigReader(exactKeeneticBaselineConfig, running, running, running, running)
	ctx := context.Background()
	if err := adapter.prepare(ctx, target); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if len(sent) != len(block) {
		t.Fatalf("prepare sent %d commands for a %d-line block: %q", len(sent), len(block), sent)
	}
	iface := "interface Wireguard10"
	for _, line := range sent {
		if line != iface && !strings.HasPrefix(line, iface+" ") || strings.Contains(line, "  ") {
			t.Errorf("not one clean full-path command: %q", line)
		}
	}
	endpoint := executionAWGEndpoint("native")
	peer := iface + " wireguard peer " + endpoint.Params["peer_public_key"].(string)
	wantPeer := []string{
		peer,
		peer + " endpoint 198.51.100.20:51820",
		peer + " keepalive-interval 25",
		peer + " preshared-key " + endpoint.Params["pre_shared_key"].(string),
		peer + " allow-ips 0.0.0.0 0.0.0.0",
		peer + " allow-ips :: 0",
		peer + " connect",
	}
	at := peerLineIndex(t, block)
	if got := sent[at : at+len(wantPeer)]; !reflect.DeepEqual(got, wantPeer) {
		t.Fatalf("peer lines sent as %q\nwant %q", got, wantPeer)
	}
	if sent[0] != iface || sent[len(sent)-1] != iface+" up" {
		t.Fatalf("block not opened and raised on its interface: %q", sent)
	}

	reconcile := exactKeeneticReconciliation(target, nil)
	sent = nil
	if err := adapter.commit(ctx, reconcile); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := adapter.postcheck(ctx, target, nil, nil); err != nil {
		t.Fatalf("postcheck: %v", err)
	}
	if err := adapter.persist(ctx, reconcile); err != nil {
		t.Fatalf("persist: %v", err)
	}
	if want := append(append([]string(nil), target.Keenetic.Routes...), exactKeeneticSaveCommand); !reflect.DeepEqual(sent, want) {
		t.Fatalf("commit/persist sent %q, want %q", sent, want)
	}
}

func TestFlattenExactKeeneticBatchFollowsEachPeer(t *testing.T) {
	lines, ok := flattenExactKeeneticBatch([]string{
		"interface Wireguard10", "wireguard peer AAAA=", "    connect",
		"wireguard peer BBBB=", "    connect", "up",
	})
	want := []string{
		"interface Wireguard10",
		"interface Wireguard10 wireguard peer AAAA=",
		"interface Wireguard10 wireguard peer AAAA= connect",
		"interface Wireguard10 wireguard peer BBBB=",
		"interface Wireguard10 wireguard peer BBBB= connect",
		"interface Wireguard10 up",
	}
	if !ok || !reflect.DeepEqual(lines, want) {
		t.Fatalf("flattened %q (ok=%v)\nwant %q", lines, ok, want)
	}
	for name, batch := range map[string][]string{
		"indented route":            {"    ip route 10.0.0.0 255.0.0.0 ISP"},
		"peer outside an interface": {"wireguard peer AAAA=", "    connect"},
	} {
		if lines, ok := flattenExactKeeneticBatch(batch); ok {
			t.Errorf("%s: flattened to %q", name, lines)
		}
	}
}

// The indent is accepted exactly where it means "this line belongs to the peer above", and the
// injection guard still holds inside an indented line. Each refusal is checked at both doors: the
// validator of the authenticated plan and the transport, which must run nothing at all.
func TestExactKeeneticPeerIndentIsAcceptedOnlyUnderAPeer(t *testing.T) {
	base := compiledKeeneticNativeTarget(t)
	at := peerLineIndex(t, base.Keenetic.Interfaces[0])
	// Only the block changes. cloneKeeneticPlanForTest is not used here: it turns a nil Singbox into an
	// empty map, which the validator refuses on its own, and every case below would then "pass" for
	// that reason instead of the block.
	withBlock := func(block []string) nativeplan.Plan {
		target, plan := base, *base.Keenetic
		plan.Interfaces = [][]string{block}
		target.Keenetic = &plan
		return target
	}
	if !validExactKeeneticTarget(withBlock(append([]string(nil), base.Keenetic.Interfaces[0]...))) {
		t.Fatal("the unmutated block is refused, so no refusal below would mean anything")
	}
	insert := func(block []string, index int, command string) []string {
		return append(block[:index], append([]string{command}, block[index:]...)...)
	}
	nestedOne := func(prefix, suffix string) func([]string) []string {
		return func(block []string) []string {
			block[at+1] = prefix + strings.TrimSpace(block[at+1]) + suffix
			return block
		}
	}
	for name, test := range map[string]struct {
		mutate func([]string) []string
		// sent separately a batch may switch interfaces; only a plan's block may not
		transportRefuses bool
	}{
		"tab indent":         {nestedOne("\t", ""), true},
		"two spaces":         {nestedOne("  ", ""), true},
		"five spaces":        {nestedOne("     ", ""), true},
		"two levels":         {nestedOne("        ", ""), true},
		"trailing space":     {nestedOne(exactKeeneticPeerIndent, " "), true},
		"newline injection":  {nestedOne(exactKeeneticPeerIndent, "\nno interface ISP"), true},
		"carriage return":    {nestedOne(exactKeeneticPeerIndent, "\rno interface ISP"), true},
		"nul":                {nestedOne(exactKeeneticPeerIndent, "\x00"), true},
		"blank nested line":  {func(b []string) []string { return insert(b, at+1, exactKeeneticPeerIndent) }, true},
		"no peer above":      {func(b []string) []string { return insert(b, 1, "    keepalive-interval 30") }, true},
		"peer closed before": {func(b []string) []string { return insert(b, at+1, "ip mtu 1280") }, true},
		"repeated peer line": {func(b []string) []string { return insert(b, at+1, b[at+1]) }, true},
		"flattened too long": {func(b []string) []string {
			b[at+1] = exactKeeneticPeerIndent + "endpoint " +
				strings.Repeat("a", exactKeeneticMaxCommandBytes-len(exactKeeneticPeerIndent+"endpoint "))
			return b
		}, true},
		"second interface": {func(b []string) []string { return insert(b, len(b)-1, "interface ISP") }, false},
	} {
		t.Run(name, func(t *testing.T) {
			block := test.mutate(append([]string(nil), base.Keenetic.Interfaces[0]...))
			if validExactKeeneticTarget(withBlock(block)) {
				t.Errorf("validator accepted %q", block)
			}
			runner := &exactKeeneticNDMCRunner{run: func(_ context.Context, _, _ string, args ...string) (string, error) {
				if test.transportRefuses {
					t.Errorf("transport ran %q from a batch it should refuse", args)
				}
				return "", nil
			}}
			_, err := runner.ParseBatch(context.Background(), block)
			if test.transportRefuses && !errors.Is(err, errExactKeeneticPlan) {
				t.Errorf("transport error = %v, want the plan refusal", err)
			}
		})
	}
}
