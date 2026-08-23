package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"wayhop/internal/nativeplan"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
)

type exactOpenWrtRunner struct {
	network  string
	firewall string
	staged   []string
	calls    []string
}

func (runner *exactOpenWrtRunner) Run(_ context.Context, _ string, name string, args ...string) (string, error) {
	cmd := name
	if len(args) != 0 {
		cmd = args[len(args)-1]
	}
	runner.calls = append(runner.calls, cmd)
	switch {
	case cmd == "uci changes", cmd == "uci changes network", cmd == "uci changes firewall":
		return "", nil
	case cmd == "uci show network":
		return runner.network + renderExactOpenWrtStaged(runner.staged), nil
	case cmd == "uci show firewall":
		if runner.firewall != "" {
			return runner.firewall, nil
		}
		return "firewall.@zone[0]=zone\nfirewall.@zone[0].name='vpn'\n", nil
	case strings.HasPrefix(cmd, "uci set network."), strings.HasPrefix(cmd, "uci add_list network."),
		strings.HasPrefix(cmd, "uci -q delete network."):
		runner.staged = append(runner.staged, cmd)
		return "", nil
	case cmd == "uci commit network":
		runner.network += renderExactOpenWrtStaged(runner.staged)
		runner.staged = nil
		return "", nil
	default:
		return "", nil
	}
}

func TestExactOpenWrtCommandEnvelopeRejectsShellEscape(t *testing.T) {
	valid := []string{
		"uci changes", "uci show network", "uci commit network",
		"/etc/init.d/network reload", "/etc/init.d/firewall reload",
		"ifdown wr_1a2b3c4d",
		"uci set network.wg0.description='safe; still quoted'",
		"uci del_list firewall.@zone[2].network='wr_1a2b3c4d'",
		`uci set network.wg0.description='it'"'"'s safe'`,
	}
	for _, command := range valid {
		if !validExactOpenWrtCommand(command) {
			t.Errorf("valid command rejected: %q", command)
		}
	}
	invalid := []string{
		"uci changes; reboot", "uci show network | cat", "uci commit network-now",
		"ifdown", "ifdown -a", "ifdown wr_good other",
		"uci set network.wg0=x && reboot", "uci set network.wg0='unterminated",
		`uci set network.wg0="$(reboot)"`, "sh -c reboot", "uci show network\nreboot",
	}
	for _, command := range invalid {
		if validExactOpenWrtCommand(command) {
			t.Errorf("unsafe command accepted: %q", command)
		}
	}
}

func renderExactOpenWrtStaged(commands []string) string {
	var lines []string
	for _, command := range commands {
		var assignment string
		switch {
		case strings.HasPrefix(command, "uci set network."):
			assignment = strings.TrimPrefix(command, "uci set ")
		case strings.HasPrefix(command, "uci add_list network."):
			assignment = strings.TrimPrefix(command, "uci add_list ")
		default:
			continue
		}
		eq := strings.IndexByte(assignment, '=')
		if eq < 1 {
			continue
		}
		key := assignment[:eq]
		value := assignment[eq+1:]
		merged := false
		for i := range lines {
			if strings.HasPrefix(lines[i], key+"=") {
				if strings.HasPrefix(command, "uci add_list ") {
					lines[i] += " " + value
				} else {
					lines[i] = assignment
				}
				merged = true
				break
			}
		}
		if !merged {
			lines = append(lines, assignment)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func TestExactOpenWrtNativeAdapterConsumesCapturedPlan(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	artifact, err := buildExecutionNativeArtifactV1(desired, host, capture, nil)
	if err != nil {
		t.Fatal(err)
	}
	runner := &exactOpenWrtRunner{network: capture.NetworkUCI}
	adapter, err := newExactOpenWrtNativeAdapter(runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.prepare(context.Background(), artifact.Plan); err != nil {
		t.Fatal(err)
	}
	iface := artifact.Plan.OpenWrt[0].Iface
	if _, found := netvpn.ParseUCIShow(runner.network)[iface]; !found {
		t.Fatalf("exact target interface %q was not committed: %s", iface, runner.network)
	}
	joined := strings.Join(runner.calls, "\n")
	if strings.LastIndex(joined, "uci commit network") < strings.LastIndex(joined, "uci show network") {
		t.Fatalf("commit occurred before staged verification:\n%s", joined)
	}
}

func TestExactOpenWrtNativeAdapterReplayIsReadOnlyWhenTargetAlreadyConverged(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	artifact, err := buildExecutionNativeArtifactV1(desired, host, capture, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.Plan.OpenWrt) != 1 {
		t.Fatalf("native plans = %d", len(artifact.Plan.OpenWrt))
	}
	plan := artifact.Plan.OpenWrt[0]
	runner := &exactOpenWrtRunner{
		network: capture.NetworkUCI + renderExactOpenWrtStaged(plan.Commands),
		firewall: "firewall.@zone[0]=zone\nfirewall.@zone[0].name='vpn'\n" +
			"firewall.@zone[0].network='" + plan.Iface + "'\n",
	}
	adapter, err := newExactOpenWrtNativeAdapter(runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.prepare(context.Background(), artifact.Plan); err != nil {
		t.Fatalf("converged replay = %v", err)
	}
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "uci set ") || strings.HasPrefix(call, "uci add_list ") ||
			strings.HasPrefix(call, "uci -q delete ") || strings.Contains(call, " commit ") ||
			strings.Contains(call, " reload") {
			t.Fatalf("converged replay mutated OpenWrt: %q", call)
		}
	}
}

func TestExactOpenWrtNativeAdapterReplayAcceptsAuthenticatedRemovalAlreadyConverged(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	artifact, err := buildExecutionNativeArtifactV1(desired, host, capture, nil)
	if err != nil {
		t.Fatal(err)
	}
	writePlan := artifact.Plan.OpenWrt[0]
	beforeNetwork := capture.NetworkUCI + renderExactOpenWrtStaged(writePlan.Commands)
	beforeFirewall := "firewall.@zone[0]=zone\nfirewall.@zone[0].name='vpn'\n" +
		"firewall.@zone[0].network='" + writePlan.Iface + "'\n"
	removal, err := netvpn.BuildRemovalPlan(writePlan.Iface, beforeNetwork, beforeFirewall)
	if err != nil {
		t.Fatal(err)
	}
	runner := &exactOpenWrtRunner{
		network:  capture.NetworkUCI,
		firewall: "firewall.@zone[0]=zone\nfirewall.@zone[0].name='vpn'\n",
	}
	adapter, err := newExactOpenWrtNativeAdapter(runner)
	if err != nil {
		t.Fatal(err)
	}
	reconcile := nativeplan.Reconciliation{
		Platform:        platform.OpenWrt,
		Target:          &nativeplan.Plan{Platform: platform.OpenWrt},
		OpenWrtRemovals: []netvpn.RemovalPlan{removal},
	}
	if err := adapter.commit(context.Background(), reconcile); err != nil {
		t.Fatalf("converged removal replay = %v", err)
	}
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "uci set ") || strings.HasPrefix(call, "uci add_list ") ||
			strings.HasPrefix(call, "uci -q delete ") || strings.HasPrefix(call, "ifdown ") ||
			strings.Contains(call, " commit ") || strings.Contains(call, " reload") {
			t.Fatalf("converged removal replay mutated OpenWrt: %q", call)
		}
	}
}

func TestExactOpenWrtNativeAdapterReplayRefusesPartialStateWithoutMutation(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	artifact, err := buildExecutionNativeArtifactV1(desired, host, capture, nil)
	if err != nil {
		t.Fatal(err)
	}
	writePlan := artifact.Plan.OpenWrt[0]
	attached := "firewall.@zone[0]=zone\nfirewall.@zone[0].name='vpn'\n" +
		"firewall.@zone[0].network='" + writePlan.Iface + "'\n"
	beforeNetwork := capture.NetworkUCI + renderExactOpenWrtStaged(writePlan.Commands)
	removal, err := netvpn.BuildRemovalPlan(writePlan.Iface, beforeNetwork, attached)
	if err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func(*exactOpenWrtNativeAdapter) error{
		"created interface without zone attachment": func(adapter *exactOpenWrtNativeAdapter) error {
			return adapter.prepare(context.Background(), artifact.Plan)
		},
		"removed interface with dangling zone attachment": func(adapter *exactOpenWrtNativeAdapter) error {
			return adapter.commit(context.Background(), nativeplan.Reconciliation{
				Platform:        platform.OpenWrt,
				Target:          &nativeplan.Plan{Platform: platform.OpenWrt},
				OpenWrtRemovals: []netvpn.RemovalPlan{removal},
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			runner := &exactOpenWrtRunner{firewall: attached}
			if strings.HasPrefix(name, "created") {
				runner.network = beforeNetwork
				runner.firewall = "firewall.@zone[0]=zone\nfirewall.@zone[0].name='vpn'\n"
			} else {
				runner.network = capture.NetworkUCI
			}
			adapter, err := newExactOpenWrtNativeAdapter(runner)
			if err != nil {
				t.Fatal(err)
			}
			if err := run(adapter); err == nil {
				t.Fatal("partial replay reported success")
			}
			for _, call := range runner.calls {
				if strings.HasPrefix(call, "uci set ") || strings.HasPrefix(call, "uci add_list ") ||
					strings.HasPrefix(call, "uci del_list ") || strings.HasPrefix(call, "uci -q delete ") ||
					strings.HasPrefix(call, "ifdown ") || strings.Contains(call, " commit ") ||
					strings.Contains(call, " reload") {
					t.Fatalf("partial replay mutated OpenWrt: %q", call)
				}
			}
		})
	}
}

func TestExactOpenWrtCommandEnvelopeCoversGeneratedWriteAndRemovalPlans(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	artifact, err := buildExecutionNativeArtifactV1(desired, host, capture, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.Plan.OpenWrt) != 1 {
		t.Fatalf("native plans = %d", len(artifact.Plan.OpenWrt))
	}
	writePlan := artifact.Plan.OpenWrt[0]
	for _, command := range append(append([]string(nil), writePlan.Commands...), writePlan.Commit...) {
		if !validExactOpenWrtCommand(command) {
			t.Fatalf("generated write command is outside exact envelope: %q", command)
		}
	}

	runner := &exactOpenWrtRunner{network: capture.NetworkUCI}
	adapter, _ := newExactOpenWrtNativeAdapter(runner)
	if err := adapter.prepare(context.Background(), artifact.Plan); err != nil {
		t.Fatal(err)
	}
	removal, err := netvpn.BuildRemovalPlan(writePlan.Iface, runner.network,
		"firewall.@zone[0]=zone\nfirewall.@zone[0].name='vpn'\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range append(append([]string(nil), removal.Commands...), removal.Commit...) {
		if !validExactOpenWrtCommand(command) {
			t.Fatalf("generated removal command is outside exact envelope: %q", command)
		}
	}
}

func TestExactOpenWrtNativeAdapterFailsClosed(t *testing.T) {
	runner := &exactOpenWrtRunner{}
	adapter, err := newExactOpenWrtNativeAdapter(runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.prepare(context.Background(), nativeplan.Plan{Platform: platform.Keenetic}); !errors.Is(err, errExactOpenWrtPlan) || len(runner.calls) != 0 {
		t.Fatalf("Keenetic target reached OpenWrt runner: %v, calls=%v", err, runner.calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := adapter.prepare(ctx, nativeplan.Plan{Platform: platform.OpenWrt}); !errors.Is(err, context.Canceled) || len(runner.calls) != 0 {
		t.Fatalf("cancelled prepare reached runner: %v, calls=%v", err, runner.calls)
	}
	removal := netvpn.RemovalPlan{
		Iface: "gone", Expected: netvpn.AWGInterface{Name: "gone"},
	}
	if err := adapter.commit(context.Background(), nativeplan.Reconciliation{
		Platform: platform.OpenWrt, Target: &nativeplan.Plan{Platform: platform.OpenWrt},
		OpenWrtRemovals: []netvpn.RemovalPlan{removal},
	}); err == nil {
		t.Fatal("stale removal was accepted")
	}
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "uci set ") || strings.Contains(call, "commit") ||
			strings.Contains(call, "ifdown") {
			t.Fatalf("stale removal mutated router: %s", call)
		}
	}
}

func TestExactOpenWrtCompatibilityHasNoNativeInterfaceClaim(t *testing.T) {
	plan := nativeplan.Plan{Platform: platform.OpenWrt, Decisions: []nativeplan.EndpointDecision{{
		EndpointID: "proxy", Path: nativeplan.PathCompatibility,
	}}}
	if err := validateExactOpenWrtTarget(plan); err != nil {
		t.Fatalf("proxy-only OpenWrt plan was rejected: %v", err)
	}
	plan.Decisions[0].Interface = "wrtun0"
	if err := validateExactOpenWrtTarget(plan); !errors.Is(err, errExactOpenWrtPlan) {
		t.Fatalf("invented OpenWrt compatibility interface accepted: %v", err)
	}
}
