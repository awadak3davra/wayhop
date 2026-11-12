package server

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// measuredShapeRunningConfig is the compiled target of compiledKeeneticNativeTarget as KeeneticOS
// would print it, written out by hand from the structure measured read-only on the test Keenetic
// (2026-11-05; the values here are synthetic). Against the block the writer sent it has no
// `wireguard private-key` and no `preshared-key` line, the peer's lines sit a level deeper with `!`
// closing the group, and it carries `ip mtu`, which every measured interface printed and this block
// never sent. %s is the peer's public key.
const measuredShapeRunningConfig = `interface Wireguard10
    description native
    security-level public
    ip address 10.8.0.2 255.255.255.255
    ip mtu 1420
    ip global 100
    ip tcp adjust-mss pmtu
    ipv6 address fd00::2/128
    wireguard asc 3 10 50 15 25 101 202 303 404
    wireguard peer %s
        endpoint 198.51.100.20:51820
        keepalive-interval 25
        allow-ips 0.0.0.0 0.0.0.0
        allow-ips :: 0
        connect
    !
    up
!
ip route 198.51.100.20 255.255.255.255 ISP !wr_bypass`

func measuredShapeFor(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(measuredShapeRunningConfig, executionAWGEndpoint("native").Params["peer_public_key"])
}

// The block the compiler writes is accepted against what the router actually prints. Before, the
// check demanded the block as one exact run of lines, private key included, which no router prints.
func TestExactKeeneticCompiledBlockMatchesTheMeasuredRunningConfig(t *testing.T) {
	target := compiledKeeneticNativeTarget(t)
	running := measuredShapeFor(t)
	for _, block := range target.Keenetic.Interfaces {
		if !verifyExactKeeneticInterfaceBlock(block, running, false) {
			t.Fatalf("block %q\nnot found in\n%s", block, running)
		}
	}
	if !verifyExactKeeneticRunningConfig(target, nil, nil, running) {
		t.Fatal("the full post-Apply check refused the measured shape")
	}
}

// Leaving out what NDM cannot print does not loosen the rest: a line missing, out of order, out of
// its peer group, under another interface or in another form still fails.
func TestExactKeeneticReadBackStillRefusesWhatIsWrong(t *testing.T) {
	target := compiledKeeneticNativeTarget(t)
	running := measuredShapeFor(t)
	peer := "    wireguard peer " + executionAWGEndpoint("native").Params["peer_public_key"].(string) + "\n"
	for name, bad := range map[string]string{
		"endpoint missing": strings.Replace(running, "        endpoint 198.51.100.20:51820\n", "", 1),
		"peer line moved to the interface": strings.Replace(
			strings.Replace(running, "        keepalive-interval 25\n", "", 1),
			"    up\n", "    keepalive-interval 25\n    up\n", 1),
		// Only the depth tells this one apart: the peer's last line, printed after its group closed.
		"peer line printed after its group": strings.Replace(running,
			"        connect\n    !\n    up\n", "    !\n    connect\n    up\n", 1),
		"peer line found only under another peer": strings.Replace(
			strings.Replace(running, "        keepalive-interval 25\n", "", 1),
			"    !\n    up\n", "    !\n    wireguard peer BBBB=\n        keepalive-interval 25\n"+
				"        allow-ips 0.0.0.0 0.0.0.0\n        allow-ips :: 0\n        connect\n    !\n    up\n", 1),
		"lines reordered": strings.Replace(running,
			"    description native\n    security-level public\n",
			"    security-level public\n    description native\n", 1),
		"another interface": strings.Replace(running, "interface Wireguard10\n", "interface Wireguard11\n", 1),
		"ip global differs": strings.Replace(running, "    ip global 100\n", "    ip global 101\n", 1),
		"asc differs":       strings.Replace(running, "wireguard asc 3 10 50", "wireguard asc 4 10 50", 1),
		"peer differs":      strings.Replace(running, peer, "    wireguard peer BBBB=\n", 1),
		"old IPv6 form": strings.Replace(running,
			"    ipv6 address fd00::2/128\n", "    ip address fd00::2 128\n", 1),
		"route missing": strings.Replace(running, "ip route 198.51.100.20 255.255.255.255 ISP !wr_bypass", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if bad == running {
				t.Fatal("the mutation did not apply")
			}
			if verifyExactKeeneticRunningConfig(target, nil, nil, bad) {
				t.Errorf("accepted:\n%s", bad)
			}
		})
	}
}

// When the plan raises a created interface on the `ip global` ladder, the ladder owns that number:
// commit sets it after the block, so the block's own `ip global` is not what the router prints, and
// the ladder's value is checked by reading it instead. An interface off the ladder keeps its own.
func TestExactKeeneticLadderOwnsTheIPGlobalOfACreatedInterface(t *testing.T) {
	target := compiledKeeneticNativeTarget(t)
	raised := strings.Replace(measuredShapeFor(t), "    ip global 100\n", "    ip global 40000\n", 1)
	if verifyExactKeeneticRunningConfig(target, nil, nil, raised) {
		t.Fatal("an interface off the ladder passed with another ip global")
	}
	target.Keenetic.GlobalPriority = map[string]int{"Wireguard10": 40000}
	if !verifyExactKeeneticRunningConfig(target, nil, nil, raised) {
		t.Fatal("the ladder's own number failed the created interface's block")
	}
	target.Keenetic.GlobalPriority = map[string]int{"Wireguard10": 40001}
	if verifyExactKeeneticRunningConfig(target, nil, nil, raised) {
		t.Fatal("a ladder value the router does not show was accepted")
	}

	// At cold boot the saved ladder value is live. Prepare must recognise the block anyway; resending
	// it would put the block's own number back and demote the default route until commit.
	target.Keenetic.GlobalPriority = map[string]int{"Wireguard10": 40000}
	runner := &exactKeeneticRecordRunner{failAt: 1}
	adapter, err := newExactKeeneticNativeAdapter(runner)
	if err != nil {
		t.Fatal(err)
	}
	adapter.readConfig = exactKeeneticConfigReader(raised, raised)
	if err := adapter.prepare(context.Background(), target); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if len(runner.batches) != 0 {
		t.Fatalf("a materialized block was resent: %#v", runner.batches)
	}
}
