package server

import (
	"slices"
	"strings"
	"testing"

	"wayhop/internal/pbr"
)

// The backstop's interfaces were the bridges only. A VPN server's clients (nwg0), a
// site-to-site tunnel's forwarded traffic (awg1) were not held in the rebuild window. Now every
// interface that is up is one, except the loopback (the router's own), bridge ports (their traffic
// arrives on the bridge), the WAN and the hand-off TUN.
func TestKillSwitchBackstopInterfaces(t *testing.T) {
	links := []linkFact{
		{name: "lo", up: true, loopback: true},
		{name: "br0", up: true}, {name: "br1", up: true},
		{name: "eth2.1", up: true, member: true}, {name: "ra0", up: true, member: true},
		{name: "nwg0", up: true}, {name: "awg1", up: true},
		{name: "ip6tnl0"}, // down
		{name: "ppp0", up: true},
		{name: pbr.HandoffIfaceDefault, up: true},
	}
	got := keeneticLANIfaces(forwardIfaces(links), "ppp0")
	if want := []string{"awg1", "br0", "br1", "nwg0"}; !slices.Equal(got, want) {
		t.Fatalf("interfaces = %v, want %v", got, want)
	}
	// One that comes up after the Apply is added once, by the mirror.
	if add := newForwardIfaces([]string{"br0", "nwg9", "awg1"}, []string{"awg1", "br0"}, nil); !slices.Equal(add, []string{"nwg9"}) {
		t.Fatalf("new = %v", add)
	}
	if add := newForwardIfaces([]string{"br0", "nwg9"}, []string{"br0"}, []string{"nwg9"}); len(add) != 0 {
		t.Fatalf("added twice: %v", add)
	}
}

// The backstop's priority comes from the live rule list read at capture, is recorded in
// the artifact, and the artifact re-renders from it byte for byte.
func TestKillSwitchBackstopPrefRecorded(t *testing.T) {
	prof := overlapLANProfile()
	prof.Groups[0].KillSwitch = true
	plan, _, err := pbr.Compile(&prof, pbr.Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	live := "0:\tfrom all lookup local\n100:\tfrom all fwmark 0xffffaac lookup 42\n32766:\tfrom all lookup main\n"
	io := keeneticPBROptions("eth3")
	io.LANIfaces = []string{"br0", "awg1"}
	io.BackstopPref = pbr.BackstopPrefFromRules(live, exactKernelOptions())
	art, err := buildKeeneticKernelIpsetArtifact(plan, exactKernelOptions(), io, keeneticPBRTestTools())
	if err != nil {
		t.Fatal(err)
	}
	if art.BackstopPref != 99 || !strings.Contains(string(art.Script), "\nip rule add iif awg1 fwmark 0x00000000/0x00ff0000 table 407 priority 99\n") {
		t.Fatalf("pref %d, script without the rule at 99", art.BackstopPref)
	}
	if !validExactKernelPresentIpsetArtifact(executionKernelArtifactV1{Plan: plan, Ipset: art}) {
		t.Fatal("the recorded artifact does not re-render from its own fields")
	}
	if got := keeneticKillSwitchOptions(*art); got.BackstopPref != 99 {
		t.Fatalf("the mirror renders at %d", got.BackstopPref)
	}
}
