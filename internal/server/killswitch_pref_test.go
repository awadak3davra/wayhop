package server

import (
	"context"
	"os"
	"strings"
	"testing"

	"wayhop/internal/pbr"
)

// The backstop's priority was derived once, at capture. An access policy the operator
// creates afterwards gets NDM rules at 100-109, ahead of the backstop, and its devices leave by the
// policy table in every rebuild window until the next Apply. The mirror re-reads the rule list after
// every hook run and moves the backstop ahead of such a rule (make-before-break, the old place stays
// until the next Apply or teardown).
func TestKillSwitchBackstopMovesAheadOfANewNDMRule(t *testing.T) {
	s, _, stamp := mirrorServer(t)
	k := &s.applyState.rec.Committed.Materialization.Kernel
	k.Ipset.BackstopPref = 140
	rules := "0:\tfrom all lookup local\n140:\tfrom all fwmark 0/0xff0000 iif br0 lookup 407\n32766:\tfrom all lookup main\n"
	var ran []string
	s.ksb.readRules = func(context.Context, executionKernelIpsetArtifactV1) (string, error) { return rules, nil }
	s.ksb.runRules = func(_ context.Context, _ executionKernelIpsetArtifactV1, program string) error {
		ran = append(ran, program)
		return nil
	}
	ctx := context.Background()
	s.killSwitchMirrorTick(ctx) // first tick re-reads: nothing ahead of 140
	if len(ran) != 0 {
		t.Fatalf("moved with nothing ahead: %q", ran)
	}
	rules = "0:\tfrom all lookup local\n101:\tfrom all fwmark 0xffffd00 lookup 42\n" + rules[len("0:\tfrom all lookup local\n"):]
	if err := os.WriteFile(stamp, nil, 0o644); err != nil { // the rebuild NDM made for its policy
		t.Fatal(err)
	}
	s.killSwitchMirrorTick(ctx)
	if len(ran) != 1 || !strings.Contains(ran[0], "table 407 priority 100") || strings.Contains(ran[0], "priority 140") {
		t.Fatalf("not moved ahead of NDM's rule 101: %q", ran)
	}
	if s.ksb.pref != 100 {
		t.Fatalf("effective priority %d", s.ksb.pref)
	}
	// A rule in WayHop's table range whose selector is not WayHop's is foreign (NDM numbering is free).
	if got := pbr.BackstopPrefFromRules("120:\tfrom all fwmark 0xffffd00 lookup 160\n", pbr.Options{}); got != 119 {
		t.Fatalf("foreign rule in the table range taken for WayHop's: %d", got)
	}
}

// After a restart the rules the mirror moved are found in the rule list and taken over
// without a new alert; a foreign rule at priority 1-2 is reported once; a teardown of the moved rules
// spares the next plane's rules when its place is the moved place's stage slot.
func TestKillSwitchMovedBackstopSurvivesARestart(t *testing.T) {
	s, _, stamp := mirrorServer(t)
	k := &s.applyState.rec.Committed.Materialization.Kernel
	k.Ipset.BackstopPref = 140
	rules := "0:\tfrom all lookup local\n100:\tfrom all fwmark 0x0/0xff0000 iif br0 lookup 407 \n101:\tfrom all fwmark 0xffffd00 lookup 42\n" +
		"140:\tfrom all fwmark 0x0/0xff0000 iif br0 lookup 407\n32766:\tfrom all lookup main\n"
	var ran []string
	s.ksb.readRules = func(context.Context, executionKernelIpsetArtifactV1) (string, error) { return rules, nil }
	s.ksb.runRules = func(_ context.Context, _ executionKernelIpsetArtifactV1, program string) error {
		ran = append(ran, program)
		return nil
	}
	_ = os.WriteFile(stamp, nil, 0o644)
	s.killSwitchMirrorTick(context.Background())
	if len(ran) != 0 || s.ksb.pref != 100 {
		t.Fatalf("restart: moved again (a new alert): ran %q pref %d", ran, s.ksb.pref)
	}
	// The next plane sits at 99, the moved rules' stage slot: their teardown must not delete it.
	next := *k.Ipset
	next.BackstopPref = 99
	s.dropExtraIfaces(context.Background(), k.Plan, *k.Ipset, &next)
	if len(ran) != 1 || strings.Contains(ran[0], "iif br0 fwmark 0x00000000/0x00ff0000 table 407 priority 99 ") || !strings.Contains(ran[0], "priority 100 ") {
		t.Fatalf("teardown of the moved rules: %q", ran)
	}
	if got := pbr.BackstopUnpreceded("1:\tfrom all fwmark 0x5 lookup 9\n2:\tfrom all lookup 77\n150:\tfrom all lookup 80\n", pbr.Options{}); len(got) != 2 {
		t.Fatalf("unpreceded: %v", got)
	}
}
