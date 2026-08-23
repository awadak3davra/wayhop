package server

import (
	"context"
	"strings"
	"testing"

	"wayhop/internal/keenetic"
	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
)

// The case this exists for, end to end through the adapter: the operator points the default rule
// back at `direct`. The target then has no interfaces, no routes and no ladder, and the previous
// version of this path reported "no native mutation" and returned before touching the router —
// leaving the tunnel WayHop had raised still sitting on top of the ip-global ladder, still carrying
// every client. Measured on a live Keenetic; the priorities had to be restored by hand.
func ladderRestoreTarget() nativeplan.Plan {
	return nativeplan.Plan{
		Platform: platform.Keenetic,
		Keenetic: &keenetic.Plan{
			RunningConfigRev: keeneticRunningConfigRevision(exactKeeneticBaselineConfig),
		},
	}
}

// The running config the router reports once the restore has landed.
const ladderRestoredConfig = "interface Wireguard3\n    description wayhop\n    ip global 10922\n!\n" +
	"interface ISP\n    ip global 54610\n!"

func TestKeeneticCommitSubmitsTheStaleLadderRestore(t *testing.T) {
	runner := &exactKeeneticRecordRunner{}
	adapter := &exactKeeneticNativeAdapter{
		runner:     runner,
		readConfig: func(context.Context) (string, error) { return ladderRestoredConfig, nil },
	}
	target := ladderRestoreTarget()
	reconcile := nativeplan.Reconciliation{
		Platform:                platform.Keenetic,
		Target:                  &target,
		KeeneticPriorityRestore: [][]string{{"interface Wireguard3", "ip global 10922"}},
	}
	if err := adapter.commit(context.Background(), reconcile); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if len(runner.batches) != 1 {
		t.Fatalf("batches = %#v, want exactly the restore", runner.batches)
	}
	got := strings.Join(runner.batches[0], " | ")
	if got != "interface Wireguard3 | ip global 10922" {
		t.Fatalf("restore batch = %q", got)
	}
}

// The predicate that skips a no-op apply must not treat a pending restore as nothing to do — that
// short circuit is precisely what swallowed it.
func TestKeeneticMutationEmptyCountsThePendingRestore(t *testing.T) {
	target := ladderRestoreTarget()
	if !exactKeeneticNativeMutationEmpty(target, nil, nil) {
		t.Fatal("an empty target with no restore should still be a no-op")
	}
	if exactKeeneticNativeMutationEmpty(target, nil, [][]string{{"interface Wireguard3", "ip global 10922"}}) {
		t.Fatal("a pending ladder restore was reported as nothing to do")
	}
}

// A restore the router accepted and ignored looks exactly like one it applied. Here that difference
// is the whole default route, so it is verified by reading the value back.
func TestKeeneticVerificationReadsTheRestoredPriorityBack(t *testing.T) {
	target := ladderRestoreTarget()
	restore := [][]string{{"interface Wireguard3", "ip global 10922"}}

	if !verifyExactKeeneticRunningConfig(target, nil, restore, ladderRestoredConfig) {
		t.Fatal("a restored priority present in the running config failed verification")
	}
	// Still on the ladder WayHop put there: the restore did not take.
	const stillRaised = "interface Wireguard3\n    ip global 33330\n!"
	if verifyExactKeeneticRunningConfig(target, nil, restore, stillRaised) {
		t.Fatal("verification passed while the interface was still raised")
	}
	// Absent from the config entirely proves nothing was restored either.
	const missing = "interface ISP\n    ip global 54610\n!"
	if verifyExactKeeneticRunningConfig(target, nil, restore, missing) {
		t.Fatal("verification passed with no observed priority at all")
	}
}

func TestRestoredPrioritiesParsesOnlyWellFormedBlocks(t *testing.T) {
	got := restoredPriorities([][]string{
		{"interface Wireguard3", "ip global 10922"},
		{"interface Wireguard5", "ip global 5461"},
		{"interface Broken"},                          // half a block
		{"interface Odd", "ip global not-a-number"},   // unparseable
		{"no interface Wireguard9", "ip global 1000"}, // not a block this code emits
	})
	want := map[string]int{"Wireguard3": 10922, "Wireguard5": 5461}
	if len(got) != len(want) {
		t.Fatalf("restoredPriorities = %v, want %v", got, want)
	}
	for iface, value := range want {
		if got[iface] != value {
			t.Fatalf("restoredPriorities[%q] = %d, want %d", iface, got[iface], value)
		}
	}
}
