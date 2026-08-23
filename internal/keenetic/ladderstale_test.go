package keenetic

import (
	"reflect"
	"testing"
)

// The ip-global ladder is the only thing this backend writes onto an interface the ROUTER owns, and
// it is the thing that decides which connection carries everything. Nothing in TeardownCommands can
// undo it — there is no `no ip global` — so reconciliation has to put the old numbers back itself.
//
// Measured on a live Keenetic: the default rule was switched to `direct`, the apply reported
// success, and every client kept egressing through Yerevan because Wireguard3 was still on top of
// the ladder. The five priorities had to be restored by hand.
func TestStaleGlobalPriorityBlocks(t *testing.T) {
	prev := &Plan{
		GlobalPriority:    map[string]int{"Wireguard3": 33330, "Wireguard5": 32818},
		GlobalPriorityWas: map[string]int{"Wireguard3": 10922, "Wireguard5": 5461},
	}

	t.Run("target no longer raises anything", func(t *testing.T) {
		got := StaleGlobalPriorityBlocks(prev, &Plan{})
		want := [][]string{
			{"interface Wireguard3", "ip global 10922"},
			{"interface Wireguard5", "ip global 5461"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("StaleGlobalPriorityBlocks = %v, want %v", got, want)
		}
	})

	t.Run("an interface the target raises again is left alone", func(t *testing.T) {
		// The target's own ladder block overwrites it in the same batch; restoring it first would be
		// a pointless write and a moment where two interfaces claim the default.
		target := &Plan{GlobalPriority: map[string]int{"Wireguard3": 40000}}
		got := StaleGlobalPriorityBlocks(prev, target)
		want := [][]string{{"interface Wireguard5", "ip global 5461"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("StaleGlobalPriorityBlocks = %v, want %v", got, want)
		}
	})

	t.Run("nothing was raised before", func(t *testing.T) {
		if got := StaleGlobalPriorityBlocks(&Plan{}, &Plan{}); got != nil {
			t.Fatalf("StaleGlobalPriorityBlocks = %v, want none", got)
		}
		if got := StaleGlobalPriorityBlocks(nil, &Plan{}); got != nil {
			t.Fatalf("a nil baseline must restore nothing, got %v", got)
		}
	})

	// Without a recorded previous value there is no number to write. Inventing one would be a guessed
	// default route — the same thing defaultRouteLadder refuses to do when it cannot see the router's
	// own priorities.
	t.Run("no recorded previous value is not a guess", func(t *testing.T) {
		partial := &Plan{
			GlobalPriority:    map[string]int{"Wireguard3": 33330, "Wireguard9": 32818},
			GlobalPriorityWas: map[string]int{"Wireguard3": 10922},
		}
		got := StaleGlobalPriorityBlocks(partial, &Plan{})
		want := [][]string{{"interface Wireguard3", "ip global 10922"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("StaleGlobalPriorityBlocks = %v, want %v", got, want)
		}
	})

	// A restore is not a teardown: the commands are positive writes, and the teardown list is
	// validated as `no …`. Getting this wrong would make the apply reject its own restore.
	t.Run("blocks are positive ip global writes", func(t *testing.T) {
		for _, block := range StaleGlobalPriorityBlocks(prev, &Plan{}) {
			if len(block) != 2 || block[0][:10] != "interface " || block[1][:10] != "ip global " {
				t.Fatalf("unexpected block shape: %q", block)
			}
		}
	})
}
