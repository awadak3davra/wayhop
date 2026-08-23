package nativeplan

import (
	"reflect"
	"testing"

	"wayhop/internal/keenetic"
	"wayhop/internal/platform"
)

// Reconcile is where the ladder's teardown belongs: it is the only place that holds BOTH the
// authenticated baseline and the target. It was reconciling interfaces and routes and silently
// leaving the ip-global ladder behind, so a profile that stopped routing the default through a
// tunnel still egressed through that tunnel after a successful apply.
func TestReconcileRestoresTheStaleLadder(t *testing.T) {
	previous := &Plan{
		Platform: platform.Keenetic,
		Keenetic: &keenetic.Plan{
			GlobalPriority:    map[string]int{"Wireguard3": 33330},
			GlobalPriorityWas: map[string]int{"Wireguard3": 10922},
		},
	}
	target := &Plan{Platform: platform.Keenetic, Keenetic: &keenetic.Plan{}}

	got, err := Reconcile(previous, target, platform.CapabilitySet{}, "", "")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	want := [][]string{{"interface Wireguard3", "ip global 10922"}}
	if !reflect.DeepEqual(got.KeeneticPriorityRestore, want) {
		t.Fatalf("KeeneticPriorityRestore = %v, want %v", got.KeeneticPriorityRestore, want)
	}
	// It must NOT be filed as a teardown: those are validated as `no …` commands, and a positive
	// write in that list is rejected by the executor.
	for _, command := range got.KeeneticTeardown {
		if command == "interface Wireguard3" || command == "ip global 10922" {
			t.Fatalf("the restore leaked into the teardown list: %v", got.KeeneticTeardown)
		}
	}
}

func TestReconcileLeavesAStillRaisedInterfaceAlone(t *testing.T) {
	previous := &Plan{
		Platform: platform.Keenetic,
		Keenetic: &keenetic.Plan{
			GlobalPriority:    map[string]int{"Wireguard3": 33330, "Wireguard5": 32818},
			GlobalPriorityWas: map[string]int{"Wireguard3": 10922, "Wireguard5": 5461},
		},
	}
	// The new plan still raises Wireguard3 (a different number) and no longer raises Wireguard5.
	target := &Plan{Platform: platform.Keenetic, Keenetic: &keenetic.Plan{
		GlobalPriority:    map[string]int{"Wireguard3": 40000},
		GlobalPriorityWas: map[string]int{"Wireguard3": 33330},
	}}

	got, err := Reconcile(previous, target, platform.CapabilitySet{}, "", "")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	want := [][]string{{"interface Wireguard5", "ip global 5461"}}
	if !reflect.DeepEqual(got.KeeneticPriorityRestore, want) {
		t.Fatalf("KeeneticPriorityRestore = %v, want %v", got.KeeneticPriorityRestore, want)
	}
}

// A first apply has no baseline to restore from, and must not invent one.
func TestReconcileWithNoBaselineRestoresNothing(t *testing.T) {
	target := &Plan{Platform: platform.Keenetic, Keenetic: &keenetic.Plan{
		GlobalPriority: map[string]int{"Wireguard3": 33330},
	}}
	got, err := Reconcile(nil, target, platform.CapabilitySet{}, "", "")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(got.KeeneticPriorityRestore) != 0 {
		t.Fatalf("KeeneticPriorityRestore = %v, want none", got.KeeneticPriorityRestore)
	}
}
