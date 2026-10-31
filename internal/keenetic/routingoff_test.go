package keenetic

import (
	"reflect"
	"testing"
)

// A plan compiled on a clean router recorded the router's own numbers: those go back as they were.
func TestRoutingOffPrioritiesRestoresTheRecordedNumbers(t *testing.T) {
	plan := &Plan{
		GlobalPriority:    map[string]int{"Wireguard10": 55634, "Wireguard11": 55122},
		GlobalPriorityWas: map[string]int{"Wireguard10": 1000, "Wireguard11": 975},
	}
	observed := map[string]int{"GigabitEthernet1": 54610, "Wireguard10": 55634, "Wireguard11": 55122, "UsbLte0": 40000}
	got, err := RoutingOffPriorities(plan, observed)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"Wireguard10": 1000, "Wireguard11": 975}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RoutingOffPriorities = %v, want %v", got, want)
	}
}

// A plan compiled over an earlier WayHop ladder recorded that ladder's raised value as "was": putting
// it back would leave the tunnel holding the default route with routing "off". Such an interface goes
// below every connection the router owns instead, in ladder order.
func TestRoutingOffPrioritiesNeverRestoresARaisedNumber(t *testing.T) {
	plan := &Plan{
		GlobalPriority:    map[string]int{"Wireguard3": 56146, "Wireguard5": 55634, "Wireguard7": 55122},
		GlobalPriorityWas: map[string]int{"Wireguard3": 55634, "Wireguard5": 2730},
	}
	observed := map[string]int{"GigabitEthernet1": 54610, "UsbLte0": 40000,
		"Wireguard3": 56146, "Wireguard5": 55634, "Wireguard7": 55122}
	got, err := RoutingOffPriorities(plan, observed)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"Wireguard3": 39999, "Wireguard5": 2730, "Wireguard7": 39998}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RoutingOffPriorities = %v, want %v", got, want)
	}
	for iface, prio := range got {
		if prio >= observed["GigabitEthernet1"] {
			t.Errorf("%s stays at %d, at or above the WAN's %d: it would keep the default route", iface, prio, observed["GigabitEthernet1"])
		}
	}
}

func TestRoutingOffPrioritiesNeedsARouterLadder(t *testing.T) {
	if got, err := RoutingOffPriorities(&Plan{}, nil); err != nil || got != nil {
		t.Fatalf("a plan with no ladder changes nothing: %v, %v", got, err)
	}
	plan := &Plan{GlobalPriority: map[string]int{"Wireguard3": 40000}}
	if _, err := RoutingOffPriorities(plan, map[string]int{"Wireguard3": 40000}); err == nil {
		t.Fatal("with no router-owned priority observed there is nothing to hand the default back to")
	}
}

// An interface the running config no longer shows is not written: `interface X` for a name NDM does
// not know would create it.
func TestRoutingOffPrioritiesSkipsAnInterfaceThatIsGone(t *testing.T) {
	plan := &Plan{
		GlobalPriority:    map[string]int{"Wireguard3": 56146, "Wireguard9": 55634},
		GlobalPriorityWas: map[string]int{"Wireguard3": 1000, "Wireguard9": 975},
	}
	got, err := RoutingOffPriorities(plan, map[string]int{"GigabitEthernet1": 54610, "Wireguard3": 56146})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]int{"Wireguard3": 1000}; !reflect.DeepEqual(got, want) {
		t.Fatalf("RoutingOffPriorities = %v, want %v", got, want)
	}
}

func TestLadderBlocksMatchesThePlanShape(t *testing.T) {
	got := LadderBlocks(map[string]int{"Wireguard5": 2730, "Wireguard3": 39999})
	want := [][]string{{"interface Wireguard3", "ip global 39999"}, {"interface Wireguard5", "ip global 2730"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LadderBlocks = %v, want %v", got, want)
	}
}
