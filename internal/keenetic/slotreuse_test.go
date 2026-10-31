package keenetic

import (
	"bytes"
	"encoding/base64"
	"slices"
	"strconv"
	"testing"

	"wayhop/internal/model"
)

// QA-108: a native endpoint keeps the WireguardN slot the previous plan created for it while its
// block is unchanged, and only then.

func slotreuse_endpoint(id, server string) model.Endpoint {
	return model.Endpoint{
		ID: id, Name: id, Engine: model.EngineSingBox, Protocol: model.ProtoWireGuard,
		Server: server, Port: 51820, Enabled: true,
		Params: map[string]any{
			"private_key":     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
			"peer_public_key": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)),
			"local_address":   []string{"192.0.2.2/32"},
		},
	}
}

// slotreuse_owned is what the server hands the next compile: each endpoint's block from plan.
func slotreuse_owned(plan *Plan) map[string][]string {
	owned := map[string][]string{}
	for id, iface := range plan.IfaceFor {
		for _, block := range plan.Interfaces {
			if block[0] == "interface "+iface {
				owned[id] = block
			}
		}
	}
	return owned
}

func slotreuse_first(t *testing.T, p *model.Profile) *Plan {
	t.Helper()
	first, err := Compile(p, CompileOptions{OccupiedInterfaces: map[string]bool{}})
	if err != nil {
		t.Fatal(err)
	}
	if first.IfaceFor["a"] != "Wireguard10" || first.IfaceFor["b"] != "Wireguard11" {
		t.Fatalf("first plan = %v, want a=Wireguard10 b=Wireguard11", first.IfaceFor)
	}
	return first
}

func TestCompile_UnchangedNativeEndpointKeepsItsSlot(t *testing.T) {
	p := &model.Profile{Endpoints: []model.Endpoint{slotreuse_endpoint("a", "198.51.100.10"), slotreuse_endpoint("b", "198.51.100.11")}}
	first := slotreuse_first(t, p)
	second, err := Compile(p, CompileOptions{
		OccupiedInterfaces: map[string]bool{"Wireguard10": true, "Wireguard11": true}, // both live now
		OwnedBlocks:        slotreuse_owned(first),
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.IfaceFor["a"] != "Wireguard10" || second.IfaceFor["b"] != "Wireguard11" {
		t.Errorf("unchanged endpoints moved: %v", second.IfaceFor)
	}
	if !slices.EqualFunc(first.Interfaces, second.Interfaces, slices.Equal[[]string]) {
		t.Errorf("kept blocks differ from the live ones:\nfirst  %v\nsecond %v", first.Interfaces, second.Interfaces)
	}
	// The adapter spares exactly these on a failed Apply, so the list is part of the contract.
	if len(first.KeptInterfaces) != 0 || !slices.Equal(second.KeptInterfaces, []string{"Wireguard10", "Wireguard11"}) {
		t.Errorf("kept = %v then %v, want none then both", first.KeptInterfaces, second.KeptInterfaces)
	}
}

// A changed block is not written over the live interface: it is created in a fresh slot, beside the
// old one, as every endpoint was before slots were kept. The unchanged one stays.
func TestCompile_ChangedNativeEndpointTakesAFreshSlot(t *testing.T) {
	p := &model.Profile{Endpoints: []model.Endpoint{slotreuse_endpoint("a", "198.51.100.10"), slotreuse_endpoint("b", "198.51.100.11")}}
	first := slotreuse_first(t, p)
	p.Endpoints[0].Port = 51821
	second, err := Compile(p, CompileOptions{
		OccupiedInterfaces: map[string]bool{"Wireguard10": true, "Wireguard11": true},
		OwnedBlocks:        slotreuse_owned(first),
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.IfaceFor["a"] != "Wireguard12" || second.IfaceFor["b"] != "Wireguard11" {
		t.Errorf("slots = %v, want the changed a on Wireguard12 and the unchanged b kept on Wireguard11", second.IfaceFor)
	}
	if !slices.Equal(second.KeptInterfaces, []string{"Wireguard11"}) {
		t.Errorf("kept = %v, want only the unchanged Wireguard11", second.KeptInterfaces)
	}
}

// A slot the previous plan created is held for its endpoint even when the running config does not
// show it: an endpoint allocated before it must not take it, or the two would share one interface.
func TestCompile_HeldSlotIsNotTakenByAnotherEndpoint(t *testing.T) {
	p := &model.Profile{Endpoints: []model.Endpoint{slotreuse_endpoint("a", "198.51.100.10"), slotreuse_endpoint("b", "198.51.100.11")}}
	first := slotreuse_first(t, p)
	p.Endpoints[0].Port = 51821
	second, err := Compile(p, CompileOptions{
		OccupiedInterfaces: map[string]bool{"Wireguard10": true}, // b's interface is not live
		OwnedBlocks:        slotreuse_owned(first),
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.IfaceFor["b"] != "Wireguard11" || second.IfaceFor["a"] != "Wireguard12" {
		t.Errorf("slots = %v, want b kept on Wireguard11 and the changed a on Wireguard12", second.IfaceFor)
	}
}

// An owned slot that an adopted tunnel now holds is not the endpoint's to keep.
func TestCompile_OwnedSlotHeldByAnAdoptedTunnelIsNotKept(t *testing.T) {
	p := &model.Profile{Endpoints: []model.Endpoint{slotreuse_endpoint("a", "198.51.100.10"), slotreuse_endpoint("b", "198.51.100.11")}}
	first := slotreuse_first(t, p)
	ext := slotreuse_endpoint("ext", "203.0.113.5")
	ext.Engine, ext.Owner = model.EngineExternal, model.OwnerExternal
	p.Endpoints = append(p.Endpoints, ext)
	second, err := Compile(p, CompileOptions{
		OccupiedInterfaces: map[string]bool{"Wireguard10": true, "Wireguard11": true},
		OwnedBlocks:        slotreuse_owned(first),
		AdoptInterfaces:    map[string]string{"ext": "nwg10"},
		AdoptNDMNames:      map[string]string{"ext": "Wireguard10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.IfaceFor["ext"] != "Wireguard10" || second.IfaceFor["a"] == "Wireguard10" || second.IfaceFor["b"] != "Wireguard11" {
		t.Errorf("slots = %v, want ext adopted on Wireguard10, a moved off it, b kept", second.IfaceFor)
	}
}

// A kept slot outlives the ladder that raised it. Its recorded GlobalPriorityWas is then what the
// PREVIOUS Apply's ladder raised it to, and the stale-ladder restore used to write exactly that back
// when the default rule moved off the tunnel: the Apply succeeded and the tunnel stayed on top,
// carrying everything. A kept interface goes back to its own block's priority; one the reconcile
// removes gets no restore at all (a read-back of a deleted interface could only fail the Apply).
func TestStaleLadderRestoreOfAKeptSlotUsesItsOwnPriority(t *testing.T) {
	viaTunnel := []model.Rule{{ID: "default", Default: true, Outbound: "a"}}
	p := &model.Profile{Endpoints: []model.Endpoint{slotreuse_endpoint("a", "198.51.100.10")}, Rules: viaTunnel}
	first, err := Compile(p, CompileOptions{OccupiedInterfaces: map[string]bool{}, GlobalPriorityNow: map[string]int{"ISP": 1000}})
	if err != nil {
		t.Fatal(err)
	}
	raised := first.GlobalPriority["Wireguard10"]
	if raised <= 1000 {
		t.Fatalf("first ladder = %v; this test lost its trigger", first.GlobalPriority)
	}
	second, err := Compile(p, CompileOptions{
		OccupiedInterfaces: map[string]bool{"Wireguard10": true},
		OwnedBlocks:        slotreuse_owned(first),
		GlobalPriorityNow:  map[string]int{"ISP": 1000, "Wireguard10": raised},
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.IfaceFor["a"] != "Wireguard10" || second.GlobalPriorityWas["Wireguard10"] != raised {
		t.Fatalf("second plan = %v, was %v; this test lost its trigger", second.IfaceFor, second.GlobalPriorityWas)
	}
	own, _, set := blockGlobalPriority(second.Interfaces, "Wireguard10")
	if !set || own == raised {
		t.Fatalf("block priority = %d (set %v)", own, set)
	}

	direct := *p
	direct.Rules = []model.Rule{{ID: "default", Default: true, Outbound: model.OutboundDirect}}
	third, err := Compile(&direct, CompileOptions{
		OccupiedInterfaces: map[string]bool{"Wireguard10": true},
		OwnedBlocks:        slotreuse_owned(second),
		GlobalPriorityNow:  map[string]int{"ISP": 1000, "Wireguard10": second.GlobalPriority["Wireguard10"]},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(third.KeptInterfaces, []string{"Wireguard10"}) {
		t.Fatalf("third kept = %v", third.KeptInterfaces)
	}
	got := StaleGlobalPriorityBlocks(second, third)
	want := [][]string{{"interface Wireguard10", "ip global " + strconv.Itoa(own)}}
	if !slices.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Errorf("restore of the kept slot = %v, want %v", got, want)
	}

	changed := direct
	changed.Endpoints = []model.Endpoint{slotreuse_endpoint("a", "198.51.100.10")}
	changed.Endpoints[0].Port = 51821
	moved, err := Compile(&changed, CompileOptions{
		OccupiedInterfaces: map[string]bool{"Wireguard10": true},
		OwnedBlocks:        slotreuse_owned(second),
		GlobalPriorityNow:  map[string]int{"ISP": 1000, "Wireguard10": second.GlobalPriority["Wireguard10"]},
	})
	if err != nil {
		t.Fatal(err)
	}
	if moved.IfaceFor["a"] == "Wireguard10" {
		t.Fatalf("a changed endpoint kept its slot: %v", moved.IfaceFor)
	}
	if got := StaleGlobalPriorityBlocks(second, moved); len(got) != 0 {
		t.Errorf("an interface the reconcile removes was given a restore: %v", got)
	}
}
