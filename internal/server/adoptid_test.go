package server

import (
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/netvpn"
)

// Spec §9 regression: "interface rename is reflected without restart", and §5: "persist stable
// identifiers independently of mutable interface names".
//
// A renamed tunnel is the SAME tunnel. If re-adoption keys off the interface name, the user ends up
// with two endpoints for one tunnel and the older one points at an interface that no longer exists —
// rules referencing it silently route nowhere.
func TestResolveAdoptedID_RenamedTunnelReusesExistingRecord(t *testing.T) {
	const key = "aGVsbG93b3JsZHB1YmxpY2tleTAxMjM0NTY3ODk9"
	existing := []model.Endpoint{{
		ID:     "external-awg0", // adopted when the interface was called awg0
		Engine: model.EngineExternal,
		Params: map[string]any{"interface": "awg0", "public_key": key},
	}}

	// The router renamed it; the key is unchanged.
	got := resolveAdoptedID(existing, netvpn.DiscoveredVPN{Iface: "awg1", PublicKey: key})

	if got != "external-awg0" {
		t.Fatalf("ID = %q, want the existing record's ID: a rename must update the tunnel in place, "+
			"not create a duplicate that leaves the original pointing at a dead interface", got)
	}
}

// A genuinely new tunnel must get its own ID rather than colliding with an unrelated record.
func TestResolveAdoptedID_NewTunnelGetsItsOwnID(t *testing.T) {
	existing := []model.Endpoint{{
		ID:     "external-awg0",
		Engine: model.EngineExternal,
		Params: map[string]any{"interface": "awg0", "public_key": "KEY-A"},
	}}

	got := resolveAdoptedID(existing, netvpn.DiscoveredVPN{Iface: "awg1", PublicKey: "KEY-B"})
	if got != "external-awg1" {
		t.Errorf("ID = %q, want external-awg1: a different key is a different tunnel", got)
	}
}

// With no key to match on, the interface name is all there is. It must still work rather than
// failing or matching something arbitrary.
func TestResolveAdoptedID_NoPublicKeyFallsBackToIface(t *testing.T) {
	existing := []model.Endpoint{{
		ID:     "external-awg0",
		Engine: model.EngineExternal,
		Params: map[string]any{"interface": "awg0", "public_key": "KEY-A"},
	}}

	got := resolveAdoptedID(existing, netvpn.DiscoveredVPN{Iface: "tun5"})
	if got != "external-tun5" {
		t.Errorf("ID = %q, want external-tun5", got)
	}
	// An empty key must never match an existing record's empty key by accident.
	withEmpty := []model.Endpoint{{
		ID: "external-old", Engine: model.EngineExternal,
		Params: map[string]any{"interface": "old"}, // no public_key at all
	}}
	if got := resolveAdoptedID(withEmpty, netvpn.DiscoveredVPN{Iface: "tun5"}); got != "external-tun5" {
		t.Errorf("ID = %q: a missing key must not match another missing key", got)
	}
}

func TestResolveAdoptedID_NoPublicKeyRepairsExactExistingInterface(t *testing.T) {
	existing := []model.Endpoint{{
		ID: "legacy-endpoint", Engine: model.EngineExternal,
		Params: map[string]any{"interface": "nwg1"},
	}}

	got := resolveAdoptedID(existing, netvpn.DiscoveredVPN{Iface: "nwg1", NDMName: "Wireguard1"})
	if got != "legacy-endpoint" {
		t.Fatalf("ID = %q, want existing legacy ID; NDM repair must not create a duplicate", got)
	}
}

// Only external (adopted) endpoints are candidates. A WayHop-created endpoint that happens to carry
// a public_key param must never be hijacked by an adoption.
func TestResolveAdoptedID_IgnoresNonExternalEndpoints(t *testing.T) {
	const key = "SHARED-KEY"
	existing := []model.Endpoint{{
		ID:     "wayhop-made",
		Engine: model.EngineSingBox,
		Params: map[string]any{"public_key": key},
	}}

	got := resolveAdoptedID(existing, netvpn.DiscoveredVPN{Iface: "awg0", PublicKey: key})
	if got != "external-awg0" {
		t.Fatalf("ID = %q: adoption must not take over a WayHop-created endpoint", got)
	}
}

// Whitespace differences in a stored key must not defeat the match — that would silently reintroduce
// the duplicate-record bug for anything that round-tripped through a text field.
func TestResolveAdoptedID_KeyMatchIgnoresSurroundingWhitespace(t *testing.T) {
	const key = "KEY-WITH-SPACE"
	existing := []model.Endpoint{{
		ID:     "external-awg0",
		Engine: model.EngineExternal,
		Params: map[string]any{"public_key": "  " + key + "  "},
	}}

	if got := resolveAdoptedID(existing, netvpn.DiscoveredVPN{Iface: "awg9", PublicKey: key}); got != "external-awg0" {
		t.Errorf("ID = %q, want external-awg0", got)
	}
}

// An empty endpoint list is the first-adoption case and must simply produce the default ID.
func TestResolveAdoptedID_NoExistingEndpoints(t *testing.T) {
	if got := resolveAdoptedID(nil, netvpn.DiscoveredVPN{Iface: "awg0", PublicKey: "K"}); got != "external-awg0" {
		t.Errorf("ID = %q, want external-awg0", got)
	}
}
