package model

import (
	"encoding/json"
	"testing"
)

// Deliverable 9: migration behaviour for the ownership model.
//
// Owner decides whether WayHop may stop, delete or rewrite the underlying tunnel. Getting the
// default wrong is destructive in one direction and silently disabling in the other:
//
//   - if a legacy endpoint defaulted to external, WayHop would stop managing tunnels it created and
//     the user's existing setup would quietly go inert after an upgrade;
//   - if a DISCOVERED native tunnel defaulted to WayHop-owned, WayHop could tear down a tunnel the
//     router (or another service) owns — destroying configuration it did not create.
//
// The zero value is OwnerWayHop precisely so existing profiles need no migration step. These tests
// pin that, because "the zero value happens to be right" is exactly the kind of property a later
// refactor breaks without noticing.

// An endpoint stored before the ownership model existed carries no "owner" key at all.
const legacyEndpointJSON = `{
  "id": "ep-legacy",
  "name": "My VPN",
  "engine": "singbox",
  "protocol": "vless",
  "server": "example.com",
  "port": 443
}`

func TestMigration_LegacyEndpointIsWayHopOwned(t *testing.T) {
	var e Endpoint
	if err := json.Unmarshal([]byte(legacyEndpointJSON), &e); err != nil {
		t.Fatalf("a pre-ownership endpoint must still parse: %v", err)
	}
	if e.Owner != OwnerWayHop {
		t.Errorf("Owner = %q, want %q (the zero value) so existing profiles need no migration",
			e.Owner, OwnerWayHop)
	}
	if !e.OwnsResource() {
		t.Error("a legacy endpoint must remain WayHop-managed after upgrade; " +
			"treating it as external would silently stop managing the user's existing tunnel")
	}
}

// The other direction: anything explicitly marked external must never be treated as WayHop's to
// destroy, which is the whole point of the field.
func TestMigration_ExternalIsNeverOwned(t *testing.T) {
	for _, owner := range []Owner{OwnerExternal, OwnerImported, OwnerUnknown} {
		e := Endpoint{ID: "x", Owner: owner}
		if e.OwnsResource() {
			t.Errorf("owner %q must NOT be treated as WayHop-owned; WayHop would be free to "+
				"delete a resource it did not create", owner)
		}
	}
}

// Round-trip: an untouched legacy endpoint must not gain an "owner" key on save. A downgrade then
// still reads a file it fully understands, and a diff of the profile shows no spurious change.
func TestMigration_LegacyEndpointRoundTripsWithoutOwnerKey(t *testing.T) {
	var e Endpoint
	if err := json.Unmarshal([]byte(legacyEndpointJSON), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal round-trip: %v", err)
	}
	if _, present := got["owner"]; present {
		t.Errorf("re-saving a legacy endpoint added an \"owner\" key: %s", out)
	}
}

// An explicitly external endpoint must persist its owner — omitempty must not drop a value that
// carries a destructive-operation guarantee.
func TestMigration_ExternalOwnerPersists(t *testing.T) {
	out, err := json.Marshal(Endpoint{ID: "ep", Owner: OwnerExternal})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round Endpoint
	if err := json.Unmarshal(out, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if round.Owner != OwnerExternal {
		t.Fatalf("Owner lost in round-trip (%q); the tunnel would become deletable", round.Owner)
	}
	if round.OwnsResource() {
		t.Error("a discovered external tunnel must never round-trip into WayHop ownership")
	}
}

// An owner value this build does not recognise (written by a newer build) must fail CLOSED — not
// owned — so an unknown marking can never authorise a destructive operation.
func TestMigration_UnrecognisedOwnerFailsClosed(t *testing.T) {
	var e Endpoint
	if err := json.Unmarshal([]byte(`{"id":"ep","owner":"some-future-owner"}`), &e); err != nil {
		t.Fatalf("unknown owner must still parse: %v", err)
	}
	if e.OwnsResource() {
		t.Error("an unrecognised owner must not be treated as WayHop-owned")
	}
}

// The finer ownership classes must ALL be non-owning. This is the invariant that keeps the
// never-destroy-external promise: adding a class must never quietly grant destroy authority.
func TestOwnership_EveryNonWayHopClassIsNonOwning(t *testing.T) {
	for _, o := range []Owner{OwnerExternal, OwnerImported, OwnerSystem, OwnerThirdParty, OwnerUnknown} {
		e := Endpoint{ID: "x", Owner: o}
		if e.OwnsResource() {
			t.Errorf("owner %q must not be treated as WayHop-owned", o)
		}
		if !e.IsExternal() {
			t.Errorf("owner %q must be classified external so destructive paths skip it", o)
		}
	}
	// Only WayHop's own resources are owned, and they are not external.
	w := Endpoint{ID: "x", Owner: OwnerWayHop}
	if !w.OwnsResource() || w.IsExternal() {
		t.Error("a WayHop-created resource must be owned and not external")
	}
}

// Every class must have a human label — a badge rendering a raw enum value would leak internals
// into the UI, and an unlabelled class would render blank.
func TestOwnership_EveryClassHasALabel(t *testing.T) {
	for _, o := range []Owner{OwnerWayHop, OwnerExternal, OwnerImported, OwnerSystem, OwnerThirdParty, OwnerUnknown} {
		if OwnerLabel(o) == "" {
			t.Errorf("owner %q has no label", o)
		}
	}
	// An unrecognised value must fall back, not render raw.
	if l := OwnerLabel(Owner("something-new")); l == "" || l == "something-new" {
		t.Errorf("unrecognised owner must get a generic label, got %q", l)
	}
}

// The new classes persist across a round-trip; losing one would silently downgrade a system-owned
// tunnel to WayHop-owned (the zero value), which is the destructive direction.
func TestOwnership_NewClassesRoundTrip(t *testing.T) {
	for _, o := range []Owner{OwnerSystem, OwnerThirdParty} {
		out, err := json.Marshal(Endpoint{ID: "ep", Owner: o})
		if err != nil {
			t.Fatalf("marshal %q: %v", o, err)
		}
		var round Endpoint
		if err := json.Unmarshal(out, &round); err != nil {
			t.Fatalf("unmarshal %q: %v", o, err)
		}
		if round.Owner != o {
			t.Fatalf("owner %q became %q in round-trip; it would become destroyable", o, round.Owner)
		}
		if round.OwnsResource() {
			t.Errorf("owner %q must never round-trip into WayHop ownership", o)
		}
	}
}
