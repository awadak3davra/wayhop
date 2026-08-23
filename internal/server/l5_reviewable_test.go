package server

import (
	"encoding/json"
	"reflect"
	"testing"

	"wayhop/internal/changeset"
	"wayhop/internal/config"
	"wayhop/internal/model"
)

// TestEveryRevisionMoveIsReviewable (L5): if a change is big enough to say "you have unapplied
// changes", it is big enough to show in the review.
//
// The two are computed independently — pending compares revision hashes, the review diffs the two
// profiles field by field — so nothing but a test keeps them agreeing. They had drifted apart in six
// places on model.RoutingList at once. Measured before the fix, mutating one field at a time:
//
//	DomainRefreshed bumped   revision moved, 0 review rows   (a scheduler timestamp, nothing to review)
//	DomainCache changed      revision moved, 0 review rows
//	DomainSource changed     revision moved, 0 review rows
//	RefreshHours changed     revision moved, 0 review rows
//	DownloadVia changed      revision moved, 0 review rows
//	ScopeMode changed        revision moved, 0 review rows
//
// Every one of those is a banner the operator cannot act on: Review & Apply opens on an empty list
// and the only way out is to apply something invisible or dismiss a warning that keeps coming back.
//
// The mutation walk is REFLECTIVE on purpose. The previous hole was a field added to the struct
// later (DomainRefreshed, the twin of an already-excluded CIDRRefreshed), and an explicit list of
// field names would have been just as blind to it as the code was. Adding a field to RoutingList now
// puts it under this property automatically: either it stays out of the revision, or it shows up in
// the review.
func TestEveryRevisionMoveIsReviewable(t *testing.T) {
	base := model.Profile{RoutingLists: []model.RoutingList{{
		ID: "l", Name: "L", Outbound: "direct", Enabled: true, Format: "text",
		Manual: []string{"a.com"}, RefreshHours: 24, DownloadVia: "direct",
		CIDRSource: "https://example.com/cidrs.txt", CIDRCache: []string{"1.2.3.0/24"},
		DomainSource: "https://example.com/names.txt", DomainCache: []string{"a.com"},
		ScopeMode: "only", ScopeGroups: []string{"g1"},
	}}}
	cfg := config.Config{}

	rev := func(p model.Profile) string {
		r, err := desiredRevision(desiredInputsV1(cfg, p))
		if err != nil {
			t.Fatalf("revision: %v", err)
		}
		return r
	}
	baseRev := rev(base)

	rlType := reflect.TypeOf(model.RoutingList{})
	for i := 0; i < rlType.NumField(); i++ {
		f := rlType.Field(i)
		if !f.IsExported() {
			continue
		}
		mutated := cloneProfileForReview(base)
		if !mutateField(reflect.ValueOf(&mutated.RoutingLists[0]).Elem().Field(i)) {
			t.Logf("%s: no mutation strategy for %s — extend mutateField", f.Name, f.Type)
			continue
		}
		desiredRev := rev(mutated)
		if desiredRev == baseRev {
			continue // deliberately outside the revision (scheduler metadata): nothing to review
		}
		rows := changeset.Diff(baseRev, desiredRev, base, mutated, cfg, cfg).Changes
		if len(rows) == 0 {
			t.Errorf("%s moves the revision but produces no review row: the panel would raise "+
				"\"unapplied changes\" over an empty changeset", f.Name)
		}
	}
}

// TestRefreshTimestampsAreNotConfiguration (L5): the background refresher stamps when it last ran.
// That stamp must never read as a configuration change — a feed that re-fetched to a byte-identical
// result has changed nothing an Apply could carry.
func TestRefreshTimestampsAreNotConfiguration(t *testing.T) {
	cfg := config.Config{}
	mk := func(cidrAt, domainAt int64) model.Profile {
		return model.Profile{RoutingLists: []model.RoutingList{{
			ID: "l", Name: "L", Outbound: "direct", Enabled: true,
			CIDRSource: "https://example.com/c.txt", CIDRCache: []string{"1.2.3.0/24"}, CIDRRefreshed: cidrAt,
			DomainSource: "https://example.com/n.txt", DomainCache: []string{"a.com"}, DomainRefreshed: domainAt,
		}}}
	}
	rev := func(p model.Profile) string {
		r, err := desiredRevision(desiredInputsV1(cfg, p))
		if err != nil {
			t.Fatalf("revision: %v", err)
		}
		return r
	}
	if rev(mk(1, 1)) != rev(mk(9999, 9999)) {
		t.Error("a refresh timestamp moved the revision: the panel would report unapplied changes " +
			"after a refresh that fetched an identical feed")
	}
	// The caches themselves must stay IN the revision: they are what the datapath matches on, and
	// excluding them would let remote prefixes enter the router without review — the opposite failure.
	moved := mk(1, 1)
	moved.RoutingLists[0].CIDRCache = []string{"1.2.3.0/24", "9.9.9.0/24"}
	if rev(moved) == rev(mk(1, 1)) {
		t.Error("a changed prefix feed must move the revision")
	}
	moved = mk(1, 1)
	moved.RoutingLists[0].DomainCache = []string{"a.com", "b.com"}
	if rev(moved) == rev(mk(1, 1)) {
		t.Error("a changed name feed must move the revision")
	}
}

// cloneProfileForReview deep-copies the parts this test mutates, so one case cannot leak into the
// next through a shared backing array.
func cloneProfileForReview(p model.Profile) model.Profile {
	out := p
	out.RoutingLists = make([]model.RoutingList, len(p.RoutingLists))
	copy(out.RoutingLists, p.RoutingLists)
	for i := range out.RoutingLists {
		out.RoutingLists[i].Manual = append([]string(nil), p.RoutingLists[i].Manual...)
		out.RoutingLists[i].CIDRCache = append([]string(nil), p.RoutingLists[i].CIDRCache...)
		out.RoutingLists[i].DomainCache = append([]string(nil), p.RoutingLists[i].DomainCache...)
		out.RoutingLists[i].ScopeGroups = append([]string(nil), p.RoutingLists[i].ScopeGroups...)
	}
	return out
}

// mutateField changes a value into a different one of the same type. It reports false for a kind it
// has no strategy for, so an unhandled type is announced rather than silently skipped.
func mutateField(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		v.SetString(v.String() + "-changed")
		return true
	case reflect.Bool:
		v.SetBool(!v.Bool())
		return true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(v.Int() + 7)
		return true
	case reflect.Slice:
		// Appending a zero element covers slices of structs (device members) as well as scalars: the
		// question is only whether the revision moves, and an extra element always moves it.
		switch v.Type().Elem().Kind() {
		case reflect.String:
			v.Set(reflect.Append(v, reflect.ValueOf("added-by-mutation")))
		default:
			v.Set(reflect.Append(v, reflect.New(v.Type().Elem()).Elem()))
		}
		return true
	case reflect.Map:
		// Endpoint.Params is where every protocol-specific setting lives (Reality keys, WireGuard
		// peers). A map excluded from the review would hide the most consequential edits there are.
		if v.IsNil() {
			v.Set(reflect.MakeMap(v.Type()))
		}
		key := reflect.New(v.Type().Key()).Elem()
		if key.Kind() != reflect.String {
			return false
		}
		key.SetString("added-by-mutation")
		val := reflect.New(v.Type().Elem()).Elem()
		if val.Kind() == reflect.Interface {
			val.Set(reflect.ValueOf("added-by-mutation"))
		} else if !mutateField(val) {
			return false
		}
		v.SetMapIndex(key, val)
		return true
	case reflect.Pointer:
		// A nil pointer becoming a value IS the change (no TLS block to a TLS block), and json spells
		// the two differently, so allocating alone moves the revision. A pointer that already holds a
		// value is mutated in place through its first mutable field.
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
			if v.Elem().Kind() != reflect.Struct {
				return mutateField(v.Elem())
			}
			return true
		}
		e := v.Elem()
		if e.Kind() != reflect.Struct {
			return mutateField(e)
		}
		for i := 0; i < e.NumField(); i++ {
			if e.Type().Field(i).IsExported() && mutateField(e.Field(i)) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// TestEveryRevisionMoveIsReviewableAcrossTheProfile (L5): the same property, for every collection a
// profile carries.
//
// The test above proves it for RoutingList, which is where the defect was found. But the defect is
// not a property of RoutingList: it is a property of the PAIR (revision inputs, changeset diff). Any
// field, on any type, that reaches the revision without being compared by the diff raises "You have
// unapplied changes" over a review with nothing in it. Endpoints, groups, rules, device groups and
// the DNS plane were never under that property, so a field added to any of them could reintroduce
// the exact bug that was just closed for lists, in a place nothing was watching.
//
// The clone here is a JSON round-trip rather than the field-by-field copy above: that one deepens
// only RoutingLists, and mutating an endpoint through a shallow copy would edit the BASE profile too,
// leaving the diff comparing a value against itself and reporting a clean bill for a real hole.
func TestEveryRevisionMoveIsReviewableAcrossTheProfile(t *testing.T) {
	cfg := config.Config{}
	rev := func(p model.Profile) string {
		r, err := desiredRevision(desiredInputsV1(cfg, p))
		if err != nil {
			t.Fatalf("revision: %v", err)
		}
		return r
	}
	base := model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "e", Name: "E", Engine: model.EngineSingBox, Protocol: "vless", Server: "198.51.100.4",
			Port: 443, Enabled: true, MTU: 1420, PersistentKeepalive: 25,
			Params: map[string]any{"flow": "xtls-rprx-vision"},
		}},
		Groups:       []model.Group{{ID: "g", Name: "G", Type: "fallback", Members: []string{"e"}}},
		Rules:        []model.Rule{{ID: "r", Outbound: "g", DomainSuffix: []string{"example.com"}, Port: []int{443}}},
		DeviceGroups: []model.DeviceGroup{{ID: "d", Name: "D"}},
		DNS:          &model.DNSSettings{},
	}
	baseRev := rev(base)

	for _, tc := range []struct {
		name string
		typ  reflect.Type
		at   func(p *model.Profile) reflect.Value
	}{
		{"Endpoint", reflect.TypeOf(model.Endpoint{}),
			func(p *model.Profile) reflect.Value { return reflect.ValueOf(&p.Endpoints[0]).Elem() }},
		{"Group", reflect.TypeOf(model.Group{}),
			func(p *model.Profile) reflect.Value { return reflect.ValueOf(&p.Groups[0]).Elem() }},
		{"Rule", reflect.TypeOf(model.Rule{}),
			func(p *model.Profile) reflect.Value { return reflect.ValueOf(&p.Rules[0]).Elem() }},
		{"DeviceGroup", reflect.TypeOf(model.DeviceGroup{}),
			func(p *model.Profile) reflect.Value { return reflect.ValueOf(&p.DeviceGroups[0]).Elem() }},
		{"DNSSettings", reflect.TypeOf(model.DNSSettings{}),
			func(p *model.Profile) reflect.Value { return reflect.ValueOf(p.DNS).Elem() }},
	} {
		for i := 0; i < tc.typ.NumField(); i++ {
			f := tc.typ.Field(i)
			if !f.IsExported() {
				continue
			}
			mutated := deepCloneProfile(t, base)
			if !mutateField(tc.at(&mutated).Field(i)) {
				t.Logf("%s.%s: no mutation strategy for %s - extend mutateField", tc.name, f.Name, f.Type)
				continue
			}
			mutatedRev := rev(mutated)
			if mutatedRev == baseRev {
				continue // deliberately outside the revision: nothing to review
			}
			rows := changeset.Diff(baseRev, mutatedRev, base, mutated, cfg, cfg).Changes
			if len(rows) == 0 {
				t.Errorf("%s.%s moves the revision but produces no review row: the panel would raise "+
					"unapplied changes over an empty changeset", tc.name, f.Name)
			}
		}
	}
}

// deepCloneProfile copies through JSON so maps, pointers and nested slices are independent. A test
// that mutates a shared backing array proves nothing.
func deepCloneProfile(t *testing.T, p model.Profile) model.Profile {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("clone marshal: %v", err)
	}
	var out model.Profile
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("clone unmarshal: %v", err)
	}
	return out
}
