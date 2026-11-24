package changeset

import (
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// Field undos of two settings that only mean something together. A field undo keeps
// the object's other edits, so it must not leave a pair no editor would have saved.

func undoListField(t *testing.T, base, desired model.RoutingList, field string) (model.RoutingList, error) {
	t.Helper()
	got, _, err := Undo(model.Profile{RoutingLists: []model.RoutingList{base}}, model.Profile{RoutingLists: []model.RoutingList{desired}},
		config.Config{}, config.Config{}, UndoRequest{Scope: ScopeField, ID: base.ID, ObjectType: "routing_list", Field: field})
	if err != nil {
		return model.RoutingList{}, err
	}
	return got.RoutingLists[0], nil
}

// The URL and the format it is read as are one feed. Undoing the URL alone left the old .srs
// file read as JSON; sing-box cannot load that, and one rule set that fails to load stops the core.
func TestUndoSourceURLTakesAContradictingFormatWithIt(t *testing.T) {
	base := model.RoutingList{ID: "r", Enabled: true, Outbound: "direct", Source: "https://example.net/list.srs", Format: "binary"}
	desired := base
	desired.Source, desired.Format = "https://example.net/list.json", "source"

	r, err := undoListField(t, base, desired, "Source URL")
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != base.Source || !model.CarriedRuleSetFormat(r.Format, r.Source) {
		t.Fatalf("source=%q format=%q: the restored file would be read as what it is not", r.Source, r.Format)
	}
	if !routingEqual(base, r) {
		t.Errorf("the format row describes the undone URL and must go with it: %+v", diffRoutingLists([]model.RoutingList{base}, []model.RoutingList{r}))
	}

	// A format the restored URL does not contradict is the operator's own edit and stays.
	mirror := base
	mirror.Source, mirror.Format = "https://mirror.example.net/feed", "binary"
	edited := mirror
	edited.Source, edited.Format = "https://mirror.example.net/feed2", "source"
	if r, err = undoListField(t, mirror, edited, "Source URL"); err != nil || r.Format != "source" {
		t.Errorf("format=%q err=%v, want the edited format kept beside a URL that names none", r.Format, err)
	}
}

// The other direction, which is the common one: saving a new URL drops a carried format,
// so the review shows "Source URL" and "Feed format: binary -> none". Undoing the format
// alone put "binary" on the new .json URL.
func TestUndoFeedFormatRefusedWhenTheNewURLContradictsIt(t *testing.T) {
	base := model.RoutingList{ID: "r", Enabled: true, Outbound: "direct", Source: "https://example.net/list.srs", Format: "binary"}
	for _, format := range []string{"", "source"} {
		desired := base
		desired.Source, desired.Format = "https://example.net/list.json", format
		_, err := undoListField(t, base, desired, "Feed format")
		if err == nil || !strings.Contains(err.Error(), "Source URL") {
			t.Errorf("desired format %q: err=%v, want a refusal that names the Source URL row", format, err)
		}
	}
	// With the URL undone first the format row is undone as before.
	desired := base
	desired.Format = ""
	if r, err := undoListField(t, base, desired, "Feed format"); err != nil || r.Format != "binary" {
		t.Errorf("format=%q err=%v, want binary back on its own URL", r.Format, err)
	}
}

// A fastest list's Outbound is its first tunnel, so the two rows overlap in that one slot only.
// Undoing "Outbound" put the whole baseline tunnel set back and discarded a tunnel added beside it.
func TestUndoOutboundKeepsTheOtherTunnelEdits(t *testing.T) {
	eps := []model.Endpoint{{ID: "a", Enabled: true}, {ID: "b", Enabled: true}, {ID: "c", Enabled: true}, {ID: "d", Enabled: true}}
	list := func(cands ...string) model.RoutingList {
		return model.RoutingList{ID: "r", Enabled: true, Manual: []string{"example.net"}, Outbound: cands[0], Candidates: cands}
	}
	for _, c := range []struct{ name, desired, want string }{
		{"first tunnel replaced, one added", "c b d", "a b d"},
		{"baseline first tunnel moved down", "b a d", "a b d"},
		{"first tunnel replaced only", "c b", "a b"},
	} {
		base, desired := list("a", "b"), list(strings.Fields(c.desired)...)
		got, _, err := Undo(model.Profile{Endpoints: eps, RoutingLists: []model.RoutingList{base}},
			model.Profile{Endpoints: eps, RoutingLists: []model.RoutingList{desired}},
			config.Config{}, config.Config{}, UndoRequest{Scope: ScopeField, ID: "r", ObjectType: "routing_list", Field: "Outbound"})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		r := got.RoutingLists[0]
		if r.Outbound != "a" || strings.Join(r.Candidates, " ") != c.want {
			t.Errorf("%s: outbound=%q tunnels=%v, want a and [%s]", c.name, r.Outbound, r.Candidates, c.want)
		}
		if desired.Candidates[0] != strings.Fields(c.desired)[0] {
			t.Errorf("%s: the undo wrote into the caller's tunnels: %v", c.name, desired.Candidates)
		}
	}
	// A list that was not in fastest mode has no first tunnel to swap: the tunnels go with the outbound.
	base := model.RoutingList{ID: "r", Enabled: true, Manual: []string{"example.net"}, Outbound: "direct"}
	r, err := undoListField(t, base, list("c", "b"), "Outbound")
	if err != nil || r.Outbound != "direct" || len(r.Candidates) != 0 {
		t.Errorf("outbound=%q tunnels=%v err=%v, want direct and no tunnels", r.Outbound, r.Candidates, err)
	}
}

// A feed's cache is what its source last returned. Undoing the source alone left the list
// naming the old source while holding (and, at Apply, routing) the new one's entries.
func TestUndoFeedSourceTakesItsCacheWithIt(t *testing.T) {
	base := model.RoutingList{ID: "r", Enabled: true, Outbound: "direct",
		CIDRSource: "asn:1", CIDRCache: []string{"192.0.2.0/24"}, CIDRRefreshed: 100,
		DomainSource: "https://a.example/names.txt", DomainCache: []string{"a.example"}, DomainRefreshed: 100}
	desired := base
	desired.CIDRSource, desired.CIDRCache, desired.CIDRRefreshed = "asn:2", []string{"198.51.100.0/24"}, 200
	desired.DomainSource, desired.DomainCache, desired.DomainRefreshed = "https://b.example/names.txt", []string{"b.example"}, 200

	r, err := undoListField(t, base, desired, "IP feed source")
	if err != nil {
		t.Fatal(err)
	}
	if r.CIDRSource != "asn:1" || strings.Join(r.CIDRCache, ",") != "192.0.2.0/24" || r.CIDRRefreshed != 100 {
		t.Errorf("IP feed: source=%q cache=%v refreshed=%d, want the baseline source with its own prefixes and fetch time", r.CIDRSource, r.CIDRCache, r.CIDRRefreshed)
	}
	if r.DomainSource != desired.DomainSource || strings.Join(r.DomainCache, ",") != "b.example" {
		t.Errorf("the name feed was not undone and must stay: source=%q cache=%v", r.DomainSource, r.DomainCache)
	}

	if r, err = undoListField(t, base, desired, "Name feed source"); err != nil {
		t.Fatal(err)
	}
	if r.DomainSource != base.DomainSource || strings.Join(r.DomainCache, ",") != "a.example" || r.DomainRefreshed != 100 {
		t.Errorf("name feed: source=%q cache=%v refreshed=%d, want the baseline source with its own names and fetch time", r.DomainSource, r.DomainCache, r.DomainRefreshed)
	}
	if r.CIDRSource != "asn:2" || strings.Join(r.CIDRCache, ",") != "198.51.100.0/24" {
		t.Errorf("the IP feed was not undone and must stay: source=%q cache=%v", r.CIDRSource, r.CIDRCache)
	}
}

// The default resolver names one of the resolvers. Undoing "Resolvers" after one was replaced
// left the default naming a resolver that was gone, which Validate refuses: the row could not be
// undone at all.
func TestUndoResolversTakesADanglingDefaultWithIt(t *testing.T) {
	server := func(tag string, on bool) model.DNSServer {
		return model.DNSServer{Tag: tag, Type: "https", Server: "192.0.2.53", Enabled: on}
	}
	undo := func(base, desired *model.DNSSettings) model.Profile {
		t.Helper()
		got, _, err := Undo(model.Profile{DNS: base}, model.Profile{DNS: desired}, config.Config{}, config.Config{},
			UndoRequest{Scope: ScopeField, ID: "dns", ObjectType: "dns", Field: "Resolvers"})
		if err != nil {
			t.Fatal(err)
		}
		if err := got.Validate(); err != nil {
			t.Fatalf("the undo left a DNS plane that cannot be saved: %v", err)
		}
		return got
	}

	base := &model.DNSSettings{Enabled: true, Servers: []model.DNSServer{server("a", true)}, Final: "a"}
	desired := &model.DNSSettings{Enabled: true, Servers: []model.DNSServer{server("b", true)}, Final: "b"}
	if got := undo(base, desired); got.DNS.Final != "a" {
		t.Errorf("final=%q, want the baseline default back with its resolver", got.DNS.Final)
	}
	if desired.Final != "b" {
		t.Error("the undo wrote into the caller's DNS plane")
	}

	// The default was moved to a resolver the baseline holds switched off.
	base = &model.DNSSettings{Enabled: true, Servers: []model.DNSServer{server("a", true), server("b", false)}, Final: "a"}
	desired = &model.DNSSettings{Enabled: true, Servers: []model.DNSServer{server("a", true), server("b", true)}, Final: "b"}
	if got := undo(base, desired); got.DNS.Final != "a" {
		t.Errorf("final=%q, want the baseline default: the edited one is switched off again", got.DNS.Final)
	}

	// A default the restored resolvers still hold is its own edit and stays.
	base = &model.DNSSettings{Enabled: true, Servers: []model.DNSServer{server("a", true), server("b", true)}, Final: "a"}
	desired = &model.DNSSettings{Enabled: true, Servers: []model.DNSServer{server("a", true), server("b", true), server("c", true)}, Final: "b"}
	if got := undo(base, desired); got.DNS.Final != "b" {
		t.Errorf("final=%q, want the edited default kept", got.DNS.Final)
	}
}

// Only an automatic (urltest) group can elect by throughput. Undoing "Type" back to a manual
// group left the election mode the edit had set, which Validate refuses.
func TestUndoGroupTypeTakesAnElectionModeItCannotRun(t *testing.T) {
	base := model.Profile{Groups: []model.Group{{ID: "g", Type: model.GroupSelector, Members: []string{"direct"}}}}
	desired := model.Profile{Groups: []model.Group{{ID: "g", Type: model.GroupURLTest, ElectionMode: model.ElectionMixed, Members: []string{"direct"}}}}
	got, _, err := Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{Scope: ScopeField, ID: "g", ObjectType: "group", Field: "Type"})
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("the undo left a group that cannot be saved: %v", err)
	}
	if g := got.Groups[0]; g.Type != model.GroupSelector || g.ElectionMode != "" {
		t.Errorf("type=%q election=%q, want the baseline selector with no election mode", g.Type, g.ElectionMode)
	}

	// Between two types that both run it, the election mode is its own edit and stays.
	base.Groups[0].Type, base.Groups[0].ElectionMode = model.GroupURLTest, model.ElectionLatency
	desired.Groups[0].Type = model.GroupURLTest
	desired.Groups[0].Name = "renamed"
	got, _, err = Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{Scope: ScopeField, ID: "g", ObjectType: "group", Field: "Name"})
	if err != nil || got.Groups[0].ElectionMode != model.ElectionMixed {
		t.Errorf("election=%q err=%v, want the edited mode kept by another row's undo", got.Groups[0].ElectionMode, err)
	}
}

// A block list is matched before every other list wherever it stands, so a move that only
// passes one (or moves one) changes no generated rule. The review said of every move that it
// "changes which rule wins". The row stays, since the saved order did change; its impact says which
// kind of move it is.
func TestPositionRowSaysWhetherTheMoveChangesWhichListWins(t *testing.T) {
	list := func(id, outbound string) model.RoutingList {
		return model.RoutingList{ID: id, Enabled: true, Outbound: outbound, Manual: []string{id + ".example"}}
	}
	a, b, c := list("a", "direct"), list("b", "block"), list("c", "direct")
	impacts := func(base, desired []model.RoutingList) map[string]bool {
		out := map[string]bool{}
		for _, ch := range diffRoutingLists(base, desired) {
			if ch.Action == ActionReordered {
				out[ch.ID] = strings.Contains(ch.Impact, "changes which rule wins")
			}
		}
		return out
	}
	// The block list moved above a routed one: two rows, neither changes which list wins.
	got := impacts([]model.RoutingList{a, b, c}, []model.RoutingList{b, a, c})
	if len(got) != 2 || got["a"] || got["b"] {
		t.Errorf("a block list passing a routed one: rows that claim a new winner = %v, want rows for a and b and no claim", got)
	}
	// Two routed lists changed sides around it: those two rows do.
	got = impacts([]model.RoutingList{a, b, c}, []model.RoutingList{c, b, a})
	if len(got) != 2 || !got["a"] || !got["c"] {
		t.Errorf("two routed lists swapped: %v, want rows for a and c that say the winner changes", got)
	}
	// All three moved: the routed pair changed sides, the block list's own row still claims nothing.
	got = impacts([]model.RoutingList{a, b, c}, []model.RoutingList{c, a, b})
	if len(got) != 3 || !got["a"] || !got["c"] || got["b"] {
		t.Errorf("a rotation: %v, want a and c to claim a new winner and b not", got)
	}
}
