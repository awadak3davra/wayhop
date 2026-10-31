package store

import (
	"errors"
	"path/filepath"
	"testing"

	"wayhop/internal/model"
)

func revStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func revEndpoint(id, server string) model.Endpoint {
	return model.Endpoint{ID: id, Name: id, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: server, Port: 443, Params: map[string]any{"uuid": "u-" + id}, Enabled: true}
}

func revOf(t *testing.T, s *Store, id string) string {
	t.Helper()
	p := s.Profile()
	e := p.EndpointByID(id)
	if e == nil {
		t.Fatalf("endpoint %s missing", id)
	}
	return model.EndpointRev(*e)
}

// QA-152: a write made At the revision its copy was read at commits only while the stored object
// still has it. A stale one is refused with ErrStale and leaves the object as it was; a current one
// commits and reports the revisions before and after it.
func TestRev_StaleWriteIsRefusedAndCurrentOneCommits(t *testing.T) {
	s := revStore(t)
	if err := s.UpsertEndpoint(revEndpoint("a", "192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	read := revOf(t, s, "a") // tab A opens the connection here

	// Tab B saves a newer version of the same connection.
	saved, err := s.UpsertEndpointAt(revEndpoint("a", "192.0.2.2"), At(read))
	if err != nil {
		t.Fatalf("a write at the current revision was refused: %v", err)
	}
	if saved.Was != read || saved.Rev != revOf(t, s, "a") || saved.Rev == read {
		t.Fatalf("saved = %+v, want was %s and the new stored revision", saved, read)
	}

	// Tab A's stale copy is refused and does not put the old server back.
	if _, err := s.UpsertEndpointAt(revEndpoint("a", "192.0.2.1"), At(read)); !errors.Is(err, ErrStale) {
		t.Fatalf("stale write: err = %v, want ErrStale", err)
	}
	if p := s.Profile(); p.EndpointByID("a").Server != "192.0.2.2" {
		t.Fatalf("server = %s after a refused stale write, want tab B's 192.0.2.2", p.EndpointByID("a").Server)
	}
	// A revision for an object that is gone is stale too: the form is editing something deleted.
	if _, err := s.UpsertEndpointAt(revEndpoint("gone", "192.0.2.9"), At(read)); !errors.Is(err, ErrStale) {
		t.Fatalf("a write At a revision of a missing endpoint: err = %v, want ErrStale", err)
	}
	// AnyRev is the write every caller made before revisions: unconditional.
	if err := s.UpsertEndpoint(revEndpoint("a", "192.0.2.3")); err != nil {
		t.Fatalf("an unconditional write was refused: %v", err)
	}
}

// The regression the profile-wide generation caused: anything saved anywhere made every open form
// stale. A write to another object, a new one, a reorder, a deletion of something else and the feed
// refresh rewriting the list's own caches all leave an open form's revision valid.
func TestRev_OtherWritesDoNotStaleAnOpenForm(t *testing.T) {
	s := revStore(t)
	for _, e := range []model.Endpoint{revEndpoint("a", "192.0.2.1"), revEndpoint("b", "192.0.2.2"), revEndpoint("x", "192.0.2.5")} {
		if err := s.UpsertEndpoint(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertGroup(model.Group{ID: "g", Name: "G", Type: model.GroupFallback, Members: []string{"a", "b"}}); err != nil {
		t.Fatal(err)
	}
	lists := []model.RoutingList{
		{ID: "l", Name: "L", CIDRSource: "https://example.com/cidrs.txt", Manual: []string{"example.org"}, Outbound: "a", Enabled: true},
		{ID: "m", Name: "M", Manual: []string{"example.net"}, Outbound: "b", Enabled: true},
	}
	for _, rl := range lists {
		if err := s.UpsertRoutingList(rl); err != nil {
			t.Fatal(err)
		}
	}
	p := s.Profile()
	formEP, formG, formL := revOf(t, s, "a"), model.GroupRev(*p.GroupByID("g")), model.RoutingListRev(p.RoutingLists[0])

	if err := s.UpsertEndpoint(revEndpoint("b", "192.0.2.22")); err != nil { // another connection
		t.Fatal(err)
	}
	if err := s.UpsertEndpoint(revEndpoint("c", "192.0.2.3")); err != nil { // a new one
		t.Fatal(err)
	}
	if err := s.DeleteEndpoint("x"); err != nil { // something else deleted
		t.Fatal(err)
	}
	if err := s.UpsertDeviceGroup(model.DeviceGroup{ID: "kids", Name: "Kids", Members: []model.DeviceMember{{IP: "192.168.1.20"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReorderRoutingLists([]string{"m", "l"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRoutingListCaches(map[string]CacheUpdate{"l": {Source: "https://example.com/cidrs.txt", CIDRs: []string{"198.51.100.0/24"}}}); err != nil {
		t.Fatal(err)
	}

	edited := revEndpoint("a", "192.0.2.11")
	if _, err := s.UpsertEndpointAt(edited, At(formEP)); err != nil {
		t.Errorf("the connection form went stale on writes to other objects: %v", err)
	}
	if _, err := s.UpsertGroupAt(model.Group{ID: "g", Name: "G2", Type: model.GroupFallback, Members: []string{"a", "b"}}, At(formG)); err != nil {
		t.Errorf("the group form went stale on writes to other objects: %v", err)
	}
	if _, err := s.UpsertRoutingListAt(model.RoutingList{ID: "l", Name: "L2", CIDRSource: "https://example.com/cidrs.txt", Manual: []string{"example.org"}, Outbound: "a", Enabled: true}, At(formL)); err != nil {
		t.Errorf("the routing list form went stale on a reorder or its own feed refresh: %v", err)
	}
	if got := s.Profile().RoutingLists; got[1].ID != "l" || len(got[1].CIDRCache) != 1 {
		t.Errorf("the list save lost the refreshed cache or the order: %+v", got)
	}
}

// Every writer an editing form or switch reaches holds the same line.
func TestRev_EveryFormWriterChecksTheRevision(t *testing.T) {
	s := revStore(t)
	for _, e := range []model.Endpoint{revEndpoint("a", "192.0.2.1"), revEndpoint("b", "192.0.2.2"), revEndpoint("c", "192.0.2.3")} {
		if err := s.UpsertEndpoint(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertGroup(model.Group{ID: "g", Name: "G", Type: model.GroupFallback, Members: []string{"a", "b"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertRoutingList(model.RoutingList{ID: "l", Name: "L", Manual: []string{"example.org"}, Outbound: "c", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	stale := At("0000000000000000")
	before := s.Gen()
	off := revEndpoint("a", "192.0.2.1")
	off.Enabled = false
	writes := map[string]func() error{
		"UpsertGroupAt": func() error {
			_, err := s.UpsertGroupAt(model.Group{ID: "g", Name: "G2", Type: model.GroupFallback, Members: []string{"a"}}, stale)
			return err
		},
		"UpsertRoutingListAt": func() error {
			_, err := s.UpsertRoutingListAt(model.RoutingList{ID: "l", Name: "L2", Outbound: "c", Enabled: true}, stale)
			return err
		},
		"SetEndpointDisabledDetachingAt": func() error {
			_, err := s.SetEndpointDisabledDetachingAt(off, stale)
			return err
		},
		"SetEndpointDisabledReplacingAt": func() error {
			_, err := s.SetEndpointDisabledReplacingAt(off, "b", stale)
			return err
		},
	}
	for name, write := range writes {
		if err := write(); !errors.Is(err, ErrStale) {
			t.Errorf("%s at a stale revision: err = %v, want ErrStale", name, err)
		}
	}
	if _, err := s.UpsertEndpointsIfGen([]model.Endpoint{revEndpoint("d", "192.0.2.4")}, before-1); !errors.Is(err, ErrStaleGen) {
		t.Errorf("UpsertEndpointsIfGen at a stale generation: err = %v, want ErrStaleGen", err)
	}
	if s.Gen() != before {
		t.Fatalf("refused writes moved the generation %d -> %d", before, s.Gen())
	}
	p := s.Profile()
	if g := p.GroupByID("g"); g.Name != "G" || len(g.Members) != 2 {
		t.Errorf("group changed by a refused write: %+v", *g)
	}
	if len(p.RoutingLists) != 1 || p.RoutingLists[0].Name != "L" || len(p.RoutingLists[0].Manual) != 1 {
		t.Errorf("routing list changed by a refused write: %+v", p.RoutingLists)
	}
	if !p.EndpointByID("a").Enabled || p.EndpointByID("d") != nil {
		t.Error("an endpoint write went through at a stale revision")
	}
}

// QA-150: a rule-set format carried over to a new URL stays when the new URL's file name says nothing
// (a mirror with no extension, a query-string feed: dropped, the generator would skip the list) or
// names the same format, and goes, to be inferred from the URL again, when the new URL names the other
// format or is a plain-text list such as .lst (kept, sing-box reads the file as what it is not, and a
// rule set that fails to load stops the whole core). A format the caller chose for the new URL, and
// one on an unchanged URL, stay.
func TestUpsertRoutingList_CarriedFormatOnANewURL(t *testing.T) {
	const srs, feed = "https://example.com/lists/ru-bundle.srs", "https://example.com/get?list=ru"
	cases := []struct {
		name, old, source, format, want string
	}{
		{"preset moved to a .json URL", srs, "https://example.com/lists/ru-bundle.json", "binary", ""},
		{"preset moved to a .json URL behind a query", srs, "https://example.com/lists/ru-bundle.json?token=x", "binary", ""},
		{"preset moved to a plain-text .lst list", srs, "https://example.com/lists/ru.lst", "binary", ""},
		{"preset moved to a mirror with no extension", srs, "https://cdn.example.com/rules/ru-bundle", "binary", "binary"},
		{"preset moved to a query-string feed", srs, feed, "binary", "binary"},
		{"preset moved to another .srs URL", srs, "https://example.com/lists/other.srs", "binary", "binary"},
		{"a format set for a feed, the feed moved", feed, "https://example.com/get?list=ru&v=2", "binary", "binary"},
		{"a format set for a feed, moved to a .json URL", feed, "https://example.com/lists/ru.json", "binary", ""},
		{"a format set for a feed, moved to a .lst list", feed, "https://example.com/lists/ru.lst", "binary", ""},
		{"a format the caller chose for the new URL", srs, "https://example.com/lists/ru.json", "source", "source"},
		{"URL unchanged", srs, srs, "binary", "binary"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := revStore(t)
			if err := s.UpsertRoutingList(model.RoutingList{ID: "ru", Name: "RU", Source: c.old, Format: "binary", Outbound: "direct", Enabled: true}); err != nil {
				t.Fatal(err)
			}
			if err := s.UpsertRoutingList(model.RoutingList{ID: "ru", Name: "RU", Source: c.source, Format: c.format, Outbound: "direct", Enabled: true}); err != nil {
				t.Fatal(err)
			}
			if got := s.Profile().RoutingLists[0].Format; got != c.want {
				t.Errorf("format = %q, want %q", got, c.want)
			}
		})
	}
}

// A parse's source format rides on the endpoint from the parse to the save; it is never stored.
func TestUpsertEndpoint_ImportFormatIsNeverStored(t *testing.T) {
	s := revStore(t)
	a, b := revEndpoint("a", "192.0.2.1"), revEndpoint("b", "192.0.2.2")
	a.Import, b.Import = "link:vless", "clash"
	if err := s.UpsertEndpoint(a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertEndpoints([]model.Endpoint{b}); err != nil {
		t.Fatal(err)
	}
	for _, e := range s.Profile().Endpoints {
		if e.Import != "" {
			t.Errorf("endpoint %s stored with import %q", e.ID, e.Import)
		}
	}
}
