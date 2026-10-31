package changeset

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// undoCase is a baseline and a desired state that differ in one reviewable way.
type undoCase struct {
	name            string
	base, desired   model.Profile
	baseCfg, desCfg config.Config
	wantRowsAtLeast int
	wantObjectType  string // the object_type every row of this case must carry (empty: not checked)
}

// reqFor is the request the review panel sends for one row: field scope when the row names a field,
// object scope otherwise, and always the row's own object type.
func reqFor(ch Change) UndoRequest {
	if ch.Field != "" {
		return UndoRequest{Scope: ScopeField, ID: ch.ID, ObjectType: ch.ObjectType, Field: ch.Field}
	}
	return UndoRequest{Scope: ScopeObject, ID: ch.ID, ObjectType: ch.ObjectType}
}

func hasRow(cs ChangeSet, ch Change) bool {
	for _, c := range cs.Changes {
		if c.ID == ch.ID && c.ObjectType == ch.ObjectType && c.Field == ch.Field && c.Action == ch.Action {
			return true
		}
	}
	return false
}

func everyRowCases() []undoCase {
	epWith := func(m func(*model.Endpoint)) model.Profile {
		return model.Profile{Endpoints: []model.Endpoint{ep("a", "A", m)}}
	}
	epBase := model.Profile{Endpoints: []model.Endpoint{ep("a", "A")}}
	awg := func(e *model.Endpoint) { e.Engine, e.Protocol = model.EngineAmneziaWG, model.ProtoAmneziaWG }

	grp := func(m func(*model.Group)) model.Profile {
		g := model.Group{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"a"}}
		if m != nil {
			m(&g)
		}
		return model.Profile{Groups: []model.Group{g}}
	}
	list := func(m func(*model.RoutingList)) model.Profile {
		r := model.RoutingList{ID: "r", Name: "R", Outbound: "direct", Enabled: true, Manual: []string{"example.net"},
			CIDRSource: "https://example.net/v4.txt", CIDRCache: []string{"10.0.0.0/8"},
			DomainSource: "https://example.net/names.txt", DomainCache: []string{"example.net"}}
		if m != nil {
			m(&r)
		}
		return model.Profile{RoutingLists: []model.RoutingList{r}}
	}
	rule := func(m func(*model.Rule)) model.Profile {
		r := model.Rule{ID: "r1", DomainSuffix: []string{"example.net"}, Outbound: "direct"}
		if m != nil {
			m(&r)
		}
		return model.Profile{Rules: []model.Rule{r}}
	}
	devg := func(m func(*model.DeviceGroup)) model.Profile {
		g := model.DeviceGroup{ID: "dg", Name: "Kids", Members: []model.DeviceMember{{IP: "192.0.2.10"}}}
		if m != nil {
			m(&g)
		}
		return model.Profile{DeviceGroups: []model.DeviceGroup{g}}
	}
	dns := func(m func(*model.DNSSettings)) model.Profile {
		d := model.DNSSettings{
			Servers: []model.DNSServer{{Tag: "up", Type: "udp", Server: "192.0.2.53"}},
			Rules:   []model.DNSRule{{DomainSuffix: []string{"example.net"}, Server: "up"}},
			Final:   "up",
		}
		if m != nil {
			m(&d)
		}
		return model.Profile{DNS: &d}
	}

	cases := []undoCase{
		// endpoints: every scalar the differ reports, the three sub-structs, health, params.
		{name: "endpoint Name", base: epBase, desired: epWith(func(e *model.Endpoint) { e.Name = "B" })},
		{name: "endpoint Server", base: epBase, desired: epWith(func(e *model.Endpoint) { e.Server = "203.0.113.10" })},
		{name: "endpoint Port", base: epBase, desired: epWith(func(e *model.Endpoint) { e.Port = 8443 })},
		{name: "endpoint Protocol", base: epBase, desired: epWith(func(e *model.Endpoint) { e.Protocol = model.ProtoVLESS })},
		{name: "endpoint Engine", base: epBase, desired: epWith(func(e *model.Endpoint) { e.Engine = model.EngineXray })},
		{name: "endpoint Enabled", base: epBase, desired: epWith(func(e *model.Endpoint) { e.Enabled = false })},
		{name: "endpoint MTU", base: epBase, desired: epWith(func(e *model.Endpoint) { e.MTU = 1280 })},
		{name: "endpoint Keepalive", base: epBase, desired: epWith(func(e *model.Endpoint) { e.PersistentKeepalive = 25 })},
		{name: "endpoint Owner", base: epBase, desired: epWith(func(e *model.Endpoint) { e.Owner = model.OwnerImported })},
		{name: "endpoint AmneziaWG engine", base: epWith(awg), desired: epWith(func(e *model.Endpoint) { awg(e); e.AWGUserspace = true })},
		{name: "endpoint TLS settings", base: epBase, desired: epWith(func(e *model.Endpoint) { e.TLS = &model.TLS{Enabled: true, SNI: "example.net"} })},
		{name: "endpoint ECH", base: epWith(func(e *model.Endpoint) { e.TLS = &model.TLS{Enabled: true, SNI: "example.net"} }),
			desired: epWith(func(e *model.Endpoint) {
				e.TLS = &model.TLS{Enabled: true, SNI: "example.net", ECH: &model.ECH{Enabled: true, QueryServerName: "example.com"}}
			})},
		{name: "endpoint certificate pin", base: epWith(func(e *model.Endpoint) { e.TLS = &model.TLS{Enabled: true, SNI: "example.net"} }),
			desired: epWith(func(e *model.Endpoint) {
				e.TLS = &model.TLS{Enabled: true, SNI: "example.net",
					PinCertSHA256: []string{strings.Repeat("ab", 32)}}
			})},
		{name: "endpoint Transport", base: epBase, desired: epWith(func(e *model.Endpoint) { e.Transport = &model.Transport{Type: "ws", Host: "example.net"} })},
		{name: "endpoint Multiplex", base: epBase, desired: epWith(func(e *model.Endpoint) {
			e.Multiplex = &model.Multiplex{Enabled: true, Protocol: "smux", MaxConnections: 4, MinStreams: 4}
		})},
		{name: "endpoint Health test", base: epBase, desired: epWith(func(e *model.Endpoint) { e.Health = &model.Health{URL: "https://example.net/204", Interval: 60} })},
		{name: "endpoint plain param", base: epBase, desired: epWith(func(e *model.Endpoint) {
			e.Params = map[string]any{"password": "SUPERSECRET", "flow": "xtls-rprx-vision"}
		})},
		{name: "endpoint secret param", base: epBase, desired: epWith(func(e *model.Endpoint) { e.Params = map[string]any{"password": "NEW"} })},
		{name: "endpoint QUIC tuning params", base: epWith(func(e *model.Endpoint) { e.Protocol = model.ProtoTUIC }),
			desired: epWith(func(e *model.Endpoint) {
				e.Protocol = model.ProtoTUIC
				e.Params = map[string]any{model.ParamQUICInitialPacketSize: 1232, model.ParamQUICDisablePMTUD: true}
			}), wantRowsAtLeast: 2},
		{name: "endpoint added", base: model.Profile{}, desired: epBase},
		{name: "endpoint removed", base: epBase, desired: model.Profile{}},

		// groups
		{name: "group Name", base: grp(nil), desired: grp(func(g *model.Group) { g.Name = "G2" })},
		{name: "group Type", base: grp(nil), desired: grp(func(g *model.Group) { g.Type = model.GroupSelector })},
		{name: "group Members", base: grp(nil), desired: grp(func(g *model.Group) { g.Members = []string{"a", "b"} })},
		{name: "group Health test", base: grp(nil), desired: grp(func(g *model.Group) { g.Test = &model.Health{Interval: 30} })},
		{name: "group Kill switch", base: grp(nil), desired: grp(func(g *model.Group) { g.KillSwitch = true })},
		{name: "group Interrupt on switch", base: grp(nil), desired: grp(func(g *model.Group) { g.InterruptOnSwitch = true })},
		{name: "group Managed", base: grp(nil), desired: grp(func(g *model.Group) { g.Managed = true })},
		{name: "group added", base: model.Profile{}, desired: grp(nil)},
		{name: "group removed", base: grp(nil), desired: model.Profile{}},

		// routing lists
		{name: "list Name", base: list(nil), desired: list(func(r *model.RoutingList) { r.Name = "R2" })},
		{name: "list Outbound", base: list(nil), desired: list(func(r *model.RoutingList) { r.Outbound = "block" })},
		{name: "list Enabled", base: list(nil), desired: list(func(r *model.RoutingList) { r.Enabled = false })},
		{name: "list Source URL", base: list(nil), desired: list(func(r *model.RoutingList) { r.Source = "https://example.net/set.srs" })},
		{name: "list Feed format", base: list(nil), desired: list(func(r *model.RoutingList) { r.Format = "binary" })},
		{name: "list Entries", base: list(nil), desired: list(func(r *model.RoutingList) { r.Manual = []string{"example.net", "example.org"} })},
		{name: "list IP feed", base: list(nil), desired: list(func(r *model.RoutingList) { r.CIDRCache = []string{"10.0.0.0/8", "198.51.100.0/24"} })},
		{name: "list Name feed", base: list(nil), desired: list(func(r *model.RoutingList) { r.DomainCache = nil })},
		{name: "list IP feed source", base: list(nil), desired: list(func(r *model.RoutingList) { r.CIDRSource = "asn:64500" })},
		{name: "list Name feed source", base: list(nil), desired: list(func(r *model.RoutingList) { r.DomainSource = "" })},
		{name: "list Download via", base: list(nil), desired: list(func(r *model.RoutingList) { r.DownloadVia = "a" })},
		{name: "list Auto-update", base: list(nil), desired: list(func(r *model.RoutingList) { r.RefreshHours = 6 })},
		{name: "list Applies to", base: list(nil), desired: list(func(r *model.RoutingList) { r.ScopeMode, r.ScopeGroups = "only", []string{"dg"} })},
		{name: "list TLS fragmentation", base: list(nil), desired: list(func(r *model.RoutingList) { r.TLSFragment = model.TLSFragmentRecord })},
		{name: "list Position", wantRowsAtLeast: 2,
			base:    model.Profile{RoutingLists: []model.RoutingList{rl("x", "X", "direct"), rl("y", "Y", "direct")}},
			desired: model.Profile{RoutingLists: []model.RoutingList{rl("y", "Y", "direct"), rl("x", "X", "direct")}}},
		{name: "list added", base: model.Profile{}, desired: list(nil)},
		{name: "list removed", base: list(nil), desired: model.Profile{}},

		// rules (per-device / source routing)
		{name: "rule definition", base: rule(nil), desired: rule(func(r *model.Rule) { r.Outbound = "a" }), wantObjectType: "rule"},
		{name: "rule disabled", base: rule(nil), desired: rule(func(r *model.Rule) { r.Disabled = true }), wantObjectType: "rule"},
		{name: "rule added", base: model.Profile{}, desired: rule(nil), wantObjectType: "rule"},
		{name: "rule removed", base: rule(nil), desired: model.Profile{}, wantObjectType: "rule"},

		// device groups
		{name: "device group members", base: devg(nil), desired: devg(func(g *model.DeviceGroup) { g.Members = append(g.Members, model.DeviceMember{IP: "192.0.2.11"}) }), wantObjectType: "device_group"},
		{name: "device group renamed", base: devg(nil), desired: devg(func(g *model.DeviceGroup) { g.Name = "Guests" }), wantObjectType: "device_group"},
		{name: "device group added", base: model.Profile{}, desired: devg(nil), wantObjectType: "device_group"},
		{name: "device group removed", base: devg(nil), desired: model.Profile{}, wantObjectType: "device_group"},

		// the DNS plane
		{name: "dns added", base: model.Profile{}, desired: dns(nil), wantObjectType: "dns"},
		{name: "dns removed", base: dns(nil), desired: model.Profile{}, wantObjectType: "dns"},
		{name: "dns management", base: dns(nil), desired: dns(func(d *model.DNSSettings) { d.Enabled = true }), wantObjectType: "dns"},
		{name: "dns leak protection", base: dns(nil), desired: dns(func(d *model.DNSSettings) { d.LeakProof = true }), wantObjectType: "dns"},
		{name: "dns fakeip", base: dns(nil), desired: dns(func(d *model.DNSSettings) { d.FakeIP = true }), wantObjectType: "dns"},
		{name: "dns strategy", base: dns(nil), desired: dns(func(d *model.DNSSettings) { d.Strategy = "ipv4_only" }), wantObjectType: "dns"},
		{name: "dns resolver count", base: dns(nil), desired: dns(func(d *model.DNSSettings) {
			d.Servers = append(d.Servers, model.DNSServer{Tag: "up2", Type: "udp", Server: "192.0.2.54"})
		}), wantObjectType: "dns"},
		{name: "dns resolver content", base: dns(nil), desired: dns(func(d *model.DNSSettings) {
			d.Servers = []model.DNSServer{{Tag: "up", Type: "udp", Server: "192.0.2.55"}}
		}), wantObjectType: "dns"},
		{name: "dns VPN resolver added", base: dns(nil), desired: dns(func(d *model.DNSSettings) {
			d.Servers = append(d.Servers, model.DNSServer{Tag: "vpn", Type: "openvpn", Endpoint: "ovpn", Enabled: true})
		}), wantObjectType: "dns"},
		{name: "dns VPN resolver switches", base: dns(func(d *model.DNSSettings) {
			d.Servers = append(d.Servers, model.DNSServer{Tag: "vpn", Type: "openconnect", Endpoint: "oc", Enabled: true})
		}), desired: dns(func(d *model.DNSSettings) {
			d.Servers = append(d.Servers, model.DNSServer{Tag: "vpn", Type: "openconnect", Endpoint: "oc", Enabled: true,
				AcceptDefaultResolvers: true, AcceptSearchDomain: true})
		}), wantObjectType: "dns"},
		{name: "dns rules", base: dns(nil), desired: dns(func(d *model.DNSSettings) { d.Rules = nil }), wantObjectType: "dns"},
		{name: "dns default resolver", base: dns(nil), desired: dns(func(d *model.DNSSettings) { d.Final = "" }), wantObjectType: "dns"},
		{name: "dns intercept", base: dns(nil), desired: dns(func(d *model.DNSSettings) { d.Intercept = true }), wantObjectType: "dns"},
		{name: "dns reject encrypted", base: dns(nil), desired: dns(func(d *model.DNSSettings) { d.InterceptRejectEncrypted = true }), wantObjectType: "dns"},
		{name: "dns cache", base: dns(nil), desired: dns(func(d *model.DNSSettings) { d.DisableCache = true }), wantObjectType: "dns"},
		{name: "dns independent cache", base: dns(nil), desired: dns(func(d *model.DNSSettings) { d.IndependentCache = true }), wantObjectType: "dns"},
		{name: "dns client subnet", base: dns(nil), desired: dns(func(d *model.DNSSettings) { d.ClientSubnet = "198.51.100.0/24" }), wantObjectType: "dns"},
		{name: "dns reverse mapping", base: dns(nil), desired: dns(func(d *model.DNSSettings) { d.ReverseMapping = true }), wantObjectType: "dns"},

		// settings
		{name: "setting routing mode", baseCfg: config.Config{RoutingMode: "tun"}, desCfg: config.Config{RoutingMode: "hybrid"}},
		{name: "setting offload", baseCfg: config.Config{Offload: "off"}, desCfg: config.Config{Offload: "sw"}},
		{name: "setting rule-set route", baseCfg: config.Config{}, desCfg: config.Config{RuleSetDetour: "a"}},
		{name: "setting core override", baseCfg: config.Config{}, desCfg: config.Config{CoreOverride: `{"log":{"level":"debug"}}`}},
	}
	return cases
}

// QA-088: every row the review shows carries an Undo button, so every row the differ emits must be
// undoable — at the row's own scope, as a group, and by "Discard all". Rules, device groups and the
// DNS plane were diffed but had no undo at all, and a dozen endpoint/group/list fields were diffed
// without a revert case: the panel answered 400 "no pending change for field …", which is false, and
// "Discard all" reported success while those rows stayed pending and shipped on the next Apply.
func TestUndo_EveryReviewRowIsUndoable(t *testing.T) {
	for _, tc := range everyRowCases() {
		t.Run(tc.name, func(t *testing.T) {
			cs := Diff("", "", tc.base, tc.desired, tc.baseCfg, tc.desCfg)
			want := tc.wantRowsAtLeast
			if want == 0 {
				want = 1
			}
			if cs.Count() < want {
				t.Fatalf("setup: want at least %d review row(s), got %+v", want, cs.Changes)
			}
			for _, ch := range cs.Changes {
				if tc.wantObjectType != "" && ch.ObjectType != tc.wantObjectType {
					t.Fatalf("setup: row %q/%q has object type %q, want %q", ch.ID, ch.Field, ch.ObjectType, tc.wantObjectType)
				}
				gotP, gotC, err := Undo(tc.base, tc.desired, tc.baseCfg, tc.desCfg, reqFor(ch))
				if err != nil {
					t.Errorf("row %s %q %q: undo refused: %v", ch.ObjectType, ch.ID, ch.Field, err)
					continue
				}
				after := Diff("", "", tc.base, gotP, tc.baseCfg, gotC)
				if hasRow(after, ch) {
					t.Errorf("row %s %q %q still pending after its own undo: %+v", ch.ObjectType, ch.ID, ch.Field, after.Changes)
				}
				if after.Count() >= cs.Count() {
					t.Errorf("row %s %q %q: undo left %d rows of %d", ch.ObjectType, ch.ID, ch.Field, after.Count(), cs.Count())
				}

				// A panel that predates object_type sends none; with no id shared between kinds the
				// row must still undo.
				legacy := reqFor(ch)
				legacy.ObjectType = ""
				if gotP, gotC, err := Undo(tc.base, tc.desired, tc.baseCfg, tc.desCfg, legacy); err != nil {
					t.Errorf("row %s %q %q without object_type: undo refused: %v", ch.ObjectType, ch.ID, ch.Field, err)
				} else if hasRow(Diff("", "", tc.base, gotP, tc.baseCfg, gotC), ch) {
					t.Errorf("row %s %q %q without object_type: still pending after its own undo", ch.ObjectType, ch.ID, ch.Field)
				}

				// The row's group.
				gotP, gotC, err = Undo(tc.base, tc.desired, tc.baseCfg, tc.desCfg, UndoRequest{Scope: ScopeSubsystem, Subsystem: ch.Subsystem})
				if err != nil {
					t.Errorf("subsystem %q: undo refused: %v", ch.Subsystem, err)
					continue
				}
				if left := Diff("", "", tc.base, gotP, tc.baseCfg, gotC).BySubsystem()[ch.Subsystem]; len(left) != 0 {
					t.Errorf("subsystem %q still has rows after undoing it: %+v", ch.Subsystem, left)
				}
			}

			gotP, gotC, err := Undo(tc.base, tc.desired, tc.baseCfg, tc.desCfg, UndoRequest{Scope: ScopeAll})
			if err != nil {
				t.Fatalf("discard all refused: %v", err)
			}
			if left := Diff("", "", tc.base, gotP, tc.baseCfg, gotC); left.Count() != 0 {
				t.Errorf("discard all reported success but %d row(s) stay pending: %+v", left.Count(), left.Changes)
			}
		})
	}
}

// A field undo inside the DNS plane reverts that ONE setting: the plane's other pending edits stay,
// and the caller's desired state is not written through the shared *DNSSettings pointer (Undo is
// pure — the store's published profile aliases that pointer).
func TestUndoField_DNSKeepsOtherEditsAndDoesNotAlias(t *testing.T) {
	base := model.Profile{DNS: &model.DNSSettings{Enabled: false, Strategy: ""}}
	desired := model.Profile{DNS: &model.DNSSettings{Enabled: true, Strategy: "ipv4_only"}}
	got, _, err := Undo(base, desired, config.Config{}, config.Config{},
		UndoRequest{Scope: ScopeField, ID: "dns", ObjectType: "dns", Field: "DNS management"})
	if err != nil {
		t.Fatal(err)
	}
	if got.DNS == nil || got.DNS.Enabled {
		t.Fatalf("DNS management should revert to Off, got %+v", got.DNS)
	}
	if got.DNS.Strategy != "ipv4_only" {
		t.Errorf("the unrelated Strategy edit must stay pending, got %q", got.DNS.Strategy)
	}
	if !desired.DNS.Enabled {
		t.Error("Undo wrote through the caller's DNS pointer")
	}
}

// A group field undo keeps the group's other edits (the smallest-safe-unit rule).
func TestUndoField_GroupKillSwitchKeepsRename(t *testing.T) {
	base := model.Profile{Groups: []model.Group{{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"a"}}}}
	desired := model.Profile{Groups: []model.Group{{ID: "g", Name: "G2", Type: model.GroupURLTest, Members: []string{"a"}, KillSwitch: true}}}
	got, _, err := Undo(base, desired, config.Config{}, config.Config{},
		UndoRequest{Scope: ScopeField, ID: "g", ObjectType: "group", Field: "Kill switch"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Groups[0].KillSwitch || got.Groups[0].Name != "G2" {
		t.Errorf("want kill switch reverted and rename kept, got %+v", got.Groups[0])
	}
}

// The differ's ids "dns" and "settings" are synthetic and not reserved: a routing list named "DNS"
// gets the slug id "dns". Undoing the DNS plane row must not revert that list (or the reverse), and
// the DNS group must revert only the DNS plane.
func TestUndo_SyntheticDNSIDDoesNotHitASameNamedList(t *testing.T) {
	base := model.Profile{RoutingLists: []model.RoutingList{rl("dns", "DNS", "direct")}}
	desired := model.Profile{
		RoutingLists: []model.RoutingList{rl("dns", "DNS", "block")},
		DNS:          &model.DNSSettings{Enabled: true},
	}
	got, _, err := Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{Scope: ScopeObject, ID: "dns", ObjectType: "dns"})
	if err != nil {
		t.Fatal(err)
	}
	if got.DNS != nil || got.RoutingLists[0].Outbound != "block" {
		t.Errorf("object undo of the DNS plane must revert only the plane, got dns=%+v list=%+v", got.DNS, got.RoutingLists[0])
	}
	got, _, err = Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{Scope: ScopeField, ID: "dns", ObjectType: "routing_list", Field: "Outbound"})
	if err != nil {
		t.Fatal(err)
	}
	if got.DNS == nil || got.RoutingLists[0].Outbound != "direct" {
		t.Errorf("field undo of the list must revert only the list, got dns=%+v list=%+v", got.DNS, got.RoutingLists[0])
	}
	got, _, err = Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{Scope: ScopeSubsystem, Subsystem: SubDNS})
	if err != nil {
		t.Fatal(err)
	}
	if got.DNS != nil || got.RoutingLists[0].Outbound != "block" {
		t.Errorf("undoing the DNS group must revert only the plane, got dns=%+v list=%+v", got.DNS, got.RoutingLists[0])
	}
}

// QA-089: restoring a removed routing list puts it back among the lists that survive in the order
// the baseline had them. At its absolute baseline index it landed after lists that used to follow it
// — [a b c d] minus a and c, undo c, gave [b d c] — so d started winning traffic c used to route, and
// the review grew two "Reordered" rows nobody made.
func TestUndo_RestoredRoutingListKeepsBaselineNeighbours(t *testing.T) {
	lists := func(ids ...string) []model.RoutingList {
		out := make([]model.RoutingList, 0, len(ids))
		for _, id := range ids {
			out = append(out, rl(id, strings.ToUpper(id), "direct"))
		}
		return out
	}
	cases := []struct {
		name          string
		base, desired []string
		req           UndoRequest
		want          string
	}{
		{"two removed, restore the later one", []string{"a", "b", "c", "d"}, []string{"b", "d"},
			UndoRequest{Scope: ScopeObject, ID: "c", ObjectType: "routing_list"}, "b,c,d"},
		// A list added in front shifts every index; counting surviving predecessors would put c before b.
		{"restore behind a list added in front", []string{"a", "b", "c", "d"}, []string{"n", "b", "d"},
			UndoRequest{Scope: ScopeObject, ID: "c", ObjectType: "routing_list"}, "n,b,c,d"},
		{"move undone behind a list added in front", []string{"a", "b", "c"}, []string{"n", "c", "a", "b"},
			UndoRequest{Scope: ScopeField, ID: "c", ObjectType: "routing_list", Field: "Position"}, "n,a,b,c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, desired := model.Profile{RoutingLists: lists(tc.base...)}, model.Profile{RoutingLists: lists(tc.desired...)}
			got, _, err := Undo(base, desired, config.Config{}, config.Config{}, tc.req)
			if err != nil {
				t.Fatal(err)
			}
			if order := strings.Join(routingIDs(got.RoutingLists), ","); order != tc.want {
				t.Errorf("order after undo = %s, want %s", order, tc.want)
			}
			for _, ch := range Diff("", "", base, got, config.Config{}, config.Config{}).Changes {
				if ch.Action == ActionReordered {
					t.Errorf("undo fabricated a move: %s %s -> %s", ch.ID, ch.Before, ch.After)
				}
			}
		})
	}
}

// Undoing a content edit leaves the list where it is when it already sits right among the lists
// both states share. It used to jump to the front over a list the user had just added there, which
// changes which of the two wins for overlapping destinations although no review row said so.
func TestUndoRoutingObject_ContentUndoDoesNotJumpOverAddedList(t *testing.T) {
	base := model.Profile{RoutingLists: []model.RoutingList{rl("a", "A", "direct"), rl("b", "B", "direct")}}
	desired := model.Profile{RoutingLists: []model.RoutingList{rl("n", "N", "direct"), rl("a", "A2", "direct"), rl("b", "B", "direct")}}
	got, _, err := Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{Scope: ScopeObject, ID: "a", ObjectType: "routing_list"})
	if err != nil {
		t.Fatal(err)
	}
	if order := strings.Join(routingIDs(got.RoutingLists), ","); order != "n,a,b" {
		t.Errorf("order after undo = %s, want n,a,b", order)
	}
	if got.RoutingLists[1].Name != "A" {
		t.Errorf("the rename should be undone, got %q", got.RoutingLists[1].Name)
	}
}

// Rules are evaluated in order too, so a restored rule goes back between its baseline neighbours.
func TestUndo_RestoredRuleKeepsBaselineNeighbours(t *testing.T) {
	r := func(id string) model.Rule {
		return model.Rule{ID: id, DomainSuffix: []string{"example.net"}, Outbound: "direct"}
	}
	base := model.Profile{Rules: []model.Rule{r("r1"), r("r2"), r("r3"), r("r4")}}
	desired := model.Profile{Rules: []model.Rule{r("r2"), r("r4")}}
	got, _, err := Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{Scope: ScopeObject, ID: "r3", ObjectType: "rule"})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, x := range got.Rules {
		ids = append(ids, x.ID)
	}
	if strings.Join(ids, ",") != "r2,r3,r4" {
		t.Errorf("rule order after undo = %v, want r2,r3,r4", ids)
	}
}

func listsOf(ids ...string) []model.RoutingList {
	out := make([]model.RoutingList, 0, len(ids))
	for _, id := range ids {
		out = append(out, rl(id, strings.ToUpper(id), "direct"))
	}
	return out
}

// idsWithout is the order of every list but id: what an undo of id alone must leave as it was.
func idsWithout(rs []model.RoutingList, id string) string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		if r.ID != id {
			out = append(out, r.ID)
		}
	}
	return strings.Join(out, ",")
}

// The review's own example of a drag: Undo on a "Position" row it lists must clear that row. The
// slot was picked by the fewest out-of-order lists while the differ reports a row when the count of
// shared lists in front differs, and the two disagreed: [a b c] -> [b c a] listed b "#2 -> #1" and
// its Undo answered 400 "no pending change"; [a b c d e] -> [c d e b a] moved b but kept its row.
func TestUndoRoutingPosition_ClearsTheRowItWasShownFor(t *testing.T) {
	cases := []struct {
		name          string
		base, desired []string
		id, want      string
	}{
		{"a dragged to the bottom, undo b", []string{"a", "b", "c"}, []string{"b", "c", "a"}, "b", "c,b,a"},
		{"two dragged down, undo b", []string{"a", "b", "c", "d", "e"}, []string{"c", "d", "e", "b", "a"}, "b", "c,b,d,e,a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, desired := model.Profile{RoutingLists: listsOf(tc.base...)}, model.Profile{RoutingLists: listsOf(tc.desired...)}
			row := Change{ID: tc.id, ObjectType: "routing_list", Field: "Position", Action: ActionReordered}
			if !hasRow(Diff("", "", base, desired, config.Config{}, config.Config{}), row) {
				t.Fatalf("setup: no Position row for %s", tc.id)
			}
			got, _, err := Undo(base, desired, config.Config{}, config.Config{}, reqFor(row))
			if err != nil {
				t.Fatalf("undo refused for a row the review lists: %v", err)
			}
			if order := strings.Join(routingIDs(got.RoutingLists), ","); order != tc.want {
				t.Errorf("order after undo = %s, want %s", order, tc.want)
			}
			if hasRow(Diff("", "", base, got, config.Config{}, config.Config{}), row) {
				t.Errorf("the Position row of %s is still pending after its own undo", tc.id)
			}
		})
	}
}

// An object undo of a list that was renamed but never moved resets the name and leaves the list
// where it is. It used to take the fewest-out-of-order slot: [a b c] -> [c b' a], undo b, gave
// [b c a] and a new "Position #2 -> #1" row for a move nobody made.
func TestUndoRoutingObject_UnmovedListStaysPut(t *testing.T) {
	base := model.Profile{RoutingLists: listsOf("a", "b", "c")}
	desired := model.Profile{RoutingLists: listsOf("c", "b", "a")}
	desired.RoutingLists[1].Name = "B2"
	if hasRow(Diff("", "", base, desired, config.Config{}, config.Config{}), Change{ID: "b", ObjectType: "routing_list", Field: "Position", Action: ActionReordered}) {
		t.Fatal("setup: b must have no Position row")
	}
	got, _, err := Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{Scope: ScopeObject, ID: "b", ObjectType: "routing_list"})
	if err != nil {
		t.Fatal(err)
	}
	if order := strings.Join(routingIDs(got.RoutingLists), ","); order != "c,b,a" {
		t.Errorf("order after undo = %s, want c,b,a", order)
	}
	for _, ch := range Diff("", "", base, got, config.Config{}, config.Config{}).Changes {
		if ch.ID == "b" {
			t.Errorf("b still has a row after its object undo: %s %s -> %s", ch.Field, ch.Before, ch.After)
		}
	}
}

// fuzzLists is a random baseline of 2..7 routing lists and a desired state the way the panel makes
// one: one list dragged or the whole order shuffled, some lists removed, new ones added anywhere,
// some renamed in place.
func fuzzLists(r *rand.Rand) (base, desired model.Profile) {
	n := 2 + r.Intn(6)
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("l%d", i)
	}
	base.RoutingLists = listsOf(ids...)
	order := r.Perm(n)
	if r.Intn(2) == 0 { // a single drag
		order = make([]int, 0, n)
		for i := 0; i < n; i++ {
			order = append(order, i)
		}
		from, to := r.Intn(n), r.Intn(n)
		moved := order[from]
		order = insertAt(append(order[:from], order[from+1:]...), moved, to)
	}
	for _, i := range order {
		if r.Intn(8) == 0 {
			continue // removed
		}
		l := base.RoutingLists[i]
		if r.Intn(5) == 0 {
			l.Name += "-renamed"
		}
		desired.RoutingLists = append(desired.RoutingLists, l)
	}
	for j, add := 0, r.Intn(3); j < add; j++ {
		at := r.Intn(len(desired.RoutingLists) + 1)
		desired.RoutingLists = insertAt(desired.RoutingLists, rl(fmt.Sprintf("n%d", j), "N", "direct"), at)
	}
	return base, desired
}

// QA-088 review: over random reorders, every routing-list row the review lists undoes at its own
// scope, its row clears, and nothing but that list moves. The slot used to come from the fewest
// out-of-order lists while the differ reports a move by the count of shared lists in front; over
// 20k reorders 2304 Position undos were refused (the base code: 1449), and clicking the first row
// again and again got stuck 1487 times (the base code: never). The seed is fixed, so a failure
// replays.
func TestUndoRouting_FuzzEveryRowUndoesAndClears(t *testing.T) {
	r := rand.New(rand.NewSource(157))
	failures := 0
	fail := func(format string, args ...any) {
		failures++
		if failures <= 8 {
			t.Errorf(format, args...)
		}
	}
	none := config.Config{}
	for iter := 0; iter < 4000; iter++ {
		base, desired := fuzzLists(r)
		state := strings.Join(routingIDs(base.RoutingLists), ",") + " -> " + strings.Join(routingIDs(desired.RoutingLists), ",")
		cs := Diff("", "", base, desired, none, none)
		moved, objects := map[string]bool{}, []string{}
		for _, ch := range cs.Changes {
			if ch.Field == "Position" {
				moved[ch.ID] = true
			}
			if len(objects) == 0 || objects[len(objects)-1] != ch.ID {
				objects = append(objects, ch.ID)
			}
		}
		desiredAt := func(id string) int { return indexOfRouting(desired.RoutingLists, id) }

		for _, ch := range cs.Changes {
			if ch.Field != "Position" {
				continue
			}
			got, _, err := Undo(base, desired, none, none, reqFor(ch))
			if err != nil {
				fail("%s: Position undo of %s refused: %v", state, ch.ID, err)
				continue
			}
			if hasRow(Diff("", "", base, got, none, none), ch) {
				fail("%s: Position row of %s %s -> %s still pending after its undo", state, ch.ID, ch.Before, ch.After)
			}
			if idsWithout(got.RoutingLists, ch.ID) != idsWithout(desired.RoutingLists, ch.ID) {
				fail("%s: Position undo of %s moved other lists: %v", state, ch.ID, routingIDs(got.RoutingLists))
			}
			if gi := indexOfRouting(got.RoutingLists, ch.ID); gi < 0 || !reflect.DeepEqual(got.RoutingLists[gi], desired.RoutingLists[desiredAt(ch.ID)]) {
				fail("%s: Position undo of %s changed its content", state, ch.ID)
			}
		}

		for _, id := range objects {
			got, _, err := Undo(base, desired, none, none, UndoRequest{Scope: ScopeObject, ID: id, ObjectType: "routing_list"})
			if err != nil {
				fail("%s: object undo of %s refused: %v", state, id, err)
				continue
			}
			for _, ch := range Diff("", "", base, got, none, none).Changes {
				if ch.ID == id {
					fail("%s: object undo of %s left its row %q %s -> %s", state, id, ch.Field, ch.Before, ch.After)
				}
			}
			if idsWithout(got.RoutingLists, id) != idsWithout(desired.RoutingLists, id) {
				fail("%s: object undo of %s moved other lists: %v", state, id, routingIDs(got.RoutingLists))
			}
			if di := desiredAt(id); di >= 0 && indexOfRouting(base.RoutingLists, id) >= 0 && !moved[id] && indexOfRouting(got.RoutingLists, id) != di {
				fail("%s: object undo of %s moved a list nobody moved: %v", state, id, routingIDs(got.RoutingLists))
			}
		}

		// The group and "Discard all" leave nothing pending.
		if len(cs.Changes) > 0 {
			for _, req := range []UndoRequest{{Scope: ScopeSubsystem, Subsystem: SubRouting}, {Scope: ScopeAll}} {
				got, _, err := Undo(base, desired, none, none, req)
				if err != nil {
					fail("%s: %s undo refused: %v", state, req.Scope, err)
				} else if left := Diff("", "", base, got, none, none); left.Count() != 0 {
					fail("%s: %s undo left %d rows, order %v", state, req.Scope, left.Count(), routingIDs(got.RoutingLists))
				}
			}
		}

		// "Keep clicking the first row": each click clears the row it was made on, and the rows run out.
		// Not fast: a click can shift lists that had no row into one, and checked over every order of
		// up to 8 lists the worst case took 2^(n-1)-1 clicks (the base code's rule does the same), so
		// the bound is 2^n.
		cur, n := desired, len(base.RoutingLists)
		for step := 0; ; step++ {
			var first *Change
			for _, ch := range Diff("", "", base, cur, none, none).Changes {
				if ch.Field == "Position" {
					first = &ch
					break
				}
			}
			if first == nil {
				break
			}
			if step > 1<<n {
				fail("%s: clicking the first Position row never runs out of rows", state)
				break
			}
			got, _, err := Undo(base, cur, none, none, reqFor(*first))
			if err != nil {
				fail("%s: clicking the first row stuck at %v: %v", state, routingIDs(cur.RoutingLists), err)
				break
			}
			if hasRow(Diff("", "", base, got, none, none), *first) {
				fail("%s: clicking the first row stuck at %v: %s stays", state, routingIDs(cur.RoutingLists), first.ID)
				break
			}
			cur = got
		}
	}
	if failures > 0 {
		t.Errorf("%d failures in total", failures)
	}
}

// QA-090 review: restoring a modified list by object, group or "Discard all" keeps the feed
// timestamps the list has now. They say when a fetch last ran, which did happen; the baseline's can
// be zero (or older), and a zero stamp marks the feed as never loaded, so the refresher re-fetched it
// at once and re-staged the very feed the operator had just declined.
func TestUndoRoutingObject_KeepsTheCurrentRefreshClock(t *testing.T) {
	list := func(name string, cache []string, cidrAt, domainAt int64) model.RoutingList {
		return model.RoutingList{ID: "r", Name: name, Outbound: "direct", Enabled: true,
			CIDRSource: "https://example.net/v4.txt", CIDRCache: cache, CIDRRefreshed: cidrAt,
			DomainSource: "https://example.net/names.txt", DomainCache: []string{"example.net"}, DomainRefreshed: domainAt}
	}
	base := model.Profile{RoutingLists: []model.RoutingList{list("R", []string{"10.0.0.0/8"}, 0, 0)}}
	desired := model.Profile{RoutingLists: []model.RoutingList{list("R2", []string{"10.0.0.0/8", "198.51.100.0/24"}, 1700000000, 1700000100)}}
	for _, req := range []UndoRequest{
		{Scope: ScopeObject, ID: "r", ObjectType: "routing_list"},
		{Scope: ScopeSubsystem, Subsystem: SubRouting},
		{Scope: ScopeAll},
	} {
		got, _, err := Undo(base, desired, config.Config{}, config.Config{}, req)
		if err != nil {
			t.Fatalf("%s: %v", req.Scope, err)
		}
		g := got.RoutingLists[0]
		if g.Name != "R" || len(g.CIDRCache) != 1 {
			t.Errorf("%s: the list should be back to its baseline, got %+v", req.Scope, g)
		}
		if g.CIDRRefreshed != 1700000000 || g.DomainRefreshed != 1700000100 {
			t.Errorf("%s: refresh clock rewound to cidr=%d domain=%d, want the current 1700000000/1700000100",
				req.Scope, g.CIDRRefreshed, g.DomainRefreshed)
		}
	}

	// A feed whose source was changed and has not loaded since has no clock of its own (the store
	// zeroes it on a source change). The restored source gets back the baseline's, not that zero.
	desired.RoutingLists[0].CIDRSource, desired.RoutingLists[0].CIDRCache, desired.RoutingLists[0].CIDRRefreshed = "https://example.net/other.txt", nil, 0
	base.RoutingLists[0].CIDRRefreshed = 1600000000
	got, _, err := Undo(base, desired, config.Config{}, config.Config{}, UndoRequest{Scope: ScopeObject, ID: "r", ObjectType: "routing_list"})
	if err != nil {
		t.Fatal(err)
	}
	if g := got.RoutingLists[0]; g.CIDRSource != "https://example.net/v4.txt" || g.CIDRRefreshed != 1600000000 {
		t.Errorf("want the baseline source with its own clock 1600000000, got source=%q clock=%d", g.CIDRSource, g.CIDRRefreshed)
	}
}
