package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/store"
)

// rev_req runs handler h on a request with the given method, body, If-Match ("" for none) and path id.
func rev_req(h http.HandlerFunc, method, ifMatch, id, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/x", strings.NewReader(body))
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	if id != "" {
		req.SetPathValue("id", id)
	}
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

func rev_json(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// rev_loaded is what the panel holds after loading the profile: GET /api/profile?lite=1, with each
// object's revision in revs.
func rev_loaded(t *testing.T, s *Server) (model.Profile, profileRevs) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/profile?lite=1", nil)
	w := httptest.NewRecorder()
	s.handleGetProfile(w, req)
	var body struct {
		Revs profileRevs `json:"revs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Revs.Endpoints == nil {
		t.Fatalf("lite profile carries no revs (%v): %s", err, w.Body.String())
	}
	return s.store.Profile(), body.Revs
}

func rev_isStale(t *testing.T, w *httptest.ResponseRecorder, what string) {
	t.Helper()
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("%s: status %d, want 412: %s", what, w.Code, w.Body.String())
	}
	var body struct{ Code, Error string }
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Code != revStaleCode || !strings.Contains(body.Error, "Nothing was saved") {
		t.Errorf("%s: body %s does not say the write was refused as stale", what, w.Body.String())
	}
}

func rev_ok(t *testing.T, w *httptest.ResponseRecorder, what string) map[string]any {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %s", what, w.Code, w.Body.String())
	}
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return m
}

// QA-152, connections: a page that loaded a connection, then had another tab save over that same
// connection, is refused when it saves its copy - the other tab's server stays. Without If-Match a
// save is unconditional, as it was for every API caller; a garbled one is refused, not ignored. A save
// answers the connection's revisions before and after it.
func TestRevision_EndpointSaveFromAStaleCopyIsRefused(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("a", "A")); err != nil {
		t.Fatal(err)
	}
	p, revs := rev_loaded(t, s) // tab A
	revA := revs.Endpoints["a"]

	tabB := *p.EndpointByID("a")
	tabB.Server = "203.0.113.77"
	out := rev_ok(t, rev_req(s.handleUpsertEndpoint, http.MethodPost, revA, "", rev_json(t, tabB)), "tab B's save at the current revision")
	cur := s.store.Profile()
	if out["was"] != revA || out["rev"] != model.EndpointRev(*cur.EndpointByID("a")) || out["server"] != "203.0.113.77" {
		t.Errorf("a save answers %v, want the connection with was %s and its new revision", out, revA)
	}

	tabA := *p.EndpointByID("a")
	tabA.Name = "renamed in tab A"
	rev_isStale(t, rev_req(s.handleUpsertEndpoint, http.MethodPost, revA, "", rev_json(t, tabA)), "tab A's stale save")
	rev_isStale(t, rev_req(s.handleUpsertEndpoint, http.MethodPost, "not-a-revision", "", rev_json(t, tabA)), "a garbled If-Match")
	if cur := s.store.Profile(); cur.EndpointByID("a").Server != "203.0.113.77" || cur.EndpointByID("a").Name != "A" {
		t.Fatalf("a refused save changed the connection: %+v", *cur.EndpointByID("a"))
	}
	rev_ok(t, rev_req(s.handleUpsertEndpoint, http.MethodPost, "", "", rev_json(t, tabA)), "a save without If-Match (API callers)")
}

// The regression a profile-wide revision caused (hunter, after the first fix): every write anywhere
// made every open form stale, and the 412 closed the form and threw its input away. Measured in the
// panel's own flow: a routing list form that creates a device group from inside itself, then saves.
// A write to another connection, a new connection, a reorder, a deletion of something else, a new
// device group and the feed refresh rewriting the list's own caches all leave each form's save valid.
func TestRevision_WritesElsewhereDoNotStaleAnOpenForm(t *testing.T) {
	s, _ := sharehandlers_server(t)
	for _, id := range []string{"a", "b", "x"} {
		e := profilehandlers_endpoint(id, strings.ToUpper(id))
		e.Params = map[string]any{"uuid": "u-" + id}
		if err := s.store.UpsertEndpoint(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.store.UpsertGroup(model.Group{ID: "g", Name: "G", Type: model.GroupFallback, Members: []string{"a", "b"}}); err != nil {
		t.Fatal(err)
	}
	for _, rl := range []model.RoutingList{
		{ID: "l", Name: "L", CIDRSource: "https://example.com/cidrs.txt", Manual: []string{"example.org"}, Outbound: "a", Enabled: true},
		{ID: "m", Name: "M", Manual: []string{"example.net"}, Outbound: "b", Enabled: true},
	} {
		if err := s.store.UpsertRoutingList(rl); err != nil {
			t.Fatal(err)
		}
	}
	p, revs := rev_loaded(t, s) // the forms open here

	other := *p.EndpointByID("b")
	other.Server = "203.0.113.9"
	rev_ok(t, rev_req(s.handleUpsertEndpoint, http.MethodPost, revs.Endpoints["b"], "", rev_json(t, other)), "another connection's save")
	rev_ok(t, rev_req(s.handleUpsertEndpoint, http.MethodPost, "", "", rev_json(t, profilehandlers_endpoint("c", "C"))), "a new connection")
	rev_ok(t, rev_req(s.handlePatchEndpoint, http.MethodPatch, "", "x", `{"enabled":false}`), "another connection's switch")
	if err := s.store.UpsertDeviceGroup(model.DeviceGroup{ID: "kids", Name: "Kids", Members: []model.DeviceMember{{IP: "192.168.1.20"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.ReorderRoutingLists([]string{"m", "l"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.SetRoutingListCaches(map[string]store.CacheUpdate{"l": {Source: "https://example.com/cidrs.txt", CIDRs: []string{"198.51.100.0/24"}}}); err != nil {
		t.Fatal(err)
	}

	e := *p.EndpointByID("a")
	e.Name = "edited"
	rev_ok(t, rev_req(s.handleUpsertEndpoint, http.MethodPost, revs.Endpoints["a"], "", rev_json(t, e)), "the open connection form")
	g := *p.GroupByID("g")
	g.Name = "edited"
	rev_ok(t, rev_req(s.handleUpsertGroup, http.MethodPost, revs.Groups["g"], "", rev_json(t, g)), "the open group form")
	rl := p.RoutingLists[0]
	rl.CIDRCache = nil // the panel's lite copy has no cache
	rl.ScopeMode, rl.ScopeGroups = "only", []string{"kids"}
	rev_ok(t, rev_req(s.handleUpsertRoutingList, http.MethodPost, revs.RoutingLists["l"], "", rev_json(t, rl)), "the open routing list form")
	if got := s.store.Profile().RoutingLists; got[1].ID != "l" || len(got[1].CIDRCache) != 1 || got[1].ScopeMode != "only" {
		t.Errorf("the list save lost its refreshed cache, its order or the edit: %+v", got)
	}
}

// QA-152, the switch: PATCH changes enabled and nothing else, so a switch flipped in a page that never
// saw another tab's edit keeps that edit. It answers the connection's revisions, and refuses any field
// but enabled.
func TestRevision_EndpointSwitchChangesOnlyEnabled(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("a", "A")); err != nil {
		t.Fatal(err)
	}
	tabB := profilehandlers_endpoint("a", "renamed in tab B")
	tabB.Server, tabB.Port = "203.0.113.77", 8443
	if err := s.store.UpsertEndpoint(tabB); err != nil {
		t.Fatal(err)
	}
	before := model.EndpointRev(tabB)

	out := rev_ok(t, rev_req(s.handlePatchEndpoint, http.MethodPatch, "", "a", `{"enabled":false}`), "PATCH")
	p := s.store.Profile()
	got := *p.EndpointByID("a")
	if out["was"] != before || out["rev"] != model.EndpointRev(got) || out["enabled"] != false {
		t.Errorf("PATCH answered %v, want enabled false, was %s and the new revision", out, before)
	}
	if got.Enabled || got.Name != "renamed in tab B" || got.Server != "203.0.113.77" || got.Port != 8443 {
		t.Fatalf("the switch changed more than enabled: %+v", got)
	}
	for _, body := range []string{`{"name":"x"}`, `{"enabled":true,"server":"192.0.2.1"}`, `not json`} {
		if w := rev_req(s.handlePatchEndpoint, http.MethodPatch, "", "a", body); w.Code != http.StatusBadRequest {
			t.Errorf("PATCH %s: %d, want 400", body, w.Code)
		}
	}
	if p := s.store.Profile(); p.EndpointByID("a").Server != "203.0.113.77" || p.EndpointByID("a").Enabled {
		t.Error("a refused PATCH changed the connection")
	}
	if w := rev_req(s.handlePatchEndpoint, http.MethodPatch, "", "nope", `{"enabled":true}`); w.Code != http.StatusNotFound {
		t.Errorf("a PATCH of a missing connection: %d, want 404", w.Code)
	}
}

// The switch goes through the same checks as a full save: switching off an exit a group still holds
// is answered with the dependents, and ?detach=1 is how to go ahead.
func TestRevision_EndpointSwitchKeepsTheDisableChecks(t *testing.T) {
	s, _ := sharehandlers_server(t)
	for _, e := range []model.Endpoint{profilehandlers_endpoint("a", "A"), profilehandlers_endpoint("b", "B")} {
		e.Params = map[string]any{"uuid": "u-" + e.ID}
		if err := s.store.UpsertEndpoint(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.store.UpsertGroup(model.Group{ID: "g", Name: "G", Type: model.GroupFallback, Members: []string{"a", "b"}}); err != nil {
		t.Fatal(err)
	}
	w := rev_req(s.handlePatchEndpoint, http.MethodPatch, "", "a", `{"enabled":false}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "ENDPOINT_IN_USE") {
		t.Fatalf("switching off a group member: %d %s, want 409 ENDPOINT_IN_USE", w.Code, w.Body.String())
	}
	req := httptest.NewRequest(http.MethodPatch, "/api/endpoints/a?detach=1", strings.NewReader(`{"enabled":false}`))
	req.SetPathValue("id", "a")
	rec := httptest.NewRecorder()
	s.handlePatchEndpoint(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH ?detach=1: %d %s", rec.Code, rec.Body.String())
	}
	if p := s.store.Profile(); p.EndpointByID("a").Enabled || len(p.GroupByID("g").Members) != 1 {
		t.Errorf("detach did not switch it off and take it out of the group: %+v", p.Groups)
	}
}

// Groups and routing lists hold the same line, and a routing list's switch keeps what another tab
// saved into the list.
func TestRevision_GroupAndRoutingListSaves(t *testing.T) {
	s, _ := sharehandlers_server(t)
	for _, e := range []model.Endpoint{profilehandlers_endpoint("a", "A"), profilehandlers_endpoint("b", "B")} {
		e.Params = map[string]any{"uuid": "u-" + e.ID}
		if err := s.store.UpsertEndpoint(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.store.UpsertGroup(model.Group{ID: "g", Name: "G", Type: model.GroupFallback, Members: []string{"a", "b", "direct"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "l", Name: "L", Source: "https://example.com/l.srs", Manual: []string{"example.org"}, Outbound: "a", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	p, revs := rev_loaded(t, s)
	if err := s.store.UpsertGroup(model.Group{ID: "g", Name: "G", Type: model.GroupFallback, Members: []string{"a", "direct"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "l", Name: "L", Source: "https://example.com/l.srs", Manual: []string{"example.org", "example.net"}, Outbound: "b", Enabled: true}); err != nil {
		t.Fatal(err)
	}

	g := *p.GroupByID("g")
	g.Name = "renamed"
	rev_isStale(t, rev_req(s.handleUpsertGroup, http.MethodPost, revs.Groups["g"], "", rev_json(t, g)), "a stale group save")
	rl := p.RoutingLists[0]
	rl.Name = "renamed"
	rev_isStale(t, rev_req(s.handleUpsertRoutingList, http.MethodPost, revs.RoutingLists["l"], "", rev_json(t, rl)), "a stale routing list save")
	if cur := s.store.Profile(); len(cur.GroupByID("g").Members) != 2 || cur.RoutingLists[0].Name != "L" {
		t.Fatalf("a refused save changed something: %+v %+v", cur.Groups, cur.RoutingLists)
	}

	out := rev_ok(t, rev_req(s.handlePatchRoutingList, http.MethodPatch, "", "l", `{"enabled":false}`), "routing list PATCH")
	got := s.store.Profile().RoutingLists[0]
	if got.Enabled || got.Outbound != "b" || len(got.Manual) != 2 || got.Source == "" || out["rev"] != model.RoutingListRev(got) {
		t.Fatalf("the list's switch changed more than enabled, or answered %v: %+v", out, got)
	}
	if w := rev_req(s.handlePatchRoutingList, http.MethodPatch, "", "l", `{"enabled":true,"name":"x"}`); w.Code != http.StatusBadRequest {
		t.Errorf("a routing list PATCH with another field: %d, want 400", w.Code)
	}
}

// QA-152, settings: GET /api/config carries the revision of what a save writes; a save from a page
// loaded before another save is refused and changes nothing; a save answers the revision it made, so
// the same page can save again; and a save without If-Match still works.
func TestRevision_ConfigSaveFromAStaleCopyIsRefused(t *testing.T) {
	s, _ := sharehandlers_server(t)
	get := func() map[string]any {
		w := rev_req(s.handleGetConfig, http.MethodGet, "", "", "")
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	settings, components := get(), get() // the Settings page and Components, open together
	rev, _ := settings["rev"].(string)
	if rev == "" {
		t.Fatalf("GET /api/config carries no rev")
	}

	// Components saves updater.download_via.
	updater, _ := components["updater"].(map[string]any)
	updater["download_via"] = "a"
	w := rev_req(s.handlePutConfig, http.MethodPut, rev, "", rev_json(t, components))
	if w.Code != http.StatusOK {
		t.Fatalf("Components' save: %d %s", w.Code, w.Body.String())
	}
	var saved struct {
		Rev string `json:"rev"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &saved)
	if saved.Rev == "" || saved.Rev == rev {
		t.Fatalf("a save answers rev %q, want the new revision", saved.Rev)
	}

	// Settings, loaded before it, saves its copy: refused, and download_via stays.
	settings["clash"].(map[string]any)["secret"] = "changed-in-settings"
	rev_isStale(t, rev_req(s.handlePutConfig, http.MethodPut, rev, "", rev_json(t, settings)), "a stale Settings save")
	if c := s.config(); c.Updater.DownloadVia != "a" || c.Clash.Secret == "changed-in-settings" {
		t.Fatalf("a refused save changed the config: download_via %q secret %q", c.Updater.DownloadVia, c.Clash.Secret)
	}

	// The page that saved can save again with the revision it was answered.
	updater["download_via"] = ""
	if w := rev_req(s.handlePutConfig, http.MethodPut, saved.Rev, "", rev_json(t, components)); w.Code != http.StatusOK {
		t.Fatalf("a second save with the answered revision: %d %s", w.Code, w.Body.String())
	}
	if w := rev_req(s.handlePutConfig, http.MethodPut, "", "", rev_json(t, settings)); w.Code != http.StatusOK {
		t.Fatalf("a save without If-Match must keep working: %d %s", w.Code, w.Body.String())
	}
}

// What a Settings save cannot write does not make its page stale.
func TestRevision_ConfigRevCoversOnlyWhatASaveWrites(t *testing.T) {
	s, _ := sharehandlers_server(t)
	c := s.config()
	before := configRev(&c)
	c.Subscription.HWID = "another-hwid"
	c.IgnoredDrift = append(c.IgnoredDrift, "x")
	if configRev(&c) != before {
		t.Error("a field the Settings save leaves alone moved the revision")
	}
	c.Updater.DownloadVia = "a"
	if configRev(&c) == before {
		t.Error("a field the Settings save writes did not move the revision")
	}
}

// QA-150 through the API: a list moved to a plain-text .lst URL with the preset's format echoed back
// is stored, and answered, without it (the generator then skips a list sing-box cannot read).
func TestRevision_RoutingListSaveAnswersTheListAsStored(t *testing.T) {
	s, _ := sharehandlers_server(t)
	preset := model.RoutingList{ID: "ru", Name: "RU", Source: "https://example.com/ru-bundle.srs", Format: "binary", Outbound: "direct", Enabled: true}
	rev_ok(t, rev_req(s.handleUpsertRoutingList, http.MethodPost, "", "", rev_json(t, preset)), "the preset")
	moved := preset
	moved.Source = "https://example.com/ru.lst"
	out := rev_ok(t, rev_req(s.handleUpsertRoutingList, http.MethodPost, "", "", rev_json(t, moved)), "the move")
	if _, ok := out["format"]; ok || s.store.Profile().RoutingLists[0].Format != "" {
		t.Errorf("the carried format survived the move: answer %v, stored %q", out, s.store.Profile().RoutingLists[0].Format)
	}
	if out["rev"] != model.RoutingListRev(s.store.Profile().RoutingLists[0]) {
		t.Errorf("the answer's rev %v is not the stored list's", out["rev"])
	}
}
