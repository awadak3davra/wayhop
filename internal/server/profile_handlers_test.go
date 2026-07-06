package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// profilehandlers_vlessLink is a realistic VLESS-Reality share link that
// importer.Parse accepts (matches the format used in importer_test.go).
const profilehandlers_vlessLink = "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443" +
	"?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision#Reality"

// profilehandlers_endpoint builds a minimal valid sing-box VLESS endpoint that
// the store accepts (non-empty id) and the generator can emit as an outbound.
func profilehandlers_endpoint(id, name string) model.Endpoint {
	return model.Endpoint{
		ID: id, Name: name, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "203.0.113.10", Port: 443,
		Params:  map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"},
		Enabled: true,
	}
}

// profilehandlers_post issues a POST with the given JSON body to handler h.
func profilehandlers_post(h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/x", strings.NewReader(body))
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

// profilehandlers_delete issues a DELETE with the path value "id" set.
func profilehandlers_delete(h http.HandlerFunc, id string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/api/x/"+id, nil)
	req.SetPathValue("id", id)
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

// --- handleImport ----------------------------------------------------------

func TestProfilehandlers_ImportBadJSON(t *testing.T) {
	s, _ := sharehandlers_server(t)
	w := profilehandlers_post(s.handleImport, `not json`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad json: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

func TestProfilehandlers_ImportUnsupportedLink400(t *testing.T) {
	s, _ := sharehandlers_server(t)
	w := profilehandlers_post(s.handleImport, `{"link":"ftp://nope"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unsupported link: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

func TestProfilehandlers_ImportVLESSLink200(t *testing.T) {
	s, _ := sharehandlers_server(t)
	body, _ := json.Marshal(map[string]string{"link": profilehandlers_vlessLink})
	w := profilehandlers_post(s.handleImport, string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("import vless: got %d, want 200 (%s)", w.Code, w.Body.String())
	}

	var e model.Endpoint
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode endpoint: %v (%s)", err, w.Body.String())
	}
	if e.Protocol != model.ProtoVLESS || e.Engine != model.EngineSingBox {
		t.Errorf("proto/engine = %s/%s, want vless/singbox", e.Protocol, e.Engine)
	}
	if e.Server != "203.0.113.10" || e.Port != 443 {
		t.Errorf("server:port = %s:%d, want 203.0.113.10:443", e.Server, e.Port)
	}
	if e.Name != "Reality" {
		t.Errorf("name = %q, want %q", e.Name, "Reality")
	}
	if e.Params["uuid"] != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("uuid = %v", e.Params["uuid"])
	}
	if e.TLS == nil || e.TLS.Type != "reality" || e.TLS.PublicKey != "PUBKEY" {
		t.Errorf("tls = %+v", e.TLS)
	}
	// Preview only: import must NOT persist the endpoint.
	if len(s.store.Profile().Endpoints) != 0 {
		t.Errorf("import unexpectedly saved endpoint(s): %+v", s.store.Profile().Endpoints)
	}
}

// --- handleUpsertEndpoint / handleDeleteEndpoint ---------------------------

func TestProfilehandlers_UpsertEndpointBadJSON(t *testing.T) {
	s, _ := sharehandlers_server(t)
	w := profilehandlers_post(s.handleUpsertEndpoint, `{`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad endpoint json: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

func TestProfilehandlers_UpsertEndpointEmptyID400(t *testing.T) {
	s, _ := sharehandlers_server(t)
	// store.UpsertEndpoint rejects an empty id -> handler maps it to 400.
	w := profilehandlers_post(s.handleUpsertEndpoint, `{"id":"","name":"x"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty id: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

func TestProfilehandlers_UpsertEndpointRoundTrip(t *testing.T) {
	s, _ := sharehandlers_server(t)
	body, _ := json.Marshal(profilehandlers_endpoint("v1", "Reality"))

	w := profilehandlers_post(s.handleUpsertEndpoint, string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("upsert: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	// Echoed endpoint.
	var echoed model.Endpoint
	if err := json.Unmarshal(w.Body.Bytes(), &echoed); err != nil {
		t.Fatalf("decode echoed: %v", err)
	}
	if echoed.ID != "v1" {
		t.Errorf("echoed id = %q, want v1", echoed.ID)
	}
	// Persisted in the store.
	prof := s.store.Profile()
	if got := prof.EndpointByID("v1"); got == nil || got.Name != "Reality" {
		t.Fatalf("endpoint not persisted: %+v", prof.Endpoints)
	}

	// Upsert again with the same id replaces (does not duplicate).
	upd := profilehandlers_endpoint("v1", "Renamed")
	body2, _ := json.Marshal(upd)
	if w2 := profilehandlers_post(s.handleUpsertEndpoint, string(body2)); w2.Code != http.StatusOK {
		t.Fatalf("re-upsert: got %d, want 200", w2.Code)
	}
	eps := s.store.Profile().Endpoints
	if len(eps) != 1 || eps[0].Name != "Renamed" {
		t.Fatalf("re-upsert did not replace: %+v", eps)
	}

	// Delete it.
	if w3 := profilehandlers_delete(s.handleDeleteEndpoint, "v1"); w3.Code != http.StatusOK {
		t.Fatalf("delete: got %d, want 200 (%s)", w3.Code, w3.Body.String())
	}
	if len(s.store.Profile().Endpoints) != 0 {
		t.Errorf("endpoint not deleted: %+v", s.store.Profile().Endpoints)
	}
}

func TestProfilehandlers_DeleteEndpointUnknown409(t *testing.T) {
	s, _ := sharehandlers_server(t)
	// store.DeleteEndpoint returns "not found" -> handler maps any error to 409.
	w := profilehandlers_delete(s.handleDeleteEndpoint, "ghost")
	if w.Code != http.StatusConflict {
		t.Fatalf("delete unknown: got %d, want 409 (%s)", w.Code, w.Body.String())
	}
}

func TestProfilehandlers_DeleteEndpointUsedByRuleConflict(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "NL")); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	if err := s.store.UpsertRule(model.Rule{ID: "r1", Outbound: "v1", Default: true}); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	// Deleting an endpoint still referenced by a rule is refused with 409.
	w := profilehandlers_delete(s.handleDeleteEndpoint, "v1")
	if w.Code != http.StatusConflict {
		t.Fatalf("delete referenced endpoint: got %d, want 409 (%s)", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if !strings.Contains(resp["error"], "r1") {
		t.Errorf("conflict error should name the rule, got %q", resp["error"])
	}
	// The endpoint must still be present after the refused delete.
	prof := s.store.Profile()
	if prof.EndpointByID("v1") == nil {
		t.Errorf("endpoint was removed despite the conflict")
	}
}

func TestProfilehandlers_DeleteEndpointPrunesGroupMember(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "NL")); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v2", "NL2")); err != nil {
		t.Fatalf("seed endpoint 2: %v", err)
	}
	// A group containing the endpoint alongside others does NOT block deletion; the
	// store prunes the member instead (rules block, and so does being a group's sole
	// member — which is why g1 also has v2).
	if err := s.store.UpsertGroup(model.Group{ID: "g1", Name: "Auto", Type: model.GroupURLTest, Members: []string{"v1", "v2"}}); err != nil {
		t.Fatalf("seed group: %v", err)
	}

	w := profilehandlers_delete(s.handleDeleteEndpoint, "v1")
	if w.Code != http.StatusOK {
		t.Fatalf("delete group-member endpoint: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	prof := s.store.Profile()
	g := prof.GroupByID("g1")
	if g == nil {
		t.Fatalf("group disappeared")
	}
	for _, m := range g.Members {
		if m == "v1" {
			t.Errorf("deleted endpoint was not pruned from group members: %+v", g.Members)
		}
	}
}

// --- handleUpsertGroup / handleDeleteGroup ---------------------------------

func TestProfilehandlers_UpsertGroupBadJSON(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if w := profilehandlers_post(s.handleUpsertGroup, `nope`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad group json: got %d, want 400", w.Code)
	}
}

func TestProfilehandlers_UpsertGroupEmptyID400(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if w := profilehandlers_post(s.handleUpsertGroup, `{"id":"","name":"x"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("empty group id: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

func TestProfilehandlers_GroupRoundTrip(t *testing.T) {
	s, _ := sharehandlers_server(t)
	g := model.Group{ID: "g1", Name: "Auto", Type: model.GroupURLTest, Members: []string{"v1"}}
	body, _ := json.Marshal(g)

	if w := profilehandlers_post(s.handleUpsertGroup, string(body)); w.Code != http.StatusOK {
		t.Fatalf("upsert group: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if prof := s.store.Profile(); prof.GroupByID("g1") == nil {
		t.Fatalf("group not persisted")
	}
	if w := profilehandlers_delete(s.handleDeleteGroup, "g1"); w.Code != http.StatusOK {
		t.Fatalf("delete group: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if len(s.store.Profile().Groups) != 0 {
		t.Errorf("group not deleted: %+v", s.store.Profile().Groups)
	}
}

func TestProfilehandlers_DeleteGroupUnknown409(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if w := profilehandlers_delete(s.handleDeleteGroup, "ghost"); w.Code != http.StatusConflict {
		t.Fatalf("delete unknown group: got %d, want 409 (%s)", w.Code, w.Body.String())
	}
}

func TestProfilehandlers_DeleteGroupUsedByRuleConflict(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertGroup(model.Group{ID: "g1", Name: "Auto", Type: model.GroupSelector, Members: []string{"v1"}}); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if err := s.store.UpsertRule(model.Rule{ID: "r1", Outbound: "g1", Default: true}); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	w := profilehandlers_delete(s.handleDeleteGroup, "g1")
	if w.Code != http.StatusConflict {
		t.Fatalf("delete referenced group: got %d, want 409 (%s)", w.Code, w.Body.String())
	}
	if prof := s.store.Profile(); prof.GroupByID("g1") == nil {
		t.Errorf("group was removed despite the conflict")
	}
}

// --- handleUpsertRule / handleDeleteRule -----------------------------------

func TestProfilehandlers_UpsertRuleBadJSON(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if w := profilehandlers_post(s.handleUpsertRule, `[`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad rule json: got %d, want 400", w.Code)
	}
}

func TestProfilehandlers_UpsertRuleEmptyID400(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if w := profilehandlers_post(s.handleUpsertRule, `{"id":"","outbound":"direct"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("empty rule id: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

func TestProfilehandlers_RuleRoundTrip(t *testing.T) {
	s, _ := sharehandlers_server(t)
	ru := model.Rule{ID: "r1", Outbound: "direct", DomainSuffix: []string{".example.com"}}
	body, _ := json.Marshal(ru)

	if w := profilehandlers_post(s.handleUpsertRule, string(body)); w.Code != http.StatusOK {
		t.Fatalf("upsert rule: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	rules := s.store.Profile().Rules
	if len(rules) != 1 || rules[0].ID != "r1" || rules[0].Outbound != "direct" {
		t.Fatalf("rule not persisted: %+v", rules)
	}
	if w := profilehandlers_delete(s.handleDeleteRule, "r1"); w.Code != http.StatusOK {
		t.Fatalf("delete rule: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if len(s.store.Profile().Rules) != 0 {
		t.Errorf("rule not deleted: %+v", s.store.Profile().Rules)
	}
}

func TestProfilehandlers_DeleteRuleUnknown409(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if w := profilehandlers_delete(s.handleDeleteRule, "ghost"); w.Code != http.StatusConflict {
		t.Fatalf("delete unknown rule: got %d, want 409 (%s)", w.Code, w.Body.String())
	}
}

// --- handleBulkEndpoints ---------------------------------------------------

func TestProfilehandlers_BulkEndpointsBadJSON(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if w := profilehandlers_post(s.handleBulkEndpoints, `xx`); w.Code != http.StatusBadRequest {
		t.Fatalf("bulk bad json: got %d, want 400", w.Code)
	}
}

func TestProfilehandlers_BulkEndpointsSkipsEmptyID(t *testing.T) {
	s, _ := sharehandlers_server(t)
	// v2 needs distinct CONTENT, not just a distinct ID: the bulk handler now skips
	// content-identical imports (importer.DedupeNew), and the shared fixture otherwise
	// gives every endpoint the same server/uuid.
	v2 := profilehandlers_endpoint("v2", "Two")
	v2.Server = "5.6.7.8"
	payload := map[string]any{
		"endpoints": []model.Endpoint{
			profilehandlers_endpoint("v1", "One"),
			profilehandlers_endpoint("", "NoID"), // skipped: empty id
			v2,
		},
	}
	body, _ := json.Marshal(payload)

	w := profilehandlers_post(s.handleBulkEndpoints, string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("bulk: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Saved int `json:"saved"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if resp.Saved != 2 {
		t.Errorf("saved = %d, want 2 (empty-id entry must be skipped)", resp.Saved)
	}
	prof := s.store.Profile()
	eps := prof.Endpoints
	if len(eps) != 2 {
		t.Fatalf("persisted %d endpoints, want 2: %+v", len(eps), eps)
	}
	if prof.EndpointByID("v1") == nil || prof.EndpointByID("v2") == nil {
		t.Errorf("expected v1 and v2 persisted, got %+v", eps)
	}
}

// --- handleGenerate --------------------------------------------------------

func TestProfilehandlers_GenerateEmptyProfile(t *testing.T) {
	s, _ := sharehandlers_server(t)
	req := httptest.NewRequest(http.MethodGet, "/api/generate", nil)
	w := httptest.NewRecorder()
	s.handleGenerate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("generate empty: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Config  map[string]any   `json:"config"`
		Plugins []map[string]any `json:"plugins"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if resp.Config["outbounds"] == nil {
		t.Errorf("config missing outbounds: %v", resp.Config)
	}
	if resp.Config["inbounds"] == nil || resp.Config["route"] == nil {
		t.Errorf("config missing inbounds/route: %v", resp.Config)
	}
	if len(resp.Plugins) != 0 {
		t.Errorf("expected no plugins for a sing-box-only/empty profile, got %v", resp.Plugins)
	}
}

func TestProfilehandlers_GenerateWithEngineEndpointSummarizesPlugin(t *testing.T) {
	s, _ := sharehandlers_server(t)
	// An AmneziaWG endpoint is a non-sing-box engine -> surfaces as a plugin.
	awg := model.Endpoint{
		ID: "a1", Name: "AWG", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
		Server: "198.51.100.20", Port: 51820,
		Params:  map[string]any{"private_key": "PRIV=", "peer_public_key": "PUB="},
		Enabled: true,
	}
	if err := s.store.UpsertEndpoint(awg); err != nil {
		t.Fatalf("seed awg: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/generate", nil)
	w := httptest.NewRecorder()
	s.handleGenerate(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("generate: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Config  map[string]any   `json:"config"`
		Plugins []map[string]any `json:"plugins"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if len(resp.Plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d: %v", len(resp.Plugins), resp.Plugins)
	}
	pl := resp.Plugins[0]
	if pl["id"] != "a1" || pl["engine"] != string(model.EngineAmneziaWG) {
		t.Errorf("plugin summary = %v", pl)
	}
	// AmneziaWG egresses via bind_interface, so its plugin has no SOCKS port.
	if sp, ok := pl["socks_port"].(float64); !ok || sp != 0 {
		t.Errorf("amneziawg plugin socks_port = %v, want 0 (bind_interface)", pl["socks_port"])
	}
}

func TestProfilehandlers_GenerateInvalidProfile400(t *testing.T) {
	s, _ := sharehandlers_server(t)
	// A rule pointing at a non-existent outbound fails model.Validate -> 400.
	if err := s.store.UpsertRule(model.Rule{ID: "r1", Outbound: "does-not-exist"}); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/generate", nil)
	w := httptest.NewRecorder()
	s.handleGenerate(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("generate invalid: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// --- handleSubscription (import preview, text path only) -------------------

func TestProfilehandlers_SubscriptionBadJSON(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if w := profilehandlers_post(s.handleSubscription, `???`); w.Code != http.StatusBadRequest {
		t.Fatalf("subscription bad json: got %d, want 400", w.Code)
	}
}

func TestProfilehandlers_SubscriptionParsesTextEndpointsAndErrors(t *testing.T) {
	s, _ := sharehandlers_server(t)
	// Two parseable links + one garbage line that should surface as an error.
	text := profilehandlers_vlessLink + "\n" +
		"trojan://secretpass@example.com:443?security=tls&sni=example.com#T1\n" +
		"ftp://garbage-line"
	body, _ := json.Marshal(map[string]string{"text": text})

	w := profilehandlers_post(s.handleSubscription, string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("subscription: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Endpoints []model.Endpoint `json:"endpoints"`
		Errors    []string         `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if len(resp.Endpoints) != 2 {
		t.Fatalf("parsed %d endpoints, want 2: %+v", len(resp.Endpoints), resp.Endpoints)
	}
	if len(resp.Errors) != 1 {
		t.Fatalf("got %d errors, want 1: %v", len(resp.Errors), resp.Errors)
	}
	if !strings.Contains(resp.Errors[0], "ftp") {
		t.Errorf("error should mention the bad line, got %q", resp.Errors[0])
	}
	protos := map[model.Protocol]bool{}
	for _, e := range resp.Endpoints {
		protos[e.Protocol] = true
	}
	if !protos[model.ProtoVLESS] || !protos[model.ProtoTrojan] {
		t.Errorf("expected vless+trojan endpoints, got %+v", resp.Endpoints)
	}
	// Preview only: subscription parsing must NOT persist anything.
	if len(s.store.Profile().Endpoints) != 0 {
		t.Errorf("subscription preview unexpectedly persisted endpoints: %+v", s.store.Profile().Endpoints)
	}
}

func TestProfilehandlers_SubscriptionEmptyTextNoEndpoints(t *testing.T) {
	s, _ := sharehandlers_server(t)
	w := profilehandlers_post(s.handleSubscription, `{"text":""}`)
	if w.Code != http.StatusOK {
		t.Fatalf("empty subscription: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Endpoints []model.Endpoint `json:"endpoints"`
		Errors    []string         `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if len(resp.Endpoints) != 0 || len(resp.Errors) != 0 {
		t.Errorf("empty text should yield no endpoints/errors, got eps=%v errs=%v", resp.Endpoints, resp.Errors)
	}
}
