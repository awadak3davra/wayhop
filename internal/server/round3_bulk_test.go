package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// TestBulkEndpoints_ManyDistinct persists a large batch of DISTINCT endpoints in one call. The fix
// replaced the per-endpoint UpsertEndpoint loop (O(N^2) whole-profile rewrites + fsyncs, a stall +
// flash-wear hazard) with a single UpsertEndpoints batch write; this asserts the batch stays correct
// — every distinct endpoint is saved, the counts are right, and all land in the profile.
func TestBulkEndpoints_ManyDistinct(t *testing.T) {
	s, _ := sharehandlers_server(t)
	const n = 200
	eps := make([]model.Endpoint, 0, n)
	for i := 0; i < n; i++ {
		e := profilehandlers_endpoint(fmt.Sprintf("e-%d", i), fmt.Sprintf("E%d", i))
		e.Server = fmt.Sprintf("10.%d.%d.%d", i/256, i%256, (i*7)%256) // distinct content
		e.Params = map[string]any{"uuid": fmt.Sprintf("uuid-%d", i)}
		eps = append(eps, e)
	}
	body, _ := json.Marshal(map[string]any{"endpoints": eps})
	w := profilehandlers_post(s.handleBulkEndpoints, string(body))
	if w.Code != 200 {
		t.Fatalf("bulk: got %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Saved      int `json:"saved"`
		Duplicates int `json:"duplicates"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Saved != n || resp.Duplicates != 0 {
		t.Fatalf("saved=%d duplicates=%d, want %d/0", resp.Saved, resp.Duplicates, n)
	}
	if got := len(s.store.Profile().Endpoints); got != n {
		t.Fatalf("persisted %d, want %d", got, n)
	}
}

// TestBulkEndpoints_Duplicates: content-identical re-imports collapse (DedupeNew), so re-POSTing the
// same set adds nothing — the single-write path preserves the dedup semantics.
func TestBulkEndpoints_Duplicates(t *testing.T) {
	s, _ := sharehandlers_server(t)
	a := profilehandlers_endpoint("a", "A")
	a.Server = "1.1.1.1"
	a.Params = map[string]any{"uuid": "ua"}
	b := profilehandlers_endpoint("b", "B")
	b.Server = "2.2.2.2"
	b.Params = map[string]any{"uuid": "ub"}
	post := func(eps []model.Endpoint) (saved, dupes int) {
		body, _ := json.Marshal(map[string]any{"endpoints": eps})
		w := profilehandlers_post(s.handleBulkEndpoints, string(body))
		var r struct {
			Saved      int `json:"saved"`
			Duplicates int `json:"duplicates"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &r)
		return r.Saved, r.Duplicates
	}
	if sv, _ := post([]model.Endpoint{a, b}); sv != 2 {
		t.Fatalf("first import saved=%d, want 2", sv)
	}
	// A re-fetched subscription re-parses the SAME content under FRESH IDs; those are content
	// duplicates and must not pile up (DedupeNew drops them; same-ID would be an in-place update).
	a2, b2 := a, b
	a2.ID, b2.ID = "a-new", "b-new"
	if _, dup := post([]model.Endpoint{a2, b2}); dup != 2 {
		t.Fatalf("re-import (fresh IDs, same content) duplicates=%d, want 2", dup)
	}
	if got := len(s.store.Profile().Endpoints); got != 2 {
		t.Fatalf("profile has %d endpoints after re-import, want 2", got)
	}
}

// QA-148: importing the same link again keeps what the user changed since the first import — the
// name, the switch, the health target, multiplex, the ID groups hold it by — and the answer says it was
// unchanged rather than "imported". A link that now carries a different param updates that param and
// still keeps the rest, and is counted as updated. The subscription timer already kept this promise;
// the manual path broke it.
func TestBulkEndpoints_ReimportKeepsTheUsersEdits(t *testing.T) {
	s, _ := sharehandlers_server(t)
	link := profilehandlers_endpoint("vless-1", "vless-de")
	link.Params = map[string]any{"uuid": "u1", "flow": "xtls-rprx-vision"}
	type counts struct {
		Saved     int `json:"saved"`
		Added     int `json:"added"`
		Updated   int `json:"updated"`
		Unchanged int `json:"unchanged"`
	}
	post := func(eps ...model.Endpoint) counts {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"endpoints": eps})
		w := profilehandlers_post(s.handleBulkEndpoints, string(body))
		var c counts
		if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil || w.Code != 200 {
			t.Fatalf("bulk import: %d %s", w.Code, w.Body.String())
		}
		return c
	}
	if c := post(link); c.Added != 1 || c.Saved != 1 {
		t.Fatalf("first import = %+v, want one added", c)
	}

	edited := link
	edited.Name, edited.Enabled = "My renamed DE", false
	edited.Health = &model.Health{URL: "https://example.org/generate_204", Interval: 60}
	edited.Multiplex = &model.Multiplex{Enabled: true, Protocol: "smux"}
	if err := s.store.UpsertEndpoint(edited); err != nil {
		t.Fatal(err)
	}
	gen := s.store.Gen()

	if c := post(link); c.Unchanged != 1 || c.Saved != 0 || c.Added != 0 || c.Updated != 0 {
		t.Fatalf("re-import of the same link = %+v, want one unchanged and nothing saved", c)
	}
	if s.store.Gen() != gen {
		t.Error("an unchanged re-import wrote the profile")
	}
	p := s.store.Profile()
	got := *p.EndpointByID("vless-1")
	if got.Name != "My renamed DE" || got.Enabled || got.Health == nil || got.Multiplex == nil {
		t.Fatalf("re-import reverted the user's edits: %+v", got)
	}

	rotated := link
	rotated.Params = map[string]any{"uuid": "u1", "flow": ""}
	if c := post(rotated); c.Updated != 1 || c.Saved != 1 {
		t.Fatalf("re-import of a link with a changed param = %+v, want one updated", c)
	}
	p = s.store.Profile()
	got = *p.EndpointByID("vless-1")
	if got.Params["flow"] != "" || got.Name != "My renamed DE" || got.Enabled || got.Multiplex == nil || got.Health == nil {
		t.Fatalf("an updating re-import: %+v, want the link's flow and the user's name, switch, health and multiplex", got)
	}
	if len(p.Endpoints) != 1 {
		t.Errorf("re-imports added connections: %d, want the one, under its ID", len(p.Endpoints))
	}
}

// QA-148 (hunter, after the first fix): a re-import laid only the values the link carries over the
// stored connection, so a link that had dropped Vision, allowInsecure, its fingerprint and its pin
// was answered "1 unchanged" and all four stayed stored. Everything the link can express now comes
// from the link, an absent value included, and the answer says the connection was updated.
func TestBulkEndpoints_ReimportClearsWhatTheLinkDropped(t *testing.T) {
	s, _ := sharehandlers_server(t)
	const base = "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?security=tls&sni=example.com&type=tcp"
	const pin = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	post := func(link string) map[string]any {
		t.Helper()
		e, err := importer.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]any{"endpoints": []model.Endpoint{*e}})
		w := profilehandlers_post(s.handleBulkEndpoints, string(body))
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil || w.Code != 200 {
			t.Fatalf("bulk import: %d %s", w.Code, w.Body.String())
		}
		return m
	}
	post(base + "&flow=xtls-rprx-vision&allowInsecure=1&fp=chrome&pcs=" + pin + "#vless-de")
	p := s.store.Profile()
	e := p.Endpoints[0]
	e.Name = "My DE"
	if err := s.store.UpsertEndpoint(e); err != nil {
		t.Fatal(err)
	}

	if m := post(base + "#vless-de"); m["updated"] != float64(1) || m["unchanged"] != float64(0) {
		t.Fatalf("re-import of a link that dropped four settings = %v, want one updated", m)
	}
	p = s.store.Profile()
	got := p.Endpoints[0]
	if _, ok := got.Params["flow"]; ok || got.TLS.Insecure || got.TLS.Fingerprint != "" || len(got.TLS.PinCertSHA256) != 0 {
		t.Errorf("a setting the link dropped is still stored: params %v tls %+v", got.Params, *got.TLS)
	}
	if got.Name != "My DE" || len(p.Endpoints) != 1 {
		t.Errorf("the user's name was not kept, or the import added a connection: %+v", p.Endpoints)
	}
	if m := post(base + "#vless-de"); m["unchanged"] != float64(1) {
		t.Errorf("the same link once more = %v, want unchanged", m)
	}
}

// A re-import keeps a public-key pin Set up Server added (no link carries one), and says so: a server
// whose key changed is refused while it stays, and the operator re-importing to fix that has to know.
func TestBulkEndpoints_ReimportSaysItKeptAServerKeyPin(t *testing.T) {
	s, _ := sharehandlers_server(t)
	const link = "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?security=tls&sni=example.com&type=tcp#vless-de"
	post := func() map[string]any {
		t.Helper()
		e, err := importer.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]any{"endpoints": []model.Endpoint{*e}})
		w := profilehandlers_post(s.handleBulkEndpoints, string(body))
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil || w.Code != 200 {
			t.Fatalf("bulk import: %d %s", w.Code, w.Body.String())
		}
		return m
	}
	post()
	p := s.store.Profile()
	e := p.Endpoints[0]
	tls := *e.TLS
	tls.PinPubKeySHA256 = []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	e.TLS = &tls
	if err := s.store.UpsertEndpoint(e); err != nil {
		t.Fatal(err)
	}
	m := post()
	notes, _ := m["notes"].([]any)
	if m["unchanged"] != float64(1) || len(notes) != 1 ||
		!strings.Contains(notes[0].(string), "kept: server public-key pin") ||
		!strings.Contains(notes[0].(string), "sing-box config") {
		t.Fatalf("re-import answered %v, want unchanged and a kept-pin note naming every source", m)
	}
	if p := s.store.Profile(); len(p.Endpoints[0].TLS.PinPubKeySHA256) != 1 {
		t.Error("the server key pin was not kept")
	}
}

// QA-156: a link that omits MTU and keepalive still clears them, but the answer names the loss.
func TestBulkEndpoints_ReimportSaysItClearedWireGuardKnobs(t *testing.T) {
	s, _ := sharehandlers_server(t)
	const base = "wireguard://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D@203.0.113.61:51820?publickey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ%3D&address=10.0.0.2/32"
	post := func(extra string) map[string]any {
		t.Helper()
		e, err := importer.Parse(base + extra + "#W")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]any{"endpoints": []model.Endpoint{*e}})
		w := profilehandlers_post(s.handleBulkEndpoints, string(body))
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil || w.Code != 200 {
			t.Fatalf("bulk import: %d %s", w.Code, w.Body.String())
		}
		return m
	}
	post("&mtu=1420&keepalive=25")
	p := s.store.Profile()
	e := p.Endpoints[0]
	e.MTU, e.PersistentKeepalive = 1420, 25
	delete(e.Params, "mtu")
	delete(e.Params, "persistent_keepalive")
	if err := s.store.UpsertEndpoint(e); err != nil {
		t.Fatal(err)
	}

	m := post("")
	notes, _ := m["notes"].([]any)
	if m["updated"] != float64(1) || len(notes) != 1 ||
		!strings.Contains(notes[0].(string), "cleared by the re-import: MTU, persistent keepalive") {
		t.Fatalf("re-import answered %v, want one update and a note naming both cleared values", m)
	}
}
