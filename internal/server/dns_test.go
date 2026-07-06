package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"wayhop/internal/model"
)

func dnsSeed(t *testing.T) *Server {
	s := applyhealth_server(t)
	if err := s.store.UpsertEndpoint(model.Endpoint{ID: "nl", Engine: model.EngineExternal, Params: map[string]any{"interface": "awg0"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.UpsertGroup(model.Group{ID: "grp", Type: model.GroupURLTest, Members: []string{"nl", "direct"}}); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestHandleGetDNS_TemplateWhenUnset: with no DNS configured, GET returns a failover-aware secure
// TEMPLATE (configured=false) whose detour is already pointed at the seeded group.
func TestHandleGetDNS_TemplateWhenUnset(t *testing.T) {
	s := dnsSeed(t)
	w := httptest.NewRecorder()
	s.handleGetDNS(w, httptest.NewRequest(http.MethodGet, "/api/dns", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	var resp struct {
		Configured bool               `json:"configured"`
		DNS        *model.DNSSettings `json:"dns"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Configured {
		t.Error("unset DNS should report configured=false")
	}
	if resp.DNS == nil || len(resp.DNS.Servers) == 0 {
		t.Fatal("template must carry servers")
	}
	if resp.DNS.Servers[0].Detour != "grp" {
		t.Errorf("template secure detour = %q, want grp (failover-aware)", resp.DNS.Servers[0].Detour)
	}
	if !resp.DNS.LeakProof || resp.DNS.Final != "dns_secure" {
		t.Errorf("template should be leak-proof with final=dns_secure, got leak=%v final=%q", resp.DNS.LeakProof, resp.DNS.Final)
	}
}

// TestHandleGetDNS_TemplateParam: ?template=1 returns a fresh secure-default template even when DNS is
// ALREADY configured — this is what the panel's "Apply secure defaults" button loads to re-seed.
func TestHandleGetDNS_TemplateParam(t *testing.T) {
	s := dnsSeed(t)
	// Configure a minimal (non-secure) plane first.
	if err := s.store.SetDNS(&model.DNSSettings{Enabled: true, Servers: []model.DNSServer{{Tag: "plain", Type: "udp", Server: "8.8.8.8", Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleGetDNS(w, httptest.NewRequest(http.MethodGet, "/api/dns?template=1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	var resp struct {
		Configured bool               `json:"configured"`
		Template   bool               `json:"template"`
		DNS        *model.DNSSettings `json:"dns"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Template || !resp.Configured {
		t.Errorf("template=1 over a configured plane: want template=true configured=true, got %+v", resp)
	}
	// It must be the SECURE template (leak-proof, failover-aware detour), not the stored plain plane.
	if resp.DNS == nil || !resp.DNS.LeakProof || resp.DNS.Servers[0].Detour != "grp" {
		t.Errorf("template must be the secure default, got %+v", resp.DNS)
	}
}

// TestDNSDetour_PrefersWANTerminal: the secure-default DoH detour must be WAN-terminal (a group that
// includes `direct`) so DNS falls to direct-DoH over the raw WAN when every tunnel is down instead of
// going dark. When the default route's group is kill-switched (no direct), dnsDetour prefers a separate
// WAN-terminal group; with none, it falls back best-effort to primaryDetour.
func TestDNSDetour_PrefersWANTerminal(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{ID: "nl", Engine: model.EngineExternal, Params: map[string]any{"interface": "awg0"}, Enabled: true}},
		Groups: []model.Group{
			{ID: "ks", Members: []string{"nl"}, KillSwitch: true}, // no direct → not WAN-terminal
			{ID: "graceful", Members: []string{"nl", "direct"}},   // WAN-terminal
		},
		Rules: []model.Rule{{ID: "d", Default: true, Outbound: "ks"}},
	}
	if got := dnsDetour(p); got != "graceful" {
		t.Errorf("dnsDetour = %q, want graceful (the WAN-terminal group)", got)
	}
	p.Rules[0].Outbound = "graceful" // default already WAN-terminal → keep it
	if got := dnsDetour(p); got != "graceful" {
		t.Errorf("dnsDetour = %q, want graceful (default already WAN-terminal)", got)
	}
	p.Groups = []model.Group{{ID: "ks", Members: []string{"nl"}, KillSwitch: true}} // none WAN-terminal
	p.Rules[0].Outbound = "ks"
	if got := dnsDetour(p); got != "ks" {
		t.Errorf("dnsDetour = %q, want ks (best-effort fallback)", got)
	}
}

func TestHandleSetDNS_ValidInvalidClear(t *testing.T) {
	s := dnsSeed(t)
	valid := model.DNSSettings{Enabled: true, Servers: []model.DNSServer{
		{Tag: "secure", Type: "https", Server: "1.1.1.1", Detour: "grp", Enabled: true},
		{Tag: "local", Type: "local", Enabled: true},
	}, Final: "secure", Strategy: "ipv4_only", LeakProof: true}
	body, _ := json.Marshal(valid)
	w := httptest.NewRecorder()
	s.handleSetDNS(w, httptest.NewRequest(http.MethodPut, "/api/dns", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("valid DNS rejected %d: %s", w.Code, w.Body)
	}
	if p := s.store.Profile(); p.DNS == nil || p.DNS.Final != "secure" {
		t.Fatalf("DNS not persisted: %+v", s.store.Profile().DNS)
	}

	// invalid: a detour to a ghost id must be a precise 400 (not a bricking Apply).
	bad, _ := json.Marshal(model.DNSSettings{Enabled: true, Final: "x", Servers: []model.DNSServer{{Tag: "x", Type: "https", Server: "1.1.1.1", Detour: "ghost", Enabled: true}}})
	w2 := httptest.NewRecorder()
	s.handleSetDNS(w2, httptest.NewRequest(http.MethodPut, "/api/dns", bytes.NewReader(bad)))
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("invalid DNS should be 400, got %d: %s", w2.Code, w2.Body)
	}

	// null body clears the plane (back to no-dns-block default).
	w3 := httptest.NewRecorder()
	s.handleSetDNS(w3, httptest.NewRequest(http.MethodPut, "/api/dns", bytes.NewReader([]byte("null"))))
	if w3.Code != http.StatusOK {
		t.Fatalf("clear DNS: %d", w3.Code)
	}
	if s.store.Profile().DNS != nil {
		t.Error("null body should clear the DNS plane")
	}
}

func TestHandleDNSCatalog(t *testing.T) {
	s := applyhealth_server(t)
	w := httptest.NewRecorder()
	s.handleDNSCatalog(w, httptest.NewRequest(http.MethodGet, "/api/dns/catalog", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("catalog: %d", w.Code)
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("catalog must set an ETag")
	}
	var resp struct {
		Presets []dnsPreset `json:"presets"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Presets) < 5 {
		t.Errorf("presets = %d, want the curated provider list", len(resp.Presets))
	}
	// If-None-Match revalidates to 304.
	req2 := httptest.NewRequest(http.MethodGet, "/api/dns/catalog", nil)
	req2.Header.Set("If-None-Match", etag)
	w2 := httptest.NewRecorder()
	s.handleDNSCatalog(w2, req2)
	if w2.Code != http.StatusNotModified {
		t.Errorf("If-None-Match should 304, got %d", w2.Code)
	}
}
