package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/platform"
	"wayhop/internal/store"
)

// sharehandlers_server builds a minimal *Server backed by a temp config.json and
// profile.json so the per-connection share and QR handlers can be exercised in
// isolation, without the full daemon wiring (hub, sing-box, watchdog, …).
func sharehandlers_server(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	st, err := store.Open(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	s := &Server{cfg: cfg, store: st}
	items := map[string]platform.Capability{
		platform.CapEngineSingbox: {ID: platform.CapEngineSingbox, State: platform.CapSupported},
	}
	for _, protocol := range []string{"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "anytls", "socks", "http"} {
		id := platform.CapProtocolPrefix + protocol
		items[id] = platform.Capability{ID: id, State: platform.CapSupported}
	}
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, operation := range []platform.NativeOperation{platform.NativeCreate, platform.NativeRemove} {
			id := platform.NativeOperationCapabilityID(protocol, operation)
			items[id] = platform.Capability{ID: id, State: platform.CapSupported}
		}
	}
	s.caps.set = platform.CapabilitySet{Items: items, ProbedAt: time.Now()}
	return s, cfgPath
}

// sharehandlers_vless is an enabled VLESS endpoint that exports as a share link.
func sharehandlers_vless(id, name string) model.Endpoint {
	return model.Endpoint{
		ID: id, Name: name, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "203.0.113.10", Port: 443,
		Params:  map[string]any{"uuid": "11111111-2222-3333-4444-555555555555", "flow": "xtls-rprx-vision"},
		TLS:     &model.TLS{Enabled: true, Type: "reality", SNI: "www.microsoft.com", Fingerprint: "chrome", PublicKey: "PUBKEYabc", ShortID: "ab12"},
		Enabled: true,
	}
}

// sharehandlers_awg is an enabled AmneziaWG endpoint. It exports as a .conf
// (Kind "conf"), NOT a share link, so it must be excluded from the subscription.
func sharehandlers_awg(id, name string) model.Endpoint {
	return model.Endpoint{
		ID: id, Name: name, Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
		Server: "198.51.100.20", Port: 51820,
		Params: map[string]any{
			"private_key": "PRIV=", "peer_public_key": "PUB=", "local_address": []string{"10.13.13.2/32"},
			"jc": 4, "jmin": 40, "jmax": 70,
		},
		Enabled: true,
	}
}

func TestSharehandlers_EndpointExportLink(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertEndpoint(sharehandlers_vless("v1", "Reality")); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/endpoints/v1/export", nil)
	req.SetPathValue("id", "v1")
	w := httptest.NewRecorder()
	s.handleEndpointExport(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("export link: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	// The export body is a full credential-bearing share link — must not be cacheable.
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store (endpoint export carries credentials)", cc)
	}
	var res struct {
		Kind string `json:"kind"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if res.Kind != "link" {
		t.Errorf("kind = %q, want link", res.Kind)
	}
	if !strings.HasPrefix(res.Text, "vless://") {
		t.Errorf("text is not a vless URI: %q", res.Text)
	}
}

func TestSharehandlers_EndpointExportConf(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertEndpoint(sharehandlers_awg("a1", "AWG Conf")); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/endpoints/a1/export", nil)
	req.SetPathValue("id", "a1")
	w := httptest.NewRecorder()
	s.handleEndpointExport(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("export conf: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var res struct {
		Kind     string `json:"kind"`
		Text     string `json:"text"`
		Filename string `json:"filename"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if res.Kind != "conf" {
		t.Errorf("kind = %q, want conf", res.Kind)
	}
	if !strings.Contains(res.Text, "[Interface]") || !strings.Contains(res.Text, "Endpoint = 198.51.100.20:51820") {
		t.Errorf("conf missing expected fields:\n%s", res.Text)
	}
	if !strings.HasSuffix(res.Filename, ".conf") {
		t.Errorf("filename = %q, want *.conf", res.Filename)
	}
}

func TestSharehandlers_EndpointExportUnknownID404(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertEndpoint(sharehandlers_vless("v1", "Reality")); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/endpoints/nope/export", nil)
	req.SetPathValue("id", "nope")
	w := httptest.NewRecorder()
	s.handleEndpointExport(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown id: got %d, want 404 (%s)", w.Code, w.Body.String())
	}
}

func TestSharehandlers_EndpointExportNonExportable422(t *testing.T) {
	s, _ := sharehandlers_server(t)
	// socks and olcrtc have no share link / conf -> 422.
	socks := model.Endpoint{
		ID: "s1", Name: "Socks", Engine: model.EngineSingBox, Protocol: model.ProtoSOCKS,
		Server: "10.0.0.1", Port: 1080, Enabled: true,
	}
	olc := model.Endpoint{
		ID: "o1", Name: "Olc", Engine: model.EngineOlcRTC, Protocol: model.ProtoOlcRTC,
		Server: "10.0.0.2", Port: 1080, Enabled: true,
	}
	for _, e := range []model.Endpoint{socks, olc} {
		if err := s.store.UpsertEndpoint(e); err != nil {
			t.Fatalf("UpsertEndpoint %s: %v", e.ID, err)
		}
	}

	for _, id := range []string{"s1", "o1"} {
		req := httptest.NewRequest(http.MethodGet, "/api/endpoints/"+id+"/export", nil)
		req.SetPathValue("id", id)
		w := httptest.NewRecorder()
		s.handleEndpointExport(w, req)
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("export %s: got %d, want 422 (%s)", id, w.Code, w.Body.String())
		}
	}
}
