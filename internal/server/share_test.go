package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"velinx/internal/config"
	"velinx/internal/model"
	"velinx/internal/store"
)

// sharehandlers_server builds a minimal *Server backed by a temp config.json and
// a temp profile.json so the share/QR/subscription handlers can be exercised in
// isolation, without the full daemon wiring (hub, sing-box, watchdog, …). It also
// returns the config path so a test can reload it to assert persistence.
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
	return &Server{cfg: cfg, store: st}, cfgPath
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

func TestSharehandlers_SubTokenStableAndPersisted(t *testing.T) {
	s, cfgPath := sharehandlers_server(t)

	if s.cfg.Subscription.Token != "" {
		t.Fatalf("expected empty token before first use, got %q", s.cfg.Subscription.Token)
	}

	tok := s.subToken()
	if tok == "" {
		t.Fatal("subToken returned empty string")
	}
	// 12 random bytes hex-encoded == 24 hex chars.
	if len(tok) != 24 {
		t.Errorf("token length = %d, want 24 (%q)", len(tok), tok)
	}

	// Stable across repeated calls (does not rotate).
	if again := s.subToken(); again != tok {
		t.Errorf("token changed on second call: %q vs %q", again, tok)
	}

	// Persisted into the in-memory config...
	if s.cfg.Subscription.Token != tok {
		t.Errorf("token not stored in cfg: %q vs %q", s.cfg.Subscription.Token, tok)
	}

	// ...and to disk: reloading the same path must yield the same token.
	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if reloaded.Subscription.Token != tok {
		t.Errorf("token not persisted to disk: %q vs %q", reloaded.Subscription.Token, tok)
	}
}

func TestSharehandlers_SubInfoReturnsTokenAndPath(t *testing.T) {
	s, _ := sharehandlers_server(t)
	req := httptest.NewRequest(http.MethodGet, "/api/subscription/info", nil)
	w := httptest.NewRecorder()
	s.handleSubInfo(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("handleSubInfo: got %d, want 200", w.Code)
	}
	var resp struct {
		Token string `json:"token"`
		Path  string `json:"path"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if resp.Token == "" {
		t.Fatal("empty token in sub info")
	}
	if want := "/api/sub/" + resp.Token; resp.Path != want {
		t.Errorf("path = %q, want %q", resp.Path, want)
	}
	if resp.Token != s.subToken() {
		t.Errorf("sub info token %q != subToken %q", resp.Token, s.subToken())
	}
}

func TestSharehandlers_SubServeWrongTokenForbidden(t *testing.T) {
	s, _ := sharehandlers_server(t)
	// Force the token to exist.
	_ = s.subToken()

	req := httptest.NewRequest(http.MethodGet, "/api/sub/not-the-token", nil)
	req.SetPathValue("token", "not-the-token")
	w := httptest.NewRecorder()
	s.handleSubServe(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("wrong token: got %d, want 403 (%s)", w.Code, w.Body.String())
	}
}

func TestSharehandlers_SubServeListsEnabledLinksExcludesAWGAndDisabled(t *testing.T) {
	s, _ := sharehandlers_server(t)

	enabledVLESS := sharehandlers_vless("v1", "Reality")
	awg := sharehandlers_awg("a1", "AWG Conf") // enabled, but conf-only -> excluded
	disabledVLESS := sharehandlers_vless("v2", "Disabled VLESS")
	disabledVLESS.Enabled = false
	socks := model.Endpoint{
		ID: "s1", Name: "Socks", Engine: model.EngineSingBox, Protocol: model.ProtoSOCKS,
		Server: "10.0.0.1", Port: 1080, Enabled: true, // not exportable as a link
	}
	for _, e := range []model.Endpoint{enabledVLESS, awg, disabledVLESS, socks} {
		if err := s.store.UpsertEndpoint(e); err != nil {
			t.Fatalf("UpsertEndpoint %s: %v", e.ID, err)
		}
	}

	tok := s.subToken()
	req := httptest.NewRequest(http.MethodGet, "/api/sub/"+tok, nil)
	req.SetPathValue("token", tok)
	w := httptest.NewRecorder()
	s.handleSubServe(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("handleSubServe: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}

	raw, err := base64.StdEncoding.DecodeString(w.Body.String())
	if err != nil {
		t.Fatalf("body is not valid base64: %v (%q)", err, w.Body.String())
	}
	links := strings.Split(strings.TrimSpace(string(raw)), "\n")

	// Exactly one share link: the enabled VLESS endpoint.
	if len(links) != 1 {
		t.Fatalf("expected exactly 1 share link, got %d: %v", len(links), links)
	}
	if !strings.HasPrefix(links[0], "vless://") {
		t.Errorf("link is not a vless URI: %q", links[0])
	}
	// AmneziaWG must NOT appear (it exports as a conf, not a link).
	decoded := string(raw)
	if strings.Contains(decoded, "198.51.100.20") || strings.Contains(decoded, "[Interface]") {
		t.Errorf("amneziawg conf leaked into subscription: %q", decoded)
	}
	// Disabled VLESS and socks must not contribute.
	if strings.Count(decoded, "vless://") != 1 {
		t.Errorf("expected only the enabled VLESS, got: %q", decoded)
	}
}

func TestSharehandlers_SubServeEmptyWhenNoExportableEndpoints(t *testing.T) {
	s, _ := sharehandlers_server(t)
	tok := s.subToken()
	req := httptest.NewRequest(http.MethodGet, "/api/sub/"+tok, nil)
	req.SetPathValue("token", tok)
	w := httptest.NewRecorder()
	s.handleSubServe(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	raw, err := base64.StdEncoding.DecodeString(w.Body.String())
	if err != nil {
		t.Fatalf("body is not valid base64: %v (%q)", err, w.Body.String())
	}
	if len(raw) != 0 {
		t.Errorf("expected empty decoded body, got %q", string(raw))
	}
}

func TestSharehandlers_QRValidTextReturnsPNG(t *testing.T) {
	s, _ := sharehandlers_server(t)
	body := `{"text":"vless://example","size":256}`
	req := httptest.NewRequest(http.MethodPost, "/api/qr", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handleQR(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("handleQR: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
	// PNG magic bytes: 89 50 4E 47 0D 0A 1A 0A.
	pngMagic := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if got := w.Body.Bytes(); len(got) < len(pngMagic) || !bytes.Equal(got[:len(pngMagic)], pngMagic) {
		t.Errorf("response is not a PNG (first bytes: %x)", got[:min(len(got), len(pngMagic))])
	}
}

func TestSharehandlers_QRDefaultSizeForOutOfRange(t *testing.T) {
	s, _ := sharehandlers_server(t)
	// size 10 is below the 128 floor -> handler falls back to 320, still valid PNG.
	body := `{"text":"hello","size":10}`
	req := httptest.NewRequest(http.MethodPost, "/api/qr", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handleQR(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("handleQR small size: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
}

func TestSharehandlers_QREmptyTextBadRequest(t *testing.T) {
	s, _ := sharehandlers_server(t)

	// Empty text field.
	req := httptest.NewRequest(http.MethodPost, "/api/qr", strings.NewReader(`{"text":""}`))
	w := httptest.NewRecorder()
	s.handleQR(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty text: got %d, want 400", w.Code)
	}

	// Malformed JSON body.
	req2 := httptest.NewRequest(http.MethodPost, "/api/qr", strings.NewReader(`not json`))
	w2 := httptest.NewRecorder()
	s.handleQR(w2, req2)
	if w2.Code != http.StatusBadRequest {
		t.Errorf("bad json: got %d, want 400", w2.Code)
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
