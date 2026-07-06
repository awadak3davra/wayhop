package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/model"
)

func TestHandlePBRPreview(t *testing.T) {
	s, _ := sharehandlers_server(t)
	// A kernel exit (UCI awg1) + a VoWiFi-style manual IP list pointed at it.
	if err := s.store.UpsertEndpoint(model.Endpoint{
		ID: "ru-awg1", Name: "RU", Engine: model.EngineExternal, Server: "198.51.100.20",
		Enabled: true, Params: map[string]any{"interface": "awg1"},
	}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	if err := s.store.UpsertRoutingList(model.RoutingList{
		ID: "carrier-carveout", Name: "VoWiFi", Manual: []string{"198.51.100.0/24"}, Outbound: "ru-awg1", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertRoutingList: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/pbr/preview", nil)
	w := httptest.NewRecorder()
	s.handlePBRPreview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (%s)", w.Code, w.Body.String())
	}

	var raw struct {
		NFT string   `json:"nft"`
		IP  []string `json:"ip"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !strings.Contains(raw.NFT, "198.51.100.0/24") {
		t.Errorf("nft missing zone CIDR:\n%s", raw.NFT)
	}
	if !strings.Contains(strings.Join(raw.IP, "\n"), "ip route replace default dev awg1 table 151") {
		t.Errorf("ip commands missing kernel route: %v", raw.IP)
	}
}

// TestHandlePBRPreviewOffload pins that the preview compiles with the apply path's offload
// options (via pbrCompileOptions), not a bare pbr.Options{} — so the flow-offload flowtable
// the real Apply would install actually appears in the previewed nft. Before the fix the
// preview silently omitted it, misleading offload users.
func TestHandlePBRPreviewOffload(t *testing.T) {
	s, _ := sharehandlers_server(t)
	// fast mode + hardware offload with explicit devices, so no host probe runs.
	s.cfg.RoutingMode = "fast"
	s.cfg.Offload = "hw"
	s.cfg.OffloadDevices = []string{"eth0", "br-lan"}

	if err := s.store.UpsertEndpoint(model.Endpoint{
		ID: "ru-awg1", Name: "RU", Engine: model.EngineExternal, Server: "198.51.100.20",
		Enabled: true, Params: map[string]any{"interface": "awg1"},
	}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	if err := s.store.UpsertRoutingList(model.RoutingList{
		ID: "list1", Name: "L", Manual: []string{"203.0.113.0/24"}, Outbound: "ru-awg1", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertRoutingList: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/pbr/preview", nil)
	w := httptest.NewRecorder()
	s.handlePBRPreview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var raw struct {
		NFT string `json:"nft"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	// The hardware flowtable must be present — proof the preview now compiles with offload.
	if !strings.Contains(raw.NFT, "flowtable ft") || !strings.Contains(raw.NFT, "flags offload") {
		t.Errorf("preview nft missing the offload flowtable (fidelity gap regressed):\n%s", raw.NFT)
	}
	if !strings.Contains(raw.NFT, "eth0") {
		t.Errorf("preview nft missing the offload device list:\n%s", raw.NFT)
	}
}
