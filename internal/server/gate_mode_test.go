package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"wayhop/internal/platform"
)

// The routing mode decides which planes Apply builds, and no server-side check consulted the
// capability for it: a PUT naming hybrid on a box with no kernel PBR was stored 200, and the panel
// then showed a mode the datapath would never realise.

func gateModeServer(t *testing.T, hybrid platform.CapState) *Server {
	t.Helper()
	s := cfgFileServer(t)
	s.caps.mu.Lock()
	s.caps.set = platform.CapabilitySet{
		Items: map[string]platform.Capability{
			platform.CapRoutingModeTun:   {ID: platform.CapRoutingModeTun, State: platform.CapSupported},
			platform.CapRoutingModeMixed: {ID: platform.CapRoutingModeMixed, State: platform.CapSupported},
			platform.CapRoutingModeHybrid: {ID: platform.CapRoutingModeHybrid, State: hybrid,
				Detail: "this firmware has no nftables", Remedy: "Use mixed or tun."},
		},
		ProbedAt: time.Now(),
	}
	s.caps.mu.Unlock()
	return s
}

func gateModePut(t *testing.T, s *Server, mode string) *ttResponse {
	t.Helper()
	cfg := s.config()
	cfg.RoutingMode = mode
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	w := putConfig(t, s, string(body))
	return &ttResponse{code: w.Code, body: w.Body.String()}
}

type ttResponse struct {
	code int
	body string
}

func TestGateMode_SwitchingToAModeTheHostCannotRunIsRefused(t *testing.T) {
	s := gateModeServer(t, platform.CapUnsupportedFirmware)
	before := s.config().RoutingMode

	got := gateModePut(t, s, "hybrid")
	if got.code != http.StatusUnprocessableEntity {
		t.Fatalf("got %d, want 422 — the kernel plane it names does not exist here (%s)", got.code, got.body)
	}
	if now := s.config().RoutingMode; now != before {
		t.Errorf("the mode was stored anyway: %q -> %q", before, now)
	}
}

// Unknown is not a verdict. Switching the whole datapath on an unfinished probe would be a guess in
// whichever direction it landed.
func TestGateMode_UnknownAsksAgain(t *testing.T) {
	s := gateModeServer(t, platform.CapUnknown)
	if got := gateModePut(t, s, "hybrid"); got.code != http.StatusServiceUnavailable {
		t.Errorf("got %d, want 503 (%s)", got.code, got.body)
	}
}

func TestGateMode_ASupportedModeIsStored(t *testing.T) {
	s := gateModeServer(t, platform.CapSupported)
	if got := gateModePut(t, s, "hybrid"); got.code != http.StatusOK {
		t.Fatalf("got %d, want 200 (%s)", got.code, got.body)
	}
	if now := s.config().RoutingMode; now != "hybrid" {
		t.Errorf("RoutingMode = %q, want hybrid", now)
	}
}

// The subject is the TRANSITION. A host that has lost the capability it is already configured for
// must still accept saves of every unrelated setting, or its own mode would lock the operator out of
// Settings entirely — and Settings is where the mode is changed back.
func TestGateMode_StayingInAnUnrunnableModeStillSavesOtherSettings(t *testing.T) {
	s := gateModeServer(t, platform.CapSupported)
	if got := gateModePut(t, s, "hybrid"); got.code != http.StatusOK {
		t.Fatalf("seed: %d %s", got.code, got.body)
	}
	// The ground moves under it: the firmware no longer has the kernel plane.
	s.caps.mu.Lock()
	item := s.caps.set.Items[platform.CapRoutingModeHybrid]
	item.State = platform.CapUnsupportedFirmware
	s.caps.set.Items[platform.CapRoutingModeHybrid] = item
	s.caps.mu.Unlock()

	cfg := s.config()
	cfg.GatewayMTU = 1380
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if w := putConfig(t, s, string(body)); w.Code != http.StatusOK {
		t.Fatalf("an unrelated setting could not be saved: %d %s", w.Code, w.Body.String())
	}
}

// The import path writes the same field and shares persistConfig, so a bundle is not a way around it.
func TestGateMode_ImportIsHeldToTheSameRule(t *testing.T) {
	s := gateModeServer(t, platform.CapUnsupportedFirmware)
	imp := s.config()
	imp.RoutingMode = "hybrid"
	body, err := json.Marshal(imp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	w := opshandlers_post(s.handleConfigImport, "/api/config/import", string(body))
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("got %d, want 422 — an import is still a switch (%s)", w.Code, w.Body.String())
	}
	if now := s.config().RoutingMode; now == "hybrid" {
		t.Error("the import stored a mode this host cannot run")
	}
}
