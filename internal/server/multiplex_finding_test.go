package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

func muxServerEndpoint(id string, p model.Protocol, m *model.Multiplex) model.Endpoint {
	params := map[string]any{"password": "pw", "uuid": "00000000-0000-4000-8000-000000000021"}
	if p == model.ProtoShadowsocks {
		params = map[string]any{"method": "aes-128-gcm", "password": "pw"}
	}
	return model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineSingBox, Protocol: p,
		Server: "192.0.2.50", Port: 443, Params: params, Multiplex: m}
}

// muxFindings is endpointFindings for one endpoint, keyed by finding ID, multiplex ones only.
func muxFindings(t *testing.T, s *Server, e model.Endpoint) map[string]PlanFinding {
	t.Helper()
	out := map[string]PlanFinding{}
	for _, f := range s.endpointFindings(model.Profile{Endpoints: []model.Endpoint{e}}, platform.CapabilitySet{}) {
		if strings.HasPrefix(f.ID, "endpoint.multiplex.") {
			out[f.ID] = f
		}
	}
	return out
}

// checkMuxFinding: exactly the one finding, degraded and to be acknowledged, saying what was asked and
// what runs, and folded into the template's code.
func checkMuxFinding(t *testing.T, got map[string]PlanFinding, id, code, effective string) {
	t.Helper()
	f, ok := got[id]
	if !ok || len(got) != 1 {
		t.Fatalf("want only %s, got %+v", id, got)
	}
	if f.Severity != platform.SeverityDegraded || f.Blocks != platform.BlocksFeature || f.Requested == "" || f.Effective != effective {
		t.Fatalf("%s: %+v", id, f)
	}
	folded := foldFindings([]PlanFinding{f}, nil)
	if len(folded) != 1 || folded[0].Code != code || !folded[0].AckRequired || !strings.Contains(folded[0].Detail, "effective: "+effective) {
		t.Fatalf("%s folded: %+v", id, folded)
	}
}

// A profile restored from a backup or edited by hand can hold a multiplex the save refuses; the
// generator then leaves it out, and the review says so.
func TestMultiplexFindingUnsupported(t *testing.T) {
	s, _ := sharehandlers_server(t)
	for _, e := range []model.Endpoint{
		muxServerEndpoint("hy2", model.ProtoHysteria2, &model.Multiplex{Enabled: true}),
		muxServerEndpoint("cool", model.ProtoVLESS, &model.Multiplex{Enabled: true, Protocol: "mux.cool"}),
	} {
		checkMuxFinding(t, muxFindings(t, s, e), "endpoint.multiplex.unsupported", "MULTIPLEX_NOT_APPLIED", "off")
	}
	// Hysteria2 and the rest have no Multiplex section to switch off: the remedy says that opening and
	// saving the connection drops the setting, and keeps the way out for a mux protocol sing-box lacks.
	f := muxFindings(t, s, muxServerEndpoint("hy2", model.ProtoHysteria2, &model.Multiplex{Enabled: true}))["endpoint.multiplex.unsupported"]
	folded := foldFindings([]PlanFinding{f}, nil)
	if r := folded[0].Remedy; !strings.Contains(r, "saving drops the setting") || !strings.Contains(r, "pick h2mux, smux or yamux") {
		t.Errorf("remedy: %q", r)
	}
	// Off, or a block the core takes: nothing to say.
	for _, m := range []*model.Multiplex{nil, {Protocol: "mux.cool"}, {Enabled: true, Protocol: "yamux", MaxStreams: 8}} {
		if got := muxFindings(t, s, muxServerEndpoint("ok", model.ProtoTrojan, m)); len(got) != 0 {
			t.Errorf("%+v: %+v", m, got)
		}
	}
}

func TestMultiplexFindingBrutalSpeed(t *testing.T) {
	s, _ := sharehandlers_server(t)
	for _, b := range []*model.Brutal{{Enabled: true, DownMbps: 50}, {Enabled: true, UpMbps: 50, DownMbps: -1},
		{Enabled: true, UpMbps: model.BrutalMaxMbps + 1, DownMbps: 50}} {
		e := muxServerEndpoint("brutal", model.ProtoVMess, &model.Multiplex{Enabled: true, Brutal: b})
		checkMuxFinding(t, muxFindings(t, s, e), "endpoint.multiplex.brutal_speed", "MULTIPLEX_BRUTAL_RATE", "TCP Brutal off")
	}
	ok := muxServerEndpoint("brutal", model.ProtoVMess, &model.Multiplex{Enabled: true, Brutal: &model.Brutal{Enabled: true, UpMbps: 50, DownMbps: 100}})
	if got := muxFindings(t, s, ok); len(got) != 0 {
		t.Errorf("valid rates: %+v", got)
	}
}

func TestMultiplexFindingUoTIgnored(t *testing.T) {
	s, _ := sharehandlers_server(t)
	e := muxServerEndpoint("ss", model.ProtoShadowsocks, &model.Multiplex{Enabled: true, Protocol: "smux"})
	e.Params["udp_over_tcp"] = true
	// The save allows it: it loads, and sing-box simply never builds the multiplex client.
	if p := model.EndpointParamProblem(&e); p != "" {
		t.Fatalf("the save refuses ss + udp_over_tcp + multiplex: %s", p)
	}
	checkMuxFinding(t, muxFindings(t, s, e), "endpoint.multiplex.uot_ignored", "MULTIPLEX_UOT_IGNORED", "multiplex off")
	// A restored profile with the switch as a string: the generator writes UDP over TCP for it, so the
	// review must say the multiplex is unused just the same.
	for _, v := range []string{"true", "1", "yes"} {
		e.Params["udp_over_tcp"] = v
		checkMuxFinding(t, muxFindings(t, s, e), "endpoint.multiplex.uot_ignored", "MULTIPLEX_UOT_IGNORED", "multiplex off")
	}
	delete(e.Params, "udp_over_tcp")
	if got := muxFindings(t, s, e); len(got) != 0 {
		t.Errorf("ss without UoT: %+v", got)
	}
}

// The save refuses what the review would otherwise have to report, and the subscription preview
// carries the importer's notes.
func TestMultiplexSaveAndImportNotes(t *testing.T) {
	s, _ := sharehandlers_server(t)
	body, _ := json.Marshal(muxServerEndpoint("hy2", model.ProtoHysteria2, &model.Multiplex{Enabled: true}))
	w := httptest.NewRecorder()
	s.handleUpsertEndpoint(w, httptest.NewRequest(http.MethodPost, "/api/endpoints", strings.NewReader(string(body))))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "multiplex works only on vless") {
		t.Fatalf("upsert: %d %s", w.Code, w.Body.String())
	}
	// A pool beside TCP Brutal does nothing (Brutal holds one connection), so the save refuses it
	// rather than store a setting whose change would be a review row that changes nothing.
	body, _ = json.Marshal(muxServerEndpoint("brutal", model.ProtoTrojan, &model.Multiplex{Enabled: true, MaxConnections: 4, MinStreams: 4,
		Brutal: &model.Brutal{Enabled: true, UpMbps: 50, DownMbps: 100}}))
	w = httptest.NewRecorder()
	s.handleUpsertEndpoint(w, httptest.NewRequest(http.MethodPost, "/api/endpoints", strings.NewReader(string(body))))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "combined with TCP Brutal") {
		t.Fatalf("upsert pool beside Brutal: %d %s", w.Code, w.Body.String())
	}

	text := "proxies:\n  - {name: t, type: trojan, server: 192.0.2.51, port: 443, password: pw, smux: {enabled: true, only-tcp: true}}\n"
	req, _ := json.Marshal(map[string]string{"text": text})
	w = httptest.NewRecorder()
	s.handleSubscription(w, httptest.NewRequest(http.MethodPost, "/api/subscription", strings.NewReader(string(req))))
	var r struct {
		Endpoints []model.Endpoint `json:"endpoints"`
		Notes     []string         `json:"notes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil || w.Code != http.StatusOK {
		t.Fatalf("subscription: %d %s", w.Code, w.Body.String())
	}
	if len(r.Endpoints) != 1 || r.Endpoints[0].Multiplex == nil || len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "only-tcp") {
		t.Fatalf("subscription answer: %s", w.Body.String())
	}
}
