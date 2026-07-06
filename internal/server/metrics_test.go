package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/core"
	"wayhop/internal/health"
	"wayhop/internal/model"
	"wayhop/internal/store"
	"wayhop/internal/traffic"
	"wayhop/internal/version"
)

// metrics_server builds a *Server with a store + hub, mirroring the construction
// style of applyhealth_server. The sing-box binary path points at a non-existent
// file so Available()/Running() are both false.
func metrics_server(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()

	cfg := config.Default()
	cfg.SingBox.Bin = filepath.Join(dir, "no-such-sing-box")
	cfg.SingBox.Config = filepath.Join(dir, "out", "singbox.json")
	cfg.Demo = true

	st, err := store.Open(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	sb := core.New(cfg.SingBox.Bin, cfg.SingBox.Config)
	if sb.Available() {
		t.Fatalf("test setup broken: sing-box reports available at %q", cfg.SingBox.Bin)
	}
	return &Server{cfg: cfg, store: st, singbox: sb, hub: traffic.NewHub(8)}
}

// secretSubstrings are sensitive values that must NEVER appear in /metrics output.
const (
	metricsSecretUUID = "11111111-2222-3333-4444-555555555555"
	metricsSecretPass = "s3cr3t-passw0rd-do-not-leak"
)

// metrics_endpoint returns an enabled endpoint carrying secret Params (uuid +
// password) plus a name with characters that must be escaped in label values.
func metrics_endpoint(id, name string) model.Endpoint {
	return model.Endpoint{
		ID: id, Name: name, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "203.0.113.10", Port: 443, Enabled: true,
		Params: map[string]any{
			"uuid":     metricsSecretUUID,
			"password": metricsSecretPass,
		},
	}
}

func TestMetrics_StaticAndPerEndpoint(t *testing.T) {
	version.Version = "0.2.0-test"
	s := metrics_server(t)

	// Two enabled endpoints; the second name embeds a quote, backslash and unicode
	// to exercise label-value escaping.
	for _, e := range []model.Endpoint{
		metrics_endpoint("e1", "Reality"),
		metrics_endpoint("e2", `RU "Reserve"\тест`),
	} {
		if err := s.store.UpsertEndpoint(e); err != nil {
			t.Fatalf("UpsertEndpoint %s: %v", e.ID, err)
		}
	}

	// Demo monitor over the same store; a single deterministic tick synthesizes
	// alive/down stats so the snapshot has populated rows.
	mon := health.NewMonitor(nil, s.store, nil, true)
	s.monitor = mon
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mon.Run(ctx)

	// Push a traffic sample so the aggregate gauges have non-zero values.
	s.hub.Push(traffic.Sample{T: 1, Up: 4096, Down: 8192})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	s.handleMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}

	body := w.Body.String()

	// Static metrics with HELP/TYPE preamble.
	for _, want := range []string{
		"# HELP wayhop_build_info",
		"# TYPE wayhop_build_info gauge",
		`wayhop_build_info{version="0.2.0-test"} 1`,
		"# HELP wayhop_up",
		"wayhop_up 1",
		"# TYPE wayhop_singbox_running gauge",
		"wayhop_singbox_running 0",
		"wayhop_singbox_available 0",
		"wayhop_traffic_rx_bytes_per_second 8192",
		"wayhop_traffic_tx_bytes_per_second 4096",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}

	// Per-endpoint series with id/name/protocol labels.
	if !strings.Contains(body, `wayhop_endpoint_up{id="e1",name="Reality",protocol="vless"} `) {
		t.Errorf("missing e1 endpoint_up series in:\n%s", body)
	}

	// Label-value escaping: " -> \" , \ -> \\ , unicode preserved verbatim.
	wantEsc := `name="RU \"Reserve\"\\тест"`
	if !strings.Contains(body, wantEsc) {
		t.Errorf("escaped name label not found (want %q) in:\n%s", wantEsc, body)
	}
	// The raw (unescaped) form must NOT appear.
	if strings.Contains(body, `name="RU "Reserve"`) {
		t.Errorf("unescaped quote leaked into label in:\n%s", body)
	}

	// Stable ordering: e1's series must precede e2's.
	if i, j := strings.Index(body, `id="e1"`), strings.Index(body, `id="e2"`); i < 0 || j < 0 || i > j {
		t.Errorf("series not sorted by id (e1=%d e2=%d)", i, j)
	}

	// NO secret may leak into the exposition.
	if strings.Contains(body, metricsSecretUUID) {
		t.Errorf("uuid secret leaked into /metrics output")
	}
	if strings.Contains(body, metricsSecretPass) {
		t.Errorf("password secret leaked into /metrics output")
	}
}

func TestMetrics_NilMonitorAndHubStillServeStatic(t *testing.T) {
	version.Version = "0.2.0-nil"
	dir := t.TempDir()
	cfg := config.Default()
	cfg.SingBox.Bin = filepath.Join(dir, "no-such-sing-box")
	// Minimal Server: nil monitor, nil hub, nil singbox, nil store.
	s := &Server{cfg: cfg}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	s.handleMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	body := w.Body.String()
	for _, want := range []string{
		`wayhop_build_info{version="0.2.0-nil"} 1`,
		"wayhop_up 1",
		"wayhop_singbox_running 0",
		"wayhop_traffic_rx_bytes_per_second 0",
		"wayhop_traffic_tx_bytes_per_second 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}
