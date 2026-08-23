package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"wayhop/internal/clash"
	"wayhop/internal/config"
	"wayhop/internal/core"
	"wayhop/internal/health"
	"wayhop/internal/serverstore"
	"wayhop/internal/store"
	"wayhop/internal/traffic"
	"wayhop/web"
)

// clashsurface_recorder is a live stub Clash controller. Unlike the loopback
// address the other harnesses use (never dialed), this one ACCEPTS connections
// and records every request that reaches it — so the assertion "the panel
// cannot reach the controller" is made against a controller that would have
// answered, not against a connection error that merely looks like a refusal.
type clashsurface_recorder struct {
	mu   sync.Mutex
	seen []string // "METHOD path" for every request that got through
}

func (r *clashsurface_recorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.seen = append(r.seen, req.Method+" "+req.URL.Path)
		r.mu.Unlock()
		_, _ = w.Write([]byte(`{"version":"stub"}`))
	})
}

func (r *clashsurface_recorder) hits() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

// clashsurface_newServer builds a full *Server through the real constructor,
// wired exactly like routing_newServer, except the clash.Client points at addr
// — the live recording stub above — with a sentinel bearer secret. If any
// route forwards to the controller, the stub records it.
func clashsurface_newServer(t *testing.T, addr string) http.Handler {
	t.Helper()
	dir := t.TempDir()

	cfgPath := filepath.Join(dir, "config.json")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.Demo = true
	cfg.SingBox.Bin = filepath.Join(dir, "sbin", "no-such-sing-box")
	cfg.SingBox.Config = filepath.Join(dir, "etc", "singbox.json")
	cfg.Clash.Controller = addr
	cfg.Clash.Secret = "internal-bearer-sentinel"

	hub := traffic.NewHub(50)

	cl, err := clash.New(cfg.Clash.Controller, cfg.Clash.Secret)
	if err != nil {
		t.Fatalf("clash.New: %v", err)
	}

	sb := core.New(cfg.SingBox.Bin, cfg.SingBox.Config)
	if sb.Available() {
		t.Fatalf("test setup broken: sing-box reports available at %q", cfg.SingBox.Bin)
	}

	st, err := store.Open(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	mon := health.NewMonitor(cl, st, sb, cfg.Demo)

	ss, err := serverstore.Open(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatalf("serverstore.Open: %v", err)
	}

	srv := New(cfg, hub, cl, sb, st, mon, ss, web.FS())
	return authenticatedTestHandler(t, srv)
}

// TestClashControllerNotReachableThroughPanel is the LOOP-009 boundary: the
// panel must expose NO route that forwards to the sing-box Clash controller.
// The controller's bearer secret exists so that only the daemon itself may
// speak to the controller; a pass-through mount under /api/clash/ handed that
// authority to any unauthenticated LAN client, for every method and every
// suffix path the controller understands — including ones a future sing-box
// adds. The UI never calls /api/clash/*: every Clash-derived view reaches it
// through typed server endpoints (/api/traffic/outbounds, health, connections),
// so the only client such a mount can serve is one this daemon never meant to.
//
// Two assertions, both required:
//   - every /api/clash/* request answers 404 (the mount does not exist, rather
//     than being auth-gated, status-mapped or method-filtered);
//   - the live stub controller saw ZERO requests — proving no forward happened,
//     not merely that a status code got rewritten on the way back.
func TestClashControllerNotReachableThroughPanel(t *testing.T) {
	rec := &clashsurface_recorder{}
	controller := httptest.NewServer(rec.handler())
	defer controller.Close()

	h := clashsurface_newServer(t, strings.TrimPrefix(controller.URL, "http://"))
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Read sweep: the exact endpoints the review exercised live (version,
	// connections), the config surface, a delay probe with a query string, the
	// bare mount, and an encoded traversal towards a sibling suffix.
	gets := []string{
		"/api/clash",
		"/api/clash/",
		"/api/clash/version",
		"/api/clash/connections",
		"/api/clash/configs",
		"/api/clash/proxies/GLOBAL/delay?timeout=1&url=http%3A%2F%2Fexample.com",
		"/api/clash/..%2Fconfigs",
	}
	for _, p := range gets {
		code, body, _ := routing_do(t, ts, http.MethodGet, p)
		if code != http.StatusNotFound {
			t.Errorf("GET %s: got %d (%.60q), want 404 — a reachable Clash surface reopens LOOP-009", p, code, body)
		}
	}

	// Mutation sweep on the most consequential suffix: the controller's config
	// endpoint. No method may reach it; 404 because the mount is absent, not
	// 405 from a method filter that would still admit the mount exists.
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		code, body, _ := routing_do(t, ts, m, "/api/clash/configs")
		if code != http.StatusNotFound {
			t.Errorf("%s /api/clash/configs: got %d (%.60q), want 404", m, code, body)
		}
	}

	if hits := rec.hits(); len(hits) != 0 {
		t.Fatalf("the stub controller received %d request(s) through the panel: %s — the internal bearer must never back a panel route", len(hits), fmt.Sprintf("%v", hits))
	}
}
