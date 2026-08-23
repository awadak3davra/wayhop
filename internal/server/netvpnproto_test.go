package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
	"wayhop/internal/store"
)

// The operator's endpoint, as their router actually holds it: protocol "wireguard", carried by
// sing-box. Until now the plan endpoint answered
//
//	{"error":"endpoint ... is wireguard; the uci writer is for amneziawg"}
//
// which is why it never appeared in LuCI.
func wgEndpoint() model.Endpoint {
	return model.Endpoint{
		ID: "ep-wg-1", Name: "WireGuard lax-310", Protocol: model.ProtoWireGuard,
		Engine: model.EngineSingBox, Server: "203.0.113.7", Port: 8443, Enabled: true, MTU: 1420,
		Params: map[string]any{
			"private_key":     "cHJpdmF0ZQ==",
			"peer_public_key": "cHVibGlj",
			"local_address":   []any{"10.0.0.30/32"},
		},
	}
}

func wgStore(t *testing.T) *store.Store { return storeWith(t, wgEndpoint()) }

// storeWith is storeWithAWG's shape with the endpoint as a parameter, so a test can vary one field
// without a second copy of the setup drifting away from the first.
func storeWith(t *testing.T, e model.Endpoint) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.UpsertEndpoint(e); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	return st
}

func protoServer(t *testing.T, st *store.Store, protos netvpn.RouterProtos) *Server {
	t.Helper()
	cfg := config.Default()
	cfg.Demo = false
	return &Server{
		cfg:            cfg,
		store:          st,
		uciReader:      emptyRouterUCI,
		platformOf:     func() platform.Platform { return platform.OpenWrt },
		netifdProtosOf: func() netvpn.RouterProtos { return protos },
	}
}

func planFor(t *testing.T, s *Server, id string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/netvpn/plan?endpoint="+id, nil)
	w := httptest.NewRecorder()
	s.handleNetvpnPlan(w, r)
	return w, w.Body.String()
}

// The whole point: a plain WireGuard endpoint on a router that carries amneziawg and not wireguard
// gets a plan, written as amneziawg, with the substitution said out loud.
func TestNetvpnPlan_WireGuardEndpointOnAnAmneziaWGOnlyRouter(t *testing.T) {
	s := protoServer(t, wgStore(t), netvpn.RouterProtos{"amneziawg": true})
	w, body := planFor(t, s, "ep-wg-1")

	if w.Code != http.StatusOK {
		t.Fatalf("status %d — the operator's endpoint is still refused: %s", w.Code, body)
	}
	if !strings.Contains(body, "proto='amneziawg'") {
		t.Errorf("not written as the protocol this router can carry:\n%s", body)
	}
	if !strings.Contains(body, "plain wireguard on the wire") {
		t.Errorf("the plan does not say the protocol was substituted, so LuCI would relabel it silently:\n%s", body)
	}
	// No obfuscation option: this must be plain WireGuard on the wire, or the peer will not answer.
	if strings.Contains(body, ".awg_") {
		t.Errorf("an obfuscation parameter was written:\n%s", body)
	}
}

// And on a router that has the real handler, it is written as itself.
func TestNetvpnPlan_WireGuardEndpointOnARouterThatHasWireGuard(t *testing.T) {
	s := protoServer(t, wgStore(t), netvpn.RouterProtos{"wireguard": true, "amneziawg": true})
	w, body := planFor(t, s, "ep-wg-1")

	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, body)
	}
	if !strings.Contains(body, "proto='wireguard'") {
		t.Errorf("a router with the wireguard handler did not get the real protocol:\n%s", body)
	}
	if !strings.Contains(body, "wireguard_") {
		t.Errorf("the peer section is not of the wireguard type:\n%s", body)
	}
}

// A router with neither handler refuses, and names what to install rather than saying "not supported".
func TestNetvpnPlan_RefusesWhenTheRouterCarriesNeitherHandler(t *testing.T) {
	s := protoServer(t, wgStore(t), netvpn.RouterProtos{"ppp": true})
	w, body := planFor(t, s, "ep-wg-1")

	if w.Code == http.StatusOK {
		t.Fatalf("a plan was produced for a router with no handler for it: %s", body)
	}
	for _, want := range []string{"wireguard.sh", "kmod-wireguard"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal does not mention %q: %s", want, body)
		}
	}
}

func TestNetvpnPlan_UnavailableHandlerProbeReturnsServiceUnavailable(t *testing.T) {
	s := protoServer(t, wgStore(t), nil)
	w, body := planFor(t, s, "ep-wg-1")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503 for unknown native capability: %s", w.Code, body)
	}
	if !strings.Contains(body, "not probed") || strings.Contains(body, "proto='") {
		t.Fatalf("unknown handler probe did not fail closed before rendering: %s", body)
	}
}

// A protocol with no native OpenWrt representation is refused for what it is, not for not being
// AmneziaWG. The old message named the writer's limitation; this one names the protocol's.
func TestNetvpnPlan_RefusesAProxyProtocolByName(t *testing.T) {
	e := wgEndpoint()
	e.Protocol = model.ProtoVLESS
	st := storeWith(t, e)
	s := protoServer(t, st, netvpn.RouterProtos{"amneziawg": true})
	w, body := planFor(t, s, "ep-wg-1")

	if w.Code == http.StatusOK {
		t.Fatalf("a proxy protocol was accepted into /etc/config/network: %s", body)
	}
	if !strings.Contains(body, "no native OpenWrt protocol") || !strings.Contains(body, "sing-box") {
		t.Errorf("the refusal does not explain what carries this endpoint instead: %s", body)
	}
}

// A WARP endpoint is refused rather than written: no native protocol has an option for the client id,
// so the tunnel would look perfect in LuCI and complete no handshake.
func TestNetvpnPlan_RefusesAWARPEndpoint(t *testing.T) {
	e := wgEndpoint()
	e.Params["reserved"] = []any{float64(1), float64(2), float64(3)}
	st := storeWith(t, e)
	s := protoServer(t, st, netvpn.RouterProtos{"amneziawg": true})
	w, body := planFor(t, s, "ep-wg-1")

	if w.Code == http.StatusOK {
		t.Fatalf("a WARP endpoint was written natively: %s", body)
	}
	if !strings.Contains(strings.ToLower(body), "warp") {
		t.Errorf("the refusal does not name WARP, so the operator cannot tell why: %s", body)
	}
}

// An endpoint with no interface address is refused. It would come up and carry nothing, and the
// differ would compare "" against "" and call it verified.
func TestNetvpnPlan_RefusesAnEndpointWithNoAddress(t *testing.T) {
	e := wgEndpoint()
	delete(e.Params, "local_address")
	st := storeWith(t, e)
	s := protoServer(t, st, netvpn.RouterProtos{"amneziawg": true})
	w, body := planFor(t, s, "ep-wg-1")

	if w.Code == http.StatusOK {
		t.Fatalf("an addressless interface was planned: %s", body)
	}
	if !strings.Contains(body, "address") {
		t.Errorf("the refusal does not name the missing field: %s", body)
	}
}
