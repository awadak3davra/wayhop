package server

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestEndpointCheckJudgesTheInterface (L5): "Check config" on a native connection used to report a
// verdict nothing had produced.
//
// A connection with Owner external is routed by pbr through an OS interface WayHop does not manage,
// and the whole of its configuration is that interface name. The handler asked sing-box instead.
// Measured on a live Keenetic: `sing-box check -c` over
// {"type":"direct","bind_interface":"iface-that-does-not-exist"} exits 0, exactly as it does over
// the real nwg1 — so the panel said "configuration is valid" for a connection whose only field was
// wrong. The verdict has to come from the router's interface list, which is the thing that decides.
func TestEndpointCheckJudgesTheInterface(t *testing.T) {
	s := dnsSeed(t)
	s.cfg.Demo = false // the shared harness is a demo; this claim is about a real router

	// One name taken from this host's own interface list (portable: "lo" is a Linux name and these
	// tests also run on Windows) and one that is a perfectly legal interface name but present on no
	// machine — the shape of a typo, which is the mistake this exists to catch.
	real := anyHostIface(t)
	for _, tc := range []struct {
		id, iface string
		wantOK    bool
	}{
		{"nat-ok", real, true},
		{"nat-gone", "whabsent0", false},
	} {
		ep := model.Endpoint{ID: tc.id, Name: tc.id, Owner: "external", Engine: model.EngineExternal,
			Enabled: true, Params: map[string]any{"interface": tc.iface}}
		if err := s.store.UpsertEndpoint(ep); err != nil {
			t.Fatalf("seed %s: %v", tc.id, err)
		}
		got := checkVerdict(t, s, tc.id)
		if got.CheckedBy != checkedByInterface {
			t.Errorf("%s: a native connection must be judged by %q, got %q — the engine does not carry it",
				tc.id, checkedByInterface, got.CheckedBy)
		}
		if got.OK != tc.wantOK {
			t.Errorf("%s (iface %q): ok=%v, want %v (%s)", tc.id, tc.iface, got.OK, tc.wantOK, got.Error)
		}
		if tc.wantOK {
			if got.Iface != tc.iface {
				t.Errorf("%s: the verdict must name the interface it checked, got %q", tc.id, got.Iface)
			}
			continue
		}
		// A failure that does not name the interface sends the operator to guess which field is wrong.
		if !strings.Contains(got.Error, tc.iface) {
			t.Errorf("%s: the reason must name the missing interface, got %q", tc.id, got.Error)
		}
	}
}

// TestEndpointCheckSparesManagedTunnels (L5): the same probe must not be applied to a tunnel WayHop
// itself brings up. An AmneziaWG device legitimately does not exist until Apply creates it, so
// judging it by the host's interface list would fail every new connection before it was ever
// applied — turning a fix for a false pass into a false failure.
func TestEndpointCheckSparesManagedTunnels(t *testing.T) {
	s := dnsSeed(t)
	s.cfg.Demo = false
	ep := model.Endpoint{ID: "awg-new", Name: "awg-new", Engine: model.EngineAmneziaWG, Enabled: true,
		Server: "198.51.100.9", Port: 51820, Params: map[string]any{
			"private_key":     "aGVsbG8gd29ybGQgdGhpcyBpcyAzMiBieXRlcyEh",
			"peer_public_key": "aGVsbG8gd29ybGQgdGhpcyBpcyAzMiBieXRlcyEh"}}
	if err := s.store.UpsertEndpoint(ep); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got := checkVerdict(t, s, "awg-new"); got.CheckedBy == checkedByInterface {
		t.Errorf("a WayHop-managed tunnel must not be judged by the live interface list: %+v", got)
	}
}

// TestEndpointCheckSparesTheDemo (L5): the demo has no awg0, no nwg1 and no router behind it, so
// probing the host's interface list there would paint every seeded native connection red — the demo
// exists to show the panel, not to report faults of the machine it runs on. It keeps the generator
// verdict, which already says out loud that nothing else was checked.
func TestEndpointCheckSparesTheDemo(t *testing.T) {
	s := dnsSeed(t) // Demo stays on
	ep := model.Endpoint{ID: "demo-nat", Name: "demo-nat", Owner: "external", Engine: model.EngineExternal,
		Enabled: true, Params: map[string]any{"interface": "awg0"}}
	if err := s.store.UpsertEndpoint(ep); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got := checkVerdict(t, s, "demo-nat")
	if got.CheckedBy == checkedByInterface {
		t.Errorf("the demo must not judge connections by this host's interfaces: %+v", got)
	}
	if !got.OK {
		t.Errorf("and must not fail them: %+v", got)
	}
}

// anyHostIface returns the name of an interface this machine really has.
func anyHostIface(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skipf("no interfaces to name here: %v", err)
	}
	return ifaces[0].Name
}

type checkResult struct {
	OK        bool   `json:"ok"`
	CheckedBy string `json:"checked_by"`
	Error     string `json:"error"`
	Iface     string `json:"iface"`
}

func checkVerdict(t *testing.T, s *Server, id string) checkResult {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/endpoints/"+id+"/check", nil)
	r.SetPathValue("id", id)
	w := httptest.NewRecorder()
	s.handleEndpointCheck(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: check should answer 200, got %d: %s", id, w.Code, w.Body)
	}
	var got checkResult
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("%s: decode: %v (%s)", id, err, w.Body)
	}
	return got
}
