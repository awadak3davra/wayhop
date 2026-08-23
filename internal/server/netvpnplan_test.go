package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/netvpn"
	"wayhop/internal/pbr"
	"wayhop/internal/store"
	"wayhop/internal/util"
)

// importedAWG is what the importer leaves in memory after parsing an AmneziaWG .conf: real Go types
// — int for numbers, []string for lists, []map[string]any for the peer list.
func importedAWG() model.Endpoint {
	return model.Endpoint{
		ID:       "ep-awg-1",
		Name:     "nl",
		Protocol: model.ProtoAmneziaWG,
		Server:   "203.0.113.7",
		Port:     8443,
		MTU:      1320,
		Params: map[string]any{
			"private_key":   "cHJpdmF0ZQ==",
			"local_address": []string{"10.0.0.30/32"},
			"jc":            5, "jmin": 49, "jmax": 998,
			"s1": 0, "s2": 0, "s3": 25, "s4": 40,
			"h1": "500000000-900000000", "h2": "1000000000-1400000000",
			"h3": "1500000000-1900000000", "h4": "2000000000-2400000000",
			// Synthetic AmneziaWG magic headers. These were the owner's REAL i1..i5 values in
			// truncated 8-digit form — the sibling fixtures carry them full-length, where the
			// publish scrub rewrites them, and a shortened copy matched no replace rule and so
			// travelled unscrubbed into the public tree. The audit caught it; the values are
			// arbitrary to the assertions below, so they are arbitrary here too.
			"i1": "0x11111111", "i2": "0x22222222", "i3": "0x33333333",
			"i4": "0x44444444", "i5": "0x55555555",
			"peers": []map[string]any{{
				"server":               "203.0.113.7",
				"port":                 8443,
				"public_key":           "cHVibGlj",
				"allowed_ips":          []string{"0.0.0.0/0"},
				"persistent_keepalive": 21,
			}},
		},
	}
}

// throughStore is what the SAME endpoint looks like after being saved and loaded again: every number
// is a float64 and every list an []any, because that is what JSON gives back.
func throughStore(t *testing.T, e model.Endpoint) model.Endpoint {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var out model.Endpoint
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// The defect this file exists to prevent. A converter written against the importer's in-memory
// types works on a freshly imported endpoint and produces an interface with no obfuscation, no
// addresses and no peers for every endpoint that has ever been saved — which is all of them, in
// every real profile. The two paths must produce identical results.
func TestAWGInterfaceFromEndpoint_SurvivesTheStoreRoundTrip(t *testing.T) {
	fresh, err := awgInterfaceFromEndpoint(importedAWG(), derivedTestIface())
	if err != nil {
		t.Fatal(err)
	}
	saved, err := awgInterfaceFromEndpoint(throughStore(t, importedAWG()), derivedTestIface())
	if err != nil {
		t.Fatalf("the same endpoint failed to convert after a JSON round trip: %v", err)
	}

	if len(fresh.Obfuscation) != 16 {
		t.Fatalf("the in-memory endpoint yielded %d obfuscation params, want all 16", len(fresh.Obfuscation))
	}
	if len(saved.Obfuscation) != len(fresh.Obfuscation) {
		t.Errorf("obfuscation survived the store as %d params, was %d — numbers arrive as float64 and were dropped",
			len(saved.Obfuscation), len(fresh.Obfuscation))
	}
	for k, v := range fresh.Obfuscation {
		if saved.Obfuscation[k] != v {
			t.Errorf("param %s: in memory %q, after the store %q", k, v, saved.Obfuscation[k])
		}
	}
	if len(saved.Addresses) != 1 || saved.Addresses[0] != "10.0.0.30/32" {
		t.Errorf("addresses did not survive the store: %v", saved.Addresses)
	}
	if len(saved.Peers) != 1 {
		t.Fatalf("peers did not survive the store: %d", len(saved.Peers))
	}
	if saved.Peers[0].PersistentKeepalive != 21 || saved.Peers[0].EndpointPort != 8443 {
		t.Errorf("peer numbers did not survive: keepalive=%d port=%d",
			saved.Peers[0].PersistentKeepalive, saved.Peers[0].EndpointPort)
	}
	if len(saved.Peers[0].AllowedIPs) != 1 {
		t.Errorf("allowed_ips did not survive the store: %v", saved.Peers[0].AllowedIPs)
	}
}

// The commonest endpoint of all — a single peer left in Server/Port/peer_public_key rather than in
// a peers list. Reading only the list would produce an interface with no peers and no error.
func TestAWGInterfaceFromEndpoint_ReadsTheFlatSinglePeerShape(t *testing.T) {
	e := importedAWG()
	delete(e.Params, "peers")
	e.Params["peer_public_key"] = "cHVibGlj"
	e.Params["allowed_ips"] = []string{"10.0.0.0/8"}
	e.PersistentKeepalive = 25

	for _, tc := range []struct {
		name string
		ep   model.Endpoint
	}{{"in memory", e}, {"after the store", throughStore(t, e)}} {
		iface, err := awgInterfaceFromEndpoint(tc.ep, derivedTestIface())
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(iface.Peers) != 1 {
			t.Fatalf("%s: the flat peer was not read: %d peers", tc.name, len(iface.Peers))
		}
		p := iface.Peers[0]
		if p.EndpointHost != "203.0.113.7" || p.EndpointPort != 8443 || p.PersistentKeepalive != 25 {
			t.Errorf("%s: peer read as %s:%d keepalive=%d", tc.name, p.EndpointHost, p.EndpointPort, p.PersistentKeepalive)
		}
	}
}

// An endpoint that could never work must be refused, not half-converted. A tunnel written without a
// key or without a peer comes up, sits there, and routes nothing — and looks configured in LuCI.
func TestAWGInterfaceFromEndpoint_RefusesWhatCouldNotWork(t *testing.T) {
	noKey := importedAWG()
	noKey.Params["private_key"] = ""
	if _, err := awgInterfaceFromEndpoint(noKey, derivedTestIface()); err == nil {
		t.Error("an endpoint with no private key was converted")
	}

	noPeer := importedAWG()
	delete(noPeer.Params, "peers")
	if _, err := awgInterfaceFromEndpoint(noPeer, derivedTestIface()); err == nil {
		t.Error("an endpoint with no peer was converted")
	}

	// A peer entry with no public key is not a peer; it must not be counted as one.
	blank := importedAWG()
	blank.Params["peers"] = []map[string]any{{"server": "203.0.113.7", "port": 8443}}
	if _, err := awgInterfaceFromEndpoint(blank, derivedTestIface()); err == nil {
		t.Error("a peer with no public key was accepted")
	}
}

// The name is interpolated into `uci set network.<name>=interface` and reaches a shell. Anything
// that is not a plain uci section name has to be refused here, at the boundary.
func TestValidUCIName_RejectsWhatWouldReachTheShell(t *testing.T) {
	for _, bad := range []string{
		"", "awg 0", "awg;reboot", "awg$(id)", "awg`id`", "awg'x", "awg\"x", "awg/0", "awg.0",
		"averyverylongifacename",
	} {
		if err := validUCIName(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, ok := range []string{"awg0", "wh_ep_awg_1", "A1_b"} {
		if err := validUCIName(ok); err != nil {
			t.Errorf("rejected the legal name %q: %v", ok, err)
		}
	}

	// And the converter has to CALL it. Testing validUCIName on its own leaves the function free to
	// stop using it — the guard would still be correct, still tested, and no longer reached, which is
	// how a boundary check quietly stops being one.
	for _, bad := range []string{"awg;reboot", "awg $(id)", ""} {
		if _, err := awgInterfaceFromEndpoint(importedAWG(), bad); err == nil {
			t.Errorf("the converter accepted the interface name %q without validating it", bad)
		}
	}
}

// The derived name has to be legal by construction, including for ids full of characters uci does
// not take — otherwise the failure surfaces as a refused write much later.
func TestDefaultIfaceName_IsAlwaysLegal(t *testing.T) {
	for _, id := range []string{
		"ep-awg-1", "a", "", "endpoint with spaces and a very long tail indeed",
		"UPPER-CASE-ID", "!!!", "ep.awg/1",
	} {
		name := defaultIfaceName(model.Endpoint{ID: id})
		if err := validUCIName(name); err != nil {
			t.Errorf("id %q produced %q, which uci would refuse: %v", id, name, err)
		}
		// It must be the SAME identity the rest of the daemon derives for this endpoint, only made
		// uci-legal. Anything else and the writer creates one device while the routing plane points
		// at another.
		if want := strings.ReplaceAll(util.AWGIface(id), "-", "_"); name != want {
			t.Errorf("id %q produced %q; the daemon's own name for it is %q", id, name, want)
		}
	}
}

// The refusal that matters most. A router whose configuration cannot be read produces the same
// empty `uci show` output as a router with nothing configured — and a plan built from the second is
// a plan to create an interface, while a plan built from the first could overwrite a working one.
// The handler must say it could not read, not hand back a plan.
func TestHandleNetvpnPlan_UnreadableRouterIsNotAnEmptyOne(t *testing.T) {
	st := storeWithAWG(t)
	fail := &Server{store: st, uciReader: func() (string, string, error) {
		return "", "", errors.New("uci: Permission denied")
	}}
	rec := httptest.NewRecorder()
	fail.handleNetvpnPlan(rec, httptest.NewRequest("GET", "/api/netvpn/plan?endpoint=ep-awg-1", nil))

	if rec.Code == http.StatusOK {
		t.Fatalf("an unreadable router produced a plan: %s", rec.Body.String())
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d, want 503 so a client can tell this apart from a bad request", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Permission denied") {
		t.Errorf("the reason the router could not be read was swallowed: %s", rec.Body.String())
	}
}

// And the working case: a readable router yields the exact commands, with route_allowed_ips='0'
// among them — the option the whole design rests on, checked here so a refactor cannot quietly drop
// it and still return a plausible-looking plan.
func TestHandleNetvpnPlan_ReturnsTheExactCommands(t *testing.T) {
	st := storeWithAWG(t)
	ok := &Server{
		store: st,
		uciReader: func() (string, string, error) {
			return "network.lan=interface\n", "firewall.@zone[0]=zone\nfirewall.@zone[0].name='vpn'\n", nil
		},
		netifdProtosOf: func() netvpn.RouterProtos {
			return netvpn.RouterProtos{"amneziawg": true}
		},
	}
	rec := httptest.NewRecorder()
	ok.handleNetvpnPlan(rec, httptest.NewRequest("GET", "/api/netvpn/plan?endpoint=ep-awg-1&iface=&zone=vpn", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Iface    string   `json:"iface"`
		Exists   bool     `json:"exists"`
		Zone     string   `json:"zone"`
		Commands []string `json:"commands"`
		Commit   []string `json:"commit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Iface != derivedTestIface() || got.Exists || got.Zone != "vpn" {
		t.Errorf("iface=%q exists=%v zone=%q", got.Iface, got.Exists, got.Zone)
	}
	joined := strings.Join(got.Commands, "\n")
	for _, want := range []string{
		"uci set network." + derivedTestIface() + ".proto=" + "'amneziawg'",
		"uci set network." + derivedTestIface() + ".awg_s4=" + "'40'",
		"uci set network." + derivedTestIface() + ".awg_i5=" + "'0x55555555'",
		"=amneziawg_" + derivedTestIface(),
		"route_allowed_ips='0'",
		"add_list firewall.@zone[0].network='" + derivedTestIface() + "'",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the plan does not contain %q:\n%s", want, joined)
		}
	}
	// The preview must not be able to apply itself: nothing staged may commit or reload.
	for _, c := range got.Commands {
		if strings.Contains(c, "commit") || strings.Contains(c, "reload") {
			t.Errorf("a mutating command is in the previewable half: %q", c)
		}
	}
	if len(got.Commit) == 0 {
		t.Error("the commit tail is missing, so a client cannot show what applying would run")
	}
}

// storeWithAWG gives the handler a real store holding one AmneziaWG endpoint — real rather than a
// stub so the endpoint goes through the same JSON persistence every profile does, which is the
// shape the converter has to survive.
func storeWithAWG(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	e := importedAWG()
	e.Enabled = true
	if err := st.UpsertEndpoint(e); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	return st
}

// The defect this pairing exists to prevent, end to end: the uci writer creates a device and the
// routing plane installs `ip route ... dev <name>` for the same endpoint. If the two names differ,
// the tunnel appears in LuCI, is configured correctly, and carries nothing — routes pointing at a
// device that does not exist. That is exactly what happened: the writer invented `wh_<id>` while
// pbr.kernelIface derived `wr-<hex>`, and no test related the two.
func TestWrittenInterfaceIsTheOneTheRoutingPlaneUses(t *testing.T) {
	ep := importedAWG()
	ep.Engine = model.EngineAmneziaWG
	ep.Enabled = true
	written := defaultIfaceName(ep)

	if err := validUCIName(written); err != nil {
		t.Fatalf("the name the writer would use is not a legal uci section name: %v", err)
	}
	// The apply path records what it created; that is what the compiler must then route through.
	ep.Params["interface"] = written

	prof := model.Profile{
		Endpoints: []model.Endpoint{ep},
		Groups:    []model.Group{},
		Rules:     []model.Rule{{ID: "r1", Outbound: ep.ID, IPCIDR: []string{"10.0.0.0/8"}}},
	}
	plan, _, err := pbr.Compile(&prof, pbr.Options{})
	if err != nil || plan == nil {
		t.Fatalf("compile: %v", err)
	}

	var routed []string
	for _, e := range plan.Egresses {
		if e.Kind == pbr.EgressInterface {
			routed = append(routed, e.Iface)
		}
	}
	if len(routed) == 0 {
		t.Fatalf("the plan routes through no interface at all, so this compares nothing: %+v", plan.Egresses)
	}
	for _, got := range routed {
		if got != written {
			t.Errorf("the writer creates %q and the routing plane sends traffic out %q; one of them "+
				"names a device that does not exist", written, got)
		}
	}
}

// The name the writer will use for the fixture endpoint, derived rather than spelled out, so these
// tests cannot drift from the identity function the way the writer once did.
func derivedTestIface() string { return defaultIfaceName(importedAWG()) }
