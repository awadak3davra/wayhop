package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wayhop/internal/awg"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// QA-133. Before KeeneticOS 4.2 the router's own AmneziaWG cannot create a connection (QA-127), and the
// planner runs one on WayHop's amneziawg-go instead - but the save check asked only for the native
// operations, so a new AmneziaWG connection could not be saved at all. Release strings are invented;
// only their shape is the firmware's.

// qa133Capabilities is the set a KeeneticOS release evaluates to with its WireGuard component installed
// (decideKeenetic: no AmneziaWG of its own below 4.2) and NDM driven for every operation.
func qa133Capabilities(release string) platform.CapabilitySet {
	gen, _ := platform.KeeneticReleaseAWG(release)
	native := map[string]bool{"wireguard": true, "amneziawg": gen != awg.GenNone}
	ops := map[string]bool{}
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, op := range []platform.NativeOperation{platform.NativeAdopt, platform.NativeCreate, platform.NativeRemove} {
			ops[platform.NativeOperationCapabilityID(protocol, op)] = true
		}
	}
	set := platform.Evaluate(platform.Capabilities{Platform: string(platform.Keenetic), FirmwareRelease: release,
		Native: native, Installable: map[string]string{}}, platform.RuntimeFacts{NativeOperations: ops})
	set.ProbedAt = time.Now()
	return set
}

// qa133Server is a router (not the demo) on p with set, /dev/net/tun as tun says, and amneziawg-go
// installed or not. It has no Updater: whether one could install amneziawg-go is the Apply review's
// question, not the save check's.
func qa133Server(t *testing.T, p platform.Platform, set platform.CapabilitySet, tun, installed bool) *Server {
	t.Helper()
	s := applyhealth_server(t)
	s.cfg.Demo = false
	s.platformOf = func() platform.Platform { return p }
	s.awgProbeOf = func() awg.Probe { return awg.Probe{Kernel: awg.GenNone, TUN: tun} }
	s.binaryPresentOf = func(name string) bool { return installed && name == "amneziawg-go" }
	s.caps.mu.Lock()
	s.caps.set = set
	s.caps.mu.Unlock()
	return s
}

func qa133Endpoint(id string) model.Endpoint {
	return model.Endpoint{ID: id, Name: id, Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
		Server: "203.0.113.40", Port: 51820, Enabled: true, Params: map[string]any{
			"private_key": "fixture-private", "peer_public_key": "fixture-public",
			"local_address": []string{"10.66.0.2/32"}, "allowed_ips": []string{"0.0.0.0/0"},
			"jc": 4, "jmin": 10, "jmax": 50, "s1": 20, "s2": 30, "h1": "1", "h2": "2", "h3": "3", "h4": "4",
		}}
}

const (
	qa133Release41 = "4.01.A.3.0-0" // no `wireguard asc`
	qa133Release50 = "5.00.B.1.0-0" // AmneziaWG 1 settings only
	qa133Release51 = "5.01.A.2.0-0" // the writer's whole generation
)

// The hunt's repro, now accepted: KeeneticOS 4.1, /dev/net/tun present, amneziawg-go installed.
func TestQA133Pre42AWGSavesOnThePlugin(t *testing.T) {
	s := qa133Server(t, platform.Keenetic, qa133Capabilities(qa133Release41), true, true)
	if code, msg := s.gateEndpoint(context.Background(), qa133Endpoint("awg-new")); code != 0 {
		t.Fatalf("gate = %d %q, want accepted: the plugin carries it", code, msg)
	}
	body, _ := json.Marshal(qa133Endpoint("awg-new"))
	w := httptest.NewRecorder()
	s.handleUpsertEndpoint(w, httptest.NewRequest(http.MethodPost, "/api/endpoints", strings.NewReader(string(body))))
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/endpoints = %d %s", w.Code, w.Body.String())
	}
	prof := s.store.Profile()
	if got := prof.EndpointByID("awg-new"); got == nil || !got.Enabled {
		t.Fatalf("stored = %+v, want enabled", got)
	}
}

// Not installed yet: the save stands, and the Apply review asks for the install
// (endpoint.engine.amneziawg_go), which the Components page makes. The save check asks nothing of the
// Updater: every WayHop has one, and the arches it ships are the arches amneziawg-go is built for.
func TestQA133Pre42AWGSavesWhileThePluginIsNotInstalled(t *testing.T) {
	s := qa133Server(t, platform.Keenetic, qa133Capabilities(qa133Release41), true, false)
	if code, msg := s.gateEndpoint(context.Background(), qa133Endpoint("awg-new")); code != 0 {
		t.Fatalf("gate = %d %q, want accepted: the Apply review asks for amneziawg-go", code, msg)
	}
}

// Neither carries it: no /dev/net/tun, so amneziawg-go cannot run. Refused, naming both reasons.
func TestQA133Pre42AWGRefusedWhenThePluginCannotCarryIt(t *testing.T) {
	s := qa133Server(t, platform.Keenetic, qa133Capabilities(qa133Release41), false, true)
	code, msg := s.gateEndpoint(context.Background(), qa133Endpoint("awg-new"))
	if code != http.StatusUnprocessableEntity || !strings.Contains(msg, "4.2") ||
		!strings.Contains(msg, "/dev/net/tun is missing") || !strings.Contains(msg, "Save it disabled") {
		t.Fatalf("gate = %d %q, want 422 naming the firmware and the TUN", code, msg)
	}
}

// KeeneticOS 5.1 carries it natively, and 4.2 to 5.0 an AmneziaWG 1 one: accepted whatever the plugin,
// as before. Where the router's own could create it but the planner still hands it to WayHop's engine
// - AmneziaWG 2 settings on 4.2 to 5.0, or the engine set to amneziawg-go by hand - the engine runs it,
// and with /dev/net/tun it can.
func TestQA133NativeReleasesUnchanged(t *testing.T) {
	awg2 := qa133Endpoint("awg2")
	awg2.Params["s3"], awg2.Params["s4"] = 15, 25
	chosen := qa133Endpoint("chosen")
	chosen.AWGUserspace = true
	for _, tc := range []struct {
		release string
		ep      model.Endpoint
		tun     bool
	}{
		{qa133Release51, qa133Endpoint("awg1"), false},
		{qa133Release51, awg2, false},
		{qa133Release50, qa133Endpoint("awg1"), false},
		{qa133Release50, awg2, true},
		{qa133Release51, chosen, true},
	} {
		s := qa133Server(t, platform.Keenetic, qa133Capabilities(tc.release), tc.tun, false)
		if code, msg := s.gateEndpoint(context.Background(), tc.ep); code != 0 {
			t.Errorf("%s %s: gate = %d %q, want accepted", tc.release, tc.ep.ID, code, msg)
		}
	}
}

// The router's own creates it, but the planner hands it to WayHop's engine, and without /dev/net/tun
// that cannot run it: refused, saying why the engine would run it, why it cannot, and what would let
// the router run it. Accepted before, and every Apply then failed to bring it up.
func TestQA133EngineLaneWithoutTUNRefused(t *testing.T) {
	awg2 := qa133Endpoint("awg2")
	awg2.Params["s3"], awg2.Params["s4"] = 15, 25
	chosen := qa133Endpoint("chosen")
	chosen.AWGUserspace = true
	for _, tc := range []struct {
		release string
		ep      model.Endpoint
		want    []string
	}{
		{qa133Release50, awg2, []string{"AmneziaWG 2 settings", "s3", "/dev/net/tun is missing", "5.1"}},
		{qa133Release51, chosen, []string{"set to run on amneziawg-go", "/dev/net/tun is missing", "back to Automatic"}},
	} {
		s := qa133Server(t, platform.Keenetic, qa133Capabilities(tc.release), false, true)
		code, msg := s.gateEndpoint(context.Background(), tc.ep)
		if code != http.StatusUnprocessableEntity || !strings.Contains(msg, "WayHop's AmneziaWG engine") ||
			!strings.Contains(msg, "Save it disabled") {
			t.Errorf("%s %s: gate = %d %q, want 422 naming WayHop's engine", tc.release, tc.ep.ID, code, msg)
			continue
		}
		for _, want := range tc.want {
			if !strings.Contains(msg, want) {
				t.Errorf("%s %s: %q does not say %q", tc.release, tc.ep.ID, msg, want)
			}
		}
	}
}

// A probe that has not answered is still not a refusal and not a pass: 503, as before.
func TestQA133UnknownNativeStillAsksAgain(t *testing.T) {
	set := qa133Capabilities(qa133Release41)
	for _, op := range []platform.NativeOperation{platform.NativeCreate, platform.NativeRemove} {
		delete(set.Items, platform.NativeOperationCapabilityID("amneziawg", op))
	}
	s := qa133Server(t, platform.Keenetic, set, true, true)
	if code, msg := s.gateEndpoint(context.Background(), qa133Endpoint("awg-new")); code != http.StatusServiceUnavailable {
		t.Fatalf("gate = %d %q, want 503", code, msg)
	}
}

// OpenWrt without a native AmneziaWG is refused as before: its planner keeps no plugin lane there.
func TestQA133OpenWrtUnchanged(t *testing.T) {
	set := platform.Evaluate(platform.Capabilities{Platform: string(platform.OpenWrt), Native: map[string]bool{},
		NetifdProtos: map[string]bool{"wireguard": true}, Installable: map[string]string{"amneziawg": "kmod-amneziawg"}},
		platform.RuntimeFacts{})
	set.ProbedAt = time.Now()
	s := qa133Server(t, platform.OpenWrt, set, true, true)
	if code, msg := s.gateEndpoint(context.Background(), qa133Endpoint("awg-new")); code != http.StatusUnprocessableEntity {
		t.Fatalf("gate = %d %q, want 422 as before", code, msg)
	}
}

// A subscription's AmneziaWG entries arrive switched on where the plugin carries them.
func TestQA133SubscriptionEntryStoredOn(t *testing.T) {
	s := qa133Server(t, platform.Keenetic, qa133Capabilities(qa133Release41), true, true)
	body, _ := json.Marshal(map[string]any{"endpoints": []model.Endpoint{qa133Endpoint("sub-awg")}})
	w := httptest.NewRecorder()
	s.handleBulkEndpoints(w, httptest.NewRequest(http.MethodPost, "/api/endpoints/bulk", strings.NewReader(string(body))))
	var out struct {
		StoredDisabled []string `json:"stored_disabled"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if len(out.StoredDisabled) != 0 {
		t.Fatalf("stored_disabled = %q", out.StoredDisabled)
	}
	prof := s.store.Profile()
	if got := prof.EndpointByID("sub-awg"); got == nil || !got.Enabled {
		t.Fatalf("stored = %+v, want enabled", got)
	}
}

// The connection form asks the same check: a new AmneziaWG connection on KeeneticOS 4.1 is offered on
// WayHop's engine with the firmware named, not offered where the engine cannot run, and left to the
// native items on 5.1 and on OpenWrt.
func TestQA133PanelOffer(t *testing.T) {
	s := qa133Server(t, platform.Keenetic, qa133Capabilities(qa133Release41), true, false)
	offer, ok := s.enginePluginOffers(qa133Capabilities(qa133Release41))["amneziawg"]
	if !ok || !offer.Carried || offer.Installed || offer.Blocked != "" ||
		!strings.Contains(offer.Reason, "4.2") || !strings.Contains(offer.Remedy, "4.2") {
		t.Fatalf("4.1 offer = %+v (present %v), want carried, not installed, firmware named", offer, ok)
	}

	s = qa133Server(t, platform.Keenetic, qa133Capabilities(qa133Release41), false, true)
	offer = s.enginePluginOffers(qa133Capabilities(qa133Release41))["amneziawg"]
	if offer.Carried || !offer.Installed || !strings.Contains(offer.Blocked, "/dev/net/tun") {
		t.Fatalf("4.1 without TUN offer = %+v, want not carried, the TUN named", offer)
	}

	s = qa133Server(t, platform.Keenetic, qa133Capabilities(qa133Release51), true, true)
	if offers := s.enginePluginOffers(qa133Capabilities(qa133Release51)); len(offers) != 0 {
		t.Fatalf("5.1 offers = %+v, want none: the router's own creates it", offers)
	}
	set := platform.Evaluate(platform.Capabilities{Platform: string(platform.OpenWrt), Native: map[string]bool{},
		NetifdProtos: map[string]bool{"wireguard": true}, Installable: map[string]string{}}, platform.RuntimeFacts{})
	s = qa133Server(t, platform.OpenWrt, set, true, true)
	if offers := s.enginePluginOffers(set); len(offers) != 0 {
		t.Fatalf("OpenWrt offers = %+v, want none", offers)
	}
}

// /api/native/capabilities asks for the offers on every request. On OpenWrt the answer is always
// empty - a connection with no settings and the engine on Automatic stays on the router's own, or
// with no native AmneziaWG is not in the lane at all - so nothing there asks the host: the kernel
// module probe the lane would take may load the module.
func TestQA133OffersAskNoKernelOnOpenWrt(t *testing.T) {
	set := platform.Evaluate(platform.Capabilities{Platform: string(platform.OpenWrt), Native: map[string]bool{"amneziawg": true},
		NetifdProtos: map[string]bool{"wireguard": true, "amneziawg": true}, Installable: map[string]string{}}, platform.RuntimeFacts{})
	set.ProbedAt = time.Now()
	s := qa133Server(t, platform.OpenWrt, set, true, true)
	probes := 0
	s.awgProbeOf = func() awg.Probe { probes++; return awg.Probe{Kernel: awg.GenNone, TUN: true} }
	s.awgKernelReadsOf = &awgKernelReads{
		handler: func() ([]byte, bool) { probes++; return nil, false },
		module:  func() (string, bool) { probes++; return "", false },
	}
	if offers := s.enginePluginOffers(set); len(offers) != 0 {
		t.Fatalf("OpenWrt offers = %+v, want none", offers)
	}
	if probes != 0 {
		t.Fatalf("the offers asked the host %d time(s) on OpenWrt, want none", probes)
	}
}
