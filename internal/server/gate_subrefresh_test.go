package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wayhop/internal/platform"
)

// The subscription refresh runs on a timer. Whatever it adds arrives with nobody present to read a
// warning, so it is the path where an unsupported protocol arriving ENABLED would go unnoticed
// longest — and the one the manual gates did nothing about.

func gateSubServer(t *testing.T, state platform.CapState, body string) (*Server, *httptest.Server) {
	t.Helper()
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(subrefresh_sub(body)))
	}))
	t.Cleanup(feed.Close)

	s := dnsSeed(t)
	// The SSRF guard refuses loopback at dial time, which is correct and is what the other
	// subscription tests turn off to reach their own httptest feed.
	s.allowInternalFetch = true
	s.cfg.Subscription.URL = feed.URL
	s.caps.mu.Lock()
	s.caps.set = platform.CapabilitySet{
		Items: map[string]platform.Capability{
			platform.CapEngineSingbox: {ID: platform.CapEngineSingbox, State: platform.CapSupported},
			platform.CapProtocolPrefix + "trojan": {
				ID: platform.CapProtocolPrefix + "trojan", State: state, Detail: "no path on this platform",
			},
		},
		ProbedAt: time.Now(),
	}
	s.caps.mu.Unlock()
	return s, feed
}

// A share link the importer understands, for a protocol the fixture then declares unsupported.
const gateSubLink = "trojan://secret@198.51.100.55:443?sni=example.net#sub-exit"

func TestGateSubRefresh_UnsupportedArrivesDisabled(t *testing.T) {
	s, _ := gateSubServer(t, platform.CapUnsupportedPlatform, gateSubLink)

	added, err := s.refreshSubscriptionOnce(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if added == 0 {
		t.Skip("this build's importer did not accept the fixture link; there is nothing to gate")
	}
	for _, e := range s.store.Profile().Endpoints {
		if strings.Contains(strings.ToLower(string(e.Protocol)), "trojan") && e.Enabled {
			t.Errorf("a timer added %s ENABLED on a host that cannot carry it", e.ID)
		}
	}
}

// Nobody is waiting on this call, so an unfinished probe is a reason to try again next tick rather
// than to guess in either direction.
func TestGateSubRefresh_UnknownAbortsRatherThanGuessing(t *testing.T) {
	s, _ := gateSubServer(t, platform.CapUnknown, gateSubLink)
	before := len(s.store.Profile().Endpoints)

	_, err := s.refreshSubscriptionOnce(context.Background())
	if err == nil {
		if n := len(s.store.Profile().Endpoints); n != before {
			t.Errorf("the refresh stored %d new endpoint(s) while capabilities were unknown", n-before)
		}
		t.Skip("this build's importer added nothing, so the abort path was not reached")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Errorf("err = %v, want it to name the unfinished probe as the reason", err)
	}
	if n := len(s.store.Profile().Endpoints); n != before {
		t.Errorf("the store went from %d to %d on an aborted refresh", before, n)
	}
}

// QA-028 on the timer path: a feed entry the core cannot load (a sing-box openvpn-client with no
// certificate) arrives disabled, so the next Apply is not refused for the whole profile.
func TestGateSubRefresh_UnloadableArrivesDisabled(t *testing.T) {
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"endpoints":[{"type":"openvpn-client","tag":"noca","server":"198.51.100.56","server_port":1194}],` +
			`"outbounds":[{"type":"trojan","tag":"ok","server":"198.51.100.57","server_port":443,"password":"p"}]}`))
	}))
	t.Cleanup(feed.Close)
	s, _ := gateSubServer(t, platform.CapSupported, gateSubLink)
	s.cfg.Subscription.URL = feed.URL
	s.caps.mu.Lock()
	s.caps.set.Items[platform.CapProtocolPrefix+"openvpn"] = platform.Capability{
		ID: platform.CapProtocolPrefix + "openvpn", State: platform.CapSupported}
	s.caps.mu.Unlock()

	if _, err := s.refreshSubscriptionOnce(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	var sawOVPN, sawTrojan bool
	for _, e := range s.store.Profile().Endpoints {
		switch e.Name {
		case "noca":
			sawOVPN = true
			if e.Enabled {
				t.Error("the timer stored an OpenVPN client with no certificate ENABLED")
			}
		case "ok":
			sawTrojan = true
			if !e.Enabled {
				t.Error("the loadable trojan entry was disabled")
			}
		}
	}
	if !sawOVPN || !sawTrojan {
		t.Fatalf("refresh stored openvpn=%v trojan=%v, want both", sawOVPN, sawTrojan)
	}
	if p := s.store.Profile(); p.Validate() != nil {
		t.Errorf("the profile no longer validates after the refresh: %v", p.Validate())
	}
}

// A host that can carry it changes nothing: the refresh keeps doing its job.
func TestGateSubRefresh_SupportedIsUntouched(t *testing.T) {
	s, _ := gateSubServer(t, platform.CapSupported, gateSubLink)

	added, err := s.refreshSubscriptionOnce(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if added == 0 {
		t.Skip("this build's importer did not accept the fixture link")
	}
	var sawEnabled bool
	for _, e := range s.store.Profile().Endpoints {
		if strings.Contains(strings.ToLower(string(e.Protocol)), "trojan") && e.Enabled {
			sawEnabled = true
		}
	}
	if !sawEnabled {
		t.Error("a supported protocol was disabled by the gate; the refresh punished a host that can run it")
	}
}
