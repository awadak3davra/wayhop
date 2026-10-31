package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"wayhop/internal/platform"
)

// A gate on one handler is worth nothing if the bulk path walks around it — and bulk is where a
// subscription import lands, which is the largest source of protocols a given host may not have.

func gateBulkServer(t *testing.T, state platform.CapState) *Server {
	t.Helper()
	s := dnsSeed(t)
	s.caps.mu.Lock()
	s.caps.set = platform.CapabilitySet{
		Items: map[string]platform.Capability{
			platform.CapEngineSingbox: {
				ID: platform.CapEngineSingbox, State: platform.CapSupported,
			},
			platform.CapProtocolPrefix + "vless": {
				ID: platform.CapProtocolPrefix + "vless", State: state,
				Detail: "no path on this platform",
			},
			platform.CapProtocolPrefix + "trojan": {
				ID: platform.CapProtocolPrefix + "trojan", State: platform.CapSupported,
			},
		},
		ProbedAt: time.Now(),
	}
	s.caps.mu.Unlock()
	return s
}

const gateBulkBody = `{"endpoints":[
  {"id":"a","name":"a","engine":"singbox","protocol":"vless","server":"198.51.100.10","port":443,"enabled":true},
  {"id":"b","name":"b","engine":"singbox","protocol":"trojan","server":"198.51.100.11","port":443,"enabled":true}
]}`

// The import survives, the unsupported member arrives disabled, and the response says so. Refusing
// the whole batch would make importing a fifty-exit subscription an all-or-nothing bet on its
// weakest member; flipping enabled without saying so would be a silent edit of what was sent.
func TestGateBulk_UnsupportedArrivesDisabledAndIsReported(t *testing.T) {
	s := gateBulkServer(t, platform.CapUnsupportedPlatform)

	w := profilehandlers_post(s.handleBulkEndpoints, gateBulkBody)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 — the supported member must still import (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Saved          int      `json:"saved"`
		StoredDisabled []string `json:"stored_disabled"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response: %v", err)
	}
	if resp.Saved != 2 {
		t.Errorf("saved = %d, want 2: both are stored, one of them disabled", resp.Saved)
	}
	if len(resp.StoredDisabled) != 1 {
		t.Fatalf("stored_disabled = %v, want exactly the vless entry — an unreported flip is a silent edit", resp.StoredDisabled)
	}

	prof := s.store.Profile()
	var seenA, seenB bool
	for _, e := range prof.Endpoints {
		switch e.ID {
		case "a":
			seenA = true
			if e.Enabled {
				t.Error("the unsupported endpoint was stored ENABLED; the bulk path walked around the gate")
			}
		case "b":
			seenB = true
			if !e.Enabled {
				t.Error("the supported endpoint was disabled; the gate punished the wrong member")
			}
		}
	}
	if !seenA || !seenB {
		t.Errorf("both endpoints should be stored; got %+v", prof.Endpoints)
	}
}

// Unknown is not a verdict. Disabling would guess in one direction and enabling in the other, so the
// batch is refused and the caller is told to come back.
func TestGateBulk_UnknownRefusesTheBatch(t *testing.T) {
	s := gateBulkServer(t, platform.CapUnknown)
	// Against the profile as it stands, not against zero: the seeded server already holds endpoints,
	// and asserting an empty store would test the fixture rather than the refusal.
	before := len(s.store.Profile().Endpoints)

	w := profilehandlers_post(s.handleBulkEndpoints, gateBulkBody)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503 (%s)", w.Code, w.Body.String())
	}
	if n := len(s.store.Profile().Endpoints); n != before {
		t.Errorf("the store went from %d to %d endpoint(s) on a refused batch; a refusal that persists part of the input is not a refusal", before, n)
	}
}

// QA-028: an entry the core cannot load (an OpenVPN client with no certificate, as a pasted sing-box
// config can carry) arrives disabled and named, instead of enabled and failing every later Apply.
func TestGateBulk_UnloadableArrivesDisabled(t *testing.T) {
	s := gateBulkServer(t, platform.CapSupported)
	s.caps.mu.Lock()
	s.caps.set.Items[platform.CapProtocolPrefix+"openvpn"] = platform.Capability{
		ID: platform.CapProtocolPrefix + "openvpn", State: platform.CapSupported}
	s.caps.mu.Unlock()
	body := `{"endpoints":[
  {"id":"noca","name":"noca","engine":"singbox","protocol":"openvpn","server":"198.51.100.12","port":1194,"enabled":true,"params":{"ca":"","mode":"tls"}},
  {"id":"b","name":"b","engine":"singbox","protocol":"trojan","server":"198.51.100.11","port":443,"enabled":true}
]}`
	w := profilehandlers_post(s.handleBulkEndpoints, body)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		StoredDisabled []string `json:"stored_disabled"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response: %v", err)
	}
	if len(resp.StoredDisabled) != 1 || !strings.Contains(resp.StoredDisabled[0], "missing required ca") {
		t.Errorf("stored_disabled = %v, want the CA-less OpenVPN named with its reason", resp.StoredDisabled)
	}
	for _, e := range s.store.Profile().Endpoints {
		if e.ID == "noca" && e.Enabled {
			t.Error("the OpenVPN client with no certificate was stored enabled")
		}
		if e.ID == "b" && !e.Enabled {
			t.Error("the loadable endpoint was disabled")
		}
	}
	if p := s.store.Profile(); p.Validate() != nil {
		err := p.Validate()
		t.Errorf("the profile no longer validates after the import: %v", err)
	}
}

// QA-028 on the single save: enabled, the same entry is refused with the reason and the way to keep
// it; disabled, it saves as a draft.
func TestUpsertEndpoint_UnloadableEnabledIsRefused(t *testing.T) {
	s := gateBulkServer(t, platform.CapSupported)
	s.caps.mu.Lock()
	s.caps.set.Items[platform.CapProtocolPrefix+"openvpn"] = platform.Capability{
		ID: platform.CapProtocolPrefix + "openvpn", State: platform.CapSupported}
	s.caps.mu.Unlock()
	const ep = `{"id":"noca","name":"noca","engine":"singbox","protocol":"openvpn","server":"198.51.100.12","port":1194,"enabled":%v,"params":{"ca":"","mode":"tls"}}`

	w := profilehandlers_post(s.handleUpsertEndpoint, fmt.Sprintf(ep, true))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "missing required ca") ||
		!strings.Contains(w.Body.String(), "Save it disabled") {
		t.Errorf("enabled: got %d %s, want 422 naming the missing ca and the draft way out", w.Code, w.Body.String())
	}
	w = profilehandlers_post(s.handleUpsertEndpoint, fmt.Sprintf(ep, false))
	if w.Code != http.StatusOK {
		t.Errorf("disabled draft: got %d %s, want 200", w.Code, w.Body.String())
	}
}

// A host that can run everything in the batch changes nothing about it.
func TestGateBulk_SupportedBatchIsUntouched(t *testing.T) {
	s := gateBulkServer(t, platform.CapSupported)

	w := profilehandlers_post(s.handleBulkEndpoints, gateBulkBody)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	for _, e := range s.store.Profile().Endpoints {
		if !e.Enabled {
			t.Errorf("endpoint %s came back disabled on a host that supports it", e.ID)
		}
	}
}
