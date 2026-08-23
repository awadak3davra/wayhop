package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// Deleting an endpoint a rule targets has always been refused. Switching that same endpoint OFF
// produced the identical broken profile and was answered 200 — as was aiming a fresh rule at one
// that is already off. Neither strands a reference, so no delete guard saw them; both leave a
// profile that fails Validate(), which means every later Apply fails, including applies that have
// nothing to do with the rule.

func disabledrefStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "p.json"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s
}

func disabledrefEndpoint(id string, enabled bool) model.Endpoint {
	return model.Endpoint{ID: id, Name: id, Engine: "singbox", Protocol: "trojan",
		Server: "198.51.100.11", Port: 443, Enabled: enabled,
		Params: map[string]any{"password": "x"}}
}

func TestDisabledRef_TurningOffAnEndpointALiveRuleTargetsIsRefused(t *testing.T) {
	s := disabledrefStore(t)
	if err := s.UpsertEndpoint(disabledrefEndpoint("e1", true)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.UpsertRule(model.Rule{ID: "r", Outbound: "e1", Domain: []string{"a.example"}}); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	err := s.UpsertEndpoint(disabledrefEndpoint("e1", false))
	if err == nil {
		t.Fatal("switching it off was accepted; the next Apply — any Apply — would then fail")
	}
	if !strings.Contains(err.Error(), "r") {
		t.Errorf("err = %v, want it to name the rule that still points at it", err)
	}
	p := s.Profile()
	if !p.Endpoints[0].Enabled {
		t.Error("the endpoint was switched off anyway; a refusal that half-applies is not a refusal")
	}
	if verr := p.Validate(); verr != nil {
		t.Errorf("the stored profile no longer validates after a REFUSED write: %v", verr)
	}
}

// The guard's subject is a LIVE reference. A rule that is itself switched off points at nothing, and
// Validate agrees — refusing here would block the ordinary way of parking a route.
func TestDisabledRef_ASwitchedOffRuleDoesNotPinTheEndpointOn(t *testing.T) {
	s := disabledrefStore(t)
	if err := s.UpsertEndpoint(disabledrefEndpoint("e1", true)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.UpsertRule(model.Rule{ID: "r", Outbound: "e1", Domain: []string{"a.example"}, Disabled: true}); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if err := s.UpsertEndpoint(disabledrefEndpoint("e1", false)); err != nil {
		t.Errorf("refused with %v; the rule that would have used it is parked, so nothing breaks", err)
	}
}

func TestDisabledRef_AimingANewRuleAtAnAlreadyOffEndpointIsRefused(t *testing.T) {
	s := disabledrefStore(t)
	if err := s.UpsertEndpoint(disabledrefEndpoint("off", false)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err := s.UpsertRule(model.Rule{ID: "r", Outbound: "off", Domain: []string{"a.example"}})
	if err == nil {
		t.Fatal("the rule was stored pointing at an endpoint that carries nothing; Apply would refuse the whole profile from here on")
	}
	if n := len(s.Profile().Rules); n != 0 {
		t.Errorf("%d rule(s) stored on a refused write", n)
	}
}

// A routing list is the same reference by another name, and the delete guard already treats it so.
func TestDisabledRef_RoutingListOutboundIsHeldToTheSameRule(t *testing.T) {
	s := disabledrefStore(t)
	if err := s.UpsertEndpoint(disabledrefEndpoint("e1", true)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.UpsertRoutingList(model.RoutingList{ID: "l", Name: "l", Enabled: true,
		Outbound: "e1", Manual: []string{"a.example"}}); err != nil {
		t.Fatalf("seed list: %v", err)
	}
	if err := s.UpsertEndpoint(disabledrefEndpoint("e1", false)); err == nil {
		t.Error("switching off an endpoint a live routing list routes through was accepted")
	}
}

// A profile that is ALREADY broken must keep accepting writes, or it could never be repaired: the
// edit that fixes one reference would be refused because another is still broken. Written straight
// to disk because no writer would produce it — which is the point.
func TestDisabledRef_AnAlreadyBrokenProfileStillAcceptsWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	broken := model.Profile{
		Endpoints: []model.Endpoint{disabledrefEndpoint("e1", false), disabledrefEndpoint("e2", true)},
		Rules: []model.Rule{
			{ID: "r1", Outbound: "e1", Domain: []string{"a.example"}},
			{ID: "r2", Outbound: "e2", Domain: []string{"b.example"}},
		},
	}
	b, err := json.Marshal(broken)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pr := s.Profile()
	if pr.Validate() == nil {
		t.Fatal("the fixture is not actually broken, so this proves nothing")
	}
	// The repair: switch the endpoint r1 needs back on.
	if err := s.UpsertEndpoint(disabledrefEndpoint("e1", true)); err != nil {
		t.Fatalf("the repair was refused because the profile was already broken: %v", err)
	}
	pr = s.Profile()
	if verr := pr.Validate(); verr != nil {
		t.Errorf("profile still broken after the repair: %v", verr)
	}
}
