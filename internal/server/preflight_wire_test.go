package server

import (
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// keeneticLikeCaps is a box with firmware PPE and no nftables flowtable.
var keeneticLikeCaps = platform.Capabilities{
	Platform: "keenetic", Accel: platform.Accel{Kind: "ppe", HW: true}, SingboxPresent: true,
}

func preflightSetting(list []platform.Unsupported, setting string) *platform.Unsupported {
	for i := range list {
		if list[i].Setting == setting {
			return &list[i]
		}
	}
	return nil
}

// The wiring must judge the EFFECTIVE routing mode. The config field is often empty (the mode is
// derived from Gateway for back-compat), so passing the raw field would judge "" — silently
// checking nothing on exactly the configurations most users run.
func TestPreflightWiring_UsesEffectiveRoutingMode(t *testing.T) {
	s := applystate_server(t)
	s.cfg.RoutingMode = "" // unset: the effective mode comes from the Gateway derivation
	s.cfg.Offload = "hw"

	got := s.preflight(keeneticLikeCaps, platform.OffloadState{})

	effective := s.routingMode(s.config())
	if effective == "" {
		t.Fatal("routingMode must resolve to a concrete mode; the preflight input depends on it")
	}
	// Whatever the derived mode is, an offload request on a PPE box must be reported — either as
	// blocked (in fast mode) or as inert (outside it). Silence would mean the raw empty field leaked
	// through and the check never ran.
	if preflightSetting(got, "offload") == nil {
		t.Errorf("offload %q on a PPE box must be reported (effective mode %q); got %+v",
			s.cfg.Offload, effective, got)
	}
}

// A disabled rule is not applied, so it must not raise a domain-rules warning. Counting it would
// make the panel nag about a limitation the user already opted out of.
func TestPreflightWiring_IgnoresDisabledRules(t *testing.T) {
	s := applystate_server(t)
	s.cfg.RoutingMode = "fast"
	s.cfg.Offload = ""
	s.pbrAvailOnce.Do(func() { s.pbrAvail = true }) // a capable nft host, so only the mode is judged

	prof := s.store.Profile()
	prof.Rules = []model.Rule{{ID: "r1", Domain: []string{"example.com"}, Outbound: model.OutboundDirect, Disabled: true}}
	if err := s.store.Replace(prof); err != nil {
		t.Fatalf("replace profile: %v", err)
	}

	if f := preflightSetting(s.preflight(keeneticLikeCaps, platform.OffloadState{}), "routing_mode"); f != nil {
		t.Errorf("a disabled domain rule must not trigger the fast-mode domain warning: %+v", f)
	}

	// Enabling the same rule must surface it — otherwise the check is dead either way.
	prof = s.store.Profile()
	prof.Rules = []model.Rule{{ID: "r1", Domain: []string{"example.com"}, Outbound: model.OutboundDirect}}
	if err := s.store.Replace(prof); err != nil {
		t.Fatalf("replace profile: %v", err)
	}
	if f := preflightSetting(s.preflight(keeneticLikeCaps, platform.OffloadState{}), "routing_mode"); f == nil {
		t.Error("an enabled domain rule in fast mode must be reported")
	}
}

// The field is consumed by a client that tests length; a nil slice marshals to null and would make
// every caller add a null guard.
func TestPreflightWiring_NeverNil(t *testing.T) {
	s := applystate_server(t)
	s.cfg.RoutingMode = "tun"
	s.cfg.Offload = ""
	s.pbrAvailOnce.Do(func() { s.pbrAvail = true })

	got := s.preflight(platform.Capabilities{
		Platform: "openwrt", Accel: platform.Accel{Kind: "nft-flowtable", HW: true}, SingboxPresent: true,
	}, platform.OffloadState{})
	if got == nil {
		t.Fatal("preflight must return a non-nil slice")
	}
	if len(got) != 0 {
		t.Errorf("a supported config should report nothing, got %+v", got)
	}
}
