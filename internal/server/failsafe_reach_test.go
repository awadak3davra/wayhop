package server

import (
	"testing"

	"wayhop/internal/failsafe"
	"wayhop/internal/model"
	"wayhop/internal/netdiag"
)

func TestFailSafeHealthAsksThroughTheDefaultExit(t *testing.T) {
	up := netdiag.PingResult{Ran: true, Ok: true}
	down := netdiag.PingResult{Ran: true, Ok: false}
	never := netdiag.PingResult{Ran: false}
	dead := func(string) (bool, bool) { return false, true }
	alive := func(string) (bool, bool) { return true, true }
	unsent := func(string) (bool, bool) { return false, false }
	cases := []struct {
		name  string
		ping  netdiag.PingResult
		core  bool
		exit  string
		reach func(string) (bool, bool)
		want  failsafe.Health
	}{
		// Measured on an emulated OpenWrt: the ping answered while every device was offline.
		{"ping up, default tunnel dead", up, true, "grp-wg", dead, failsafe.HealthDown},
		{"ping up, default tunnel alive", up, true, "grp-wg", alive, failsafe.HealthUp},
		{"a request that could not be sent says nothing", up, true, "grp-wg", unsent, failsafe.HealthUp},
		{"default route on the provider's line", up, true, "", dead, failsafe.HealthUp},
		{"no core in this configuration", up, false, "grp-wg", dead, failsafe.HealthUp},
		{"ping down stays down", down, true, "grp-wg", alive, failsafe.HealthDown},
		{"a ping that never ran stays unknown", never, true, "grp-wg", dead, failsafe.HealthUnknown},
	}
	for _, c := range cases {
		if got := failSafeHealth(c.ping, c.core, c.exit, c.reach); got != c.want {
			t.Errorf("%s: health = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFailSafeDefaultExit(t *testing.T) {
	prof := func(out string) model.Profile {
		return model.Profile{Rules: []model.Rule{{ID: "r1", Outbound: "grp-a"}, {ID: "def", Default: true, Outbound: out}}}
	}
	for out, want := range map[string]string{"grp-wg": "grp-wg", "wg-1": "wg-1", model.OutboundDirect: "", "": "", "block": ""} {
		if got := failSafeDefaultExit(prof(out)); got != want {
			t.Errorf("default rule to %q: exit = %q, want %q", out, got, want)
		}
	}
	if got := failSafeDefaultExit(model.Profile{}); got != "" {
		t.Errorf("no default rule: exit = %q", got)
	}
}
