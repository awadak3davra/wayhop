package netvpn

import (
	"context"
	"testing"
)

// TestDiscoverNDM_AbsentNdmcIsNotError: on a host without ndmc (dev/CI/OpenWrt), DiscoverNDM must
// treat the missing binary as "not a KeeneticOS host" — (nil, nil), NOT an error — so Discover does
// not report a spurious failure off-router. (An ndmc that EXISTS and fails would error; that path
// needs a Keenetic box and is validated on-device.)
func TestDiscoverNDM_AbsentNdmcIsNotError(t *testing.T) {
	got, err := DiscoverNDM(context.Background())
	if err != nil {
		t.Errorf("absent ndmc must not error, got %v", err)
	}
	if got != nil {
		t.Errorf("absent ndmc must yield nil tunnels, got %#v", got)
	}
}

// TestDiscover_NoToolsIsNotError: with no wg/awg/ndmc present, Discover returns an empty result and a
// nil error — "no tunnels" must stay distinguishable from "discovery broke".
func TestDiscover_NoToolsIsNotError(t *testing.T) {
	got, err := Discover(context.Background())
	if err != nil {
		t.Errorf("no discovery tools present must not error, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want no tunnels off-router, got %d", len(got))
	}
}
