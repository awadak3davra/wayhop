package server

import (
	"strings"
	"testing"

	"wayhop/internal/keenetic"
	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
)

// The ladder that expresses a native default route is verified by reading `ip global` back, not by
// matching it as a command line next to its interface. KeeneticOS prints description, address and
// mtu in between, so an exact-sequence match never finds it — and the Apply that submitted the
// ladder then failed its own verification and rolled the router back, which is how this was found.
func TestVerifyExactKeeneticRunningConfig_ReadsTheGlobalLadderBack(t *testing.T) {
	const running = `interface GigabitEthernet1
    description Provider
    ip global 54610
!
interface Wireguard1
    description WgProvider_SiteA
    security-level public
    ip address 10.50.1.82 255.255.255.255
    ip mtu 1280
    ip global 56146
!
`
	target := nativeplan.Plan{
		Platform: platform.Keenetic,
		Keenetic: &keenetic.Plan{
			RunningConfigRev: strings.Repeat("a", 64),
			GlobalPriority:   map[string]int{"Wireguard1": 56146},
		},
	}
	if !verifyExactKeeneticRunningConfig(target, nil, nil, running) {
		t.Fatal("a ladder the router is actually holding was reported as not applied")
	}

	target.Keenetic.GlobalPriority = map[string]int{"Wireguard1": 60000}
	if verifyExactKeeneticRunningConfig(target, nil, nil, running) {
		t.Fatal("a ladder the router did NOT take was reported as applied")
	}
}
