package platform

import "testing"

// PPTP must be DETECTED (existing router configs use it) but never presented as a normal choice.
// Detection without the warning is worse than not detecting it: a protocol listed beside WireGuard
// reads as an endorsement.
func TestLegacy_PPTPCarriesAWarning(t *testing.T) {
	if !IsLegacyProtocol("pptp") {
		t.Fatal("pptp must be marked legacy")
	}
	w := LegacyProtocolWarning["pptp"]
	if w == "" {
		t.Fatal("pptp must carry a warning")
	}
	// The warning has to say what it MEANS for the user, not just label it.
	if len(w) < 60 {
		t.Errorf("warning is too terse to be useful: %q", w)
	}
}

// Modern protocols must not be flagged — a warning on everything is a warning on nothing.
func TestLegacy_ModernProtocolsAreNotFlagged(t *testing.T) {
	for _, p := range []string{"wireguard", "amneziawg", "vless", "openvpn", "ipsec", "trojan"} {
		if IsLegacyProtocol(p) {
			t.Errorf("%s must not be marked legacy", p)
		}
	}
}

// A host reporting pptp natively must surface the warning in its capabilities, so the UI can mark it
// at the point of choice rather than only before Apply.
func TestLegacy_CapabilitiesCarryTheWarning(t *testing.T) {
	caps := withInstallCmds(Capabilities{
		Native:      map[string]bool{"pptp": true, "wireguard": true},
		Installable: map[string]string{},
	}, "opkg")
	if caps.Legacy["pptp"] == "" {
		t.Error("a host that reports pptp must carry its warning in capabilities")
	}
	if _, flagged := caps.Legacy["wireguard"]; flagged {
		t.Error("wireguard must not be flagged")
	}
}

// A host with no legacy protocol carries no Legacy map at all (omitempty keeps the response clean).
func TestLegacy_AbsentWhenNoLegacyProtocol(t *testing.T) {
	caps := withInstallCmds(Capabilities{Native: map[string]bool{"wireguard": true}}, "opkg")
	if len(caps.Legacy) != 0 {
		t.Errorf("no legacy protocols present; Legacy should be empty, got %v", caps.Legacy)
	}
}

// Preflight must warn when a configured endpoint actually USES a legacy protocol.
func TestPreflight_LegacyProtocolWarns(t *testing.T) {
	got := Preflight(PreflightInput{
		RoutingMode: "tun", PBRAvailable: true,
		Protocols: []string{"pptp", "pptp", "wireguard"}, // duplicate must collapse
	}, Capabilities{Platform: "keenetic", SingboxPresent: true})

	f := find(got, "protocol:pptp")
	if f == nil {
		t.Fatal("a configured pptp endpoint must be warned about")
	}
	if f.Severity != SeverityDegraded {
		t.Errorf("severity = %q, want %q: pptp works, it just protects nothing", f.Severity, SeverityDegraded)
	}
	if f.Remedy == "" {
		t.Error("the warning must name a better alternative")
	}
	if len(got) != 1 {
		t.Errorf("wireguard must not be flagged and pptp must appear once; got %+v", got)
	}
}
