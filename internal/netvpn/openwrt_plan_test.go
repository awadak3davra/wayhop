package netvpn

import (
	"strings"
	"testing"
)

var testRouterProtos = RouterProtos{"amneziawg": true, "wireguard": true}

func newIface(name string) AWGInterface {
	i := liveShapedIface()
	i.Name = name
	return i
}

// The plan must never be applicable by itself. Everything that changes the device lives in Commit.
func TestBuildPlan_PreviewCannotApplyItself(t *testing.T) {
	p, err := BuildPlanFor(newIface("awg2"), testRouterProtos, "vpn", liveUCIShow, liveFirewallShow)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	for _, c := range p.Commands {
		for _, forbidden := range []string{"uci commit", "/etc/init.d/", "reload", "restart"} {
			if strings.Contains(c, forbidden) {
				t.Fatalf("a mutating command leaked into the plan: %s", c)
			}
		}
	}
	joined := strings.Join(p.Commit, " ")
	for _, want := range []string{"uci commit network", "uci commit firewall"} {
		if !strings.Contains(joined, want) {
			t.Errorf("commit tail is missing %q: %s", want, joined)
		}
	}
	if !strings.Contains(p.Preview(), "nothing above changes the running configuration") {
		t.Error("the preview does not tell the reader which half is inert")
	}
}

// A zone that is not on the router must stop the plan. Guessing another one would apply the wrong
// policy: on the live device the wan zone forwards REJECT, so the tunnel would exist and be dead.
func TestBuildPlan_UnknownZoneIsRefused(t *testing.T) {
	_, err := BuildPlanFor(newIface("awg2"), testRouterProtos, "no-such-zone", liveUCIShow, liveFirewallShow)
	if err == nil {
		t.Fatal("a plan naming a zone that does not exist was accepted")
	}
	if !strings.Contains(err.Error(), "vpn") {
		t.Errorf("the error should list the zones that DO exist, so the operator can pick one: %v", err)
	}
}

// Attaching to a zone the interface is already in must not add it twice — fw4 would render the rules
// twice. The live config already has awg0 in the vpn zone, so this is the real case.
func TestBuildPlan_ZoneAttachIsIdempotent(t *testing.T) {
	p, err := BuildPlanFor(newIface("awg0"), testRouterProtos, "vpn", liveUCIShow, liveFirewallShow)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if n := strings.Count(strings.Join(p.Commands, "\n"), "firewall.@zone[2].network"); n != 0 {
		t.Errorf("awg0 is already in the vpn zone; the plan should not touch it, got %d command(s)", n)
	}
}

// The pre-write check is the operator's stop switch. It compares the device against what the plan was
// BUILT on — not against the intended result, which would pass exactly when someone else had already
// made the change.
func TestPreflight_RefusesWhenTheRouterChangedUnderneath(t *testing.T) {
	p, err := BuildPlanFor(newIface("awg0"), testRouterProtos, "vpn", liveUCIShow, liveFirewallShow)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if d := p.PreflightAgainst(liveUCIShow); len(d) != 0 {
		t.Fatalf("nothing changed, yet preflight reported: %v", d)
	}

	// Somebody opened LuCI and changed the MTU after the plan was built.
	edited := strings.Replace(liveUCIShow, "network.awg0.mtu='1280'", "network.awg0.mtu='1400'", 1)
	d := p.PreflightAgainst(edited)
	if len(d) == 0 {
		t.Fatal("an edit made after the plan was built was not detected")
	}
	if !strings.Contains(joinDiffs(d), "mtu") {
		t.Errorf("the changed field was not named: %v", d)
	}
}

// Creating an interface that appeared in the meantime is the mirror case, and it has to be told
// apart from the ordinary create — otherwise the plan silently overwrites a tunnel someone else made.
func TestPreflight_NoticesAnInterfaceThatAppeared(t *testing.T) {
	p, err := BuildPlanFor(newIface("awg7"), testRouterProtos, "vpn", liveUCIShow, liveFirewallShow) // awg7 does not exist
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if d := p.PreflightAgainst(liveUCIShow); len(d) != 0 {
		t.Fatalf("awg7 is absent in both views, yet preflight reported: %v", d)
	}

	appeared := liveUCIShow + "network.awg7=interface\nnetwork.awg7.proto='amneziawg'\n"
	d := p.PreflightAgainst(appeared)
	if len(d) != 1 || !strings.Contains(d[0].Got, "after the plan was built") {
		t.Fatalf("an interface created in the meantime was not reported: %v", d)
	}
}

// After the write, the device is compared against Intended. This is the only evidence the write did
// what it said — a zero exit status is not.
func TestVerify_ComparesAgainstTheIntendedResult(t *testing.T) {
	intended := newIface("awg0")
	p, err := BuildPlanFor(intended, testRouterProtos, "vpn", liveUCIShow, liveFirewallShow)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	// The device still holds the OLD awg0 (fixture differs from intended in its peer set), so the
	// post-write check must complain rather than shrug.
	if d := p.VerifyAgainst(liveUCIShow); len(d) == 0 {
		t.Fatal("verify passed although the device does not match what was intended")
	}
	if d := p.VerifyAgainst(""); len(d) != 1 || d[0].Got != "absent" {
		t.Fatalf("a missing interface after the write must be reported: %v", d)
	}
}

// A parameter the router has and the plan does not is about to be dropped. That is sometimes right
// and sometimes somebody's hand-edit, so it is surfaced rather than decided.
func TestBuildPlan_WarnsAboutParamsItWouldDrop(t *testing.T) {
	i := newIface("awg0")
	delete(i.Obfuscation, "i1") // the router has awg_i1; this plan no longer carries it
	p, err := BuildPlanFor(i, testRouterProtos, "vpn", liveUCIShow, liveFirewallShow)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "awg_i1") {
		t.Errorf("dropping a parameter the router carries was not mentioned: %v", p.Warnings)
	}
}

// A tunnel with no peers can never carry traffic; accepting one produces a configuration that looks
// finished and does nothing.
func TestBuildPlan_RefusesAPeerlessTunnel(t *testing.T) {
	i := newIface("awg3")
	i.Peers = nil
	if _, err := BuildPlanFor(i, testRouterProtos, "vpn", liveUCIShow, liveFirewallShow); err == nil {
		t.Fatal("a tunnel with no peers was accepted")
	}
}
