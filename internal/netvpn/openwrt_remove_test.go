package netvpn

import (
	"strings"
	"testing"
)

// The exact shape the AX3000T reports: a named peer section, and a vpn zone that lists the tunnel.
const removeNetUCI = `network.wrprobe0=interface
network.wrprobe0.proto='amneziawg'
network.wrprobe0.private_key='cHJpdmF0ZQ=='
network.wrprobe0.addresses='10.99.99.2/32'
network.wrprobe0.mtu='1420'
network.wrprobe0_peer1=amneziawg_wrprobe0
network.wrprobe0_peer1.public_key='cHVibGlj'
network.wrprobe0_peer1.endpoint_host='203.0.113.7'
network.wrprobe0_peer1.endpoint_port='51820'
network.wrprobe0_peer1.allowed_ips='10.99.99.0/24'
`

const removeFwUCI = `firewall.@zone[0]=zone
firewall.@zone[0].name='lan'
firewall.@zone[0].network='lan'
firewall.@zone[2]=zone
firewall.@zone[2].name='vpn'
firewall.@zone[2].network='awg0' 'awg1' 'wrprobe0'
`

// The defect this file was written for: removing the tunnel left the firewall zone still naming it.
// Found on a real router, not in review — the network config was clean and the zone was not.
func TestBuildRemovalPlan_DetachesTheFirewallZone(t *testing.T) {
	p, err := BuildRemovalPlan("wrprobe0", removeNetUCI, removeFwUCI)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(p.Commands, "\n")
	if !strings.Contains(joined, "del_list firewall.@zone[2].network='wrprobe0'") {
		t.Fatalf("the zone is never detached, so it keeps a member that no longer exists:\n%s", joined)
	}
	if !strings.Contains(joined, "uci -q delete network.wrprobe0_peer1") {
		t.Error("the peer section is not removed")
	}
	if !strings.Contains(joined, "uci -q delete network.wrprobe0") {
		t.Error("the interface section is not removed")
	}
	if len(p.Zones) != 1 || p.Zones[0] != "vpn" {
		t.Errorf("the zone is recorded by name for the report: got %v", p.Zones)
	}
	// Nothing in Commands may mutate the router; that separation is what makes a preview safe.
	for _, c := range p.Commands {
		if strings.Contains(c, "commit") || strings.Contains(c, "reload") || strings.HasPrefix(c, "ifdown") {
			t.Errorf("a mutating command leaked into the stageable half: %q", c)
		}
	}
}

// ifdown has to come before the commit: netifd can only tear down an interface it can still find in
// the config. Run afterwards it answers "Interface … not found" and does nothing — measured on the
// router, where the device was left to disappear on netifd's own schedule instead.
func TestBuildRemovalPlan_IfdownPrecedesTheCommit(t *testing.T) {
	p, err := BuildRemovalPlan("wrprobe0", removeNetUCI, removeFwUCI)
	if err != nil {
		t.Fatal(err)
	}
	var ifdownAt, commitAt = -1, -1
	for i, c := range p.Commit {
		if strings.HasPrefix(c, "ifdown ") && ifdownAt < 0 {
			ifdownAt = i
		}
		if strings.Contains(c, "uci commit network") && commitAt < 0 {
			commitAt = i
		}
	}
	if ifdownAt < 0 {
		t.Fatalf("no ifdown at all, so the device teardown is left to whenever netifd notices: %v", p.Commit)
	}
	if commitAt < 0 {
		t.Fatalf("no network commit: %v", p.Commit)
	}
	if ifdownAt > commitAt {
		t.Errorf("ifdown runs after the config is committed, when the interface is already gone from it: %v", p.Commit)
	}
}

// A tunnel in no zone must not produce a firewall commit — reloading fw4 for nothing is a cost paid
// on every removal, and the plan should say why it is doing nothing rather than doing it silently.
func TestBuildRemovalPlan_NoZoneMeansNoFirewallWork(t *testing.T) {
	fw := strings.Replace(removeFwUCI, " 'wrprobe0'", "", 1)
	p, err := BuildRemovalPlan("wrprobe0", removeNetUCI, fw)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range append(p.Commands, p.Commit...) {
		if strings.Contains(c, "firewall") {
			t.Errorf("firewall work was scheduled for a tunnel in no zone: %q", c)
		}
	}
	if len(p.Warnings) == 0 {
		t.Error("nothing was said about why no zone was detached")
	}
}

// An interface listed in two zones must be detached from both. Detaching only the first is the same
// defect this file fixes, one level in.
func TestBuildRemovalPlan_DetachesEveryZoneThatNamesIt(t *testing.T) {
	fw := removeFwUCI + "firewall.@zone[3]=zone\nfirewall.@zone[3].name='guest'\nfirewall.@zone[3].network='wrprobe0'\n"
	p, err := BuildRemovalPlan("wrprobe0", removeNetUCI, fw)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Zones) != 2 {
		t.Fatalf("expected both zones detached, got %v", p.Zones)
	}
	joined := strings.Join(p.Commands, "\n")
	for _, ref := range []string{"@zone[2]", "@zone[3]"} {
		if !strings.Contains(joined, "del_list firewall."+ref+".network") {
			t.Errorf("zone %s keeps a member that no longer exists:\n%s", ref, joined)
		}
	}
}

// VerifyRemoved is the only evidence the removal worked: RemoveUCI's deletes are `-q`, and deleting
// a section that is not there is not an error, so exit codes prove nothing here.
func TestVerifyRemoved_CatchesEachHalfSeparately(t *testing.T) {
	p, err := BuildRemovalPlan("wrprobe0", removeNetUCI, removeFwUCI)
	if err != nil {
		t.Fatal(err)
	}
	cleanNet, cleanFw := "network.lan=interface\n", "firewall.@zone[2].name='vpn'\nfirewall.@zone[2].network='awg0'\n"

	if d := p.VerifyRemoved(cleanNet, cleanFw); len(d) != 0 {
		t.Fatalf("a clean removal was reported as incomplete: %v", d)
	}
	// The interface gone but the zone still naming it — exactly what the router did.
	if d := p.VerifyRemoved(cleanNet, removeFwUCI); len(d) != 1 {
		t.Errorf("a dangling zone member was not reported: %v", d)
	}
	// And the reverse: the zone tidy but the section still there.
	if d := p.VerifyRemoved(removeNetUCI, cleanFw); len(d) != 1 {
		t.Errorf("a surviving interface section was not reported: %v", d)
	}
}

func TestRemovalApply_RefusesWhenSomethingElseIsStaged(t *testing.T) {
	p, err := BuildRemovalPlan("wrprobe0", removeNetUCI, removeFwUCI)
	if err != nil {
		t.Fatal(err)
	}
	r := &RecordRunner{Responses: map[string]string{"uci changes network": "network.lan.ipaddr='10.0.0.1'"}}
	res, err := p.Apply(r)
	if err == nil {
		t.Fatal("removal proceeded while somebody else had edits staged; rolling back would discard them")
	}
	// It has to refuse FOR THAT REASON. With the staged-changes check removed this test still passed:
	// the applier got one step further, found the interface missing from the recorder's empty `uci
	// show`, and refused as stale — a different guard, a different message, and no protection at all
	// for the case this test is named for.
	if !strings.Contains(err.Error(), "uncommitted changes") {
		t.Errorf("it refused for some other reason than the staged edits: %v", err)
	}
	if res.Applied {
		t.Error("it reported the removal as applied")
	}
	for _, c := range r.Cmds {
		if strings.Contains(c, "delete") || strings.Contains(c, "commit") {
			t.Errorf("it had already started changing things: %q", c)
		}
	}
}
