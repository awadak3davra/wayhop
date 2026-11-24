package pbr

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestZoneOrderIsNotTheOperatorOrder (L5): pins the precedence the KERNEL plane actually applies, so
// the Routing page's wording and this compiler cannot drift apart again.
//
// The page says "Evaluated top to bottom: the first list that matches wins". That is true of the
// plane that reads a rule list; it is not true here. Compile sorts zones — blocks last, then by zone
// NAME — and each zone emits one non-terminating mark, so an address in two zones takes the LAST
// emitted. Verified on a live Keenetic: the panel lists Telegram, Antifilter, Meta, Twitter,
// Re:filter, TeamViewer, GitHub in that order, while `iptables -t mangle -S WR_PREROUTING` emits
// antifilter, meta, refilter, telegram, twitter, github, teamviewer — alphabetical. It changed
// nothing there only because all seven carry the same mark.
//
// Two properties are pinned: a block always outranks an ordinary zone, and among ordinary zones the
// emitted order is by name and NOT the order they were given in.
func TestZoneOrderIsNotTheOperatorOrder(t *testing.T) {
	zones := []Zone{
		{Name: "zzz_last_by_name", EgressTag: "tunA"},
		{Name: "aaa_first_by_name", EgressTag: "tunB"},
		{Name: "mmm_blocked", EgressTag: "blocker"},
	}
	kinds := map[string]EgressKind{"tunA": EgressInterface, "tunB": EgressInterface, "blocker": EgressBlackhole}

	got := orderZonesForEmit(zones, kinds, nil)
	names := []string{}
	for _, z := range got {
		names = append(names, z.Name)
	}
	if len(names) != 3 {
		t.Fatalf("every zone must survive ordering: %v", names)
	}
	if names[2] != "mmm_blocked" {
		t.Errorf("a block must be emitted last so its mark wins an overlap, got %v", names)
	}
	if names[0] != "aaa_first_by_name" || names[1] != "zzz_last_by_name" {
		t.Errorf("ordinary zones are emitted by NAME, not in the order given: %v", names)
	}
	// The input order was the reverse of the output for the two ordinary zones: that IS the property
	// the Routing page has to disclose rather than promise away.
	if zones[0].Name != "zzz_last_by_name" {
		t.Error("the caller's slice must not be reordered in place under it")
	}
}

// Kill switch audit / precedence: the emitted order is direct, tunnels, kill-switched tunnels,
// blocks, by name inside each rank, whatever the names.
func TestZoneOrderPrecedence(t *testing.T) {
	zones := []Zone{
		{Name: "a_block", EgressTag: "blocker"},
		{Name: "b_killswitched", EgressTag: "ks"},
		{Name: "c_tunnel", EgressTag: "tun"},
		{Name: "d_policy", EgressTag: "ndm-policy:x", NDMPolicy: "x"},
		{Name: "e_direct", EgressTag: "direct"},
	}
	kinds := map[string]EgressKind{"blocker": EgressBlackhole, "ks": EgressInterface, "tun": EgressInterface, "direct": EgressWAN}
	got := orderZonesForEmit(zones, kinds, map[string]bool{"ks": true})
	var names []string
	for _, z := range got {
		names = append(names, z.Name)
	}
	want := []string{"e_direct", "c_tunnel", "d_policy", "b_killswitched", "a_block"}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("order %v, want %v", names, want)
		}
	}
}

// A device's own "direct" rule or list is an explicit exemption of that device. It ranks
// with the tunnels, after them, so it keeps applying to listed destinations; below the kill-switched
// lists, so the kill switch stays absolute. An unscoped direct list stays the weakest claim.
func TestZoneOrderDeviceDirectBeatsTunnels(t *testing.T) {
	zones := []Zone{
		{Name: "a_tv_direct", EgressTag: "direct", SrcScoped: true},
		{Name: "b_killswitched", EgressTag: "ks"},
		{Name: "c_tunnel", EgressTag: "tun"},
		{Name: "e_direct", EgressTag: "direct"},
	}
	kinds := map[string]EgressKind{"ks": EgressInterface, "tun": EgressInterface, "direct": EgressWAN}
	var names []string
	for _, z := range orderZonesForEmit(zones, kinds, map[string]bool{"ks": true}) {
		names = append(names, z.Name)
	}
	if want := "e_direct,c_tunnel,a_tv_direct,b_killswitched"; strings.Join(names, ",") != want {
		t.Fatalf("order %v, want %s", names, want)
	}
	// Ported from the reviewer's scratch TestR2DeviceDirectRule: the TV's direct rule is the last
	// mark of the rendered chain, after every tunnel list.
	p := keeneticProfile()
	p.Rules = append(p.Rules, model.Rule{ID: "tv", Outbound: model.OutboundDirect, SourceMAC: []string{"aa:bb:cc:dd:ee:01"}})
	pl, _, err := Compile(p, Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	var marks []string
	for _, l := range strings.Split(pl.RenderIptablesScript(IpsetOptions{}), "\n") {
		if strings.HasPrefix(l, "-A WR_PREROUTING") && strings.Contains(l, "-j MARK") {
			marks = append(marks, l)
		}
	}
	if len(marks) == 0 || !strings.Contains(marks[len(marks)-1], "--mac-source aa:bb:cc:dd:ee:01") {
		t.Fatalf("the device's direct rule is not the last mark:\n%s", strings.Join(marks, "\n"))
	}
}
