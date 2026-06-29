package keenetic

import (
	"context"
	"strings"
	"testing"

	"velinx/internal/model"
)

func TestTeardownCommands(t *testing.T) {
	awg := awgEndpoint()
	awg.ID, awg.Enabled = "awg-nl", true
	p := &model.Profile{
		Endpoints: []model.Endpoint{awg},
		RoutingLists: []model.RoutingList{
			{ID: "ru", Manual: []string{"109.254.0.0/16"}, Outbound: model.OutboundDirect, Enabled: true}, // → ISP auto-less
			{ID: "banks", Manual: []string{"85.21.0.0/16"}, Outbound: "awg-nl", Enabled: true},
			{ID: "blk", Manual: []string{"192.0.2.0/24"}, Outbound: model.OutboundBlock, Enabled: true},
		},
	}
	plan, err := Compile(p, CompileOptions{BaseIndex: 10})
	if err != nil {
		t.Fatal(err)
	}
	cmds := TeardownCommands(plan)
	joined := strings.Join(cmds, "\n")

	for _, w := range []string{
		"no ip route 85.21.0.0 255.255.0.0 Wireguard10", // list route removed
		"no ip route 192.0.2.0 255.255.255.0 reject",    // blackhole removed
		"no interface Wireguard10",                      // native interface removed
	} {
		if !strings.Contains(joined, w) {
			t.Errorf("missing teardown %q\n--- got ---\n%s", w, joined)
		}
	}
	// Comments stripped from the `no` form (route key only).
	if strings.Contains(joined, "!") {
		t.Errorf("teardown route should drop the !comment: %s", joined)
	}
	// Routes are torn down before interfaces.
	iRoute := strings.Index(joined, "no ip route")
	iIface := strings.Index(joined, "no interface")
	if iRoute < 0 || iIface < 0 || iRoute > iIface {
		t.Errorf("routes must be removed before interfaces (route@%d iface@%d)", iRoute, iIface)
	}
}

func TestRouteKey(t *testing.T) {
	cases := map[string]string{
		"ip route 109.254.0.0 255.255.0.0 ISP auto !RU_direct": "ip route 109.254.0.0 255.255.0.0 ISP",
		"ip route 203.0.113.10 255.255.255.255 ISP !wr_bypass": "ip route 203.0.113.10 255.255.255.255 ISP",
		"ip route 192.0.2.0 255.255.255.0 reject":              "ip route 192.0.2.0 255.255.255.0 reject",
		"ipv6 route 2001:db8:: 32 Wireguard10":                 "ipv6 route 2001:db8:: 32 Wireguard10",
	}
	for in, want := range cases {
		if got := routeKey(in); got != want {
			t.Errorf("routeKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPlanTeardown(t *testing.T) {
	ts, recorded := fakeKeenetic(t, "admin", "secret")
	rci, _ := NewRCIClient(ts.URL, "admin", "secret")

	awg := awgEndpoint()
	awg.ID, awg.Enabled = "awg-nl", true
	p := &model.Profile{
		Endpoints:    []model.Endpoint{awg},
		RoutingLists: []model.RoutingList{{ID: "ru", Manual: []string{"109.254.0.0/16"}, Outbound: "awg-nl", Enabled: true}},
	}
	plan, _ := Compile(p, CompileOptions{BaseIndex: 10})

	if err := plan.Teardown(context.Background(), rci, ApplyOptions{Save: true}); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(*recorded, "\n")
	for _, w := range []string{
		"no ip route 109.254.0.0 255.255.0.0 Wireguard10",
		"no interface Wireguard10",
		"system configuration save",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("Teardown did not submit %q\n%s", w, got)
		}
	}
}
