package server

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

const procRoute4LE = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
	"wan\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
	"wan\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
	"br-lan\t004DA8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
	"br-lab\t00054D0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
	"br-lan\t0000320A\t024DA8C0\t0003\t0\t0\t0\t0000FFFF\t0\t0\t0\n" + // a static route to a segment behind a LAN router
	"br-lan\t000000E0\t00000000\t0001\t0\t0\t0\t000000F0\t0\t0\t0\n" + // 224.0.0.0/4
	"awg9\t00000000\t00000000\t0001\t0\t0\t0\t00000080\t0\t0\t0\n" + // 0.0.0.0/1: a default route in halves
	"awg9\t0000090A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n" +
	"down0\t0000630A\t00000000\t0000\t0\t0\t0\t0000FFFF\t0\t0\t0\n" +
	"*\t0000640A\t00000000\t0201\t0\t0\t0\t0000FFFF\t0\t0\t0\n"

// procRoute6Line is one line of /proc/net/ipv6_route: destination and its length, source and its
// length, next hop, metric, reference count, use count, flags, device; addresses as 32 hex digits.
func procRoute6Line(dst string, plen int, flags uint32, dev string) string {
	a := netip.MustParseAddr(dst).As16()
	zero := strings.Repeat("0", 32)
	return fmt.Sprintf("%s %02x %s 00 %s 00000400 00000001 00000000 %08x %8s\n", hex.EncodeToString(a[:]), plen, zero, zero, flags, dev)
}

var procRoute6 = procRoute6Line("fd77:0:0:5::", 64, 0x1, "br-lab") +
	procRoute6Line("2001:db8:aa::", 64, 0x1, "br-lan") +
	procRoute6Line("2001:db8:aa::1", 128, 0x80200001, "br-lan") + // the router's own address
	procRoute6Line("fe80::", 64, 0x1, "br-lan") +
	procRoute6Line("ff00::", 8, 0x1, "br-lan") +
	procRoute6Line("::", 0, 0x3, "wan6") +
	procRoute6Line("2001:db8:bb::", 64, 0x1, "wan6") +
	procRoute6Line("::", 0, 0x201, "lo") + // a blackhole default of a policy table
	procRoute6Line("::1", 128, 0x80200001, "lo")

func gl(pairs ...string) []pbr.GuardLocal {
	var out []pbr.GuardLocal
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, pbr.GuardLocal{Dev: pairs[i], Prefix: netip.MustParsePrefix(pairs[i+1])})
	}
	return out
}

// The router's own routes as they are read: what the main table has beside its
// default routes, which of them go by a gateway, and which devices carry a default route.
func TestLocalRoutesAreReadFromProc(t *testing.T) {
	reading := localRoutesFrom(procRoute4LE, procRoute6, binary.LittleEndian)
	routes, out := reading.Routes, reading.Uplink
	want := gl("wan", "192.168.1.0/24", "br-lan", "192.168.77.0/24", "br-lab", "10.77.5.0/24", "br-lan", "10.50.0.0/16", "awg9", "10.9.0.0/16",
		"br-lab", "fd77:0:0:5::/64", "br-lan", "2001:db8:aa::/64", "wan6", "2001:db8:bb::/64")
	if !reflect.DeepEqual(routes, want) {
		t.Errorf("routes:\n got %v\nwant %v", routes, want)
	}
	if via := gl("br-lan", "10.50.0.0/16")[0]; len(reading.Via) != 1 || !reading.Via[via] {
		t.Errorf("routes by a gateway: %v", reading.Via)
	}
	for _, dev := range []string{"wan", "wan6", "awg9"} {
		if !out[dev] {
			t.Errorf("%s is not a way out: %v", dev, out)
		}
	}
	if out["br-lan"] {
		t.Errorf("br-lan reads as a way out (its multicast route is not a default route): %v", out)
	}
	// A big-endian router prints the same bytes the other way round.
	be := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"br-lan\tC0A84D00\t00000000\t0001\t0\t0\t0\tFFFFFF00\t0\t0\t0\n"
	routes = localRoutesFrom(be, "", binary.BigEndian).Routes
	if want := gl("br-lan", "192.168.77.0/24"); !reflect.DeepEqual(routes, want) {
		t.Errorf("big-endian: got %v want %v", routes, want)
	}
}

func officePlan(t *testing.T) *pbr.Plan {
	t.Helper()
	ext := func(id, iface, peer string) model.Endpoint {
		return model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineExternal,
			Params: map[string]any{"interface": iface, "endpoint_ip": peer}}
	}
	p := model.Profile{
		Endpoints: []model.Endpoint{ext("nl", "awg0", "198.51.100.48"), ext("fi", "awg2", "198.51.100.144")},
		Groups:    []model.Group{{ID: "grp-office", Name: "Office", Type: model.GroupFallback, Members: []string{"nl"}, KillSwitch: true}},
		RoutingLists: []model.RoutingList{
			{ID: "office", Name: "Office", Outbound: "grp-office", Enabled: true, Manual: []string{"10.77.0.0/16"}},
			{ID: "plain", Name: "Plain", Outbound: "fi", Enabled: true, Manual: []string{"192.0.2.0/24"}},
		},
	}
	plan, _, err := pbr.Compile(&p, pbr.Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
