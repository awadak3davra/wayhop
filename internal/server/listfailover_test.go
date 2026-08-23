package server

import (
	"bytes"
	"errors"
	"log"
	"os"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// The live shape from a live router: WayHop's own table 151 defaulting to the elected
// tunnel, alongside the firmware's per-interface tables and a via-gateway default that belongs to a
// different question.
const routeShowFixture = `default via 172.20.0.1 dev eth3  metric 1000
default dev nwg3 scope link table 151
1.1.1.1 via 172.20.0.1 dev eth3 table 4096  metric 1000
default via 172.20.0.1 dev eth3 table 4096  metric 1000
192.168.0.0/24 dev br0 scope link  src 192.168.50.1
blackhole default metric 4000 table 152
default dev nwg5 scope link table 152
`

func TestParseTableDefaultsPicksTheDeviceRoutePerTable(t *testing.T) {
	got := parseTableDefaults(routeShowFixture)
	want := map[int]string{151: "nwg3", 152: "nwg5"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTableDefaults = %v, want %v", got, want)
	}
	// A `default via <gw> dev <iface>` line is a gateway route, not the device route this loop owns;
	// counting it would make the loop think table 4096 (the firmware's) is one of ours.
	if _, leaked := got[4096]; leaked {
		t.Fatal("a via-gateway default was read as a device route")
	}
	// The main table has no `table N` at all and must not become table 0.
	if _, zero := got[0]; zero {
		t.Fatal("the main table was given a number")
	}
}

// The election is the operator's ORDER, first healthy member wins — the same rule the Failover page
// states for a native group, and the same one Apply pins the table with.
func TestElectHealthyMemberFollowsTheOperatorsOrder(t *testing.T) {
	ifaceOf := map[string]string{
		"external-nwg3": "nwg3", "external-nwg5": "nwg5",
		"external-nwg1": "nwg1", "external-nwg0": "nwg0",
	}
	group := model.Group{ID: "grp", Members: []string{"external-nwg3", "external-nwg5", "external-nwg1", "external-nwg0"}}

	t.Run("the first member is taken while it is alive", func(t *testing.T) {
		got, ok := electMember(group, ifaceOf, map[string]bool{
			"external-nwg3": true, "external-nwg5": true,
		})
		if !ok || got != "nwg3" {
			t.Fatalf("elected %q (%v), want nwg3", got, ok)
		}
	})

	t.Run("a dead first member is skipped, order otherwise kept", func(t *testing.T) {
		got, ok := electMember(group, ifaceOf, map[string]bool{
			"external-nwg3": false, "external-nwg5": true, "external-nwg1": true,
		})
		if !ok || got != "nwg5" {
			t.Fatalf("elected %q (%v), want nwg5", got, ok)
		}
	})

	// Everything down elects NOTHING, and the caller leaves the table alone: moving to another dead
	// member is churn, and turning the leak into a drop is Apply's decision, not this loop's.
	t.Run("all members down elects nothing", func(t *testing.T) {
		if got, ok := electMember(group, ifaceOf, map[string]bool{}); ok {
			t.Fatalf("elected %q with every member down", got)
		}
	})

	// A member the plan cannot route (no interface) is not a candidate, however healthy it looks.
	t.Run("a member with no interface is not elected", func(t *testing.T) {
		got, ok := electMember(group, map[string]string{"external-nwg5": "nwg5"}, map[string]bool{
			"external-nwg3": true, "external-nwg5": true,
		})
		if !ok || got != "nwg5" {
			t.Fatalf("elected %q (%v), want nwg5", got, ok)
		}
	})
}

// A failover owner that cannot write must say so — once. The file exists because the router's
// previous owner was a cron that did not exist and nothing ever reported the silence; an owner that
// runs and fails every 20 seconds without a word would be that same silence with a process attached.
// Equally, it must not spend the router's bounded log on one line per tick.
func TestListFailoverWriteFailureIsReportedOnceAndOnRecovery(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	s := &Server{}
	boom := errors.New("RTNETLINK answers: operation not permitted")
	s.noteListFailoverWrite(151, boom)
	s.noteListFailoverWrite(151, boom)
	s.noteListFailoverWrite(151, boom)
	if n := strings.Count(buf.String(), "cannot repoint table 151"); n != 1 {
		t.Fatalf("the same refusal was logged %d times, want 1:\n%s", n, buf.String())
	}

	// A DIFFERENT refusal is news again: the reason changed, and the first one no longer explains it.
	s.noteListFailoverWrite(151, errors.New("Cannot find device \"nwg5\""))
	if n := strings.Count(buf.String(), "cannot repoint table 151"); n != 2 {
		t.Fatalf("a changed refusal was not reported: %s", buf.String())
	}

	// And the recovery, because "it stopped failing" is the half an operator waits for.
	s.noteListFailoverWrite(151, nil)
	if !strings.Contains(buf.String(), "table 151 is writable again") {
		t.Fatalf("recovery was not reported: %s", buf.String())
	}
	before := buf.Len()
	s.noteListFailoverWrite(151, nil)
	if buf.Len() != before {
		t.Fatalf("a healthy write logged again: %s", buf.String()[before:])
	}
}

// The election rule must not depend on the platform's firewall tooling.
//
// The loop was gated on ipset AND iptables being present — a Keenetic-shaped question that answers
// "no" on modern OpenWrt, which carries nftables and often no iptables binary. A routing list backed
// by a native group there had no owner at all: the table stayed pinned to whichever member Apply
// chose, and when that member died the fwmark lookup found an empty table and fell through to the
// provider. That is the leak this file exists to close, and it was closed on one platform only.
//
// What keeps the core and this loop from fighting is structural, not platform: only a GROUP egress
// of kind EgressInterface in the CURRENT plan produces a target, and a core-carried group produces
// no such egress. These assert the rule itself, which is what has to hold on every router.
func TestElectMemberIsPlatformIndependent(t *testing.T) {
	group := model.Group{ID: "grp", Members: []string{"a", "b", "c"}}
	ifaceOf := map[string]string{"a": "awg0", "b": "awg1", "c": "nwg3"}

	// The operator's order decides, not the map's iteration order or the platform's naming.
	if got, ok := electMember(group, ifaceOf, map[string]bool{"a": true, "b": true, "c": true}); !ok || got != "awg0" {
		t.Fatalf("all healthy elected %q, want the first in the operator's order", got)
	}
	// OpenWrt-shaped names elect exactly as Keenetic-shaped ones do.
	if got, ok := electMember(group, ifaceOf, map[string]bool{"a": false, "b": true, "c": true}); !ok || got != "awg1" {
		t.Fatalf("first member down elected %q, want awg1", got)
	}
	if got, ok := electMember(group, ifaceOf, map[string]bool{"a": false, "b": false, "c": true}); !ok || got != "nwg3" {
		t.Fatalf("two down elected %q, want nwg3", got)
	}
	// Everything down elects NOTHING: moving to another dead member is churn, and turning the leak
	// into a drop is Apply's decision, not this loop's.
	if got, ok := electMember(group, ifaceOf, map[string]bool{}); ok {
		t.Fatalf("all down elected %q, want no election", got)
	}
	// A member with no kernel link is not a candidate however healthy it looks.
	if got, ok := electMember(group, map[string]string{"b": "awg1"}, map[string]bool{"a": true, "b": true}); !ok || got != "awg1" {
		t.Fatalf("unbindable first member elected %q, want awg1", got)
	}
}
