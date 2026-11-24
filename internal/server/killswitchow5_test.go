package server

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"wayhop/internal/pbr"
)

// The second segment shape: the second access point's segment is routed by
// the operator's own rule into one tunnel, ahead of WayHop's marks (the operator's notes of 19.09
// and 12.11; the rule and its table are not measured for this test).
const (
	ow5Rules = "0:\tfrom all lookup local\n30:\tfrom 192.168.70.0/24 lookup 160\n150:\tfrom all fwmark 0x20000/0xff0000 lookup 151\n" +
		"9001:\tfrom all fwmark 0x2023 lookup 2022\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default\n"
	ow5Network = ow4Network + "network.awg1=interface\nnetwork.awg1.proto='amneziawg'\n" +
		"network.awg_guest=interface\nnetwork.awg_guest.proto='amneziawg'\n" +
		"network.welcome=interface\nnetwork.welcome.device='br-welcome'\nnetwork.welcome.proto='static'\n"
)

func ow5Tables(dev string) string {
	return "default via 192.168.50.1 dev wan proto static\ndefault dev awg0 table 151 scope link\nblackhole default table 151 metric 1000\n" +
		"default dev " + dev + " table 160 scope link\n"
}

func ow5Judge(t *testing.T, plan *pbr.Plan) ksJudge {
	t.Helper()
	return parseSides(ow5Network, ow4FirewallWith(true)).judge(map[string]bool{"wan": true}, planTunnels(plan))
}

// The device a source rule's table leaves by is judged: a tunnel of the configuration that is not
// the provider's is the segment's own way out; the uplink is not, and neither is a network of the
// LAN used as a gateway.
func TestSourceRoutesAreJudgedByTheDeviceTheyLeaveBy(t *testing.T) {
	plan := ow4Plan(t, "198.18.5.0/24")
	j := ow5Judge(t, plan)
	for dev, want := range map[string]struct {
		side ksSide
		ok   bool
	}{
		"awg1":      {sideHouse, true},  // the operator's tunnel, in the tunnels' zone, not one of the plan's
		"awg_guest": {sideUnsure, true}, // a tunnel by its protocol, in no zone
		"awg0":      {sideTunnel, true}, // one of the plan's
		"wan":       {sideProvider, false},
		"br-lan":    {sideHouse, false},  // a LAN gateway: where it goes next is not known
		"eth7":      {sideUnsure, false}, // nothing says what it is
	} {
		got := sourceRoutes(ksSourceDump{rules4: ow5Rules, routes4: ow5Tables(dev)}, j)
		if len(got) != 1 || got[0].Dev != dev || got[0].Src != netip.MustParsePrefix("192.168.70.0/24") || got[0].Side != want.side || got[0].ok() != want.ok {
			t.Errorf("%s: %+v, want side %d ok %v", dev, got, want.side, want.ok)
		}
	}
	// A table with no default route routes nothing by itself.
	if got := sourceRoutes(ksSourceDump{rules4: ow5Rules, routes4: "192.168.70.0/24 dev br-welcome table 160\n"}, j); len(got) != 0 {
		t.Errorf("a table without a default route: %+v", got)
	}
}

func ow5Server(t *testing.T, dump *ksSourceDump, fail *error) *Server {
	t.Helper()
	header := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
	route4 := ow4Route("br-lan", "192.168.2.0/24", "") + ow4Route("br-welcome", "192.168.70.0/24", "") + ow4Route("wan", "0.0.0.0/0", "192.168.50.1")
	text := header + route4
	s := ow4Server(t, ow4UCI(ow5Network, ow4FirewallWith(true)), &text)
	old := ksReadSourceRouting
	ksReadSourceRouting = func(context.Context, func(context.Context, bool) (string, error)) (ksSourceDump, error) {
		return *dump, *fail
	}
	t.Cleanup(func() { ksReadSourceRouting = old })
	return s
}

// The guard the daemon loads lets the source-routed segment leave by its own tunnel and never by
// the provider; what it is told survives a reading that fails and a rule that moves, and a device
// that becomes the uplink is taken out.
func TestGuardProgramFollowsTheOperatorsSourceRouting(t *testing.T) {
	dump := ksSourceDump{rules4: ow5Rules, routes4: ow5Tables("awg1")}
	var fail error
	s := ow5Server(t, &dump, &fail)
	plan := ow4Plan(t, "198.18.5.0/24")
	s.noteGuardTunnels(plan)
	s.refreshGuardLocal(true)
	const accept = "\t\tip saddr 192.168.70.0/24 oifname \"awg1\" accept\n"
	first := s.nftGuardProgram(plan)
	if !strings.Contains(first, accept+"\t\tcounter drop\n") {
		t.Fatalf("the list's chain does not let the second segment leave by awg1:\n%s", first)
	}
	if strings.Contains(first, `oifname "wan" accept`) || strings.Contains(first, `saddr 192.168.70.0/24 oifname "wan"`) {
		t.Fatalf("the provider's device is accepted:\n%s", first)
	}
	// A reading that fails changes nothing.
	fail = errors.New("ip: busy")
	if s.refreshGuardLocal(true) || s.nftGuardProgram(plan) != first {
		t.Errorf("a failed reading of the rules changed the guard")
	}
	fail = nil
	// The operator points the segment at the uplink: no accept by the uplink, ever.
	dump.routes4 = ow5Tables("wan")
	s.refreshGuardLocal(true)
	if got := s.nftGuardProgram(plan); strings.Contains(got, `oifname "wan" accept`) {
		t.Fatalf("a segment routed to the uplink is accepted there:\n%s", got)
	}
	// And at another tunnel: both are told (each bound to its device), one reload.
	dump.routes4 = ow5Tables("awg_guest")
	if !s.refreshGuardLocal(true) {
		t.Errorf("a new tunnel for the segment did not read as a change")
	}
	got := s.nftGuardProgram(plan)
	if !strings.Contains(got, accept) || !strings.Contains(got, "ip saddr 192.168.70.0/24 oifname \"awg_guest\" accept\n") {
		t.Fatalf("the segment's tunnels after a move:\n%s", got)
	}
	dump.routes4 = ow5Tables("awg1")
	if s.refreshGuardLocal(true) {
		t.Errorf("the segment moving back between two known tunnels read as a change")
	}
	// awg1 gains a default route in the main table: it is a way out now, the provider's side.
	s.ksLocal.mu.Lock()
	s.ksLocal.uplink["awg1"] = true
	s.ksLocal.mu.Unlock()
	s.refreshGuardLocal(true)
	if got := s.nftGuardProgram(plan); strings.Contains(got, `oifname "awg1" accept`) {
		t.Fatalf("a device that became an uplink is still accepted:\n%s", got)
	}
	// Bounded.
	var many strings.Builder
	many.WriteString("0:\tfrom all lookup local\n")
	for i := 0; i < 3*ksSourceMax; i++ {
		many.WriteString("30:\tfrom 10.9." + string(rune('0'+i/10)) + string(rune('0'+i%10)) + ".0/24 lookup 160\n")
	}
	dump = ksSourceDump{rules4: many.String(), routes4: ow5Tables("awg_guest")}
	s.refreshGuardLocal(true)
	if n := len(s.guardSources()); n > ksSourceMax {
		t.Errorf("%d pairs told, the bound is %d", n, ksSourceMax)
	}
}

// Review says what a source-routed segment means for each kill-switched list: reached by the
// segment's own tunnel instead of the list's, or held when the rule leads to the provider.
func TestReviewNamesASourceRoutedSegmentAgainstAKillSwitchedList(t *testing.T) {
	plan := ow4Plan(t, "198.18.5.0/24")
	j := ow5Judge(t, plan)
	routes := sourceRoutes(ksSourceDump{rules4: ow5Rules, routes4: ow5Tables("awg1")}, j)
	fs := sourceRoutedFindings(plan, routes, false)
	if len(fs) != 1 || fs[0].ID != findingSourceRouted || fs[0].Item != "192.168.70.0/24 by awg1" ||
		!strings.Contains(fs[0].Detail, `"30: from 192.168.70.0/24 lookup 160"`) ||
		!strings.Contains(fs[0].Detail, `the list "office" (its tunnels: awg0, awg2) leaves by awg1`) ||
		!strings.Contains(fs[0].Detail, "never leaves by the provider") {
		t.Fatalf("a source-routed segment and a list by other tunnels: %+v", fs)
	}
	// The segment's tunnel is one of the list's: nothing to say.
	if fs := sourceRoutedFindings(plan, sourceRoutes(ksSourceDump{rules4: ow5Rules, routes4: ow5Tables("awg0")}, j), false); len(fs) != 0 {
		t.Errorf("a segment routed to the list's own tunnel: %+v", fs)
	}
	// The rule leads to the uplink: held, and under a names hold the whole segment is.
	fs = sourceRoutedFindings(plan, sourceRoutes(ksSourceDump{rules4: ow5Rules, routes4: ow5Tables("wan")}, j), true)
	if len(fs) != 1 || fs[0].ID != findingSourceHeld || !strings.Contains(fs[0].Detail, "wan is the provider's side") ||
		!strings.Contains(fs[0].Detail, `the list "office" cannot be reached`) || !strings.Contains(fs[0].Detail, "every new connection of that network") {
		t.Fatalf("a segment routed to the uplink: %+v", fs)
	}
	// No kill switch at all: nothing.
	open := ow4Plan(t, "198.18.5.0/24")
	for i := range open.Egresses {
		open.Egresses[i].FailClosed = false
	}
	if fs := sourceRoutedFindings(open, routes, false); len(fs) != 0 {
		t.Errorf("no kill switch: %+v", fs)
	}
}

// TestHelperUCIHang is not a test: it is the uci that never answers, for the test below.
func TestHelperUCIHang(t *testing.T) {
	if os.Getenv("WAYHOP_UCI_HANG") != "1" {
		t.Skip("helper process for TestReadUCIGivesUpOnAUCIThatHangs")
	}
	time.Sleep(time.Minute)
}

// A uci that hangs does not hold the reconcile tick behind it.
func TestReadUCIGivesUpOnAUCIThatHangs(t *testing.T) {
	oldCmd, oldPresent, oldTimeout := uciCommand, uciPresent, uciReadTimeout
	t.Cleanup(func() { uciCommand, uciPresent, uciReadTimeout = oldCmd, oldPresent, oldTimeout })
	uciPresent = func() bool { return true }
	uciReadTimeout = 300 * time.Millisecond
	uciCommand = func(ctx context.Context, _ ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperUCIHang$")
		cmd.Env = append(os.Environ(), "WAYHOP_UCI_HANG=1")
		return cmd
	}
	start := time.Now()
	_, _, err := readUCI()
	if err == nil || !strings.Contains(err.Error(), "no answer") {
		t.Fatalf("a hanging uci: err = %v", err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("readUCI took %s", took)
	}
}
