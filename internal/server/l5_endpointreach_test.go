package server

import (
	"context"
	"strings"
	"testing"
)

// TestEndpointReachVerdict (L5): "VPN servers reachable" must be able to go red on a router whose
// exits are native tunnels.
//
// Measured on a live Keenetic: all five exits are adopted NDM tunnels, so each has server "",
// port 0 and no endpoint_ip. The row dialled nothing, reported "no dialable endpoints - nothing to
// reach", and would have reported exactly that with all five tunnels down - while the monitor held
// state alive, handshake ok and a latency for every one of them. The battery answered fourteen
// questions and skipped the only one those five tunnels can fail.
func TestEndpointReachVerdict(t *testing.T) {
	// Five tunnels, all measured up: a real answer, not "nothing to reach".
	status, summary, _ := endpointReachVerdict(5, nil, nil)
	if status != "pass" || !strings.Contains(summary, "5") {
		t.Errorf("five measured, none down must pass and count them: %q %q", status, summary)
	}

	// One down of five is a warning that names the casualty.
	status, summary, detail := endpointReachVerdict(5, []string{"Armenia"}, nil)
	if status != "warn" || !strings.Contains(summary, "1 of 5") {
		t.Errorf("one down of five must warn: %q %q", status, summary)
	}
	if !strings.Contains(detail, "Armenia") {
		t.Errorf("the detail must name which one: %q", detail)
	}

	// Every exit down is not a warning. Nothing routed through a tunnel moves in that state.
	if status, _, _ := endpointReachVerdict(2, []string{"a", "b"}, nil); status != "fail" {
		t.Errorf("all exits down must fail, not warn: %q", status)
	}

	// The line that must never be crossed: never probed is not unreachable. An endpoint the monitor
	// has no sample for must not be counted as down, and must not read as a verified failure.
	status, summary, detail = endpointReachVerdict(0, nil, []string{"fresh"})
	if status != "na" {
		t.Errorf("an unprobed endpoint must be na, never a failure: %q", status)
	}
	if strings.Contains(summary, "unreachable") || strings.Contains(detail, "unreachable") {
		t.Errorf("nothing may read as unreachable when nothing was measured: %q / %q", summary, detail)
	}
	if !strings.Contains(detail, "fresh") {
		t.Errorf("and it must say which endpoint is unmeasured: %q", detail)
	}

	// A genuinely empty profile keeps the old, truthful answer.
	if status, summary, _ := endpointReachVerdict(0, nil, nil); status != "na" ||
		!strings.Contains(summary, "no endpoints") {
		t.Errorf("nothing configured must stay na: %q %q", status, summary)
	}

	// A router where some are measured and some are not must pass on what it measured AND disclose
	// what it did not. Silence there reads as "all five verified" when only four were.
	status, _, detail = endpointReachVerdict(4, nil, []string{"unprobed-one"})
	if status != "pass" || !strings.Contains(detail, "unprobed-one") {
		t.Errorf("a partial measurement must pass but disclose the gap: %q %q", status, detail)
	}
}

// TestEndpointReachDemoOpensNoSockets (L5): the demo answers from the monitor, never from a dial.
//
// The demo fixture points at reserved documentation addresses, so dialling them really does fail and
// the row reported "7 of 7 endpoint(s) unreachable" - a hard FAIL that drove the whole Diagnostics
// verdict to "Something is broken", while the flight recorder two cards below showed the same seven
// exits at 100% over 178 probes. Two contradictory claims about one set of endpoints on one screen,
// and the failing one was about the fixture rather than about anything a reader could act on. Every
// other environment-reading check on that page is already demo-aware.
func TestEndpointReachDemoOpensNoSockets(t *testing.T) {
	s := applyhealth_server(t) // Demo: true
	ep := applyhealth_endpoint("dead", "DeadServer")
	ep.Server, ep.Port = "127.0.0.1", 9 // discard port: a dial here is refused at once
	if err := s.store.UpsertEndpoint(ep); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	row := s.endpointReachCheck(context.Background())
	if row.Status == "warn" || row.Status == "fail" {
		t.Errorf("the demo must not call an endpoint unreachable on the strength of a socket it "+
			"opened: %+v", row)
	}
	if strings.Contains(row.Detail, "DeadServer") {
		t.Errorf("and must not name it as unreachable: %q", row.Detail)
	}
}
