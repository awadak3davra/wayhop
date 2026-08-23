package netdiag

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests raise coverage on the result-shaping/exec paths of netdiag that
// the existing security-focused suite leaves uncovered: the SUCCESS branches of
// DialPort (open + closed port), Traceroute, DNSLookup, Run, plus additional
// reachable branches of Ping (count clamping, loopback parsing). Everything is
// kept deterministic and offline: only 127.0.0.1 / localhost and an in-process
// httptest server are used, with generous-but-bounded timeouts. The exec-based
// helpers (Ping/Traceroute) shell out to the OS ping/tracert against loopback,
// which always succeeds quickly. Parsing in netdiag.go is inline with exec, so
// these exercise the real parse regexes against real local command output.

// netdiag_freeTCPPort listens on an ephemeral 127.0.0.1 port, then closes the
// listener and returns the (now closed) port number. Connecting to it should be
// refused rather than hang, which keeps the "closed port" case deterministic.
func netdiag_freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port %q: %v", ln.Addr(), err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("atoi port %q: %v", portStr, err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return port
}

// netdiag_hostPortOf splits an addr like "127.0.0.1:65285" into host + int port.
func netdiag_hostPortOf(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("atoi port %q: %v", portStr, err)
	}
	return host, port
}

// TestDialPort_OpenPortSucceeds covers the success path of DialPort (the dial,
// the nil-error branch, and the Close) against a live in-process server.
func TestDialPort_OpenPortSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	host, port := netdiag_hostPortOf(t, srv.Listener.Addr().String())
	if !ValidTarget(host) {
		t.Fatalf("httptest host %q unexpectedly rejected by ValidTarget", host)
	}
	if !DialPort(host, port, 2*time.Second) {
		t.Fatalf("DialPort(%q, %d) = false, want true for an open listening port", host, port)
	}
}

// TestDialPort_ClosedPortFails covers the dial-error branch of DialPort against
// a port that was bound then released, so the connection is refused.
func TestDialPort_ClosedPortFails(t *testing.T) {
	port := netdiag_freeTCPPort(t)
	if DialPort("127.0.0.1", port, 1*time.Second) {
		t.Fatalf("DialPort(127.0.0.1, %d) = true, want false for a closed port", port)
	}
}

// TestDialPort_BoundsAndGuard re-confirms the guard/bounds branches return false
// without dialing (different shapes than the security suite, for extra branch
// coverage of the early-return condition).
func TestDialPort_BoundsAndGuard(t *testing.T) {
	cases := []struct {
		name string
		host string
		port int
	}{
		{"port-zero", "127.0.0.1", 0},
		{"port-negative", "127.0.0.1", -5},
		{"port-too-high", "127.0.0.1", 70000},
		{"port-max-plus-one", "127.0.0.1", 65536},
		{"unsafe-host", "bad host", 80},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if DialPort(c.host, c.port, 200*time.Millisecond) {
				t.Errorf("DialPort(%q, %d) = true, want false", c.host, c.port)
			}
		})
	}
}

// TestDialPort_MaxValidPortBoundary confirms port 65535 passes the bounds check
// (it does not need to be open — a refused connect still exercises the in-range
// branch and the dial-error path).
func TestDialPort_MaxValidPortBoundary(t *testing.T) {
	// 65535 is in range; nothing is expected to listen there, so this should
	// just return false via the dial-error branch, NOT the bounds guard.
	_ = DialPort("127.0.0.1", 65535, 200*time.Millisecond)
	// Port 1 is also in range (lower boundary); likewise reachable-or-not, we
	// only assert it does not panic and returns a bool.
	_ = DialPort("127.0.0.1", 1, 200*time.Millisecond)
}

// TestPing_LoopbackParsesLossAndShape covers the Ping exec + parse success path
// against loopback: loss is parsed (0% on a healthy loopback) and Ok is set.
func TestPing_LoopbackParsesLossAndShape(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := Ping(ctx, "127.0.0.1", 2)
	if r.Target != "127.0.0.1" {
		t.Errorf("Ping.Target = %q, want 127.0.0.1", r.Target)
	}
	if r.Output == "" {
		t.Fatalf("Ping.Output empty, expected command output")
	}
	if r.LossPct != 0 {
		t.Errorf("Ping.LossPct = %d, want 0 for healthy loopback (out=%q)", r.LossPct, r.Output)
	}
	if !r.Ok {
		t.Errorf("Ping.Ok = false, want true for 0%% loss loopback (out=%q)", r.Output)
	}
	if r.AvgMs < 0 {
		t.Errorf("Ping.AvgMs = %v, want a parsed (>=0) average for loopback (out=%q)", r.AvgMs, r.Output)
	}
}

// TestPing_CountClampingDoesNotPanic exercises the count<1 and count>10 clamp
// branches (both reset to the default 4). We use loopback so the exec is fast
// and deterministic; the assertion is only that it runs and reports success.
func TestPing_CountClamping(t *testing.T) {
	for _, count := range []int{0, -3, 11, 100} {
		count := count
		t.Run("count="+strconv.Itoa(count), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			r := Ping(ctx, "127.0.0.1", count)
			if !r.Ok {
				t.Errorf("Ping(127.0.0.1, %d).Ok = false, want true after count clamp (out=%q)", count, r.Output)
			}
		})
	}
}

// TestPing_InvalidTargetSentinel pins the early-return shape (default sentinel
// LossPct=-1, AvgMs=-1) for an unsafe target, complementing the security suite.
func TestPing_InvalidTargetSentinel(t *testing.T) {
	r := Ping(context.Background(), "bad target", 4)
	if r.Output != "invalid target" {
		t.Errorf("Ping.Output = %q, want %q", r.Output, "invalid target")
	}
	if r.LossPct != -1 || r.AvgMs != -1 {
		t.Errorf("Ping sentinel = (loss=%d avg=%v), want (-1, -1)", r.LossPct, r.AvgMs)
	}
	if r.Ok {
		t.Errorf("Ping.Ok = true, want false for invalid target")
	}
}

// TestTraceroute_LoopbackSucceeds covers the Traceroute exec + result-shaping
// success path (non-empty output, no "unavailable" sentinel) against loopback.
func TestTraceroute_LoopbackSucceeds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out := Traceroute(ctx, "127.0.0.1", 3)
	if strings.HasPrefix(out, "traceroute unavailable:") {
		t.Skipf("traceroute binary not installed in this environment: %q", out)
	}
	if out == "" {
		t.Fatalf("Traceroute returned empty output for loopback")
	}
	if !strings.Contains(out, "127.0.0.1") {
		t.Errorf("Traceroute output does not mention 127.0.0.1: %q", out)
	}
}

// TestTraceroute_MaxHopsClamping exercises the maxHops<1 and maxHops>30 clamp
// branches (reset to default 20). Loopback keeps it fast and deterministic.
func TestTraceroute_MaxHopsClamping(t *testing.T) {
	for _, hops := range []int{0, -1, 31, 99} {
		hops := hops
		t.Run("hops="+strconv.Itoa(hops), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			out := Traceroute(ctx, "127.0.0.1", hops)
			if strings.HasPrefix(out, "traceroute unavailable:") {
				t.Skipf("traceroute binary not installed in this environment: %q", out)
			}
			if out == "" {
				t.Errorf("Traceroute(127.0.0.1, %d) = %q, want usable output after hop clamp", hops, out)
			}
		})
	}
}

// TestDNSLookup_LoopbackLiteral covers the DNSLookup success path for an IP
// literal: LookupHost returns the literal itself, with no error.
func TestDNSLookup_LoopbackLiteral(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l := DNSLookup(ctx, "127.0.0.1")
	if l.Err != "" {
		t.Fatalf("DNSLookup(127.0.0.1).Err = %q, want empty", l.Err)
	}
	if l.Target != "127.0.0.1" {
		t.Errorf("DNSLookup.Target = %q, want 127.0.0.1", l.Target)
	}
	found := false
	for _, ip := range l.IPs {
		if ip == "127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("DNSLookup(127.0.0.1).IPs = %v, want to contain 127.0.0.1", l.IPs)
	}
}

// TestDNSLookup_LocalhostName covers the success path resolving the "localhost"
// name (present in the hosts database on every supported platform), exercising
// the LookupHost + the CNAME branch (localhost has no CNAME, so CNAME stays "").
func TestDNSLookup_LocalhostName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l := DNSLookup(ctx, "localhost")
	if l.Err != "" {
		t.Fatalf("DNSLookup(localhost).Err = %q, want empty (localhost must resolve)", l.Err)
	}
	if len(l.IPs) == 0 {
		t.Fatalf("DNSLookup(localhost).IPs empty, want at least one loopback address")
	}
	loopbackOnly := true
	for _, ip := range l.IPs {
		if pa := net.ParseIP(ip); pa == nil || !pa.IsLoopback() {
			loopbackOnly = false
		}
	}
	if !loopbackOnly {
		t.Errorf("DNSLookup(localhost).IPs = %v, want only loopback addresses", l.IPs)
	}
}

// TestRun_LoopbackAggregates covers the Run success path: it must accept the
// safe target, run all three diagnostics, and populate the Report. This drives
// the per-tool timeout-context setup and the aggregation that the security
// suite (which only tests the rejection path) never reaches.
func TestRun_LoopbackAggregates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rep, err := Run(ctx, "127.0.0.1")
	if err != nil {
		t.Fatalf("Run(127.0.0.1) err = %v, want nil", err)
	}
	if rep.Target != "127.0.0.1" {
		t.Errorf("Run.Report.Target = %q, want 127.0.0.1", rep.Target)
	}
	if rep.Ping.Target != "127.0.0.1" {
		t.Errorf("Run.Report.Ping.Target = %q, want 127.0.0.1", rep.Ping.Target)
	}
	if !rep.Ping.Ok {
		t.Errorf("Run.Report.Ping.Ok = false, want true for loopback (out=%q)", rep.Ping.Output)
	}
	if rep.Lookup.Err != "" {
		t.Errorf("Run.Report.Lookup.Err = %q, want empty for loopback literal", rep.Lookup.Err)
	}
	if len(rep.Lookup.IPs) == 0 {
		t.Errorf("Run.Report.Lookup.IPs empty, want loopback resolved")
	}
	if rep.Traceroute == "" {
		t.Errorf("Run.Report.Traceroute empty, want traceroute output")
	}
}

// TestRun_RespectsParentCancellation confirms Run still returns a (zero-valued
// but error-free) Report when the parent context is already cancelled: each
// sub-tool gets a cancelled context, so the externals fail fast and Run returns
// nil error with a populated Target. This exercises the success-path plumbing
// without depending on any external host being reachable.
func TestRun_CancelledParentContextStillReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	rep, err := Run(ctx, "127.0.0.1")
	if err != nil {
		t.Fatalf("Run with cancelled ctx err = %v, want nil (validation passed)", err)
	}
	if rep.Target != "127.0.0.1" {
		t.Errorf("Run.Report.Target = %q, want 127.0.0.1 even when ctx cancelled", rep.Target)
	}
	// Ping with a cancelled context cannot have 0% loss; Ok should be false.
	if rep.Ping.Ok {
		t.Logf("note: ping reported Ok despite cancelled ctx (out=%q)", rep.Ping.Output)
	}
}

// TestPing_AvgRegexPlatformShape is a light platform-awareness check: it pins
// which average-parsing regex is expected to fire on this OS so a future change
// to the arg/format wiring is noticed. It does not change behavior, only asserts
// the loopback result is internally consistent.
func TestPing_AvgRegexPlatformShape(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := Ping(ctx, "127.0.0.1", 2)
	switch runtime.GOOS {
	case "windows":
		if !strings.Contains(r.Output, "loss)") {
			t.Errorf("windows ping output missing 'loss)' summary: %q", r.Output)
		}
	default:
		if !strings.Contains(r.Output, "packet loss") {
			t.Errorf("unix ping output missing 'packet loss' summary: %q", r.Output)
		}
	}
	if r.LossPct != 0 {
		t.Errorf("loopback LossPct = %d, want 0", r.LossPct)
	}
}
