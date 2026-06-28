package netdiag

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"syscall"
	"testing"
)

func TestProbeTLS_Loopback(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	// httptest serves https on 127.0.0.1:<port>; ProbeTLS takes host[:port].
	res := ProbeTLS(context.Background(), u.Host)
	if !res.Reachable {
		t.Fatalf("expected Reachable=true, got error %q", res.Error)
	}
	if !res.ServedCert {
		t.Fatalf("expected ServedCert=true (httptest serves a cert)")
	}
	if res.Version == "" {
		t.Fatalf("expected a Version label, got empty")
	}
	// TLS13 must agree with the version the connection actually negotiated. The Go
	// httptest server's max version varies by toolchain, so assert consistency rather
	// than a fixed version.
	wantTLS13 := negotiatedTLS13(t, u.Host)
	if res.TLS13 != wantTLS13 {
		t.Fatalf("TLS13=%v but a direct handshake negotiated tls13=%v (version %q)", res.TLS13, wantTLS13, res.Version)
	}
	if res.TLS13 && res.Version != "1.3" {
		t.Fatalf("TLS13=true but Version=%q", res.Version)
	}
}

// TestProbeTLSWithControl_BlocksDial: the dial-time Control hook gates the TCP connection — even a
// reachable server is refused when the hook errors. This is what makes the probe's SSRF guard
// rebinding-proof: it vets the IP actually dialed (via blockInternalDial in the handler), not a
// separate resolve-time lookup that a rebinding DNS name could slip past.
func TestProbeTLSWithControl_BlocksDial(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	// Baseline: with no control the loopback server is reachable.
	if res := ProbeTLS(context.Background(), u.Host); !res.Reachable {
		t.Fatalf("baseline: expected Reachable=true, got %q", res.Error)
	}
	// With a Control hook that rejects the dial, the same reachable server must be refused.
	blocked := func(_, _ string, _ syscall.RawConn) error { return errors.New("refused by control") }
	res := ProbeTLSWithControl(context.Background(), u.Host, blocked)
	if res.Reachable {
		t.Fatal("the Control hook should have blocked the dial, but Reachable=true")
	}
	if res.Error == "" {
		t.Fatal("expected a dial error when the Control hook refuses the connection")
	}
}

// negotiatedTLS13 dials host directly and reports whether the negotiated version is
// TLS 1.3, so the probe's TLS13 flag can be checked against ground truth.
func negotiatedTLS13(t *testing.T, host string) bool {
	t.Helper()
	c, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("direct dial: %v", err)
	}
	defer c.Close()
	return c.ConnectionState().Version == tls.VersionTLS13
}

func TestProbeTLS_ClosedPort(t *testing.T) {
	// Bind a listener to grab a free port, then close it so the port is dead.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	res := ProbeTLS(context.Background(), addr)
	if res.Reachable {
		t.Fatalf("expected Reachable=false for a closed port")
	}
	if res.Error == "" {
		t.Fatalf("expected a non-empty Error for a closed port")
	}
}

func TestProbeTLS_BadHost(t *testing.T) {
	res := ProbeTLS(context.Background(), "no-such-host.invalid.")
	if res.Reachable {
		t.Fatalf("expected Reachable=false for an unresolvable host")
	}
	if res.Error == "" {
		t.Fatalf("expected a non-empty Error for an unresolvable host")
	}
}

func TestProbeTLS_EmptyHost(t *testing.T) {
	res := ProbeTLS(context.Background(), "   ")
	if res.Reachable || res.Error == "" {
		t.Fatalf("expected empty host to be rejected, got %+v", res)
	}
}
