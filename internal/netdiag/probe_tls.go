package netdiag

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

// ProbeTLSResult summarizes a TLS-handshake probe of a host — the signal a Reality
// dest/SNI check needs: is the camouflage site TCP-reachable, does it actually speak
// TLS (serve a cert), and does it negotiate TLS 1.3? Reality borrows a real public
// TLS 1.3 site's SNI as cover, so a dest that is unreachable, not TLS, or stuck on
// TLS 1.2 silently breaks the connection — this surfaces that before the user saves.
type ProbeTLSResult struct {
	Host       string `json:"host"`              // the host probed (as given, normalized)
	Reachable  bool   `json:"reachable"`         // TCP connect + TLS handshake completed
	TLS13      bool   `json:"tls13"`             // negotiated TLS 1.3 (Reality requires it)
	ServedCert bool   `json:"served_cert"`       // the server presented a certificate
	Version    string `json:"version,omitempty"` // "1.3" / "1.2" / … (best-effort label)
	ALPN       string `json:"alpn,omitempty"`    // negotiated ALPN protocol, if any
	Error      string `json:"error,omitempty"`   // short cause when unreachable
}

// probeTLSTimeout bounds the whole dial+handshake. Reality dests are public sites;
// 6s is generous for a TCP+TLS round-trip while still failing fast on a dead host.
const probeTLSTimeout = 6 * time.Second

// ProbeTLS dials host (appending :443 when no port is given) and performs a TLS
// handshake with ServerName set to the bare hostname, reporting reachability, the
// negotiated version, and whether a certificate was served. It is PURE: it applies
// NO SSRF policy (the handler is responsible for refusing internal hosts) so it stays
// unit-testable against a loopback httptest TLS server.
//
// InsecureSkipVerify is intentional — this probes reachability / TLS version / that
// the host speaks TLS, NOT cert-chain validity: a Reality dest's certificate won't
// chain to the router, and the user is vetting the camouflage site, not trusting it.
// It never panics; any dial/handshake failure yields Reachable=false with a short
// Error.
func ProbeTLS(ctx context.Context, host string) ProbeTLSResult {
	return ProbeTLSWithControl(ctx, host, nil)
}

// ProbeTLSWithControl is ProbeTLS with a net.Dialer.Control hook applied to the TCP dial,
// so the caller can vet the ACTUALLY-RESOLVED address at connect time (e.g. the server's
// blockInternalDial). That makes an SSRF guard rebinding-proof: a resolve-time host check
// re-resolves independently at dial time and can be defeated by a name that rebinds to an
// internal IP between the two lookups, whereas Control fires on the IP actually dialed (for
// every candidate address). A nil control keeps the unrestricted dial the loopback handshake
// tests rely on.
func ProbeTLSWithControl(ctx context.Context, host string, control func(network, address string, c syscall.RawConn) error) ProbeTLSResult {
	host = strings.TrimSpace(host)
	res := ProbeTLSResult{Host: host}
	if host == "" {
		res.Error = "empty host"
		return res
	}

	// Split an optional :port; default to 443. The SNI must be the bare hostname
	// (no port), or the handshake's server_name extension is malformed.
	sni := host
	addr := net.JoinHostPort(host, "443") // default when host carries no :port
	if h, p, err := net.SplitHostPort(host); err == nil {
		sni = h
		addr = net.JoinHostPort(h, p)
	}

	dctx, cancel := context.WithTimeout(ctx, probeTLSTimeout)
	defer cancel()

	d := tls.Dialer{
		NetDialer: &net.Dialer{Control: control},
		Config: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true, //nolint:gosec // reachability/version probe, not a trust check (see doc)
			MinVersion:         tls.VersionTLS10,
		},
	}
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		res.Error = shortDialErr(err)
		return res
	}
	defer conn.Close()

	tc, ok := conn.(*tls.Conn)
	if !ok {
		// tls.Dialer always returns *tls.Conn on success; guard anyway so a future
		// change can't panic this probe.
		res.Error = "unexpected connection type"
		return res
	}
	st := tc.ConnectionState()
	res.Reachable = true
	res.ServedCert = len(st.PeerCertificates) > 0
	res.TLS13 = st.Version == tls.VersionTLS13
	res.Version = tlsVersionLabel(st.Version)
	res.ALPN = st.NegotiatedProtocol
	return res
}

// tlsVersionLabel maps a crypto/tls version constant to a short human label.
func tlsVersionLabel(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// shortDialErr reduces a dial/handshake error to a compact, user-facing cause so the
// UI pill stays readable (timeouts and refusals are the common cases).
func shortDialErr(err error) string {
	if err == nil {
		return ""
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return "timed out"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"):
		return "connection refused"
	case strings.Contains(msg, "no such host"):
		return "host not found"
	case strings.Contains(msg, "network is unreachable"):
		return "network unreachable"
	}
	// Trim a wrapped "tls:" / "dial tcp …:" prefix noise to a single short line.
	if i := strings.LastIndex(msg, ": "); i >= 0 && len(msg)-i < 60 {
		return msg[i+2:]
	}
	return msg
}
