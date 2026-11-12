package dnscheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"syscall"
	"time"
)

const maxDNSMessage = 64 << 10

// NetClient is the real network implementation of Net. Port overrides UDP's default port; tests can also
// put an explicit port in a DoT server or Cert address. RootCAs nil uses the host roots.
type NetClient struct {
	Port        int
	RootCAs     *x509.CertPool
	CertTimeout time.Duration

	control func(iface string) func(network, address string, c syscall.RawConn) error
}

// NewNet returns a network client whose sockets are bound through control when a path names an interface.
func NewNet(control func(iface string) func(network, address string, c syscall.RawConn) error) Net {
	return &NetClient{Port: 53, CertTimeout: 5 * time.Second, control: control}
}

func (n *NetClient) udpPort() int {
	if n.Port == 0 {
		return 53
	}
	return n.Port
}

func (n *NetClient) timeout() time.Duration {
	if n.CertTimeout == 0 {
		return 5 * time.Second
	}
	return n.CertTimeout
}

func (n *NetClient) dialer(path Path) *net.Dialer {
	d := &net.Dialer{}
	if n.control != nil && path.Iface != "" {
		d.Control = n.control(path.Iface)
	}
	return d
}

// UDP deliberately uses an unconnected socket: connected UDP would discard the foreign-source replies
// this check is meant to expose.
func (n *NetClient) UDP(ctx context.Context, path Path, server string, q []byte, wait time.Duration) ([]Reply, error) {
	if len(q) < 2 {
		return nil, errors.New("UDP query has no DNS id")
	}
	if wait <= 0 {
		wait = 2 * time.Second
	}
	address := withPort(server, n.udpPort())
	network := udpNetwork(address)
	lc := net.ListenConfig{}
	if n.control != nil && path.Iface != "" {
		lc.Control = n.control(path.Iface)
	}
	conn, err := lc.ListenPacket(ctx, network, ":0")
	if err != nil {
		return nil, fmt.Errorf("open UDP probe socket: %w", err)
	}
	defer conn.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	remote, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP probe address: %w", err)
	}
	start := time.Now()
	if _, err := conn.WriteTo(q, remote); err != nil {
		return nil, fmt.Errorf("send UDP probe: %w", err)
	}

	end := start.Add(wait)
	deadline := end
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set UDP probe deadline: %w", err)
	}

	var replies []Reply
	buf := make([]byte, 65535)
	for {
		read, from, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return replies, ctx.Err()
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return replies, nil
			}
			return replies, fmt.Errorf("read UDP probe: %w", err)
		}
		if read < 2 || buf[0] != q[0] || buf[1] != q[1] {
			continue
		}
		msg := append([]byte(nil), buf[:read]...)
		ms := int(time.Since(start) / time.Millisecond)
		if ms < 1 {
			ms = 1 // the caller fills in a zero from its own clock, which has run on through the second-reply wait
		}
		replies = append(replies, Reply{From: addressHost(from.String()), Msg: msg, Ms: ms})
		if len(replies) == 1 {
			// Keep listening briefly for an injected second answer, without extending the original wait.
			tail := time.Now().Add(700 * time.Millisecond)
			if tail.Before(deadline) {
				deadline = tail
				if err := conn.SetReadDeadline(deadline); err != nil {
					return replies, fmt.Errorf("set UDP second-reply deadline: %w", err)
				}
			}
		}
	}
}

// DoT sends one length-prefixed DNS query over a certificate-verified TLS connection.
func (n *NetClient) DoT(ctx context.Context, path Path, server, sni string, q []byte) ([]byte, string, error) {
	if len(q) > 65535 {
		return nil, "", errors.New("DNS query is too large for DoT")
	}
	ctx, cancel := context.WithTimeout(ctx, n.timeout())
	defer cancel()
	d := tls.Dialer{
		NetDialer: n.dialer(path),
		Config: &tls.Config{
			ServerName: sni,
			RootCAs:    n.RootCAs,
			MinVersion: tls.VersionTLS12,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", withPort(server, 853))
	if err != nil {
		return nil, "", fmt.Errorf("DoT connection: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, "", fmt.Errorf("set DoT deadline: %w", err)
		}
	}

	frame := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(q)))
	copy(frame[2:], q)
	if err := writeAll(conn, frame); err != nil {
		return nil, "", fmt.Errorf("write DoT query: %w", err)
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, "", fmt.Errorf("read DoT response size: %w", err)
	}
	msg := make([]byte, int(binary.BigEndian.Uint16(size[:])))
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, "", fmt.Errorf("read DoT response: %w", err)
	}
	certName := ""
	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			certName = state.PeerCertificates[0].Subject.CommonName
		}
	}
	return msg, certName, nil
}

// DoH posts one DNS message. A private transport is required because the default transport does not
// necessarily attempt HTTP/2 for an IP URL, and some resolvers require it.
func (n *NetClient) DoH(ctx context.Context, path Path, url string, q []byte) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, n.timeout())
	defer cancel()
	dialer := n.dialer(path)
	transport := &http.Transport{
		DialContext:       dialer.DialContext,
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			RootCAs:    n.RootCAs,
			MinVersion: tls.VersionTLS12,
		},
		TLSHandshakeTimeout: n.timeout(),
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(q))
	if err != nil {
		return nil, "", fmt.Errorf("build DoH request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("DoH request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("DoH status %s", resp.Status)
	}
	msg, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessage+1))
	if err != nil {
		return nil, "", fmt.Errorf("read DoH response: %w", err)
	}
	if len(msg) > maxDNSMessage {
		return nil, "", errors.New("DoH response exceeds 64 KB")
	}
	certName := ""
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		certName = resp.TLS.PeerCertificates[0].Subject.CommonName
	}
	return msg, certName, nil
}

// Cert treats only certificate verification failures as proof of a bad endpoint. A provider refusing the
// connection or aborting TLS says nothing about the certificate that a working path would present.
func (n *NetClient) Cert(ctx context.Context, path Path, ip, name string) CertResult {
	ctx, cancel := context.WithTimeout(ctx, n.timeout())
	defer cancel()
	d := tls.Dialer{
		NetDialer: n.dialer(path),
		Config: &tls.Config{
			ServerName: name,
			RootCAs:    n.RootCAs,
			MinVersion: tls.VersionTLS12,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", withPort(ip, 443))
	if err != nil {
		if isCertificateError(err) {
			return CertBad
		}
		return CertNoConn
	}
	_ = conn.Close()
	return CertOK
}

func withPort(server string, port int) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, strconv.Itoa(port))
}

func addressHost(address string) string {
	if host, _, err := net.SplitHostPort(address); err == nil {
		return host
	}
	return address
}

func udpNetwork(address string) string {
	host := addressHost(address)
	ip := net.ParseIP(host)
	switch {
	case ip == nil:
		return "udp"
	case ip.To4() != nil:
		return "udp4"
	default:
		return "udp6"
	}
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func isCertificateError(err error) bool {
	var hostname x509.HostnameError
	var authority x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var verification *tls.CertificateVerificationError
	return errors.As(err, &hostname) || errors.As(err, &authority) || errors.As(err, &invalid) || errors.As(err, &verification)
}

func encryptedErrorDetail(err error) string {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}
	var alert tls.AlertError
	var record tls.RecordHeaderError
	if isCertificateError(err) || errors.As(err, &alert) || errors.As(err, &record) {
		return "tls"
	}
	return "other"
}
