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
	"sync"
	"syscall"
	"time"
)

// FastCertificate is the leaf certificate evidence from one verified connection.
type FastCertificate struct {
	CertName string
	Issuer   string
	CertDays int
}

// FastConn keeps one encrypted connection open for all queries in a transport measurement.
type FastConn interface {
	Query(ctx context.Context, q []byte) ([]byte, error)
	Certificate() FastCertificate
	Close() error
}

// FastNet opens the two encrypted transports. Implementations dial entry.IP directly and verify the
// certificate for entry.Host; neither method may resolve that host.
type FastNet interface {
	DoH(ctx context.Context, path Path, entry FastEntry) (FastConn, error)
	DoT(ctx context.Context, path Path, entry FastEntry) (FastConn, error)
}

// FastNetClient is the real FastNet. Port overrides both protocols' default port in loopback tests;
// zero uses 443 for DoH and 853 for DoT. RootCAs nil uses the host roots.
type FastNetClient struct {
	Port    int
	RootCAs *x509.CertPool

	control func(iface string) func(network, address string, c syscall.RawConn) error
}

// NewFastNet returns a client whose sockets are bound through control when a path names an interface.
func NewFastNet(control func(iface string) func(network, address string, c syscall.RawConn) error) FastNet {
	return &FastNetClient{control: control}
}

func (n *FastNetClient) port(fallback int) int {
	if n.Port != 0 {
		return n.Port
	}
	return fallback
}

func (n *FastNetClient) dialer(path Path) *net.Dialer {
	d := &net.Dialer{}
	if n.control != nil && path.Iface != "" {
		d.Control = n.control(path.Iface)
	}
	return d
}

func (n *FastNetClient) DoT(ctx context.Context, path Path, entry FastEntry) (FastConn, error) {
	d := tls.Dialer{
		NetDialer: n.dialer(path),
		Config: &tls.Config{
			ServerName: entry.Host,
			RootCAs:    n.RootCAs,
			MinVersion: tls.VersionTLS12,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", withPort(entry.IP, n.port(853)))
	if err != nil {
		return nil, fmt.Errorf("fast DoT connection: %w", err)
	}
	return &fastDoTConn{conn: conn}, nil
}

type fastDoTConn struct {
	conn net.Conn
}

func (c *fastDoTConn) Query(ctx context.Context, q []byte) ([]byte, error) {
	if len(q) > 65535 {
		return nil, errors.New("fast DoT query is too large")
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set fast DoT deadline: %w", err)
		}
	}
	// A cancelled context must interrupt a blocked read, not wait for the transport's original deadline.
	stopCancel := context.AfterFunc(ctx, func() { _ = c.conn.SetDeadline(time.Now()) })
	defer stopCancel()

	frame := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(q)))
	copy(frame[2:], q)
	if err := writeAll(c.conn, frame); err != nil {
		return nil, fmt.Errorf("write fast DoT query: %w", err)
	}
	var size [2]byte
	if _, err := io.ReadFull(c.conn, size[:]); err != nil {
		return nil, fmt.Errorf("read fast DoT response size: %w", err)
	}
	msg := make([]byte, int(binary.BigEndian.Uint16(size[:])))
	if _, err := io.ReadFull(c.conn, msg); err != nil {
		return nil, fmt.Errorf("read fast DoT response: %w", err)
	}
	return msg, nil
}

func (c *fastDoTConn) Certificate() FastCertificate {
	if conn, ok := c.conn.(*tls.Conn); ok {
		state := conn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			return fastCertificate(state.PeerCertificates[0])
		}
	}
	return FastCertificate{}
}

func (c *fastDoTConn) Close() error { return c.conn.Close() }

func (n *FastNetClient) DoH(_ context.Context, path Path, entry FastEntry) (FastConn, error) {
	dialer := n.dialer(path)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// The URL carries the certificate name for providers that require it; the socket never does.
			return dialer.DialContext(ctx, network, withPort(entry.IP, n.port(443)))
		},
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			ServerName: entry.Host,
			RootCAs:    n.RootCAs,
			MinVersion: tls.VersionTLS12,
		},
		TLSHandshakeTimeout: 6 * time.Second,
		MaxConnsPerHost:     1,
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
	}
	host := entry.Host
	if n.Port != 0 {
		host = net.JoinHostPort(host, strconv.Itoa(n.Port))
	}
	return &fastDoHConn{
		client:    &http.Client{Transport: transport},
		transport: transport,
		url:       "https://" + host + entry.DoHPath,
	}, nil
}

type fastDoHConn struct {
	client    *http.Client
	transport *http.Transport
	url       string

	mu          sync.Mutex
	certificate FastCertificate
}

func (c *fastDoHConn) Query(ctx context.Context, q []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(q))
	if err != nil {
		return nil, fmt.Errorf("build fast DoH request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fast DoH request: %w", err)
	}
	defer resp.Body.Close()
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := fastCertificate(resp.TLS.PeerCertificates[0])
		c.mu.Lock()
		c.certificate = cert
		c.mu.Unlock()
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &fastHTTPStatusError{status: resp.Status}
	}
	msg, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessage+1))
	if err != nil {
		return nil, fmt.Errorf("read fast DoH response: %w", err)
	}
	if len(msg) > maxDNSMessage {
		return nil, &fastResponseError{problem: "response exceeds 64 KB"}
	}
	return msg, nil
}

func (c *fastDoHConn) Certificate() FastCertificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.certificate
}

func (c *fastDoHConn) Close() error {
	c.transport.CloseIdleConnections()
	return nil
}

type fastHTTPStatusError struct{ status string }

func (e *fastHTTPStatusError) Error() string { return "fast DoH status " + e.status }

type fastResponseError struct{ problem string }

func (e *fastResponseError) Error() string { return "fast DoH " + e.problem }

func fastCertificate(cert *x509.Certificate) FastCertificate {
	name := cert.Subject.CommonName
	if name == "" && len(cert.DNSNames) > 0 {
		name = cert.DNSNames[0]
	}
	issuer := cert.Issuer.CommonName
	if issuer == "" {
		issuer = cert.Issuer.String()
	}
	days := int(time.Until(cert.NotAfter) / (24 * time.Hour))
	if days < 0 {
		days = 0
	}
	return FastCertificate{CertName: name, Issuer: issuer, CertDays: days}
}
