package dnscheck

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestNetUDPCollectsRepliesAndForeignSource(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	foreign, err := net.ListenPacket("udp4", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()

	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		read, from, err := server.ReadFrom(buf)
		if err != nil {
			serverErr <- err
			return
		}
		response := loopbackDNSResponse(buf[:read])
		if _, err := foreign.WriteTo(response, from); err != nil {
			serverErr <- err
			return
		}
		if _, err := server.WriteTo(response, from); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	n := NewNet(nil).(*NetClient)
	n.Port = server.LocalAddr().(*net.UDPAddr).Port
	q, err := BuildQuery("www.example.com", dnsTypeA, dnsClassIN, false)
	if err != nil {
		t.Fatal(err)
	}
	replies, err := n.UDP(context.Background(), Path{}, "127.0.0.1", q, 1500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if len(replies) != 2 {
		t.Fatalf("got %d replies, want 2", len(replies))
	}
	sources := map[string]bool{}
	for _, reply := range replies {
		sources[reply.From] = true
	}
	if !sources["127.0.0.1"] || !sources["127.0.0.2"] {
		t.Errorf("sources = %v, want both loopback addresses", sources)
	}
}

func TestNetDoT(t *testing.T) {
	roots, certificate := loopbackPKI(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			serverErr <- err
			return
		}
		query := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if _, err := io.ReadFull(conn, query); err != nil {
			serverErr <- err
			return
		}
		response := loopbackDNSResponse(query)
		frame := append([]byte{byte(len(response) >> 8), byte(len(response))}, response...)
		serverErr <- writeAll(conn, frame)
	}()

	n := NewNet(nil).(*NetClient)
	n.RootCAs = roots
	n.CertTimeout = 2 * time.Second
	query, err := BuildQuery("www.example.com", dnsTypeA, dnsClassIN, false)
	if err != nil {
		t.Fatal(err)
	}
	msg, certName, err := n.DoT(context.Background(), Path{}, listener.Addr().String(), "dns.test", query)
	if err != nil {
		t.Fatal(err)
	}
	if certName != "wayhop-loopback-test" || len(msg) != 12 {
		t.Errorf("DoT response = %x, certificate %q", msg, certName)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestNetDoH(t *testing.T) {
	roots, certificate := loopbackPKI(t)
	handlerErr := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			handlerErr <- fmt.Errorf("protocol = %s, want HTTP/2", r.Proto)
			return
		}
		if r.Header.Get("Content-Type") != "application/dns-message" {
			handlerErr <- fmt.Errorf("content type = %q", r.Header.Get("Content-Type"))
			return
		}
		query, err := io.ReadAll(r.Body)
		if err != nil {
			handlerErr <- err
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, err = w.Write(loopbackDNSResponse(query))
		handlerErr <- err
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	n := NewNet(nil).(*NetClient)
	n.RootCAs = roots
	n.CertTimeout = 2 * time.Second
	query, err := BuildQuery("locations.publicdns.goog", dnsTypeTXT, dnsClassIN, false)
	if err != nil {
		t.Fatal(err)
	}
	msg, certName, err := n.DoH(context.Background(), Path{}, server.URL, query)
	if err != nil {
		t.Fatal(err)
	}
	if certName != "wayhop-loopback-test" || len(msg) != 12 {
		t.Errorf("DoH response = %x, certificate %q", msg, certName)
	}
	if err := <-handlerErr; err != nil {
		t.Fatal(err)
	}
}

func TestNetCertResults(t *testing.T) {
	roots, certificate := loopbackPKI(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
				_ = conn.Close()
			}()
		}
	}()

	n := NewNet(nil).(*NetClient)
	n.RootCAs = roots
	n.CertTimeout = 2 * time.Second
	if got := n.Cert(context.Background(), Path{}, listener.Addr().String(), "canary.test"); got != CertOK {
		t.Errorf("valid certificate = %s", got)
	}
	if got := n.Cert(context.Background(), Path{}, listener.Addr().String(), "wrong.test"); got != CertBad {
		t.Errorf("wrong certificate name = %s", got)
	}

	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	go func() {
		conn, err := plain.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	if got := n.Cert(context.Background(), Path{}, plain.Addr().String(), "canary.test"); got != CertNoConn {
		t.Errorf("closed TLS connection = %s", got)
	}
}

func TestNetControlErrorFailsSocket(t *testing.T) {
	want := errors.New("interface disappeared")
	control := func(iface string) func(string, string, syscall.RawConn) error {
		return func(string, string, syscall.RawConn) error { return want }
	}
	n := NewNet(control).(*NetClient)
	query, err := BuildQuery("www.example.com", dnsTypeA, dnsClassIN, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = n.UDP(context.Background(), Path{Iface: "test0"}, "127.0.0.1", query, time.Second)
	if !errors.Is(err, want) {
		t.Fatalf("UDP error = %v, want control error", err)
	}
}

func TestEncryptedErrorDetail(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{context.DeadlineExceeded, "timeout"},
		{syscall.ECONNREFUSED, "refused"},
		{x509.HostnameError{}, "tls"},
		{tls.AlertError(40), "tls"},
		{errors.New("bad HTTP status"), "other"},
	} {
		if got := encryptedErrorDetail(tc.err); got != tc.want {
			t.Errorf("encryptedErrorDetail(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func loopbackDNSResponse(query []byte) []byte {
	msg := make([]byte, 12)
	if len(query) >= 2 {
		copy(msg, query[:2])
	}
	binary.BigEndian.PutUint16(msg[2:4], 0x8180)
	return msg
}

func loopbackPKI(t *testing.T) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	now := time.Now()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "wayhop-loopback-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "wayhop-loopback-test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"dns.test", "canary.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, leafPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return roots, tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafPrivate}
}

func TestWithPort(t *testing.T) {
	if got := withPort("127.0.0.1", 53); got != net.JoinHostPort("127.0.0.1", strconv.Itoa(53)) {
		t.Errorf("withPort = %q", got)
	}
	if got := withPort("127.0.0.1:5353", 53); got != "127.0.0.1:5353" {
		t.Errorf("explicit port changed to %q", got)
	}
}
