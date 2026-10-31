package health

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

type clockLogs []string

func (l clockLogs) LogLines() []string { return l }

// handshakeError runs a real crypto/tls handshake against a certificate valid from an hour ago for 90
// days and returns the client's error. skew moves the client's clock; trusted says whether the client
// knows the issuing CA. The text is Go's own, so the knowledge base is judged on what a router logs,
// not on a phrase written to suit the pattern.
func handshakeError(t *testing.T, skew time.Duration, trusted bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "exit.example"},
		DNSNames: []string{"exit.example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if trusted {
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		pool.AddCert(leaf)
	}
	c1, c2 := net.Pipe()
	defer c2.Close()
	srv := tls.Server(c1, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	done := make(chan struct{})
	go func() { _ = srv.Handshake(); c1.Close(); close(done) }()
	cli := tls.Client(c2, &tls.Config{ServerName: "exit.example", RootCAs: pool,
		Time: func() time.Time { return now.Add(skew) }})
	err = cli.Handshake()
	c2.Close()
	<-done
	if err == nil {
		t.Fatal("the handshake succeeded; the fixture must fail certificate verification")
	}
	return err.Error()
}

// QA-130. A router without an RTC boots after a power cut with its clock behind and every TLS exit
// fails with Go's "certificate has expired or is not yet valid". The down-exit card, the Test button
// and the bot's exits view show the first knowledge-base match, and that was the certificate-trust
// entry: "enable insecure or add the CA", which switches off certificate checking on a working server.
// The cause is the clock, in both directions.
func TestDeriveCause_ClockSkewIsTheClockNotTrust(t *testing.T) {
	for _, c := range []struct {
		name string
		skew time.Duration
		want string // the detail Go writes, so the fixture is the case named
	}{
		{"clock behind", -30 * 24 * time.Hour, "is before"},
		{"clock ahead", 120 * 24 * time.Hour, "is after"},
	} {
		msg := handshakeError(t, c.skew, true)
		if !strings.Contains(msg, "tls: failed to verify certificate: x509: certificate has expired or is not yet valid") || !strings.Contains(msg, c.want) {
			t.Fatalf("%s: Go's error changed shape: %q", c.name, msg)
		}
		line := "ERROR [3141592 12ms] connection: open outbound connection: " + msg
		m := &Monitor{logs: clockLogs{line}}
		id, title, fix := m.deriveCause()
		if id != "gen-clock" {
			t.Errorf("%s: derived %q (%s), want gen-clock", c.name, id, title)
		}
		if strings.Contains(fix, "enable 'insecure'") || strings.Contains(fix, "enable 'Allow insecure'") {
			t.Errorf("%s: the fix tells the owner to switch certificate checking off: %q", c.name, fix)
		}
	}
}

// A certificate the router does not trust, with the clock right, is still a trust problem: the
// reorder must not take that advice away from the case it is for.
func TestDeriveCause_UntrustedCertificateKeepsTheTrustAdvice(t *testing.T) {
	msg := handshakeError(t, 0, false)
	if !strings.Contains(msg, "x509: certificate signed by unknown authority") {
		t.Fatalf("Go's error changed shape: %q", msg)
	}
	m := &Monitor{logs: clockLogs{"ERROR connection: open outbound connection: " + msg}}
	if id, title, _ := m.deriveCause(); id != "gen-self-signed" {
		t.Errorf("derived %q (%s), want gen-self-signed, the trust entry it was before", id, title)
	}
}
