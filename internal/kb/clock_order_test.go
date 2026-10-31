package kb

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// verifyError is the line Go's TLS client logs when certificate verification fails at clock now:
// crypto/x509's own error, wrapped the way crypto/tls wraps it. The certificate is valid from
// notBefore to notAfter and its issuer is trusted, so only the clock can fail it.
func verifyError(t *testing.T, notBefore, notAfter, now time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "exit.example"},
		DNSNames: []string{"exit.example"}, NotBefore: notBefore, NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "exit.example", CurrentTime: now})
	if err == nil {
		t.Fatal("verification passed; the fixture must fail on the clock")
	}
	return (&tls.CertificateVerificationError{Err: err}).Error()
}

// QA-130. The first entry a line matches is the cause the panel and the bot show. A clock-driven
// failure matches the certificate-trust entries too, and theirs is the advice to turn certificate
// checking off, so the clock entry has to come first for Go's real text, in both directions.
func TestClockFailureIsFirstMatchedAsTheClock(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name, line, detail string
	}{
		{"clock behind", verifyError(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), now.Add(-30*24*time.Hour)), "is before"},
		{"clock ahead", verifyError(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), now.Add(120*24*time.Hour)), "is after"},
	} {
		if !strings.HasPrefix(c.line, "tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time ") || !strings.Contains(c.line, c.detail) {
			t.Fatalf("%s: Go's error changed shape: %q", c.name, c.line)
		}
		m := Match("ERROR connection: open outbound connection: " + c.line)
		if len(m) == 0 || m[0].ID != "gen-clock" {
			t.Errorf("%s: first match %v, want gen-clock", c.name, ids(m))
		}
	}
}

// With the router clock right, the end of Go's message says which way the certificate fails, and the
// advice has to follow it: "is after" is a certificate that has expired and is renewed on the server;
// "is before" is one that starts in the future, which is the server's clock, not an expiry. The
// fixture is Go's own text for a certificate issued two days ahead of a correct clock.
func TestClockEntryNamesBothServerSideCases(t *testing.T) {
	now := time.Now()
	line := verifyError(t, now.Add(48*time.Hour), now.Add(90*24*time.Hour), now)
	if !strings.HasPrefix(line, "tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time ") || !strings.Contains(line, " is before ") {
		t.Fatalf("Go's error changed shape: %q", line)
	}
	m := Match("ERROR connection: open outbound connection: " + line)
	if len(m) == 0 || m[0].ID != "gen-clock" {
		t.Fatalf("first match %v, want gen-clock", ids(m))
	}
	text := m[0].Explanation + " " + m[0].Fix
	for _, want := range []string{
		"'is after'", "has expired", "renewed on the server", // the expired certificate
		"'is before'", "not valid yet", "server's clock", "issue the certificate again", // the one not valid yet
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the clock entry does not say %q: %q", want, text)
		}
	}
}

// The trust entries keep the lines that are theirs: an unknown issuer with the clock right is still
// reported first by the same trust entry as before the reorder.
func TestTrustFailureIsStillFirstMatchedAsTrust(t *testing.T) {
	line := `tls: failed to verify certificate: x509: certificate signed by unknown authority`
	if m := Match(line); len(m) == 0 || m[0].ID != "gen-self-signed" {
		t.Errorf("first match %v, want gen-self-signed", ids(m))
	}
	line = `tls: failed to verify certificate: x509: certificate is valid for a.example, not b.example`
	if m := Match(line); len(m) == 0 || m[0].ID == "gen-clock" {
		t.Errorf("a name mismatch was read as the clock: %v", ids(m))
	}
}

func ids(m []Entry) []string {
	out := make([]string, 0, len(m))
	for _, e := range m {
		out = append(out, e.ID)
	}
	return out
}
