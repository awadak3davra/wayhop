package dnscheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

type testCAs struct {
	rootPool      *x509.CertPool
	serverTLSConf *tls.Config
	wrongTLSConf  *tls.Config
}

func setupTestPKI(t *testing.T) testCAs {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Fast CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCert)

	// Valid leaf certificate for wh-fast-test.invalid
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "wh-fast-test.invalid"},
		DNSNames:     []string{"wh-fast-test.invalid"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafDER},
			PrivateKey:  leafKey,
		}},
	}

	// Wrong/untrusted leaf certificate
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	wrongTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "untrusted.invalid"},
		DNSNames:     []string{"untrusted.invalid"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	wrongDER, err := x509.CreateCertificate(rand.Reader, wrongTemplate, wrongTemplate, &wrongKey.PublicKey, wrongKey)
	if err != nil {
		t.Fatalf("create wrong cert: %v", err)
	}
	wrongTLSConf := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{wrongDER},
			PrivateKey:  wrongKey,
		}},
	}

	return testCAs{
		rootPool:      rootPool,
		serverTLSConf: serverTLSConf,
		wrongTLSConf:  wrongTLSConf,
	}
}

func startTestDoTServer(t *testing.T, conf *tls.Config) (int, func()) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", conf)
	if err != nil {
		t.Fatalf("listen DoT: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					var size [2]byte
					if _, err := io.ReadFull(c, size[:]); err != nil {
						return
					}
					qLen := int(binary.BigEndian.Uint16(size[:]))
					q := make([]byte, qLen)
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					resp := makeFakeDNSReply(q, rcodeNoError, "93.184.216.34")
					frame := make([]byte, 2+len(resp))
					binary.BigEndian.PutUint16(frame[:2], uint16(len(resp)))
					copy(frame[2:], resp)
					if _, err := c.Write(frame); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	cleanup := func() {
		_ = ln.Close()
	}
	return port, cleanup
}

func startTestDoHServer(t *testing.T, conf *tls.Config, statusCode int) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen DoH: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		if statusCode != 0 && statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := makeFakeDNSReply(body, rcodeNoError, "93.184.216.34")
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
	})

	srv := &http.Server{
		Handler:   mux,
		TLSConfig: conf,
	}
	go func() {
		_ = srv.ServeTLS(ln, "", "")
	}()

	cleanup := func() {
		_ = srv.Close()
		_ = ln.Close()
	}
	return port, cleanup
}

// 6. Real FastNet against 127.0.0.1 listeners with a test CA, using a port and root-pool override:
// DoT and DoH give Ms, ConnectMs, CertName; a wrong certificate gives bad_cert; a listener that accepts
// and stalls gives timeout inside the limit; refused gives refused; HTTP 500 gives bad_answer.
func TestFastNetRealLoopback(t *testing.T) {
	pki := setupTestPKI(t)

	// DoT test
	dotPort, dotCleanup := startTestDoTServer(t, pki.serverTLSConf)
	defer dotCleanup()

	dotNet := &FastNetClient{Port: dotPort, RootCAs: pki.rootPool}
	dotEntry := FastEntry{ID: "dot-test", IP: "127.0.0.1", Host: "wh-fast-test.invalid", DoT: true}
	dotRes := MeasureFast(context.Background(), dotNet, Path{}, []FastEntry{dotEntry}, FastOptions{})
	if len(dotRes) != 1 || !dotRes[0].Alive {
		t.Fatalf("DoT measure failed: %#v", dotRes)
	}
	dotTr := dotRes[0].Transports[0]
	if dotTr.Status != FastOK || dotTr.Ms <= 0 || dotTr.ConnectMs <= 0 || dotTr.CertName != "wh-fast-test.invalid" {
		t.Errorf("DoT transport mismatch: %#v", dotTr)
	}

	// DoH test
	dohPort, dohCleanup := startTestDoHServer(t, pki.serverTLSConf, http.StatusOK)
	defer dohCleanup()

	dohNet := &FastNetClient{Port: dohPort, RootCAs: pki.rootPool}
	dohEntry := FastEntry{ID: "doh-test", IP: "127.0.0.1", Host: "wh-fast-test.invalid", DoHPath: "/dns-query"}
	dohRes := MeasureFast(context.Background(), dohNet, Path{}, []FastEntry{dohEntry}, FastOptions{})
	if len(dohRes) != 1 || !dohRes[0].Alive {
		t.Fatalf("DoH measure failed: %#v", dohRes)
	}
	dohTr := dohRes[0].Transports[0]
	if dohTr.Status != FastOK || dohTr.Ms <= 0 || dohTr.ConnectMs <= 0 || dohTr.CertName != "wh-fast-test.invalid" {
		t.Errorf("DoH transport mismatch: %#v", dohTr)
	}

	// Wrong certificate gives bad_cert
	wrongPort, wrongCleanup := startTestDoTServer(t, pki.wrongTLSConf)
	defer wrongCleanup()

	wrongNet := &FastNetClient{Port: wrongPort, RootCAs: pki.rootPool}
	wrongEntry := FastEntry{ID: "wrong-test", IP: "127.0.0.1", Host: "wh-fast-test.invalid", DoT: true}
	wrongRes := MeasureFast(context.Background(), wrongNet, Path{}, []FastEntry{wrongEntry}, FastOptions{})
	if len(wrongRes) != 1 || wrongRes[0].Alive || wrongRes[0].Transports[0].Status != FastBadCert {
		t.Errorf("expected bad_cert on wrong cert, got: %#v", wrongRes)
	}

	// Listener that accepts and stalls gives timeout inside the limit
	stallLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen stall: %v", err)
	}
	stallPort := stallLn.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := stallLn.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	defer stallLn.Close()

	stallNet := &FastNetClient{Port: stallPort, RootCAs: pki.rootPool}
	stallEntry := FastEntry{ID: "stall-test", IP: "127.0.0.1", Host: "wh-fast-test.invalid", DoT: true}
	stallStart := time.Now()
	stallRes := MeasureFast(context.Background(), stallNet, Path{}, []FastEntry{stallEntry}, FastOptions{
		Timeout: 300 * time.Millisecond,
	})
	stallElapsed := time.Since(stallStart)
	if stallElapsed > 1500*time.Millisecond {
		t.Errorf("stall took %v, want timeout inside limit (~300ms)", stallElapsed)
	}
	if len(stallRes) != 1 || stallRes[0].Alive || stallRes[0].Transports[0].Status != FastTimeout {
		t.Errorf("expected timeout on stalling listener, got: %#v", stallRes)
	}

	// Refused gives refused
	freeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free: %v", err)
	}
	refusedPort := freeLn.Addr().(*net.TCPAddr).Port
	_ = freeLn.Close() // closed immediately, nothing listening

	refusedNet := &FastNetClient{Port: refusedPort, RootCAs: pki.rootPool}
	refusedEntry := FastEntry{ID: "refused-test", IP: "127.0.0.1", Host: "wh-fast-test.invalid", DoT: true}
	refusedRes := MeasureFast(context.Background(), refusedNet, Path{}, []FastEntry{refusedEntry}, FastOptions{})
	if len(refusedRes) != 1 || refusedRes[0].Alive || refusedRes[0].Transports[0].Status != FastRefused {
		t.Errorf("expected refused on closed port, got: %#v", refusedRes)
	}

	// HTTP 500 gives bad_answer
	h500Port, h500Cleanup := startTestDoHServer(t, pki.serverTLSConf, http.StatusInternalServerError)
	defer h500Cleanup()

	h500Net := &FastNetClient{Port: h500Port, RootCAs: pki.rootPool}
	h500Entry := FastEntry{ID: "500-test", IP: "127.0.0.1", Host: "wh-fast-test.invalid", DoHPath: "/dns-query"}
	h500Res := MeasureFast(context.Background(), h500Net, Path{}, []FastEntry{h500Entry}, FastOptions{})
	if len(h500Res) != 1 || h500Res[0].Alive || h500Res[0].Transports[0].Status != FastBadAnswer {
		t.Errorf("expected bad_answer on HTTP 500, got: %#v", h500Res)
	}
}

// 7. No lookups: the dial goes to entry.IP even when Host does not resolve; prove it with a host under .invalid.
func TestFastNetNoLookupsDialGoesToIP(t *testing.T) {
	pki := setupTestPKI(t)
	dotPort, dotCleanup := startTestDoTServer(t, pki.serverTLSConf)
	defer dotCleanup()

	dohPort, dohCleanup := startTestDoHServer(t, pki.serverTLSConf, http.StatusOK)
	defer dohCleanup()

	// Prove that the host does not resolve:
	unresolvableHost := "wh-fast-test.invalid"
	if _, err := net.LookupHost(unresolvableHost); err == nil {
		t.Fatalf("expected host %q to not resolve, but it resolved", unresolvableHost)
	}

	// DoT to 127.0.0.1 succeeds because dial uses IP, not Host:
	dotNet := &FastNetClient{Port: dotPort, RootCAs: pki.rootPool}
	dotEntry := FastEntry{ID: "dot-no-lookup", IP: "127.0.0.1", Host: unresolvableHost, DoT: true}
	dotConn, err := dotNet.DoT(context.Background(), Path{}, dotEntry)
	if err != nil {
		t.Fatalf("DoT dial failed: %v", err)
	}
	defer dotConn.Close()

	query, _ := BuildQuery("www.example.com", dnsTypeA, dnsClassIN, false)
	reply, err := dotConn.Query(context.Background(), query)
	if err != nil {
		t.Fatalf("DoT query failed: %v", err)
	}
	if parsed, err := parseFastReply(query, reply); err != nil || firstAddress(parsed) == "" {
		t.Fatalf("DoT unexpected reply: %v", err)
	}

	// DoH to 127.0.0.1 succeeds because dial uses IP, not Host:
	dohNet := &FastNetClient{Port: dohPort, RootCAs: pki.rootPool}
	dohEntry := FastEntry{ID: "doh-no-lookup", IP: "127.0.0.1", Host: unresolvableHost, DoHPath: "/dns-query"}
	dohConn, err := dohNet.DoH(context.Background(), Path{}, dohEntry)
	if err != nil {
		t.Fatalf("DoH setup failed: %v", err)
	}
	defer dohConn.Close()

	dohReply, err := dohConn.Query(context.Background(), query)
	if err != nil {
		t.Fatalf("DoH query failed: %v", err)
	}
	if parsed, err := parseFastReply(query, dohReply); err != nil || firstAddress(parsed) == "" {
		t.Fatalf("DoH unexpected reply: %v", err)
	}
}
