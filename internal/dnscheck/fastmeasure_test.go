package dnscheck

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

type fakeFastConn struct {
	queryFn func(ctx context.Context, q []byte) ([]byte, error)
	cert    FastCertificate
}

func (c *fakeFastConn) Query(ctx context.Context, q []byte) ([]byte, error) {
	if c.queryFn != nil {
		return c.queryFn(ctx, q)
	}
	return nil, errors.New("no fake query function")
}

func (c *fakeFastConn) Certificate() FastCertificate {
	return c.cert
}

func (c *fakeFastConn) Close() error {
	return nil
}

type fakeFastNet struct {
	dohFn func(ctx context.Context, path Path, entry FastEntry) (FastConn, error)
	dotFn func(ctx context.Context, path Path, entry FastEntry) (FastConn, error)
}

func (f *fakeFastNet) DoH(ctx context.Context, path Path, entry FastEntry) (FastConn, error) {
	if f.dohFn != nil {
		return f.dohFn(ctx, path, entry)
	}
	return nil, errors.New("doh not configured")
}

func (f *fakeFastNet) DoT(ctx context.Context, path Path, entry FastEntry) (FastConn, error) {
	if f.dotFn != nil {
		return f.dotFn(ctx, path, entry)
	}
	return nil, errors.New("dot not configured")
}

func makeFakeDNSReply(query []byte, rcode uint16, ip string) []byte {
	if len(query) < 12 {
		return nil
	}
	msg := append([]byte(nil), query...)
	flags := uint16(0x8180) | (rcode & 0x0f)
	binary.BigEndian.PutUint16(msg[2:4], flags)
	if ip != "" && rcode == 0 {
		parsed := net.ParseIP(ip).To4()
		binary.BigEndian.PutUint16(msg[6:8], 1)
		msg = append(msg, 0xc0, 0x0c)
		msg = binary.BigEndian.AppendUint16(msg, dnsTypeA)
		msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
		msg = binary.BigEndian.AppendUint32(msg, 300)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(parsed)))
		msg = append(msg, parsed...)
	}
	return msg
}

// 1. Fake FastNet: all pass, sorted by Ms; a tie keeps catalog order.
func TestMeasureFastAllPassSortedWithTie(t *testing.T) {
	catalogRank := make(map[string]int, len(FastCatalog))
	for i, e := range FastCatalog {
		catalogRank[e.ID] = i
	}

	fake := &fakeFastNet{
		dohFn: func(ctx context.Context, path Path, entry FastEntry) (FastConn, error) {
			return &fakeFastConn{
				cert: FastCertificate{CertName: entry.Host, Issuer: "Test CA", CertDays: 90},
				queryFn: func(ctx context.Context, q []byte) ([]byte, error) {
					if bytes.Contains(q, []byte("dnssec-failed")) {
						return makeFakeDNSReply(q, rcodeServFail, ""), nil
					}
					// Introduce slight delay for predictable sorting:
					// first 3 entries sleep 15ms, others sleep 2ms (tied)
					if catalogRank[entry.ID] < 3 {
						time.Sleep(15 * time.Millisecond)
					} else {
						time.Sleep(2 * time.Millisecond)
					}
					return makeFakeDNSReply(q, rcodeNoError, "93.184.216.34"), nil
				},
			}, nil
		},
		dotFn: func(ctx context.Context, path Path, entry FastEntry) (FastConn, error) {
			return &fakeFastConn{
				cert: FastCertificate{CertName: entry.Host, Issuer: "Test CA", CertDays: 90},
				queryFn: func(ctx context.Context, q []byte) ([]byte, error) {
					if bytes.Contains(q, []byte("dnssec-failed")) {
						return makeFakeDNSReply(q, rcodeServFail, ""), nil
					}
					if catalogRank[entry.ID] < 3 {
						time.Sleep(15 * time.Millisecond)
					} else {
						time.Sleep(2 * time.Millisecond)
					}
					return makeFakeDNSReply(q, rcodeNoError, "93.184.216.34"), nil
				},
			}, nil
		},
	}

	progressCalls := 0
	results := MeasureFast(context.Background(), fake, Path{}, FastCatalog, FastOptions{
		OnProgress: func(done, total int) {
			progressCalls++
		},
	})

	if len(results) != len(FastCatalog) {
		t.Fatalf("results len = %d, want %d", len(results), len(FastCatalog))
	}
	if progressCalls != FastTransportCount(FastCatalog) {
		t.Errorf("OnProgress calls = %d, want %d", progressCalls, FastTransportCount(FastCatalog))
	}

	for i, r := range results {
		if !r.Alive {
			t.Errorf("entry %q not alive", r.ID)
		}
		if r.Best == "" {
			t.Errorf("entry %q has no Best", r.ID)
		}
		if r.Ms <= 0 {
			t.Errorf("entry %q non-positive Ms: %d", r.ID, r.Ms)
		}
		if i > 0 {
			prev := results[i-1]
			if r.Ms < prev.Ms {
				t.Fatalf("results not sorted by Ms: [%d] %s (%d ms) < [%d] %s (%d ms)",
					i, r.ID, r.Ms, i-1, prev.ID, prev.Ms)
			}
			if r.Ms == prev.Ms {
				// Ties must keep catalog order:
				if catalogRank[r.ID] < catalogRank[prev.ID] {
					t.Fatalf("tie between %s (rank %d) and %s (rank %d) violated catalog order",
						prev.ID, catalogRank[prev.ID], r.ID, catalogRank[r.ID])
				}
			}
		}
	}
}

// 2. DoH times out and DoT passes: Alive, Best dot, both transports reported.
func TestMeasureFastDoHTimeoutDoTPasses(t *testing.T) {
	entry := FastEntry{ID: "cloudflare", Host: "one.one.one.one", IP: "1.1.1.1", DoHPath: "/dns-query", DoT: true}
	fake := &fakeFastNet{
		dohFn: func(ctx context.Context, path Path, e FastEntry) (FastConn, error) {
			return nil, context.DeadlineExceeded
		},
		dotFn: func(ctx context.Context, path Path, e FastEntry) (FastConn, error) {
			return &fakeFastConn{
				cert: FastCertificate{CertName: e.Host, Issuer: "DigiCert", CertDays: 60},
				queryFn: func(ctx context.Context, q []byte) ([]byte, error) {
					if bytes.Contains(q, []byte("dnssec-failed")) {
						return makeFakeDNSReply(q, rcodeServFail, ""), nil
					}
					return makeFakeDNSReply(q, rcodeNoError, "104.16.132.229"), nil
				},
			}, nil
		},
	}

	results := MeasureFast(context.Background(), fake, Path{}, []FastEntry{entry}, FastOptions{})
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if !r.Alive {
		t.Errorf("expected Alive true, got false")
	}
	if r.Best != "dot" {
		t.Errorf("expected Best dot, got %q", r.Best)
	}
	if len(r.Transports) != 2 {
		t.Fatalf("expected 2 transports, got %d", len(r.Transports))
	}
	statusByProto := map[string]string{}
	for _, tr := range r.Transports {
		statusByProto[tr.Proto] = tr.Status
	}
	if statusByProto["doh"] != FastTimeout {
		t.Errorf("doh status = %q, want %q", statusByProto["doh"], FastTimeout)
	}
	if statusByProto["dot"] != FastOK {
		t.Errorf("dot status = %q, want %q", statusByProto["dot"], FastOK)
	}
}

// 3. bad_cert on both: not Alive, status kept.
func TestMeasureFastBadCertOnBoth(t *testing.T) {
	entry := FastEntry{ID: "broken-cert", Host: "broken.example", IP: "192.0.2.1", DoHPath: "/dns-query", DoT: true}
	fake := &fakeFastNet{
		dohFn: func(ctx context.Context, path Path, e FastEntry) (FastConn, error) {
			return nil, x509.UnknownAuthorityError{}
		},
		dotFn: func(ctx context.Context, path Path, e FastEntry) (FastConn, error) {
			return nil, x509.HostnameError{Certificate: &x509.Certificate{}, Host: e.Host}
		},
	}

	results := MeasureFast(context.Background(), fake, Path{}, []FastEntry{entry}, FastOptions{})
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if r.Alive {
		t.Errorf("expected Alive false, got true")
	}
	if len(r.Transports) != 2 {
		t.Fatalf("expected 2 transports, got %d", len(r.Transports))
	}
	for _, tr := range r.Transports {
		if tr.Status != FastBadCert {
			t.Errorf("transport %s status = %q, want %q", tr.Proto, tr.Status, FastBadCert)
		}
	}
}

// 4. Every transport bad_cert: CertsUnreliable. Two of three: not.
func TestFastCertsUnreliable(t *testing.T) {
	// Case A: 3 transports all bad_cert -> CertsUnreliable is true
	allBad := []FastResult{
		{ID: "e1", Transports: []FastTransport{{Proto: "doh", Status: FastBadCert}, {Proto: "dot", Status: FastBadCert}}},
		{ID: "e2", Transports: []FastTransport{{Proto: "doh", Status: FastBadCert}}},
	}
	if !FastCertsUnreliable(allBad) {
		t.Errorf("expected FastCertsUnreliable true when every transport is bad_cert (3 transports)")
	}

	// Case B: Two of three are bad_cert (the 3rd is timeout) -> CertsUnreliable is false
	twoOfThreeTimeout := []FastResult{
		{ID: "e1", Transports: []FastTransport{{Proto: "doh", Status: FastBadCert}, {Proto: "dot", Status: FastBadCert}}},
		{ID: "e2", Transports: []FastTransport{{Proto: "doh", Status: FastTimeout}}},
	}
	if FastCertsUnreliable(twoOfThreeTimeout) {
		t.Errorf("expected FastCertsUnreliable false for two of three bad_cert")
	}

	// Case C: Two of three are bad_cert (the 3rd is OK) -> CertsUnreliable is false
	twoOfThreeOK := []FastResult{
		{ID: "e1", Transports: []FastTransport{{Proto: "doh", Status: FastBadCert}, {Proto: "dot", Status: FastBadCert}}},
		{ID: "e2", Alive: true, Transports: []FastTransport{{Proto: "doh", Status: FastOK}}},
	}
	if FastCertsUnreliable(twoOfThreeOK) {
		t.Errorf("expected FastCertsUnreliable false when one passed")
	}

	// Case D: Only 2 transports total, both bad_cert (< 3 total) -> CertsUnreliable is false
	twoTotalBad := []FastResult{
		{ID: "e1", Transports: []FastTransport{{Proto: "doh", Status: FastBadCert}, {Proto: "dot", Status: FastBadCert}}},
	}
	if FastCertsUnreliable(twoTotalBad) {
		t.Errorf("expected FastCertsUnreliable false when fewer than 3 verdicts")
	}
}

// 5. Validates: true, false and nil.
func TestMeasureFastValidatesValues(t *testing.T) {
	runTest := func(t *testing.T, dnssecRcode uint16, dnssecIP string, dnssecErr error, want *bool) {
		t.Helper()
		entry := FastEntry{ID: "cf", Host: "one.one.one.one", IP: "1.1.1.1", DoHPath: "/dns-query"}
		fake := &fakeFastNet{
			dohFn: func(ctx context.Context, path Path, e FastEntry) (FastConn, error) {
				return &fakeFastConn{
					cert: FastCertificate{CertName: e.Host, Issuer: "DigiCert", CertDays: 60},
					queryFn: func(ctx context.Context, q []byte) ([]byte, error) {
						if bytes.Contains(q, []byte("dnssec-failed")) {
							if dnssecErr != nil {
								return nil, dnssecErr
							}
							return makeFakeDNSReply(q, dnssecRcode, dnssecIP), nil
						}
						return makeFakeDNSReply(q, rcodeNoError, "93.184.216.34"), nil
					},
				}, nil
			},
		}

		results := MeasureFast(context.Background(), fake, Path{}, []FastEntry{entry}, FastOptions{})
		if len(results) != 1 {
			t.Fatalf("got %d results, want 1", len(results))
		}
		got := results[0].Validates
		if want == nil {
			if got != nil {
				t.Errorf("Validates = %v, want nil", *got)
			}
		} else {
			if got == nil {
				t.Fatalf("Validates is nil, want %v", *want)
			}
			if *got != *want {
				t.Errorf("Validates = %v, want %v", *got, *want)
			}
		}
	}

	t.Run("SERVFAIL validates true", func(t *testing.T) {
		yes := true
		runTest(t, rcodeServFail, "", nil, &yes)
	})

	t.Run("NOERROR with address validates false", func(t *testing.T) {
		no := false
		runTest(t, rcodeNoError, "192.0.2.100", nil, &no)
	})

	t.Run("silence leaves validates nil", func(t *testing.T) {
		runTest(t, 0, "", context.DeadlineExceeded, nil)
	})
}

// 8. A cancelled context returns within a second.
func TestMeasureFastCancelledContextReturnsWithinASecond(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately before or right as MeasureFast begins:
	cancel()

	fake := &fakeFastNet{
		dohFn: func(ctx context.Context, path Path, e FastEntry) (FastConn, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
				return nil, errors.New("timeout")
			}
		},
		dotFn: func(ctx context.Context, path Path, e FastEntry) (FastConn, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
				return nil, errors.New("timeout")
			}
		},
	}

	start := time.Now()
	_ = MeasureFast(ctx, fake, Path{}, FastCatalog, FastOptions{
		Timeout: 6 * time.Second,
	})
	elapsed := time.Since(start)

	if elapsed >= time.Second {
		t.Fatalf("cancelled MeasureFast took %v, want < 1s", elapsed)
	}
}

func TestFastCertsUnreliableNeedsMostOfWhatWasTried(t *testing.T) {
	row := func(status string) FastResult {
		return FastResult{ID: status, Transports: []FastTransport{{Proto: "doh", Status: status}}}
	}
	few := []FastResult{row(FastBadCert), row(FastBadCert), row(FastBadCert)}
	for i := 0; i < 20; i++ {
		few = append(few, row(FastTimeout))
	}
	if FastCertsUnreliable(few) {
		t.Error("three bad certificates among twenty timeouts blamed the router")
	}
	if !FastCertsUnreliable([]FastResult{row(FastBadCert), row(FastBadCert), row(FastBadCert), row(FastTimeout)}) {
		t.Error("nearly every certificate failing did not point at the router")
	}
}

func TestParseFastReplyAcceptsAnErrorWithNoQuestion(t *testing.T) {
	query := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	msg := []byte{0x12, 0x34, 0x81, 0x82, 0, 0, 0, 0, 0, 0, 0, 0}
	reply, err := parseFastReply(query, msg)
	if err != nil || reply.Rcode != rcodeServFail {
		t.Errorf("reply = %+v, err = %v", reply, err)
	}
}
