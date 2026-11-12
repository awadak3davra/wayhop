package dnscheck

import (
	"context"
	"errors"
	"testing"
	"time"
)

// "Forged" is the one word on the page that sends a person to change their network, so these are the
// honest failures that must not reach it.

func TestEveryCertificateFailingIsNotForgery(t *testing.T) {
	fake := &scriptedNet{}
	fake.certFn = func(context.Context, Path, string, string) CertResult { return CertBad }
	result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}, Options{})
	if probe := probeByID(t, result, ProbeCanary); result.Verdict != VerdictPartial || probe.Code != CodeCanaryUnverified {
		t.Fatalf("no CA bundle or a wrong clock = %+v, canary = %+v", result, probe)
	}
}

func TestIdentitySERVFAILIsNotForgery(t *testing.T) {
	for _, tc := range []struct{ server, name string }{
		{"1.1.1.1", "id.server"},
		{"9.9.9.9", "id.server"},
		{"8.8.8.8", "o-o.myaddr.l.google.com"},
	} {
		fake := &scriptedNet{}
		fake.udpFn = func(_ context.Context, path Path, server string, q []byte, _ time.Duration) ([]Reply, error) {
			if name, _, _ := testQueryInfo(q); name == tc.name {
				return []Reply{{From: server, Msg: testDNSReply(q, rcodeServFail, false)}}, nil
			}
			return genuineUDP(path, server, q)
		}
		result := authenticateOne(t, fake, Target{Address: tc.server, Path: Path{Kind: PathTunnel}}, Options{})
		if probe := probeByID(t, result, ProbeIdentity); result.Verdict != VerdictPartial || probe.Code != CodeIdentitySilent {
			t.Errorf("%s: %+v, identity = %+v", tc.server, result.Verdict, probe)
		}
	}
}

func TestCloudflareEgressOutsideCompiledRangesIsNotForgery(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(_ context.Context, path Path, server string, q []byte, _ time.Duration) ([]Reply, error) {
		if name, _, _ := testQueryInfo(q); name == "o-o.myaddr.l.google.com" {
			return []Reply{{From: server, Msg: testDNSReply(q, rcodeServFail, false)}}, nil
		}
		return genuineUDP(path, server, q)
	}
	result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}, Options{})
	if result.Verdict != VerdictGenuine {
		t.Errorf("a silent or failing second reading must not lower the verdict: %+v", result)
	}
}

// Google's answer is two TXT records in no promised order.
func TestGoogleEgressIsFoundWhicheverRecordComesFirst(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(_ context.Context, path Path, server string, q []byte, _ time.Duration) ([]Reply, error) {
		if name, _, _ := testQueryInfo(q); name == "o-o.myaddr.l.google.com" {
			msg := testDNSReply(q, rcodeNoError, false, testTXT("edns0-client-subnet 203.0.113.0/24"), testTXT("8.8.8.9"))
			return []Reply{{From: server, Msg: msg}}, nil
		}
		return genuineUDP(path, server, q)
	}
	result := authenticateOne(t, fake, Target{Address: "8.8.8.8", Path: Path{Kind: PathTunnel}}, Options{})
	if result.Verdict != VerdictGenuine || result.Egress != "8.8.8.9" {
		t.Errorf("record order decided the verdict: %+v", result)
	}
}

func TestSilentNXDomainNamesAreNotRewriting(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(_ context.Context, path Path, server string, q []byte, _ time.Duration) ([]Reply, error) {
		if name, _, _ := testQueryInfo(q); len(name) > 3 && name[:3] == "wh-" {
			return nil, nil
		}
		return genuineUDP(path, server, q)
	}
	result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}, Options{})
	if probe := probeByID(t, result, ProbeNXDomain); probe.Status != StatusNoData || probe.Code != CodeNoReply {
		t.Errorf("silence reported as %+v", probe)
	}
}

func TestProgressReachesItsTotalWhenATargetStopsAtTheBaseProbe(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(context.Context, Path, string, []byte, time.Duration) ([]Reply, error) { return nil, nil }
	done, total := 0, 0
	Authenticate(context.Background(), fake, []Target{{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}}, nil, Options{
		OnProgress: func(d, t int) { done, total = d, t },
	})
	if done != total || total == 0 {
		t.Errorf("progress stopped at %d/%d", done, total)
	}
}

func TestIdentityNoErrorEmptyTXTIsNotForgery(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(_ context.Context, path Path, server string, q []byte, _ time.Duration) ([]Reply, error) {
		if name, _, _ := testQueryInfo(q); name == "id.server" {
			// NOERROR with no TXT records
			return []Reply{{From: server, Msg: testDNSReply(q, rcodeNoError, false)}}, nil
		}
		return genuineUDP(path, server, q)
	}
	result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}, Options{})
	if probe := probeByID(t, result, ProbeIdentity); result.Verdict != VerdictPartial || probe.Status != StatusNoData || probe.Code != CodeIdentitySilent {
		t.Errorf("NOERROR with empty TXT: verdict=%v, identity=%+v", result.Verdict, probe)
	}
}

func TestBogonRangesIncludesZeroAndClassE(t *testing.T) {
	if !bogonAddress("0.0.0.1") || !bogonAddress("0.255.255.255") {
		t.Errorf("0.0.0.0/8 should be bogon")
	}
	if !bogonAddress("240.0.0.1") || !bogonAddress("250.1.2.3") || !bogonAddress("255.255.255.254") {
		t.Errorf("240.0.0.0/4 should be bogon")
	}
	if bogonAddress("1.1.1.1") || bogonAddress("8.8.8.8") {
		t.Errorf("public resolvers must not be bogon")
	}
}

func TestCertsProveRetriesOnFailureUpToThreeTimes(t *testing.T) {
	calls := 0
	fake := &scriptedNet{}
	fake.certFn = func(context.Context, Path, string, string) CertResult {
		calls++
		if calls == 1 {
			return CertBad // first attempt fails
		}
		return CertOK // second attempt succeeds
	}
	run := newAuthRun(fake, Options{}, 1)
	path := Path{Kind: PathTunnel}
	if run.certsProve(context.Background(), path) {
		t.Fatalf("first call should return false")
	}
	if !run.certsProve(context.Background(), path) {
		t.Fatalf("second call should return true")
	}
	// Third call should use cached success without calling Cert
	if !run.certsProve(context.Background(), path) {
		t.Fatalf("third call should return cached true")
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls, got %d", calls)
	}

	// Now test 3 consecutive failures
	calls3 := 0
	fake3 := &scriptedNet{}
	fake3.certFn = func(context.Context, Path, string, string) CertResult {
		calls3++
		return CertBad
	}
	run3 := newAuthRun(fake3, Options{}, 1)
	for i := 1; i <= 3; i++ {
		if run3.certsProve(context.Background(), path) {
			t.Fatalf("attempt %d should fail", i)
		}
	}
	// 4th attempt should return false without calling Cert
	if run3.certsProve(context.Background(), path) {
		t.Fatalf("4th attempt should return false")
	}
	if calls3 != 3 {
		t.Fatalf("expected 3 calls, got %d", calls3)
	}
}

func TestGoogleLocationsRetriesOnNewPath(t *testing.T) {
	var dohPaths []Path
	fake := &scriptedNet{}
	fake.dohFn = func(_ context.Context, p Path, _ string, q []byte) ([]byte, string, error) {
		dohPaths = append(dohPaths, p)
		if p.Kind == PathWAN {
			return nil, "", errors.New("timeout on WAN")
		}
		// Return valid Google locations on Tunnel
		msg := testDNSReply(q, rcodeNoError, false, testTXT("8.8.8.0/24 iata"))
		return msg, "dns.google", nil
	}
	run := newAuthRun(fake, Options{}, 1)
	wanPath := Path{Kind: PathWAN}
	tunnelPath := Path{Kind: PathTunnel}

	// First attempt on WAN should fail and not cache failure
	ranges, err := run.googleLocations(context.Background(), wanPath)
	if err == nil || len(ranges) != 0 {
		t.Fatalf("expected WAN to fail, got ranges=%v, err=%v", ranges, err)
	}

	// Second attempt on Tunnel should succeed and cache
	ranges, err = run.googleLocations(context.Background(), tunnelPath)
	if err != nil || len(ranges) == 0 {
		t.Fatalf("expected Tunnel to succeed, got ranges=%v, err=%v", ranges, err)
	}

	// Third attempt on WAN should return cached ranges without calling DoH
	ranges, err = run.googleLocations(context.Background(), wanPath)
	if err != nil || len(ranges) == 0 {
		t.Fatalf("expected cached ranges, got %v, %v", ranges, err)
	}
	if len(dohPaths) != 2 {
		t.Fatalf("expected 2 DoH calls, got %d (%v)", len(dohPaths), dohPaths)
	}
}

func TestNXDomainUnclearWhenServfailOrNoRecords(t *testing.T) {
	for _, rcode := range []int{rcodeServFail, rcodeNoError} {
		fake := &scriptedNet{}
		fake.udpFn = func(_ context.Context, path Path, server string, q []byte, _ time.Duration) ([]Reply, error) {
			if name, _, _ := testQueryInfo(q); len(name) > 3 && name[:3] == "wh-" {
				// rcodeServFail or rcodeNoError with NO records
				return []Reply{{From: server, Msg: testDNSReply(q, rcode, false)}}, nil
			}
			return genuineUDP(path, server, q)
		}
		result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}, Options{})
		probe := probeByID(t, result, ProbeNXDomain)
		if probe.Status != StatusNoData || probe.Code != CodeNXUnclear {
			t.Errorf("rcode %d: expected StatusNoData/CodeNXUnclear, got %+v", rcode, probe)
		}
	}
}
