package dnscheck

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fakeUDPCall struct {
	path   Path
	server string
	name   string
	qtype  uint16
	class  uint16
}

type fakeCertCall struct {
	path Path
	ip   string
	name string
}

type scriptedNet struct {
	mu        sync.Mutex
	udpCalls  []fakeUDPCall
	certCalls []fakeCertCall
	dohPaths  []Path

	udpFn  func(context.Context, Path, string, []byte, time.Duration) ([]Reply, error)
	dotFn  func(context.Context, Path, string, string, []byte) ([]byte, string, error)
	dohFn  func(context.Context, Path, string, []byte) ([]byte, string, error)
	certFn func(context.Context, Path, string, string) CertResult
}

func (f *scriptedNet) UDP(ctx context.Context, path Path, server string, q []byte, wait time.Duration) ([]Reply, error) {
	name, qtype, class := testQueryInfo(q)
	f.mu.Lock()
	f.udpCalls = append(f.udpCalls, fakeUDPCall{path: path, server: server, name: name, qtype: qtype, class: class})
	f.mu.Unlock()
	if f.udpFn != nil {
		return f.udpFn(ctx, path, server, q, wait)
	}
	return genuineUDP(path, server, q)
}

func (f *scriptedNet) DoT(ctx context.Context, path Path, server, sni string, q []byte) ([]byte, string, error) {
	if f.dotFn != nil {
		return f.dotFn(ctx, path, server, sni, q)
	}
	return testDNSReply(q, rcodeNoError, false), "one.one.one.one", nil
}

func (f *scriptedNet) DoH(ctx context.Context, path Path, url string, q []byte) ([]byte, string, error) {
	f.mu.Lock()
	f.dohPaths = append(f.dohPaths, path)
	f.mu.Unlock()
	if f.dohFn != nil {
		return f.dohFn(ctx, path, url, q)
	}
	name, _, _ := testQueryInfo(q)
	if name == "locations.publicdns.goog" {
		return testDNSReply(q, rcodeNoError, false, testTXT("8.8.8.0/24 iad")), "dns.google", nil
	}
	return testDNSReply(q, rcodeNoError, false), "dns.google", nil
}

func (f *scriptedNet) Cert(ctx context.Context, path Path, ip, name string) CertResult {
	f.mu.Lock()
	f.certCalls = append(f.certCalls, fakeCertCall{path: path, ip: ip, name: name})
	f.mu.Unlock()
	if f.certFn != nil {
		return f.certFn(ctx, path, ip, name)
	}
	return CertOK
}

func genuineUDP(path Path, server string, q []byte) ([]Reply, error) {
	name, qtype, _ := testQueryInfo(q)
	if server == "192.0.2.1" || server == "198.51.100.7" {
		return nil, nil
	}
	response := func(rcode int, ad bool, records ...testRecord) []Reply {
		return []Reply{{From: addressHost(server), Msg: testDNSReply(q, rcode, ad, records...), Ms: 20}}
	}
	switch name {
	case "www.example.com":
		return response(rcodeNoError, false, testA("1.1.1.1")), nil
	case "id.server":
		if qtype != dnsTypeTXT {
			return response(rcodeNoError, false), nil
		}
		switch server {
		case "1.1.1.1", "1.0.0.1":
			return response(rcodeNoError, false, testTXT("arn02")), nil
		case "9.9.9.9":
			return response(rcodeNoError, false, testTXT("res701.arn")), nil
		default:
			return response(rcodeServFail, false), nil
		}
	case "o-o.myaddr.l.google.com":
		switch server {
		case "1.1.1.1", "1.0.0.1":
			return response(rcodeNoError, false, testTXT("162.158.0.1")), nil
		default:
			return response(rcodeNoError, false, testTXT("8.8.8.8", "edns0-client-subnet 0.0.0.0/0")), nil
		}
	case "dnssec-failed.org":
		return response(rcodeServFail, false), nil
	case "cloudflare.com":
		return response(rcodeNoError, true, testA("1.1.1.1"), testRRSIG()), nil
	default:
		if strings.HasPrefix(name, "wh-") {
			return response(rcodeNXDomain, false), nil
		}
		return response(rcodeNoError, false, testA("1.1.1.1")), nil
	}
}

func authenticateOne(t *testing.T, fake *scriptedNet, target Target, options Options) ResolverResult {
	t.Helper()
	results := Authenticate(context.Background(), fake, []Target{target}, nil, options)
	if len(results) != 1 {
		t.Fatalf("got %d resolver results", len(results))
	}
	return results[0]
}

func probeByID(t *testing.T, result ResolverResult, id string) Probe {
	t.Helper()
	for _, probe := range result.Probes {
		if probe.ID == id {
			return probe
		}
	}
	t.Fatalf("probe %q is missing from %+v", id, result.Probes)
	return Probe{}
}

func TestAuthenticateCloudflareGenuine(t *testing.T) {
	result := authenticateOne(t, &scriptedNet{}, Target{Address: "1.1.1.1", Path: Path{Kind: PathTunnel, Iface: "tun0"}}, Options{})
	if result.Verdict != VerdictGenuine || result.Site != "arn02" || result.RttMs != 20 {
		t.Fatalf("Cloudflare result = %+v", result)
	}
	for _, id := range []string{ProbeBase, ProbeIdentity, ProbeBogus, ProbeSigned, ProbeNXDomain, ProbeSecondReply, ProbeSource, ProbeCanary} {
		if probe := probeByID(t, result, id); probe.Status != StatusPass {
			t.Errorf("%s = %+v", id, probe)
		}
	}
}

func TestAuthenticateGoogleGenuine(t *testing.T) {
	fake := &scriptedNet{}
	result := authenticateOne(t, fake, Target{Address: "8.8.8.8", Path: Path{Kind: PathTunnel, Iface: "tun0"}}, Options{})
	if result.Verdict != VerdictGenuine || result.Egress != "8.8.8.8" {
		t.Fatalf("Google result = %+v", result)
	}
	if len(fake.dohPaths) != 1 {
		t.Errorf("Google locations fetched %d times", len(fake.dohPaths))
	}
}

func TestAuthenticateFilteringExit(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(ctx context.Context, path Path, server string, q []byte, wait time.Duration) ([]Reply, error) {
		_, qtype, _ := testQueryInfo(q)
		if qtype == dnsTypeTXT {
			return nil, nil
		}
		return genuineUDP(path, server, q)
	}
	result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}, Options{})
	identity := probeByID(t, result, ProbeIdentity)
	if result.Verdict != VerdictPartial || identity.Status != StatusNoData || identity.Code != CodeIdentitySilent {
		t.Fatalf("filtering result = %+v, identity = %+v", result, identity)
	}
}

func TestAuthenticateUnreachablePair(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(context.Context, Path, string, []byte, time.Duration) ([]Reply, error) { return nil, nil }
	targets := []Target{{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}, {Address: "1.0.0.1", Path: Path{Kind: PathTunnel}}}
	results := Authenticate(context.Background(), fake, targets, nil, Options{})
	if len(results) != 2 {
		t.Fatalf("got %d results", len(results))
	}
	for _, result := range results {
		if result.Verdict != VerdictUnreachable || len(result.Probes) != 1 || result.Probes[0].ID != ProbeBase {
			t.Errorf("unreachable result = %+v", result)
		}
	}
}

func TestAuthenticateRealInterceptor(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(ctx context.Context, path Path, server string, q []byte, wait time.Duration) ([]Reply, error) {
		name, _, _ := testQueryInfo(q)
		if server == "192.0.2.1" || server == "198.51.100.7" {
			return []Reply{{From: server, Msg: testDNSReply(q, rcodeNoError, false, testA("1.1.1.1"))}}, nil
		}
		switch name {
		case "id.server":
			return []Reply{{From: server, Msg: testDNSReply(q, 4, false)}}, nil // NOTIMP, as measured
		case "dnssec-failed.org":
			return nil, nil
		case "cloudflare.com":
			return []Reply{{From: server, Msg: testDNSReply(q, rcodeNoError, false, testA("1.1.1.1"), testRRSIG())}}, nil
		default:
			return genuineUDP(path, server, q)
		}
	}
	path := Path{Kind: PathWAN, Iface: "wan0"}
	interceptions := Interceptions(context.Background(), fake, []Path{path}, Options{})
	if len(interceptions) != 1 || !interceptions[0].Intercepted {
		t.Fatalf("interceptions = %+v", interceptions)
	}
	results := Authenticate(context.Background(), fake, []Target{{Address: "1.1.1.1", Path: path}}, interceptions, Options{CanariesOnWAN: true})
	result := results[0]
	if result.Verdict != VerdictForged {
		t.Fatalf("interceptor result = %+v", result)
	}
	if probe := probeByID(t, result, ProbeInterception); probe.Code != CodePathIntercepted {
		t.Errorf("decoy probe = %+v", probe)
	}
	if probe := probeByID(t, result, ProbeIdentity); probe.Status != StatusFail || probe.Code != CodeIdentityMismatch {
		t.Errorf("identity probe = %+v", probe)
	}
	if probe := probeByID(t, result, ProbeSigned); probe.Status != StatusWarn || probe.Code != CodeADMissing {
		t.Errorf("signed probe = %+v", probe)
	}
}

func TestAuthenticateSelectiveBadCertificate(t *testing.T) {
	fake := &scriptedNet{}
	fake.certFn = func(ctx context.Context, path Path, ip, name string) CertResult {
		if name == "instagram.com" {
			return CertBad
		}
		return CertOK
	}
	result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}, Options{})
	probe := probeByID(t, result, ProbeCanary)
	if result.Verdict != VerdictForged || probe.Code != CodeCanaryBadCert || !strings.HasPrefix(probe.Detail, "instagram.com ") {
		t.Fatalf("selective forgery = %+v, canary = %+v", result, probe)
	}
}

func TestAuthenticateSecondReplyInjection(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(ctx context.Context, path Path, server string, q []byte, wait time.Duration) ([]Reply, error) {
		name, _, _ := testQueryInfo(q)
		if name == "x.com" {
			return []Reply{
				{From: server, Msg: testDNSReply(q, rcodeNoError, false, testA("1.1.1.1"))},
				{From: server, Msg: testDNSReply(q, rcodeNoError, false, testA("8.8.8.8"))},
			}, nil
		}
		return genuineUDP(path, server, q)
	}
	result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}, Options{})
	probe := probeByID(t, result, ProbeSecondReply)
	if result.Verdict != VerdictForged || probe.Code != CodeSecondReply || probe.Detail != "x.com" {
		t.Fatalf("injection = %+v, second reply = %+v", result, probe)
	}
}

func TestAuthenticateIdenticalDuplicatesPass(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(ctx context.Context, path Path, server string, q []byte, wait time.Duration) ([]Reply, error) {
		replies, err := genuineUDP(path, server, q)
		if len(replies) == 1 {
			replies = append(replies, replies[0])
		}
		return replies, err
	}
	result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}, Options{})
	if probe := probeByID(t, result, ProbeSecondReply); probe.Status != StatusPass {
		t.Fatalf("identical duplicates = %+v", probe)
	}
}

func TestAuthenticateProviderConnectionBlock(t *testing.T) {
	fake := &scriptedNet{}
	fake.certFn = func(context.Context, Path, string, string) CertResult { return CertNoConn }
	result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathWAN}}, Options{CanariesOnWAN: true})
	probe := probeByID(t, result, ProbeCanary)
	if result.Verdict != VerdictPartial || probe.Status != StatusNoData || probe.Code != CodeCanaryUnverified || probe.Detail != "0/6" {
		t.Fatalf("blocked connections = %+v, canary = %+v", result, probe)
	}
}

func TestAuthenticateProofPath(t *testing.T) {
	fake := &scriptedNet{}
	fake.certFn = func(ctx context.Context, path Path, ip, name string) CertResult {
		if path.Kind == PathTunnel {
			return CertOK
		}
		return CertNoConn
	}
	proof := Path{Kind: PathTunnel, Iface: "tun0"}
	result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathWAN, Iface: "wan0"}}, Options{CanariesOnWAN: true, ProofPath: &proof})
	if result.Verdict != VerdictGenuine {
		t.Fatalf("proof path result = %+v", result)
	}
	if len(fake.certCalls) != 6 {
		t.Fatalf("got %d certificate calls", len(fake.certCalls))
	}
	for _, call := range fake.certCalls {
		if call.path != proof {
			t.Errorf("certificate call used %+v, want %+v", call.path, proof)
		}
	}
}

func TestAuthenticateNXDomainRewriting(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(ctx context.Context, path Path, server string, q []byte, wait time.Duration) ([]Reply, error) {
		name, _, _ := testQueryInfo(q)
		if strings.HasPrefix(name, "wh-") {
			return []Reply{{From: server, Msg: testDNSReply(q, rcodeNoError, false, testA("1.1.1.1"))}}, nil
		}
		return genuineUDP(path, server, q)
	}
	result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}, Options{})
	if probe := probeByID(t, result, ProbeNXDomain); result.Verdict != VerdictForged || probe.Code != CodeNXRewritten || probe.Status != StatusFail {
		t.Fatalf("NXDOMAIN rewriting = %+v, probe = %+v", result, probe)
	}
}

func TestAuthenticateUnknownNonValidator(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(ctx context.Context, path Path, server string, q []byte, wait time.Duration) ([]Reply, error) {
		name, _, _ := testQueryInfo(q)
		switch name {
		case "dnssec-failed.org":
			return []Reply{{From: server, Msg: testDNSReply(q, rcodeNoError, false, testA("1.1.1.1"))}}, nil
		case "cloudflare.com":
			return []Reply{{From: server, Msg: testDNSReply(q, rcodeNoError, false, testA("1.1.1.1"))}}, nil
		default:
			return genuineUDP(path, server, q)
		}
	}
	result := authenticateOne(t, fake, Target{Address: "203.0.113.53", Path: Path{Kind: PathTunnel}}, Options{})
	if result.Verdict != VerdictUnknownOperator || result.Verdict == VerdictForged {
		t.Fatalf("unknown resolver = %+v", result)
	}
	if probe := probeByID(t, result, ProbeBogus); probe.Status != StatusWarn || probe.Code != CodeNotValidating {
		t.Errorf("unknown bogus probe = %+v", probe)
	}
}

func TestAuthenticateBogonCanary(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(ctx context.Context, path Path, server string, q []byte, wait time.Duration) ([]Reply, error) {
		name, _, _ := testQueryInfo(q)
		if name == "linkedin.com" {
			return []Reply{{From: server, Msg: testDNSReply(q, rcodeNoError, false, testA("192.0.2.20"))}}, nil
		}
		return genuineUDP(path, server, q)
	}
	result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}, Options{})
	probe := probeByID(t, result, ProbeCanary)
	if result.Verdict != VerdictForged || probe.Code != CodeCanaryBogon || probe.Detail != "linkedin.com 192.0.2.20" {
		t.Fatalf("bogon canary = %+v, probe = %+v", result, probe)
	}
	for _, call := range fake.certCalls {
		if call.name == "linkedin.com" {
			t.Error("bogon canary reached certificate probe")
		}
	}
}

func TestAuthenticateWANCanariesOffSendNothing(t *testing.T) {
	fake := &scriptedNet{}
	extra := "household-secret-name.invalid"
	result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathWAN}}, Options{Names: []string{extra}})
	if result.Verdict != VerdictGenuine {
		t.Fatalf("WAN canaries off = %+v", result)
	}
	if probe := probeByID(t, result, ProbeCanary); probe.Status != StatusSkipped || probe.Code != CodeCanaryOnWANOff {
		t.Errorf("canary = %+v", probe)
	}
	blocked := append(append([]string(nil), defaultCanaries...), extra)
	for _, call := range fake.udpCalls {
		for _, name := range blocked {
			if call.name == name {
				t.Errorf("canary %q reached UDP while disabled", name)
			}
		}
	}
	for _, call := range fake.certCalls {
		t.Errorf("certificate probe %q ran while canaries were disabled", call.name)
	}
}

func TestAuthenticateGoogleLocationsUnavailable(t *testing.T) {
	fake := &scriptedNet{}
	fake.dohFn = func(context.Context, Path, string, []byte) ([]byte, string, error) {
		return nil, "", errors.New("DoH unavailable")
	}
	result := authenticateOne(t, fake, Target{Address: "8.8.8.8", Path: Path{Kind: PathTunnel}}, Options{})
	probe := probeByID(t, result, ProbeIdentity)
	if result.Verdict != VerdictPartial || probe.Status != StatusNoData || probe.Code != CodeIdentitySilent {
		t.Fatalf("unavailable locations = %+v, identity = %+v", result, probe)
	}
}

func TestAuthenticateCancelledContext(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(ctx context.Context, path Path, server string, q []byte, wait time.Duration) ([]Reply, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(25 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	results := Authenticate(ctx, fake, []Target{{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}}, nil, Options{})
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Fatalf("cancellation took %s", elapsed)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results", len(results))
	}
}

func TestAuthenticateForeignSource(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(ctx context.Context, path Path, server string, q []byte, wait time.Duration) ([]Reply, error) {
		replies, err := genuineUDP(path, server, q)
		if len(replies) > 0 {
			replies[0].From = "203.0.113.99"
		}
		return replies, err
	}
	result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}, Options{})
	if probe := probeByID(t, result, ProbeSource); result.Verdict != VerdictForged || probe.Code != CodeForeignSource || probe.Detail != "203.0.113.99" {
		t.Fatalf("foreign source = %+v, probe = %+v", result, probe)
	}
}

func TestAuthenticateCloudflareForeignEgress(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(ctx context.Context, path Path, server string, q []byte, wait time.Duration) ([]Reply, error) {
		name, _, _ := testQueryInfo(q)
		if name == "o-o.myaddr.l.google.com" {
			return []Reply{{From: server, Msg: testDNSReply(q, rcodeNoError, false, testTXT("8.8.8.8"))}}, nil
		}
		return genuineUDP(path, server, q)
	}
	result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}, Options{})
	if probe := probeByID(t, result, ProbeIdentity); result.Verdict != VerdictPartial || probe.Status != StatusWarn || probe.Code != CodeIdentityMismatch {
		t.Fatalf("foreign Cloudflare egress = %+v, identity = %+v", result, probe)
	}
}

func TestGoogleLocationsProofAndFallback(t *testing.T) {
	proof := Path{Kind: PathTunnel, Iface: "tun0"}
	target := Path{Kind: PathWAN, Iface: "wan0"}
	fake := &scriptedNet{}
	fake.dohFn = func(ctx context.Context, path Path, url string, q []byte) ([]byte, string, error) {
		if path != proof {
			return nil, "", errors.New("wrong proof path")
		}
		return testDNSReply(q, rcodeNoError, false, testTXT("8.8.8.0/24 iad")), "dns.google", nil
	}
	result := authenticateOne(t, fake, Target{Address: "8.8.8.8", Path: target}, Options{CanariesOnWAN: true, ProofPath: &proof})
	if result.Verdict != VerdictGenuine || len(fake.dohPaths) != 1 || fake.dohPaths[0] != proof {
		t.Fatalf("locations proof = %+v, paths = %+v", result, fake.dohPaths)
	}

	fake = &scriptedNet{}
	fake.dohFn = func(ctx context.Context, path Path, url string, q []byte) ([]byte, string, error) {
		if path == proof {
			return nil, "", errors.New("proof DoH blocked")
		}
		return testDNSReply(q, rcodeNoError, false, testTXT("8.8.8.0/24 iad")), "dns.google", nil
	}
	result = authenticateOne(t, fake, Target{Address: "8.8.8.8", Path: target}, Options{CanariesOnWAN: true, ProofPath: &proof})
	if result.Verdict != VerdictGenuine || len(fake.dohPaths) != 2 || fake.dohPaths[1] != target {
		t.Fatalf("locations fallback = %+v, paths = %+v", result, fake.dohPaths)
	}
}

func TestAuthenticateConcurrencyLimit(t *testing.T) {
	fake := &scriptedNet{}
	var mu sync.Mutex
	active, maximum := 0, 0
	fake.udpFn = func(ctx context.Context, path Path, server string, q []byte, wait time.Duration) ([]Reply, error) {
		mu.Lock()
		active++
		if active > maximum {
			maximum = active
		}
		mu.Unlock()
		time.Sleep(15 * time.Millisecond)
		replies, err := genuineUDP(path, server, q)
		mu.Lock()
		active--
		mu.Unlock()
		return replies, err
	}
	result := authenticateOne(t, fake, Target{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}, Options{Concurrency: 2})
	if result.Verdict != VerdictGenuine {
		t.Fatalf("concurrent result = %+v", result)
	}
	if maximum != 2 {
		t.Errorf("maximum concurrent UDP calls = %d, want 2", maximum)
	}
}

func TestVerdictFor(t *testing.T) {
	basePass := Probe{ID: ProbeBase, Status: StatusPass, Code: CodeOK}
	baseSilent := Probe{ID: ProbeBase, Status: StatusNoData, Code: CodeNoReply}
	for _, tc := range []struct {
		name     string
		operator string
		path     Path
		probes   []Probe
		want     Verdict
	}{
		{"decoy beats unreachable", "cloudflare", Path{Kind: PathWAN}, []Probe{baseSilent, {ID: ProbeInterception, Status: StatusFail}}, VerdictForged},
		{"base silent", "cloudflare", Path{Kind: PathWAN}, []Probe{baseSilent}, VerdictUnreachable},
		{"failure", "cloudflare", Path{Kind: PathWAN}, []Probe{basePass, {ID: ProbeSource, Status: StatusFail}}, VerdictForged},
		{"unknown before partial", "", Path{Kind: PathWAN}, []Probe{basePass, {ID: ProbeSigned, Status: StatusWarn}}, VerdictUnknownOperator},
		{"router is unknown", "cloudflare", Path{Kind: PathRouter}, []Probe{basePass}, VerdictUnknownOperator},
		{"partial", "cloudflare", Path{Kind: PathWAN}, []Probe{basePass, {ID: ProbeIdentity, Status: StatusNoData}}, VerdictPartial},
		{"skipped does not lower", "cloudflare", Path{Kind: PathWAN}, []Probe{basePass, {ID: ProbeCanary, Status: StatusSkipped}}, VerdictGenuine},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := verdictFor(tc.operator, tc.path, tc.probes); got != tc.want {
				t.Errorf("verdictFor = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestInterceptionsRouterOmittedAndSendError(t *testing.T) {
	fake := &scriptedNet{}
	fake.udpFn = func(context.Context, Path, string, []byte, time.Duration) ([]Reply, error) {
		return nil, errors.New("send failed")
	}
	paths := []Path{{Kind: PathRouter}, {Kind: PathWAN}}
	results := Interceptions(context.Background(), fake, paths, Options{})
	if len(results) != 1 || results[0].Path.Kind != PathWAN || results[0].Status != StatusNoData || results[0].Code != CodeNoReply {
		t.Fatalf("interceptions = %+v", results)
	}
}

func TestEncrypted(t *testing.T) {
	fake := &scriptedNet{}
	targets := []Target{{Address: "1.1.1.1", Path: Path{Kind: PathTunnel}}, {Address: "203.0.113.53", Path: Path{Kind: PathTunnel}}}
	results := Encrypted(context.Background(), fake, targets, Options{})
	if len(results) != 2 || results[0].Proto != "dot" || results[1].Proto != "doh" {
		t.Fatalf("encrypted results = %+v", results)
	}
	for _, result := range results {
		if result.Status != StatusPass || result.CertName == "" {
			t.Errorf("encrypted result = %+v", result)
		}
	}

	fake.dotFn = func(context.Context, Path, string, string, []byte) ([]byte, string, error) {
		return nil, "", context.DeadlineExceeded
	}
	fake.dohFn = func(context.Context, Path, string, []byte) ([]byte, string, error) {
		return nil, "", syscall.ECONNREFUSED
	}
	results = Encrypted(context.Background(), fake, targets[:1], Options{})
	if len(results) != 2 || results[0].Detail != "timeout" || results[1].Detail != "refused" || results[0].Status != StatusNoData || results[1].Status != StatusNoData {
		t.Fatalf("encrypted failures = %+v", results)
	}
}

type testRecord struct {
	typ     uint16
	address string
	txt     []string
}

func testA(address string) testRecord {
	return testRecord{typ: dnsTypeA, address: address}
}

func testTXT(text ...string) testRecord {
	return testRecord{typ: dnsTypeTXT, txt: text}
}

func testRRSIG() testRecord {
	return testRecord{typ: dnsTypeRRSIG}
}

func testDNSReply(query []byte, rcode int, ad bool, records ...testRecord) []byte {
	questionEnd := testQuestionEnd(query)
	if len(query) < questionEnd+4 {
		panic("short test DNS query")
	}
	msg := append([]byte(nil), query[:questionEnd+4]...)
	if len(msg) < 12 {
		panic("short test DNS header")
	}
	flags := uint16(0x8180 | rcode)
	if ad {
		flags |= 0x0020
	}
	binary.BigEndian.PutUint16(msg[2:4], flags)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	binary.BigEndian.PutUint16(msg[6:8], uint16(len(records)))
	binary.BigEndian.PutUint16(msg[8:12], 0)
	for _, record := range records {
		var rdata []byte
		switch record.typ {
		case dnsTypeA:
			rdata = net.ParseIP(record.address).To4()
			if rdata == nil {
				panic("bad test A address")
			}
		case dnsTypeTXT:
			for _, text := range record.txt {
				if len(text) > 255 {
					panic("test TXT string is too long")
				}
				rdata = append(rdata, byte(len(text)))
				rdata = append(rdata, text...)
			}
		case dnsTypeRRSIG:
			rdata = make([]byte, 18)
		default:
			panic(fmt.Sprintf("unsupported test record %d", record.typ))
		}
		msg = append(msg, 0xc0, 0x0c)
		msg = binary.BigEndian.AppendUint16(msg, record.typ)
		msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
		msg = binary.BigEndian.AppendUint32(msg, 60)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
		msg = append(msg, rdata...)
	}
	return msg
}

func testQueryInfo(query []byte) (name string, qtype, qclass uint16) {
	end := testQuestionEnd(query)
	if len(query) < end+4 {
		return "", 0, 0
	}
	var labels []string
	for off := 12; off < end-1; {
		length := int(query[off])
		off++
		labels = append(labels, string(query[off:off+length]))
		off += length
	}
	return strings.Join(labels, "."), binary.BigEndian.Uint16(query[end : end+2]), binary.BigEndian.Uint16(query[end+2 : end+4])
}

func testQuestionEnd(query []byte) int {
	if len(query) < 13 {
		return 0
	}
	for off := 12; off < len(query); {
		length := int(query[off])
		if length == 0 {
			return off + 1
		}
		if length > 63 || off+1+length > len(query) {
			return 0
		}
		off += 1 + length
	}
	return 0
}
