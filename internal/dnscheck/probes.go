package dnscheck

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	rcodeNoError  = 0
	rcodeServFail = 2
	rcodeNXDomain = 3
)

var defaultCanaries = []string{
	"facebook.com", "instagram.com", "x.com", "www.youtube.com", "linkedin.com", "discord.com",
}

type authRun struct {
	n     Net
	o     Options
	sem   chan struct{}
	total int

	progressMu sync.Mutex
	done       int
	randMu     sync.Mutex

	googleMu      sync.Mutex
	googleRanges  []netip.Prefix
	googleTried   map[Path]bool
	googleLastErr error

	controlMu    sync.Mutex
	controlTries int
	controlOK    bool
}

func newAuthRun(n Net, o Options, total int) *authRun {
	if o.Concurrency <= 0 {
		o.Concurrency = 16
	}
	if o.Wait <= 0 {
		o.Wait = 2 * time.Second
	}
	if o.Rand == nil {
		o.Rand = cryptoLabel
	}
	o.Names = append([]string(nil), o.Names...)
	return &authRun{
		n:           n,
		o:           o,
		sem:         make(chan struct{}, o.Concurrency),
		total:       total,
		googleTried: make(map[Path]bool),
	}
}

func cryptoLabel() string {
	var label [8]byte
	if _, err := rand.Read(label[:]); err != nil {
		return "0"
	}
	return hex.EncodeToString(label[:])
}

func (r *authRun) label() string {
	r.randMu.Lock()
	label := r.o.Rand()
	r.randMu.Unlock()
	if label == "" {
		return "0"
	}
	return label
}

func (r *authRun) progress() {
	if r.o.OnProgress == nil {
		return
	}
	r.progressMu.Lock()
	defer r.progressMu.Unlock()
	r.done++
	r.o.OnProgress(r.done, r.total)
}

func (r *authRun) acquire(ctx context.Context) error {
	select {
	case r.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *authRun) release() {
	<-r.sem
}

func countInterceptions(paths []Path) int {
	total := 0
	for _, path := range paths {
		if path.Kind != PathRouter {
			total++
		}
	}
	return total
}

func countTargetProbes(targets []Target) int {
	total := 0
	for _, target := range targets {
		total += probesOf(target)
	}
	return total
}

func probesOf(target Target) int {
	if _, known := catalogFor(target.Address); known {
		return 8 // identity on top of the rest
	}
	return 7 // base, bogus, signed, NXDOMAIN, second reply, source and canary
}

func countEncryptedProbes(targets []Target) int {
	total := 0
	for _, target := range targets {
		if _, known := catalogFor(target.Address); known {
			total += 2
		}
	}
	return total
}

type querySpec struct {
	name   string
	qtype  uint16
	qclass uint16
	do     bool
}

type queryResult struct {
	name    string
	replies []Reply
	err     error
}

func (r *authRun) udp(ctx context.Context, path Path, server string, spec querySpec) queryResult {
	result := queryResult{name: spec.name}
	query, err := BuildQuery(spec.name, spec.qtype, spec.qclass, spec.do)
	if err != nil {
		result.err = err
		return result
	}
	if err := r.acquire(ctx); err != nil {
		result.err = err
		return result
	}
	defer r.release()
	start := time.Now()
	result.replies, result.err = r.n.UDP(ctx, path, server, query, r.o.Wait)
	if len(result.replies) > 0 && result.replies[0].Ms == 0 {
		result.replies[0].Ms = int(time.Since(start) / time.Millisecond)
	}
	return result
}

func (r *authRun) interceptions(ctx context.Context, paths []Path) []Interception {
	type indexed struct {
		index  int
		result Interception
	}
	type decoyResult struct {
		decoy  string
		result queryResult
	}
	out := make(chan indexed, len(paths))
	var wg sync.WaitGroup
	for i, path := range paths {
		if path.Kind == PathRouter {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := Interception{Path: path, Status: StatusPass, Code: CodeOK}
			decoys := []string{"192.0.2.1", "198.51.100.7"}
			results := make(chan decoyResult, len(decoys))
			for _, decoy := range decoys {
				go func() {
					answer := r.udp(ctx, path, decoy, querySpec{name: "www.example.com", qtype: dnsTypeA, qclass: dnsClassIN})
					results <- decoyResult{decoy: decoy, result: answer}
				}()
			}
			failed := false
			for range decoys {
				answer := <-results
				if len(answer.result.replies) > 0 {
					// A decoy has no DNS service, so any datagram is a positive interception result.
					if !failed {
						result.Detail = answer.decoy
					}
					failed = true
					result.Status = StatusFail
					result.Code = CodeDecoyAnswered
					result.Intercepted = true
				} else if answer.result.err != nil && !failed {
					result.Status = StatusNoData
					result.Code = CodeNoReply
				}
			}
			out <- indexed{index: i, result: result}
			r.progress()
		}()
	}
	wg.Wait()
	close(out)
	ordered := make([]Interception, len(paths))
	present := make([]bool, len(paths))
	for item := range out {
		ordered[item.index] = item.result
		present[item.index] = true
	}
	results := make([]Interception, 0, len(paths))
	for i, result := range ordered {
		if present[i] {
			results = append(results, result)
		}
	}
	return results
}

type targetRun struct {
	*authRun
	target  Target
	catalog *operatorCatalog

	mu           sync.Mutex
	observations []queryResult
}

func (t *targetRun) query(ctx context.Context, spec querySpec) queryResult {
	result := t.udp(ctx, t.target.Path, t.target.Address, spec)
	t.mu.Lock()
	t.observations = append(t.observations, result)
	t.mu.Unlock()
	return result
}

func (t *targetRun) queryPair(ctx context.Context, first, second querySpec) (queryResult, queryResult) {
	type pairResult struct {
		index  int
		result queryResult
	}
	results := make(chan pairResult, 2)
	go func() { results <- pairResult{index: 0, result: t.query(ctx, first)} }()
	go func() { results <- pairResult{index: 1, result: t.query(ctx, second)} }()
	var out [2]queryResult
	for range 2 {
		item := <-results
		out[item.index] = item.result
	}
	return out[0], out[1]
}

func (r *authRun) authenticate(ctx context.Context, targets []Target, interceptions []Interception) []ResolverResult {
	results := make([]ResolverResult, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			run := &targetRun{authRun: r, target: target}
			run.catalog, _ = catalogFor(target.Address)
			results[i] = run.authenticate(ctx, interceptions)
		}()
	}
	wg.Wait()
	return results
}

type probeOutcome struct {
	probe  Probe
	site   string
	egress string
}

func (t *targetRun) authenticate(ctx context.Context, interceptions []Interception) ResolverResult {
	result := ResolverResult{Address: t.target.Address, Path: t.target.Path}
	if t.catalog != nil {
		result.Operator = t.catalog.name
	}

	base := t.query(ctx, querySpec{name: "www.example.com", qtype: dnsTypeA, qclass: dnsClassIN})
	if len(base.replies) == 0 {
		result.Probes = append(result.Probes, Probe{ID: ProbeBase, Status: StatusNoData, Code: CodeNoReply})
		for i := 0; i < probesOf(t.target); i++ {
			t.progress()
		}
	} else {
		ms := base.replies[0].Ms
		result.RttMs = ms
		result.Probes = append(result.Probes, Probe{ID: ProbeBase, Status: StatusPass, Code: CodeOK, Ms: ms})
		t.progress()
	}

	if len(base.replies) > 0 {
		outcomes := make(chan probeOutcome, 16)
		var wg sync.WaitGroup
		launch := func(fn func(context.Context) probeOutcome) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				outcomes <- fn(ctx)
				t.progress()
			}()
		}
		if t.catalog != nil {
			launch(t.identity)
		}
		launch(t.bogus)
		launch(t.signed)
		launch(t.nxdomain)
		launch(t.canary)
		wg.Wait()
		close(outcomes)

		byID := make(map[string]probeOutcome)
		for outcome := range outcomes {
			byID[outcome.probe.ID] = outcome
		}
		for _, id := range []string{ProbeIdentity, ProbeBogus, ProbeSigned, ProbeNXDomain} {
			if outcome, ok := byID[id]; ok {
				result.Probes = append(result.Probes, outcome.probe)
				if id == ProbeIdentity {
					result.Site = outcome.site
					result.Egress = outcome.egress
				}
			}
		}
		result.Probes = append(result.Probes, t.secondReply(), t.source())
		t.progress()
		t.progress()
		if canary, ok := byID[ProbeCanary]; ok {
			result.Probes = append(result.Probes, canary.probe)
		}
	}

	if intercepted, detail := pathIntercepted(t.target.Path, interceptions); intercepted {
		result.Probes = append(result.Probes, Probe{ID: ProbeInterception, Status: StatusFail, Code: CodePathIntercepted, Detail: detail})
	}
	result.Verdict = verdictFor(result.Operator, result.Path, result.Probes)
	return result
}

func pathIntercepted(path Path, interceptions []Interception) (bool, string) {
	for _, interception := range interceptions {
		if interception.Path == path && (interception.Intercepted || interception.Status == StatusFail) {
			return true, interception.Detail
		}
	}
	return false, ""
}

// verdictFor is pure so decoy and base-silence precedence cannot depend on goroutine completion order.
func verdictFor(operator string, path Path, probes []Probe) Verdict {
	for _, probe := range probes {
		if probe.ID == ProbeInterception && probe.Status == StatusFail {
			return VerdictForged
		}
	}
	for _, probe := range probes {
		if probe.ID == ProbeBase && probe.Status == StatusNoData && probe.Code == CodeNoReply {
			return VerdictUnreachable
		}
	}
	for _, probe := range probes {
		if probe.Status == StatusFail {
			return VerdictForged
		}
	}
	if operator == "" || path.Kind == PathRouter {
		return VerdictUnknownOperator
	}
	for _, probe := range probes {
		if probe.Status == StatusNoData || probe.Status == StatusWarn {
			return VerdictPartial
		}
	}
	return VerdictGenuine
}

func (t *targetRun) identity(ctx context.Context) probeOutcome {
	if t.catalog.name == "google" {
		return t.googleIdentity(ctx)
	}
	primarySpec := querySpec{name: t.catalog.identityName, qtype: dnsTypeTXT, qclass: t.catalog.identityClass}
	var primary queryResult
	var secondary *queryResult
	if t.catalog.name == "cloudflare" {
		first, second := t.queryPair(ctx, primarySpec, querySpec{name: "o-o.myaddr.l.google.com", qtype: dnsTypeTXT, qclass: dnsClassIN})
		primary, secondary = first, &second
	} else {
		primary = t.query(ctx, primarySpec)
	}
	outcome := probeOutcome{probe: Probe{ID: ProbeIdentity}}
	if len(primary.replies) == 0 {
		outcome.probe.Status = StatusNoData
		outcome.probe.Code = CodeIdentitySilent
		return outcome
	}
	reply, err := ParseReply(primary.replies[0].Msg)
	if err == nil && reply.Rcode == rcodeServFail {
		// A resolver having a bad moment is not a different resolver.
		outcome.probe.Status = StatusNoData
		outcome.probe.Code = CodeIdentitySilent
		return outcome
	}
	if err != nil || reply.Rcode != rcodeNoError {
		outcome.probe.Status = StatusFail
		outcome.probe.Code = CodeIdentityMismatch
		return outcome
	}
	site := firstTXT(reply)
	if site == "" {
		outcome.probe.Status = StatusNoData
		outcome.probe.Code = CodeIdentitySilent
		return outcome
	}
	if !t.catalog.sitePattern.MatchString(site) {
		outcome.probe.Status = StatusFail
		outcome.probe.Code = CodeIdentityMismatch
		return outcome
	}
	outcome.site = site
	outcome.probe.Detail = site
	outcome.probe.Status = StatusPass
	outcome.probe.Code = CodeOK

	if secondary != nil && len(secondary.replies) > 0 {
		egressReply, err := ParseReply(secondary.replies[0].Msg)
		if err == nil && egressReply.Rcode == rcodeNoError {
			if address, found := txtAddress(egressReply); found {
				outcome.egress = address
				if !addressInRanges(address, t.catalog.ownRanges) {
					// These ranges are compiled in and will age, so this alone never calls a resolver forged.
					outcome.probe.Status = StatusWarn
					outcome.probe.Code = CodeIdentityMismatch
					outcome.probe.Detail = address
				}
			}
		}
	}
	return outcome
}

func (t *targetRun) googleIdentity(ctx context.Context) probeOutcome {
	query := make(chan queryResult, 1)
	go func() {
		query <- t.query(ctx, querySpec{name: t.catalog.identityName, qtype: dnsTypeTXT, qclass: dnsClassIN})
	}()
	ranges, rangeErr := t.googleLocations(ctx, t.target.Path)
	answer := <-query
	outcome := probeOutcome{probe: Probe{ID: ProbeIdentity}}
	if rangeErr != nil || len(answer.replies) == 0 {
		outcome.probe.Status = StatusNoData
		outcome.probe.Code = CodeIdentitySilent
		return outcome
	}
	reply, err := ParseReply(answer.replies[0].Msg)
	if err == nil && reply.Rcode == rcodeServFail {
		outcome.probe.Status = StatusNoData
		outcome.probe.Code = CodeIdentitySilent
		return outcome
	}
	if err != nil || reply.Rcode != rcodeNoError {
		outcome.probe.Status = StatusFail
		outcome.probe.Code = CodeIdentityMismatch
		return outcome
	}
	// The answer is two TXT records in no promised order: the address and an edns0-client-subnet line.
	egress, found := txtAddress(reply)
	if !found {
		outcome.probe.Status = StatusNoData
		outcome.probe.Code = CodeIdentitySilent
		return outcome
	}
	outcome.egress = egress
	outcome.probe.Detail = egress
	if !addressInRanges(egress, ranges) {
		outcome.probe.Status = StatusFail
		outcome.probe.Code = CodeIdentityMismatch
		return outcome
	}
	outcome.probe.Status = StatusPass
	outcome.probe.Code = CodeOK
	return outcome
}

func (r *authRun) googleLocations(ctx context.Context, targetPath Path) ([]netip.Prefix, error) {
	r.googleMu.Lock()
	defer r.googleMu.Unlock()
	if len(r.googleRanges) > 0 {
		return r.googleRanges, nil
	}

	paths := []Path{}
	if r.o.ProofPath != nil {
		paths = append(paths, *r.o.ProofPath)
	}
	paths = append(paths, targetPath)

	query, err := BuildQuery("locations.publicdns.goog", dnsTypeTXT, dnsClassIN, false)
	if err != nil {
		r.googleLastErr = err
		return nil, err
	}

	for _, path := range paths {
		if r.googleTried[path] {
			continue
		}
		r.googleTried[path] = true

		if err := r.acquire(ctx); err != nil {
			r.googleLastErr = fmt.Errorf("fetch Google locations: %w", err)
			continue
		}
		msg, _, err := r.n.DoH(ctx, path, "https://8.8.8.8/dns-query", query)
		r.release()
		if err != nil {
			r.googleLastErr = fmt.Errorf("fetch Google locations: %w", err)
			continue
		}
		reply, err := ParseReply(msg)
		if err != nil || reply.Rcode != rcodeNoError {
			r.googleLastErr = fmt.Errorf("fetch Google locations: %w", errors.New("the Google locations lookup returned an invalid DNS reply"))
			continue
		}
		ranges, err := parseGoogleLocations(reply)
		if err != nil {
			r.googleLastErr = fmt.Errorf("fetch Google locations: %w", err)
			continue
		}
		r.googleRanges = ranges
		r.googleLastErr = nil
		return r.googleRanges, nil
	}

	if r.googleLastErr == nil {
		r.googleLastErr = errors.New("fetch Google locations: no untried path")
	}
	return nil, r.googleLastErr
}

func (t *targetRun) bogus(ctx context.Context) probeOutcome {
	answer := t.query(ctx, querySpec{name: "dnssec-failed.org", qtype: dnsTypeA, qclass: dnsClassIN})
	probe := Probe{ID: ProbeBogus}
	if len(answer.replies) == 0 {
		probe.Status, probe.Code = StatusNoData, CodeNoReply
		return probeOutcome{probe: probe}
	}
	reply, err := ParseReply(answer.replies[0].Msg)
	if err == nil && reply.Rcode == rcodeServFail {
		probe.Status, probe.Code = StatusPass, CodeOK
		return probeOutcome{probe: probe}
	}
	if err == nil && reply.Rcode == rcodeNoError {
		if address := firstAddress(reply); address != "" {
			probe.Detail = address
			if t.catalog != nil {
				probe.Status, probe.Code = StatusFail, CodeBogusAccepted
			} else {
				probe.Status, probe.Code = StatusWarn, CodeNotValidating
			}
			return probeOutcome{probe: probe}
		}
	}
	probe.Status, probe.Code = StatusWarn, CodeNotValidating
	return probeOutcome{probe: probe}
}

func (t *targetRun) signed(ctx context.Context) probeOutcome {
	answer := t.query(ctx, querySpec{name: "cloudflare.com", qtype: dnsTypeA, qclass: dnsClassIN, do: true})
	probe := Probe{ID: ProbeSigned}
	if len(answer.replies) == 0 {
		probe.Status, probe.Code = StatusNoData, CodeNoReply
		return probeOutcome{probe: probe}
	}
	reply, err := ParseReply(answer.replies[0].Msg)
	if err == nil && reply.AD && reply.RRSIGCount > 0 {
		probe.Status, probe.Code = StatusPass, CodeOK
	} else if t.catalog != nil {
		probe.Status, probe.Code = StatusWarn, CodeADMissing
	} else {
		probe.Status, probe.Code = StatusWarn, CodeNotValidating
	}
	return probeOutcome{probe: probe}
}

func (t *targetRun) nxdomain(ctx context.Context) probeOutcome {
	first := querySpec{name: "wh-" + t.label() + "-nx.com", qtype: dnsTypeA, qclass: dnsClassIN}
	second := querySpec{name: "wh-" + t.label() + ".invalid", qtype: dnsTypeA, qclass: dnsClassIN}
	answers := [2]queryResult{}
	answers[0], answers[1] = t.queryPair(ctx, first, second)

	for _, answer := range answers {
		if len(answer.replies) == 0 {
			continue
		}
		reply, err := ParseReply(answer.replies[0].Msg)
		if err == nil && reply.Rcode == rcodeNoError {
			if address := firstAddress(reply); address != "" {
				return probeOutcome{probe: Probe{
					ID:     ProbeNXDomain,
					Status: StatusFail,
					Code:   CodeNXRewritten,
					Detail: address,
				}}
			}
		}
	}
	for _, answer := range answers {
		if len(answer.replies) == 0 {
			return probeOutcome{probe: Probe{ID: ProbeNXDomain, Status: StatusNoData, Code: CodeNoReply}}
		}
		reply, err := ParseReply(answer.replies[0].Msg)
		if err != nil || reply.Rcode != rcodeNXDomain {
			return probeOutcome{probe: Probe{ID: ProbeNXDomain, Status: StatusNoData, Code: CodeNXUnclear}}
		}
	}
	return probeOutcome{probe: Probe{ID: ProbeNXDomain, Status: StatusPass, Code: CodeOK}}
}

func (t *targetRun) secondReply() Probe {
	probe := Probe{ID: ProbeSecondReply, Status: StatusPass, Code: CodeOK}
	t.mu.Lock()
	observations := append([]queryResult(nil), t.observations...)
	t.mu.Unlock()
	for _, observation := range observations {
		seen := make(map[string]bool)
		for _, reply := range observation.replies {
			fingerprint := replyFingerprint(reply.Msg)
			if seen[fingerprint] {
				continue
			}
			if len(seen) > 0 {
				probe.Status, probe.Code, probe.Detail = StatusFail, CodeSecondReply, observation.name
				return probe
			}
			seen[fingerprint] = true
		}
	}
	return probe
}

func replyFingerprint(msg []byte) string {
	reply, err := ParseReply(msg)
	if err != nil {
		return "invalid"
	}
	addresses := make([]string, 0, len(reply.Answers))
	for _, answer := range reply.Answers {
		if answer.Address != "" {
			addresses = append(addresses, answer.Address)
		}
	}
	sort.Strings(addresses)
	return strconv.Itoa(reply.Rcode) + "|" + strings.Join(addresses, ",")
}

func (t *targetRun) source() Probe {
	probe := Probe{ID: ProbeSource, Status: StatusPass, Code: CodeOK}
	t.mu.Lock()
	observations := append([]queryResult(nil), t.observations...)
	t.mu.Unlock()
	for _, observation := range observations {
		for _, reply := range observation.replies {
			if !sameAddress(reply.From, t.target.Address) {
				probe.Status, probe.Code, probe.Detail = StatusFail, CodeForeignSource, reply.From
				return probe
			}
		}
	}
	return probe
}

func sameAddress(first, second string) bool {
	a, aerr := netip.ParseAddr(addressHost(first))
	b, berr := netip.ParseAddr(addressHost(second))
	if aerr == nil && berr == nil {
		return a.Unmap() == b.Unmap()
	}
	return addressHost(first) == addressHost(second)
}

type canaryOutcome struct {
	verified bool
	failure  *Probe
}

func (t *targetRun) canary(ctx context.Context) probeOutcome {
	probe := Probe{ID: ProbeCanary}
	if (t.target.Path.Kind == PathWAN && !t.o.CanariesOnWAN) ||
		(t.target.Path.Kind == PathRouter && !t.o.CanariesOnWAN && !t.o.RouterHidden) {
		probe.Status, probe.Code = StatusSkipped, CodeCanaryOnWANOff
		return probeOutcome{probe: probe}
	}

	names := append(append([]string(nil), defaultCanaries...), t.o.Names...)
	outcomes := make([]canaryOutcome, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outcomes[i] = t.checkCanary(ctx, name)
		}()
	}
	wg.Wait()

	verified := 0
	for _, outcome := range outcomes {
		if outcome.failure != nil {
			return probeOutcome{probe: *outcome.failure}
		}
		if outcome.verified {
			verified++
		}
	}
	probe.Detail = strconv.Itoa(verified) + "/" + strconv.Itoa(len(names))
	if verified != len(names) {
		probe.Status, probe.Code = StatusNoData, CodeCanaryUnverified
	} else {
		probe.Status, probe.Code = StatusPass, CodeOK
	}
	return probeOutcome{probe: probe}
}

func (t *targetRun) checkCanary(ctx context.Context, name string) canaryOutcome {
	answer := t.query(ctx, querySpec{name: name, qtype: dnsTypeA, qclass: dnsClassIN})
	if len(answer.replies) == 0 {
		return canaryOutcome{}
	}
	reply, err := ParseReply(answer.replies[0].Msg)
	if err != nil || reply.Rcode != rcodeNoError {
		return canaryOutcome{}
	}
	address := firstAddress(reply)
	if address == "" {
		return canaryOutcome{}
	}
	for _, answer := range reply.Answers {
		if answer.Address != "" && bogonAddress(answer.Address) {
			probe := Probe{ID: ProbeCanary, Status: StatusFail, Code: CodeCanaryBogon, Detail: name + " " + answer.Address}
			return canaryOutcome{failure: &probe}
		}
	}
	path := t.target.Path
	if t.o.ProofPath != nil {
		path = *t.o.ProofPath
	}
	switch t.n.Cert(ctx, path, address, name) {
	case CertOK:
		return canaryOutcome{verified: true}
	case CertBad:
		if !t.certsProve(ctx, path) {
			return canaryOutcome{}
		}
		probe := Probe{ID: ProbeCanary, Status: StatusFail, Code: CodeCanaryBadCert, Detail: name + " " + address}
		return canaryOutcome{failure: &probe}
	default:
		return canaryOutcome{}
	}
}

// certsProve says whether a bad certificate means anything here. A router with no CA bundle, or a clock
// that has not synced yet, fails every certificate, and calling the whole internet forged over that would
// be false. A passed control is cached; a failed one is tried again on the next bad certificate, at most
// 3 times in a run, so one timeout does not excuse a real forgery.
func (r *authRun) certsProve(ctx context.Context, path Path) bool {
	r.controlMu.Lock()
	defer r.controlMu.Unlock()
	if r.controlOK {
		return true
	}
	if r.controlTries >= 3 {
		return false
	}
	r.controlTries++
	if r.n.Cert(ctx, path, "1.1.1.1", "one.one.one.one") == CertOK {
		r.controlOK = true
		return true
	}
	return false
}

var bogonRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func bogonAddress(address string) bool {
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return true
	}
	ip = ip.Unmap()
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, prefix := range bogonRanges {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func firstAddress(reply DNSReply) string {
	for _, answer := range reply.Answers {
		if answer.Address != "" {
			return answer.Address
		}
	}
	return ""
}

func txtAddress(reply DNSReply) (string, bool) {
	for _, answer := range reply.Answers {
		if answer.Type != dnsTypeTXT {
			continue
		}
		for _, text := range answer.TXT {
			if address, err := netip.ParseAddr(text); err == nil {
				return address.String(), true
			}
		}
	}
	return "", false
}

func firstTXT(reply DNSReply) string {
	for _, answer := range reply.Answers {
		if answer.Type == dnsTypeTXT && len(answer.TXT) > 0 {
			return answer.TXT[0]
		}
	}
	return ""
}

func (r *authRun) encrypted(ctx context.Context, targets []Target) []EncryptedResult {
	type indexed struct {
		index  int
		result EncryptedResult
	}
	total := countEncryptedProbes(targets)
	out := make(chan indexed, total)
	var wg sync.WaitGroup
	index := 0
	for _, target := range targets {
		catalog, known := catalogFor(target.Address)
		if !known {
			continue
		}
		for _, protocol := range []string{"dot", "doh"} {
			resultIndex := index
			wg.Add(1)
			go func() {
				defer wg.Done()
				result := EncryptedResult{Address: target.Address, Operator: catalog.name, Path: target.Path, Proto: protocol}
				query, err := BuildQuery("www.example.com", dnsTypeA, dnsClassIN, false)
				if err == nil {
					err = r.acquire(ctx)
				}
				start := time.Now()
				if err == nil {
					var msg []byte
					if protocol == "dot" {
						msg, result.CertName, err = r.n.DoT(ctx, target.Path, target.Address, catalog.dotSNI, query)
					} else {
						msg, result.CertName, err = r.n.DoH(ctx, target.Path, catalog.dohURL, query)
					}
					r.release()
					if err == nil {
						if reply, perr := ParseReply(msg); perr != nil || (reply.Rcode != rcodeNoError && reply.Rcode != rcodeNXDomain) {
							err = errors.New("no usable answer")
						}
					}
				}
				if err != nil {
					result.Status = StatusNoData
					result.Detail = encryptedErrorDetail(err)
					result.CertName = ""
				} else {
					result.Status = StatusPass
					result.RttMs = int(time.Since(start) / time.Millisecond)
				}
				out <- indexed{index: resultIndex, result: result}
				r.progress()
			}()
			index++
		}
	}
	wg.Wait()
	close(out)
	ordered := make([]EncryptedResult, total)
	for item := range out {
		ordered[item.index] = item.result
	}
	return ordered
}
