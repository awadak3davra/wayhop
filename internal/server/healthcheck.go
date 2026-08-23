package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"wayhop/internal/nativedns"
	"wayhop/internal/netdiag"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// healthRow is one server-side diagnostic result, shaped for the Diagnostics
// "Run all checks" battery in the UI (status drives the pill colour).
type healthRow struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// pass | warn | fail | na.
	//
	// `na` is "this check did not run" — either there was nothing here to check (no dialable
	// endpoints, no subscription configured) or the measurement was impossible (a /proc file this
	// host does not have). It exists because the other three could not say it, and both substitutes
	// were lies: `pass` made "nothing was checked" indistinguishable from "checked and fine", and
	// `warn` put an unmeasurable thing on the operator's to-do list. Measured on the dev host, where
	// 6 of 11 "things to look at" were checks that never ran, and on a live Keenetic, where 3
	// of 19 greens had verified nothing.
	//
	// An `na` row is never a finding: it is not counted in the verdict and never colours the page.
	Status  string `json:"status"`
	Summary string `json:"summary"`
	Detail  string `json:"detail,omitempty"`
	Fix     string `json:"fix,omitempty"`
}

// handleHealthCheck runs the diagnostic probes the BROWSER cannot do itself — it is
// same-origin-locked and can read neither /proc nor a raw cross-origin Date/IPv6
// response. Two high-leverage VPN checks live here: router clock skew (from a remote
// HTTP Date header, since NTP is often blocked) and an IPv6-leak test (the tunnels
// are IPv4-only, so working global IPv6 silently bypasses the VPN). A sub-check that
// cannot run degrades to its own row rather than failing the whole call — "na" when it
// had nothing to measure, "warn"/"fail" only for what it actually measured. The UI
// battery folds these rows in next to its client-composed checks
// (core/tunnels/internet/exit/log).
func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	// The checks are independent + each fans out to remote probes, so run them
	// concurrently — sequential would risk blowing the request timeout.
	// The DNS row needs the router's own resolvers to answer its privacy half, and the effective
	// path is the same thing the DNS page reads. Gathered ONCE here rather than inside the check, so
	// the five commands it shells out to are not paid for twice if another row ever wants them.
	dnsUpstreams, dnsPathKnown := s.effectiveDNSUpstreams()
	// The offload verdict is resolved ONCE, by the same call /api/native/capabilities makes, so the
	// two endpoints cannot disagree about one router's datapath.
	offload := s.offloadObservation(ctx).State
	checks := []func(context.Context) healthRow{clockSkewCheck, ipv6LeakCheck, ipv6CarriedCheck,
		func(ctx context.Context) healthRow { return dnsHealthCheck(ctx, dnsUpstreams, dnsPathKnown) },
		func(ctx context.Context) healthRow { return flowOffloadCheck(ctx, offload) },
		conntrackCheck,
		func(ctx context.Context) healthRow { return s.pbrKernelCheck(ctx) },
		func(ctx context.Context) healthRow { return s.listsInForceCheck(ctx) },
		func(ctx context.Context) healthRow { return s.nativeOnlyCheck(ctx) },
		func(ctx context.Context) healthRow { return s.endpointReachCheck(ctx) },
		func(ctx context.Context) healthRow { return s.groupDepthCheck(ctx) },
		func(ctx context.Context) healthRow { return s.sourceRuleCheck(ctx) },
		func(ctx context.Context) healthRow { return s.dnsBypassCheck(ctx) },
		func(ctx context.Context) healthRow { return s.rttCeilingCheck(ctx) },
		func(ctx context.Context) healthRow { return s.singboxBuildCheck(ctx) },
		func(ctx context.Context) healthRow { return s.diskSpaceCheck(ctx) },
		func(ctx context.Context) healthRow { return s.subscriptionCheck(ctx) }}
	rows := make([]healthRow, len(checks))
	var wg sync.WaitGroup
	for i, fn := range checks {
		wg.Add(1)
		go func(i int, fn func(context.Context) healthRow) { defer wg.Done(); rows[i] = fn(ctx) }(i, fn)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"checks": rows})
}

// clockSkewCheck compares the router clock to a remote server's Date header.
func clockSkewCheck(ctx context.Context) healthRow {
	row := healthRow{ID: "time", Label: "Router clock is correct"}
	cl := &http.Client{Timeout: 6 * time.Second}
	defer cl.CloseIdleConnections() // release pooled TCP conns (matches dohProbe) — no idle-conn buildup on the 256 MB router
	var dateHdr string
	for _, u := range []string{"https://www.cloudflare.com/", "https://www.google.com/generate_204"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
		if err != nil {
			continue
		}
		resp, err := cl.Do(req)
		if err != nil {
			continue
		}
		dateHdr = resp.Header.Get("Date")
		resp.Body.Close()
		if dateHdr != "" {
			break
		}
	}
	if dateHdr == "" {
		row.Status, row.Summary = "na", "no time source answered — clock not checked"
		return row
	}
	t, err := http.ParseTime(dateHdr)
	if err != nil {
		row.Status, row.Summary = "na", "the time source was unreadable — clock not checked"
		return row
	}
	row.Status, row.Summary, row.Fix = skewVerdict(time.Since(t))
	row.Detail = "remote time " + dateHdr + "; local skew " + time.Since(t).Round(time.Second).String()
	return row
}

// skewVerdict maps an absolute clock skew to a status + plain-language fix.
func skewVerdict(skew time.Duration) (status, summary, fix string) {
	if skew < 0 {
		skew = -skew
	}
	s := skew.Round(time.Second).String()
	switch {
	case skew < 30*time.Second:
		return "pass", "clock is correct", ""
	case skew < 5*time.Minute:
		return "warn", "clock is off by " + s, "The router clock drifts. Enable NTP / fix the time — large skew breaks secure (TLS/Reality) connections."
	default:
		return "fail", "clock is wrong by " + s, "The router's clock is far off, which breaks secure (TLS/Reality) tunnels and makes working exits look broken. Fix the time / enable NTP."
	}
}

// ipv6LeakCheck flags the dual-stack bypass: the tunnels are IPv4-only, so a working
// global IPv6 path lets v6 traffic skip the VPN and expose the real address.
func ipv6LeakCheck(ctx context.Context) healthRow {
	// The title must not claim the result before the probe has one. In particular, a router with a
	// global IPv6 address whose egress probe times out is UNKNOWN, not "No IPv6 leak".
	row := healthRow{ID: "ipv6", Label: "IPv6 bypass check"}
	b, err := os.ReadFile("/proc/net/if_inet6")
	if err != nil {
		row.Status, row.Summary = "na", "this host has no IPv6 state to read"
		return row
	}
	if !ipv6HasGlobal(string(b)) {
		row.Label = "No IPv6 leak"
		row.Status, row.Summary = "pass", "no global IPv6 on the router"
		return row
	}
	// Before probing the internet, ask the router where its v6 default route POINTS. The question this
	// row exists for is whether v6 goes AROUND the tunnels, and a default route that egresses a tunnel
	// answers it directly — no reachability needed. Measured on a live router: v6 defaults out nwg3
	// and nwg4 (the tunnels), while the ipify probe timed out because v6 inside those tunnels does not
	// carry traffic. The old code called that "could not complete" and left a permanent warning on a
	// router with nothing to leak.
	if devs := ipv6DefaultRouteDevices(); len(devs) > 0 {
		wan, _ := probeWANInterface()
		bypass := false
		for _, d := range devs {
			if wan == "" || d == wan {
				bypass = true // out the uplink itself, or we cannot tell which one that is
			}
		}
		if !bypass {
			row.Label = "No IPv6 leak"
			row.Status = "pass"
			row.Summary = "IPv6 defaults through " + strings.Join(devs, ", ") + ", not around the tunnels"
			row.Detail = "The router has global IPv6, and its IPv6 default route egresses a tunnel rather than the uplink — so v6 traffic cannot bypass the VPN. Whether that tunnel actually carries v6 is a separate question from a leak."
			return row
		}
	}
	// Global v6 present and defaulting out the uplink — does raw v6 actually reach the internet?
	cl := &http.Client{Timeout: 6 * time.Second}
	defer cl.CloseIdleConnections() // release pooled TCP conns (matches dohProbe) — no idle-conn buildup on the 256 MB router
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api6.ipify.org", nil)
	resp, err := cl.Do(req)
	if err != nil {
		// A probe that did not COMPLETE is not evidence that the path is closed, and this row used to
		// say it was: a failed request produced `pass` — "IPv6 present but firewalled (OK)" — which
		// announces the absence of the exact leak the request failed to test.
		//
		// The request can fail for reasons that say nothing about the router's v6 egress: api6.ipify.org
		// down or blocked, its AAAA not resolving, or the 6-second deadline expiring on a loaded 256 MB
		// router. In every one of those the global v6 address is still there and may still be carrying
		// traffic around the v4-only tunnels.
		//
		// Every other unreadable-state branch in this file already degrades to warn — the
		// /proc/net/if_inet6 read a few lines above does. This one is the branch where guessing wrong
		// costs the most, and it was the only one guessing in the reassuring direction.
		row.Status, row.Summary = "warn", "global IPv6 present; the leak test could not complete"
		row.Detail = "a direct IPv6 request did not finish, so whether v6 reaches the internet is unknown: " + err.Error()
		row.Fix = "This router has a global IPv6 address and the check could not determine whether it bypasses the tunnels. Re-run it; if it keeps failing, test from a device on the LAN (e.g. open an IPv6-only address) or disable IPv6 forwarding until you know."
		return row
	}
	defer resp.Body.Close()
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	row.Status, row.Summary = "fail", "IPv6 reaches the internet directly"
	row.Detail = "raw IPv6 egress works (real v6 address " + strings.TrimSpace(string(buf[:n])) + ") — the v4-only tunnels don't cover it"
	row.Fix = "Your device can use IPv6 to bypass the VPN and expose your real address. Disable IPv6 on the router, or block IPv6 forwarding."
	return row
}

// ipv6HasGlobal reports whether /proc/net/if_inet6 lists a global (internet-scope)
// IPv6 address. Each line is "addr ifindex prefixlen scope flags devname"; scope
// "00" is global. Loopback (::1), link-local (fe80::/10) and ULA (fc00::/7) are
// skipped — only a genuinely routable address counts (the live GET is the real test).
func ipv6HasGlobal(ifInet6 string) bool {
	for _, ln := range strings.Split(ifInet6, "\n") {
		f := strings.Fields(ln)
		if len(f) < 4 || f[3] != "00" {
			continue
		}
		addr := strings.ToLower(f[0])
		if addr == "00000000000000000000000000000001" || strings.HasPrefix(addr, "fe80") ||
			strings.HasPrefix(addr, "fc") || strings.HasPrefix(addr, "fd") {
			continue
		}
		return true
	}
	return false
}

// flowOffloadCheck reports what the kernel flow-offload fast path is ACTUALLY doing.
//
// It reads the shared platform.OffloadState rather than probing on its own. Its own probe used to be
// `/etc/config/firewall` alone, which measures intent and not the datapath: on the AX3000T that made
// this row say "flow offload is off … the hardware fast path is unused" while /api/native/capabilities
// reported 54 of 225 sampled connections offloaded, from the same router, at the same moment. Two
// endpoints cannot describe one datapath differently, so there is now one resolver and this row
// renders it. Advisory only — it never changes a setting.
func flowOffloadCheck(ctx context.Context, st platform.OffloadState) healthRow {
	row := healthRow{ID: "offload", Label: "Flow offload (fast path)"}
	if ctx.Err() != nil {
		row.Status, row.Summary = "na", "cancelled before it ran"
		return row
	}
	row.Detail = strings.Join(st.Reasons, "; ")
	row.Fix = st.Recommendation
	switch st.Effective {
	case "hw":
		row.Status, row.Summary = "pass", "hardware flow offload is in use"
		row.Fix = "" // nothing to advise: the fast path is already carrying traffic.
	case "sw":
		row.Status, row.Summary = "pass", "software flow offload is in use"
	case "off":
		row.Status, row.Summary = "warn", "flow offload is off"
		if row.Detail == "" {
			row.Detail = "general routed throughput is bounded by the CPU forwarding rate"
		}
	default:
		// Not a fault: an unmeasurable datapath is a gap in evidence, and saying "off" here is the
		// false claim this row was rewritten to stop making.
		row.Status, row.Summary = "na", "the offload state could not be read"
	}
	return row
}

// dnsHealthCheck probes whether encrypted DNS (DoH) is REACHABLE from the router, and — separately —
// whether the router's own lookups actually take an encrypted path.
//
// The two are not the same measurement, and this row used to make the second claim from the first.
// It was labelled "DNS is private (DoH)" and printed a green "encrypted DNS (DoH) working · 3/3
// resolvers" whenever three outbound HTTPS calls to Cloudflare, Google and AdGuard succeeded. Nothing
// in it read /etc/resolv.conf, the listeners, or the adopted upstreams — the function took no profile
// and no effective path — so on a router forwarding every query in plaintext to the ISP the row was
// green, provided :443 worked. The three probes had to resolve cloudflare-dns.com through the very
// resolver they were judging.
//
// Measured on a live AX3000T while this said "DNS is private": the neighbouring row on the
// same screen read "1 client(s) may be bypassing the router's DNS (DoH/DoT)". Two rows, one page,
// opposite stories.
//
// So: the probes keep their meaning and lose the borrowed one. Reachability is stated as
// reachability, and the privacy half is answered from what the router actually resolves through —
// which the daemon already computes for the DNS page (nativedns.RunEffectivePath). When that cannot
// be read, the row says the encrypted path is reachable and stops there rather than inferring.
func dnsHealthCheck(ctx context.Context, upstreams []string, pathKnown bool) healthRow {
	row := healthRow{ID: "dns", Label: "Encrypted DNS (DoH)"}
	// All three must expose a JSON DoH API (?name=&type= + Accept: application/dns-json):
	// Cloudflare + AdGuard answer at /dns-query and /resolve, Google at /resolve. NB:
	// Quad9 is deliberately NOT here — its /dns-query speaks only RFC8484 wireformat
	// (a ?name= query returns HTTP 400) and it has no JSON endpoint, so it can't be
	// probed this way without a wireformat encoder.
	providers := []struct{ name, url string }{
		{"Cloudflare", "https://cloudflare-dns.com/dns-query?name=cloudflare.com&type=A"},
		{"Google", "https://dns.google/resolve?name=google.com&type=A"},
		{"AdGuard", "https://dns.adguard-dns.com/resolve?name=adguard.com&type=A"},
	}
	type res struct {
		name string
		ok   bool
		ms   int64
	}
	out := make([]res, len(providers))
	var wg sync.WaitGroup
	for i, p := range providers {
		wg.Add(1)
		go func(i int, name, u string) {
			defer wg.Done()
			ok, ms := dohProbe(ctx, u)
			out[i] = res{name, ok, ms}
		}(i, p.name, p.url)
	}
	wg.Wait()

	healthy := 0
	var parts []string
	for _, r := range out {
		if r.ok {
			healthy++
			parts = append(parts, fmt.Sprintf("%s ✓ %d ms", r.name, r.ms))
		} else {
			parts = append(parts, r.name+" ✗")
		}
	}
	row.Detail = strings.Join(parts, " · ")
	if healthy == 0 {
		row.Status = "warn"
		row.Summary = "no DoH resolver reachable"
		row.Fix = "Encrypted DNS (DoH) couldn't be reached from the router, so DNS may be falling back to your ISP's plaintext servers. Check https-dns-proxy / your DNS settings — or it may just be a transient network blip."
		return row
	}
	// Reachability, stated as reachability.
	reach := fmt.Sprintf("encrypted DNS (DoH) reachable · %d/%d providers", healthy, len(providers))

	// The privacy half, answered from the router's own resolvers rather than inferred from the
	// probes. A plaintext upstream is the leak this row is read for; naming it is the whole point,
	// because "the router CAN reach DoH" and "the router's lookups ARE encrypted" differ exactly when
	// it matters.
	if !pathKnown {
		row.Status = "pass"
		row.Summary = reach
		row.Detail = strings.TrimSpace(row.Detail + " · the router's own resolvers could not be read, so this says nothing about whether its lookups are encrypted")
		return row
	}
	if plain := plaintextUpstreams(upstreams); len(plain) > 0 {
		row.Status = "warn"
		row.Summary = fmt.Sprintf("%s, but the router resolves through %s", reach, strings.Join(plain, ", "))
		row.Fix = "Encrypted DNS is reachable, but this router's own lookups go to a plaintext resolver, so they are visible to whoever carries them. Point the router at a DoH/DoT resolver (https-dns-proxy, or the DNS page's upstreams) if you want them private."
		return row
	}
	row.Status = "pass"
	row.Summary = reach
	return row
}

// effectiveDNSUpstreams reads the resolvers this router actually uses, and says whether it could be
// read at all. The second return is the difference between "no plaintext upstream" and "we never
// looked" — collapsing them is how a row ends up asserting privacy it never measured, which is the
// defect this whole path was changed for.
//
// nil hook is production (the same reader the DNS page uses); tests inject, because no development
// host has a router's resolv.conf and the interesting cases are the ones a dev box cannot produce.
func (s *Server) effectiveDNSUpstreams() ([]string, bool) {
	if s.dnsUpstreamsOf != nil {
		return s.dnsUpstreamsOf()
	}
	if s.config().Demo {
		return nil, false
	}
	eff := nativedns.RunEffectivePath(dnsExecRunner)
	// An empty resolv.conf is indistinguishable from an unread one here, and treating it as "no
	// plaintext upstream" would be the same false negative in a new place.
	if len(eff.Upstreams) == 0 {
		return nil, false
	}
	return eff.Upstreams, true
}

// plaintextUpstreams returns the router's resolvers that carry queries in the clear.
//
// A loopback address is NOT one of them: it names a local resolver (dnsmasq, https-dns-proxy, or
// WayHop's own listener) whose upstream is a separate question this row does not answer — reporting
// 127.0.0.1 as a leak would cry wolf on the commonest correct setup, including the operator's own
// AX3000T. Anything else in resolv.conf is a plaintext nameserver by definition: resolv.conf has no
// way to express DoH or DoT.
func plaintextUpstreams(upstreams []string) []string {
	var out []string
	for _, u := range upstreams {
		ip := net.ParseIP(strings.TrimSpace(u))
		if ip == nil || ip.IsLoopback() {
			continue
		}
		out = append(out, ip.String())
	}
	return out
}

// dohProbe sends one dns-json query and returns whether it produced a valid DNS
// answer plus the round-trip in ms. Errors (network, HTTP, bad rcode) -> false.
func dohProbe(ctx context.Context, u string) (bool, int64) {
	cl := &http.Client{Timeout: 6 * time.Second}
	defer cl.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, 0
	}
	req.Header.Set("Accept", "application/dns-json")
	start := time.Now()
	resp, err := cl.Do(req)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()
	ms := time.Since(start).Milliseconds()
	if resp.StatusCode != http.StatusOK {
		return false, ms
	}
	body := make([]byte, 0, 2048)
	buf := make([]byte, 2048)
	for len(body) < 8192 {
		n, e := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if e != nil {
			break
		}
	}
	return dnsJSONOK(body), ms
}

// dnsJSONOK reports whether a dns-json body is a successful resolution: rcode 0
// (NOERROR) with at least one answer record.
func dnsJSONOK(body []byte) bool {
	var v struct {
		Status int               `json:"Status"`
		Answer []json.RawMessage `json:"Answer"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return false
	}
	return v.Status == 0 && len(v.Answer) > 0
}

// endpointReachCheck dials each enabled endpoint's server:port DIRECTLY from the router to
// isolate transport reachability from proxy/protocol health. The per-endpoint monitor tests
// the full proxy path (clash delay); this complements it: a failed direct dial means the
// server is down / the port is wrong / the path is blocked at the network, whereas a
// reachable server whose connection still fails points at a config/protocol problem. Dials
// run concurrently with a short timeout; endpoints with no dialable host:port (e.g. a
// kernel-managed external tunnel with no server set) are skipped. These are the operator's
// own configured servers, so there is no SSRF surface here.
func (s *Server) endpointReachCheck(ctx context.Context) healthRow {
	row := healthRow{ID: "endpoint_reach", Label: "VPN servers reachable"}
	p := s.store.Profile()
	type tgt struct {
		id, name, host string
		port           int
	}
	var tgts []tgt
	// The demo opens no sockets. Its fixture points at reserved documentation addresses, so dialling
	// them really does fail, and the row reported "7 of 7 endpoint(s) unreachable" - a hard FAIL that
	// set the whole page verdict to "Something is broken" while the flight recorder two cards below
	// showed the same seven exits at 100% over 178 probes. Two contradictory claims about one set of
	// endpoints, on one screen, and the honest-looking one was about the fixture rather than about
	// anything a reader could act on.
	//
	// Skipping the dial hands every endpoint to the monitor branch below, which is the source the rest
	// of this page already draws from, so the demo shows one story: six alive, the fixture's dead exit
	// named. Every other environment-reading check here is demo-aware for the same reason.
	demo := s.config().Demo
	for _, e := range p.Endpoints {
		if !e.Enabled || demo {
			continue
		}
		host, port := e.Server, e.Port
		if host == "" { // an external/native tunnel may carry the peer in params instead
			if ip, _ := e.Params["endpoint_ip"].(string); ip != "" {
				host = ip
			}
		}
		if host == "" || port <= 0 || port > 65535 {
			continue // nothing dialable
		}
		name := e.Name
		if name == "" {
			name = e.ID
		}
		tgts = append(tgts, tgt{e.ID, name, host, port})
	}
	type res struct {
		name string
		ok   bool
	}
	out := make([]res, len(tgts))
	// Bound concurrent dials: this fans out one DialPort per enabled endpoint, so a
	// many-endpoint profile would otherwise open every socket at once during a single
	// "Run all checks" — spiking FDs on a small router. Cap mirrors the other probes.
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, t := range tgts {
		wg.Add(1)
		go func(i int, t tgt) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = res{t.name, netdiag.DialPort(t.host, t.port, 4*time.Second)}
		}(i, t)
	}
	wg.Wait()

	var down []string
	for _, r := range out {
		if !r.ok {
			down = append(down, r.name)
		}
	}
	measured := len(tgts)

	// An endpoint with nothing to dial is not an endpoint with nothing to say.
	//
	// Measured on a live Keenetic: all five exits are adopted NDM tunnels, so every one has
	// server "", port 0 and no endpoint_ip, this row reported "no dialable endpoints" and it would
	// have reported exactly that with all five tunnels DOWN. Meanwhile the monitor held state alive,
	// handshake ok and a latency for each. A row titled "VPN servers reachable" that cannot go red on
	// the only exits a router has is the lists_in_force defect over again: every answer true in
	// isolation, the question the operator asked left unanswered.
	//
	// The monitor's verdict is READ, never re-probed. It is the same measurement the Failover page
	// shows and the election loop acts on, so a second opinion here could only disagree with the one
	// the router actually uses. "unknown" stays unknown: an endpoint that has never been probed must
	// never be reported as unreachable.
	var unknown []string
	if s.monitor != nil {
		dialed := make(map[string]bool, len(tgts))
		for _, t := range tgts {
			dialed[t.id] = true
		}
		state := map[string]string{}
		for _, v := range s.monitor.Snapshot() {
			if v.Kind == "endpoint" {
				state[v.ID] = v.State
			}
		}
		for _, e := range p.Endpoints {
			if !e.Enabled || dialed[e.ID] {
				continue
			}
			switch state[e.ID] {
			case "alive":
				measured++
			case "down":
				measured++
				down = append(down, nameOrID(e.Name, e.ID))
			}
			if st, ok := state[e.ID]; ok && st != "alive" && st != "down" {
				unknown = append(unknown, nameOrID(e.Name, e.ID))
			}
		}
	}

	row.Status, row.Summary, row.Detail = endpointReachVerdict(measured, down, unknown)
	if row.Status == "warn" || row.Status == "fail" {
		row.Fix = "Unreachable means one of two measurements failed: the router could not open a TCP connection to a proxy server, or a native tunnel's own probe got no handshake. Check the peer is up and the port right, and that the path is not blocked (DPI/firewall); for a native tunnel also check its keys and endpoint are still valid. A server that IS reachable while its connection still fails points at the proxy/protocol config, not the network."
	}
	return row
}

// endpointReachVerdict turns the measurements into the row. Pure, so the states that decide it can
// be tested without standing up a monitor: everything up, some down, everything down, and the one
// that must never be folded into "down" - an endpoint nothing has probed yet. Reporting a tunnel as
// unreachable because no probe has run is the same lie in the other direction.
func endpointReachVerdict(measured int, down, unknown []string) (status, summary, detail string) {
	if len(unknown) > 0 {
		detail = "not probed yet: " + strings.Join(unknown, ", ")
	}
	if measured == 0 {
		if len(unknown) > 0 {
			return "na", fmt.Sprintf("%d endpoint(s) have not been probed yet", len(unknown)), detail
		}
		return "na", "no endpoints to reach", ""
	}
	if len(down) == 0 {
		return "pass", fmt.Sprintf("all %d endpoint(s) reachable", measured), detail
	}
	// Every exit being down is not a warning. In that state nothing the operator routed through a
	// tunnel is moving at all, and the battery should say so at the strength it deserves.
	status = "warn"
	if len(down) == measured {
		status = "fail"
	}
	return status, fmt.Sprintf("%d of %d endpoint(s) unreachable", len(down), measured),
		"unreachable: " + strings.Join(down, ", ")
}

// pbrKernelCheck verifies the nft table is present when hybrid PBR is supposed to be installed.
// Only runs a real nft probe when the plan is active; returns pass/skip otherwise.
//
// Native-only ("fast" + ProfileNativeOnly + nothing surviving into sing-box, per
// generator.DatapathNativeOnly): the kernel plane carries everything and sing-box is
// intentionally absent. The companion native-only check (nativeOnlyCheck) reports that
// state as informational so the battery does NOT read the missing core as a fault.
func (s *Server) pbrKernelCheck(ctx context.Context) healthRow {
	row := healthRow{ID: "pbr_kernel", Label: "Kernel routing (PBR)"}

	c := s.config()
	mode := s.routingMode(c)
	// The applied record says what the kernel plane should be; the reconcile loop's last postcheck
	// says whether the router still carries it. On Keenetic the plane is ipset/iptables re-asserted
	// from a netfilter.d hook, so report that observation instead of probing an nft table it never had.
	base := s.appliedBaseline()
	var plan *pbr.Plan
	if base != nil {
		plan = base.Materialization.kernelPlan()
	}
	if s.detectedPlatform() == platform.Keenetic && !c.Demo {
		row.Label = "Routing datapath"
		switch {
		case mode != "hybrid" && mode != "fast":
			row.Status, row.Summary = "pass", "native/TUN mode — no kernel policy plane needed"
		case plan == nil:
			row.Status, row.Summary = "warn", mode+" mode but the policy plane is not applied — click Apply"
			row.Fix = "Apply a config with at least one routing list to activate the kernel policy plane."
		case s.kernelPlaneObserved() == kernelPlaneMissing:
			row.Status, row.Summary = "warn", "the ipset/iptables policy plane is missing — WayHop reinstalls it on its next reconcile"
		default:
			row.Status = "pass"
			row.Summary = fmt.Sprintf("active — %d zone(s) applied", len(plan.Zones))
		}
		return row
	}

	// In "fast"/native-only the kernel PBR IS the datapath (no TUN), so a kernel probe is
	// warranted exactly as in hybrid. In "tun"/"mixed" the TUN carries general traffic and
	// no kernel PBR is expected. Treat "fast" like "hybrid" below.
	if mode != "hybrid" && mode != "fast" {
		row.Status, row.Summary = "pass", "TUN mode — no kernel PBR needed"
		return row
	}
	// No nftables plane on this host (Keenetic — native backend not yet wired — or no `nft`): fast/
	// hybrid CANNOT route correctly here (the kernel carve-outs can't install, and an apply of those
	// modes is refused for that reason). Warn with an actionable fix instead of the "table missing /
	// click Apply" advice (which can never succeed here).
	if !s.kernelPBRAvailable() {
		row.Status = "warn"
		row.Summary = "kernel PBR (nftables) not available on this router"
		row.Detail = "`nft` is absent, so " + mode + " mode can't install its kernel carve-outs."
		row.Fix = "Switch routing mode to tun or mixed — those route entirely through the sing-box TUN and need no kernel plane."
		return row
	}
	if plan == nil {
		row.Status, row.Summary = "warn", mode+" mode but plan not installed — click Apply"
		row.Fix = "Apply a config with at least one routing list to activate kernel PBR."
		return row
	}

	cmd := exec.CommandContext(ctx, "nft", "list", "table", "inet", plan.Table)
	if out, err := cmd.CombinedOutput(); err != nil {
		row.Status = "warn"
		row.Summary = "nft table missing — plan was applied but table is gone"
		row.Detail = strings.TrimSpace(string(out))
		row.Fix = "Click Apply to re-install the nftables routing rules (fw4 reload may have flushed them)."
		return row
	}
	row.Status = "pass"
	row.Summary = fmt.Sprintf("active — %d zone(s) installed", len(plan.Zones))
	return row
}

// nativeOnlyCheck reports whether the sing-box core is intentionally absent because the
// live profile is native-only (generator.DatapathNativeOnly: "fast" mode + every enabled
// endpoint kernel-native + the default egress is WAN/direct + nothing survives into
// sing-box). In that regime the kernel plane (PBR) carries everything and there is NO
// sing-box process to probe — so the battery's core/clash checks must NOT read the absent
// core as a fault. This row makes that state explicit: a "pass" row "no sing-box core
// needed". When the profile is NOT native-only, sing-box IS the (or a) datapath and its
// presence is governed by the normal core checks — this row reports a benign pass that
// just states the core is in use, never a false alarm in either direction.
//
// Fail-safe-aligned: DatapathNativeOnly is conservative (false on any ambiguity — nil
// profile, non-fast mode, anything that would survive into sing-box), so this row only
// claims "core not needed" when it is provably safe to omit it.
func (s *Server) nativeOnlyCheck(ctx context.Context) healthRow {
	row := healthRow{ID: "native_only", Label: "Datapath core (sing-box)"}
	if ctx.Err() != nil {
		row.Status, row.Summary = "na", "cancelled before it ran"
		return row
	}
	p := s.store.Profile()
	// The same platform-aware predicate the Apply review and /api/health use. It said the opposite
	// here — "sing-box core is part of the datapath" on a router whose datapath is entirely native —
	// because generator.DatapathNativeOnly is the generic one and never holds on KeeneticOS. Two
	// endpoints answering differently about one router is the exact failure this file warns about
	// elsewhere.
	if !s.datapathRequiresCore(s.config(), p) {
		row.Status = "pass"
		row.Summary = "sing-box not needed (native-only mode)"
		row.Detail = "All endpoints are kernel-native and traffic is routed by the kernel plane (PBR) in fast mode, so the sing-box core is intentionally absent — its absence is NOT a fault."
		return row
	}
	row.Status = "pass"
	row.Summary = "sing-box core is part of the datapath"
	row.Detail = "The profile is not native-only, so sing-box carries part of the traffic; the core/clash checks govern whether it is actually running."
	// WHICH part, when this platform can answer. Saying only that the core is in the datapath leaves
	// "run without sing-box" as a goal with no first step: on a live router everything except
	// the DNS plane is carried natively, and nothing on this page said so.
	if why := s.datapathCoreReasons(s.config(), p); len(why) > 0 {
		row.Detail = "sing-box is required by: " + strings.Join(why, "; ") +
			". Everything else in this profile is carried by the kernel plane and the resolver."
	}
	return row
}

// ipv6DefaultRouteDevices lists the interfaces the router's IPv6 default route(s) egress, read from
// the kernel's own table. Empty when there is no v6 default or the table cannot be read — the caller
// then falls through to the reachability probe rather than assuming either answer.
func ipv6DefaultRouteDevices() []string {
	b, err := os.ReadFile("/proc/net/ipv6_route")
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		// dst prefix, dst len, src prefix, src len, next hop, metric, refcnt, use, flags, device
		if len(f) < 10 {
			continue
		}
		// A default route is ::/0 — all-zero destination with prefix length 0.
		if f[1] != "00" || strings.Trim(f[0], "0") != "" {
			continue
		}
		dev := f[9]
		if dev == "" || dev == "lo" || seen[dev] {
			continue
		}
		seen[dev] = true
		out = append(out, dev)
	}
	return out
}
