package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"wayhop/internal/generator"
	"wayhop/internal/netdiag"
)

// healthRow is one server-side diagnostic result, shaped for the Diagnostics
// "Run all checks" battery in the UI (status drives the pill colour).
type healthRow struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Status  string `json:"status"` // pass | warn | fail
	Summary string `json:"summary"`
	Detail  string `json:"detail,omitempty"`
	Fix     string `json:"fix,omitempty"`
}

// handleHealthCheck runs the diagnostic probes the BROWSER cannot do itself — it is
// same-origin-locked and can read neither /proc nor a raw cross-origin Date/IPv6
// response. Two high-leverage VPN checks live here: router clock skew (from a remote
// HTTP Date header, since NTP is often blocked) and an IPv6-leak test (the tunnels
// are IPv4-only, so working global IPv6 silently bypasses the VPN). Each sub-check
// degrades to a warn result rather than failing the whole call. The UI battery folds
// these rows in next to its client-composed checks (core/tunnels/internet/exit/log).
func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	// The checks are independent + each fans out to remote probes, so run them
	// concurrently — sequential would risk blowing the request timeout.
	checks := []func(context.Context) healthRow{clockSkewCheck, ipv6LeakCheck, dnsHealthCheck, flowOffloadCheck, conntrackCheck,
		func(ctx context.Context) healthRow { return s.pbrKernelCheck(ctx) },
		func(ctx context.Context) healthRow { return s.nativeOnlyCheck(ctx) },
		func(ctx context.Context) healthRow { return s.endpointReachCheck(ctx) },
		func(ctx context.Context) healthRow { return s.sourceRuleCheck(ctx) },
		func(ctx context.Context) healthRow { return s.dnsBypassCheck(ctx) },
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
		row.Status, row.Summary = "warn", "couldn't reach a time source"
		return row
	}
	t, err := http.ParseTime(dateHdr)
	if err != nil {
		row.Status, row.Summary = "warn", "unreadable time source"
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
	row := healthRow{ID: "ipv6", Label: "No IPv6 leak"}
	b, err := os.ReadFile("/proc/net/if_inet6")
	if err != nil {
		row.Status, row.Summary = "warn", "can't read IPv6 state (non-Linux?)"
		return row
	}
	if !ipv6HasGlobal(string(b)) {
		row.Status, row.Summary = "pass", "no global IPv6 on the router"
		return row
	}
	// Global v6 present — does raw v6 actually reach the internet (bypassing v4 tunnels)?
	cl := &http.Client{Timeout: 6 * time.Second}
	defer cl.CloseIdleConnections() // release pooled TCP conns (matches dohProbe) — no idle-conn buildup on the 256 MB router
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api6.ipify.org", nil)
	resp, err := cl.Do(req)
	if err != nil {
		row.Status, row.Summary = "pass", "IPv6 present but firewalled (OK)"
		row.Detail = "a direct IPv6 request did not reach the internet: " + err.Error()
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

// flowOffloadCheck reports whether the kernel flow-offload fast path is enabled. On capable
// hardware (e.g. the MediaTek PPE on MT7981) hardware offload can multiply routed throughput
// and cut CPU; with it off, forwarding is bounded by the CPU. This is advisory only and reads
// the fw4 (uci) firewall config — it never changes it. IMPORTANT: WayHop routes tunnel
// carve-outs by firewall mark, so a flowtable must EXCLUDE marked connections; otherwise a
// carve-out could be offloaded straight past the VPN (a leak). The fix text says so, to avoid
// a naive flow_offloading_hw flip. Degrades to a warn off-OpenWrt.
func flowOffloadCheck(ctx context.Context) healthRow {
	row := healthRow{ID: "offload", Label: "Flow offload (fast path)"}
	if ctx.Err() != nil {
		row.Status, row.Summary = "warn", "check cancelled"
		return row
	}
	b, err := os.ReadFile("/etc/config/firewall")
	if err != nil {
		row.Status, row.Summary = "warn", "can't read the firewall config (non-OpenWrt?)"
		return row
	}
	sw, hw := parseOffloadConfig(string(b))
	switch {
	case sw && hw:
		row.Status, row.Summary = "pass", "hardware flow offload enabled"
		row.Detail = "general routed (non-tunnel) traffic uses the hardware fast path"
	case sw:
		row.Status, row.Summary = "pass", "software flow offload enabled"
		row.Detail = "routed traffic uses the software fast path; hardware offload may give more throughput on capable NICs"
	case hw && !sw:
		row.Status, row.Summary = "warn", "hardware offload set but software offload is off"
		row.Detail = "flow_offloading_hw has no effect unless flow_offloading is also enabled"
		row.Fix = "Set firewall flow_offloading '1' as well so hardware offload can take effect."
	default:
		row.Status, row.Summary = "warn", "flow offload is off"
		row.Detail = "general routed throughput is bounded by the CPU forwarding rate; the hardware fast path is unused"
		row.Fix = "Enabling flow offload (hardware where supported) can greatly increase routed throughput and lower CPU. Because WayHop routes tunnel carve-outs by firewall mark, the flowtable must EXCLUDE marked connections so a carve-out isn't offloaded past the VPN — don't just flip flow_offloading_hw without that exclusion."
	}
	return row
}

// parseOffloadConfig reads the fw4 (uci) firewall text and reports whether software and
// hardware flow offloading are enabled in the defaults section. Pure (no I/O) for testing;
// accepts the common uci truthy spellings ('1'/true/on/yes, quoted or not).
func parseOffloadConfig(cfg string) (sw, hw bool) {
	for _, ln := range strings.Split(cfg, "\n") {
		f := strings.Fields(ln)
		if len(f) >= 3 && f[0] == "option" {
			on := false
			switch strings.Trim(f[2], "'\"") {
			case "1", "true", "on", "yes":
				on = true
			}
			switch f[1] {
			case "flow_offloading":
				sw = on
			case "flow_offloading_hw":
				hw = on
			}
		}
	}
	return sw, hw
}

// dnsHealthCheck probes whether encrypted DNS (DoH) is reachable from the router.
// It queries a few major DoH resolvers with a dns-json request and verifies the
// DNS rcode is NOERROR (Status==0 with an answer) — not merely HTTP 200. If at
// least one resolver answers, the router can resolve names over DoH rather than
// leaking plaintext queries to the ISP; if none answer it degrades to warn (it
// can't prove a leak, only that the encrypted path is unreachable).
func dnsHealthCheck(ctx context.Context) healthRow {
	row := healthRow{ID: "dns", Label: "DNS is private (DoH)"}
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
	row.Status = "pass"
	row.Summary = fmt.Sprintf("encrypted DNS (DoH) working · %d/%d resolvers", healthy, len(providers))
	return row
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
		name, host string
		port       int
	}
	var tgts []tgt
	for _, e := range p.Endpoints {
		if !e.Enabled {
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
		tgts = append(tgts, tgt{name, host, port})
	}
	if len(tgts) == 0 {
		row.Status, row.Summary = "pass", "no dialable endpoints to check"
		return row
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
	if len(down) == 0 {
		row.Status = "pass"
		row.Summary = fmt.Sprintf("all %d server(s) TCP-reachable", len(tgts))
		return row
	}
	row.Status = "warn"
	row.Summary = fmt.Sprintf("%d of %d server(s) unreachable", len(down), len(tgts))
	row.Detail = "unreachable: " + strings.Join(down, ", ")
	row.Fix = "These VPN servers didn't accept a TCP connection from the router — the server may be down, the port wrong, or the path blocked (DPI/firewall). If a server IS reachable here but its connection still fails, the problem is the proxy/protocol config, not the network."
	return row
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
	s.pbrMu.Lock()
	plan := s.pbrPlan
	s.pbrMu.Unlock()

	// In "fast"/native-only the kernel PBR IS the datapath (no TUN), so a kernel probe is
	// warranted exactly as in hybrid. In "tun"/"mixed" the TUN carries general traffic and
	// no kernel PBR is expected. Treat "fast" like "hybrid" below.
	if mode != "hybrid" && mode != "fast" {
		row.Status, row.Summary = "pass", "TUN mode — no kernel PBR needed"
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
		row.Status, row.Summary = "warn", "check cancelled"
		return row
	}
	p := s.store.Profile()
	mode := s.routingMode(s.config())
	if generator.DatapathNativeOnly(&p, mode) {
		row.Status = "pass"
		row.Summary = "sing-box not needed (native-only mode)"
		row.Detail = "All endpoints are kernel-native and traffic is routed by the kernel plane (PBR) in fast mode, so the sing-box core is intentionally absent — its absence is NOT a fault."
		return row
	}
	row.Status = "pass"
	row.Summary = "sing-box core is part of the datapath"
	row.Detail = "The profile is not native-only, so sing-box carries part of the traffic; the core/clash checks govern whether it is actually running."
	return row
}
