package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/nativedns"
	"wayhop/internal/platform"
	"wayhop/internal/store"
)

// handleGetDNS returns the profile's DNS plane. When the user has not configured DNS yet it returns
// a synthesized failover-aware secure-default TEMPLATE (never persisted) so the panel can prefill the
// "Apply secure defaults" form with a detour already pointed at this profile's primary route.
func (s *Server) handleGetDNS(w http.ResponseWriter, r *http.Request) {
	// One atomic load for BOTH the plane and the rev the client will hand back as its If-Match.
	// Reading Profile() then Gen() separately let a write land between them, returning the old plane
	// with the new rev — a client editing that stale plane would then pass the SetDNSIfGen CAS with a
	// version it never actually saw, silently discarding the other edit. See store.Snapshot.
	p, rev := s.store.Snapshot()
	// tun: whether the core this plane is generated into keeps fakeip servers, so the page names the
	// resolver that really answers what no rule matches (model.DNSSettings.DefaultServer).
	tun := s.runningDNSPlaneTUN()
	// ?template=1 always returns a freshly-computed secure-default template (detour pointed at the
	// current primary route), regardless of what is configured — this is what the panel's "Apply
	// secure defaults" button loads so it can re-seed even a profile that already has DNS.
	if r.URL.Query().Get("template") == "1" {
		writeJSON(w, http.StatusOK, map[string]any{"dns": secureDNSTemplate(&p), "configured": p.DNS != nil, "template": true, "rev": rev, "tun": tun})
		return
	}
	if p.DNS != nil {
		writeJSON(w, http.StatusOK, map[string]any{"dns": p.DNS, "configured": true, "rev": rev, "tun": tun})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"dns": secureDNSTemplate(&p), "configured": false, "rev": rev, "tun": tun})
}

// dnsPlaneTUN reports whether the core is generated with its TUN inbound, the only plane that keeps
// fakeip servers: in tun and hybrid mode (executionGeneratorOptions), and on KeeneticOS in every mode,
// where every core config is generated with its TUN (keenetic.AssembleSingboxConfig and
// executionKeeneticCompatibilityOptions). The Apply check and the DNS page both read it, so the
// finding and the page name the same resolver.
func dnsPlaneTUN(mode string, plat platform.Platform) bool {
	return mode == "tun" || mode == "hybrid" || plat == platform.Keenetic
}

// runningDNSPlaneTUN is dnsPlaneTUN for the running daemon: its effective routing mode on the
// platform it runs on (the demo stands in for an OpenWrt router, as planCapabilities does).
func (s *Server) runningDNSPlaneTUN() bool {
	c := s.config()
	plat := s.detectedPlatform()
	if c.Demo {
		plat = platform.Platform(platform.DemoCapabilities().Platform)
	}
	return dnsPlaneTUN(s.routingMode(c), plat)
}

// dnsRevHeader carries the profile generation the client's DNS plane was read at.
//
// The DNS plane has no per-object API: every edit submits the whole plane, so deleting one resolver
// rewrites all of them. Two editors would otherwise silently overwrite each other and both receive
// a 200. The header is REQUIRED — a write that cannot say what it was based on cannot be shown to
// be safe, and per the capability contract there is no force escape. Refusals reuse the same
// vocabulary as the Apply gate: 409 means "re-read and decide again", never "retry harder".
const dnsRevHeader = "If-Match"

// handleSetDNS replaces the DNS plane. It validates the DNS PLANE against the current profile's
// namespace first (so a bad detour/rule_set/final reference or a leak-protection violation is rejected
// with a precise 400 instead of bricking a later Apply), then persists copy-on-write. It deliberately
// validates only the DNS plane — not the whole profile — matching the per-plane CRUD writers (which
// never whole-validate); an unrelated pre-existing profile issue is Apply's gate to surface, not a
// reason to block a DNS edit. A null body clears the plane (back to the no-dns-block default).
func (s *Server) handleSetDNS(w http.ResponseWriter, r *http.Request) {
	raw := strings.Trim(r.Header.Get(dnsRevHeader), `"`)
	if raw == "" {
		writeErr(w, http.StatusConflict, "STALE_CONFIG: this write did not say which version of the "+
			"DNS settings it was based on, so it cannot be applied safely. Reload the DNS page and "+
			"make the change again. Current version: "+strconv.FormatUint(s.store.Gen(), 10))
		return
	}
	wantGen, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		writeErr(w, http.StatusConflict, "STALE_CONFIG: unreadable version marker on this write. "+
			"Reload the DNS page and make the change again.")
		return
	}
	var dns *model.DNSSettings
	if err := decodeJSONBody(r.Body, &dns); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid DNS JSON")
		return
	}
	// Validate against the current profile's namespace — Profile() is a value copy, so setting DNS on
	// cand does not touch the shared read-only profile; ValidateDNS only reads the (shared) slices.
	cand := s.store.Profile()
	cand.DNS = dns
	if err := cand.ValidateDNS(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	newGen, err := s.store.SetDNSIfGen(dns, wantGen)
	if err != nil {
		if errors.Is(err, store.ErrStaleGen) {
			// Somebody committed between this client's read and its write. Refusing is the whole
			// point: merging blind is how one editor's resolvers vanish under another's. newGen is the
			// current generation reported by the CAS itself, not a fresh re-read.
			writeErr(w, http.StatusConflict, "STALE_CONFIG: the DNS settings changed after you loaded "+
				"them, so applying this would discard the other change. Reload the DNS page to see "+
				"the current settings, then make your change again. Current version: "+
				strconv.FormatUint(newGen, 10))
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// newGen is the generation this write produced, read under the store's write lock — so the plane
	// returned here and the rev returned with it are the same published pair (no separate Gen()).
	writeJSON(w, http.StatusOK, map[string]any{"dns": dns, "configured": dns != nil, "rev": newGen})
}

// handleDNSCatalog returns the curated DoH/DoT provider presets for the add-server modal. Static, so
// memoized + ETag-revalidated (If-None-Match → 304) like the routing catalog.
func (s *Server) handleDNSCatalog(w http.ResponseWriter, r *http.Request) {
	body, etag := dnsCatalogCached()
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

type serveClientsStatus struct {
	Configured bool   `json:"configured"`
	Listening  bool   `json:"listening"`
	Port       int    `json:"port"`
	HeldBy     string `json:"held_by,omitempty"`
}

// serveClientsFact separates the saved switch from the running listener. The probe is injected so
// tests need no resolver on the host; the demo reports the configuration rather than pretending it ran one.
func (s *Server) serveClientsFact(ctx context.Context, probe func(context.Context, string) error) serveClientsStatus {
	cfg := s.config()
	prof := s.store.Profile()
	fact := serveClientsStatus{Port: cfg.Ports.DNS}
	fact.Configured = prof.DNS != nil && prof.DNS.Enabled && prof.DNS.ServeClients && fact.Port > 0
	if !fact.Configured {
		return fact
	}
	if cfg.Demo {
		fact.Listening = true
		return fact
	}
	if run := s.dnsRunner(); run != nil {
		if out, err := run("netstat", "-lnup"); err == nil {
			targetPort := ":" + strconv.Itoa(fact.Port)
			for _, ln := range strings.Split(out, "\n") {
				f := strings.Fields(ln)
				if len(f) < 4 {
					continue
				}
				proto := strings.ToLower(f[0])
				if !strings.HasPrefix(proto, "udp") {
					continue
				}
				var hasPort bool
				var proc string
				for _, tok := range f {
					if strings.HasSuffix(tok, targetPort) {
						hasPort = true
					}
					if i := strings.Index(tok, "/"); i > 0 && proc == "" {
						proc = tok[i+1:]
					}
				}
				if hasPort && proc != "" {
					// Ours and listening, even if its resolver cannot be reached this moment: a probe
					// would call that "not running" and tell the person to Apply again.
					fact.Listening = strings.HasPrefix(proc, "sing-box")
					if !fact.Listening {
						fact.HeldBy = proc
					}
					return fact
				}
			}
		}
	}
	if probe == nil {
		probe = nativedns.ProbeResolver
	}
	probeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	fact.Listening = probe(probeCtx, "127.0.0.1:"+strconv.Itoa(fact.Port)) == nil
	return fact
}

// dnsPortHolder names the program that stops a loopback listener binding this port: one holding it on
// loopback or on every address, over TCP or UDP. "" when nothing does, or when netstat cannot say.
func dnsPortHolder(run nativedns.Runner, port int) string {
	if run == nil || port <= 0 {
		return ""
	}
	out, err := run("netstat", "-lnutp")
	if err != nil {
		return ""
	}
	suffix := ":" + strconv.Itoa(port)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		proto := strings.ToLower(f[0])
		if !strings.HasPrefix(proto, "udp") && !strings.HasPrefix(proto, "tcp") {
			continue
		}
		if !strings.HasSuffix(f[3], suffix) {
			continue
		}
		switch strings.TrimSuffix(f[3], suffix) {
		case "127.0.0.1", "0.0.0.0", "::", "::1", "*", "[::]", "[::1]":
		default:
			continue // Bound to another address: both can have the port.
		}
		for _, tok := range f[4:] {
			if i := strings.Index(tok, "/"); i > 0 {
				if proc := tok[i+1:]; !strings.HasPrefix(proc, "sing-box") {
					return proc
				}
				break
			}
		}
	}
	return ""
}

// dnsPortFindings names a DNS port another program already holds. sing-box would not start over it, and
// the first sign of that used to be a failed Apply in the core's own words. The default port is the mDNS
// port, so a router running a responder meets this on the first try.
func (s *Server) dnsPortFindings(cfg config.Config, prof model.Profile) []PlanFinding {
	port := servedDNSPort(cfg, prof)
	if port <= 0 || cfg.Demo {
		return nil
	}
	holder := dnsPortHolder(s.dnsRunner(), port)
	if holder == "" {
		return nil
	}
	return []PlanFinding{{
		ID: "dns.port_busy", Setting: "dns", Item: holder + " :" + strconv.Itoa(port),
		Severity: platform.SeverityBlocked, Reason: platform.ReasonSavedValueIncompat, Blocks: platform.BlocksApply,
	}}
}

// dnsPlaneFindings names DNS switches this router will not carry, which an Apply otherwise reported as
// applied. A hunter on an emulated OpenWrt turned both on, Apply said "Applied & saved", and nothing
// changed for a device: interception is a redirect WayHop renders only into the KeeneticOS kernel plane
// (hybrid and fast, see interceptEnforced), and on OpenWrt WayHop does not touch dnsmasq, so its resolver
// listens on loopback where no device asks.
func (s *Server) dnsPlaneFindings(cfg config.Config, prof model.Profile) []PlanFinding {
	if cfg.Demo || prof.DNS == nil || !prof.DNS.Enabled {
		return nil
	}
	var out []PlanFinding
	plat := s.detectedPlatform()
	if mode := s.routingMode(cfg); prof.DNS.Intercept && !(plat == platform.Keenetic && (mode == "hybrid" || mode == "fast")) {
		out = append(out, PlanFinding{ID: "dns.intercept.not_installed", Setting: "dns.intercept",
			Item: "Intercept clients' DNS", Requested: "on", Effective: "not installed",
			Severity: platform.SeverityDegraded, Reason: platform.ReasonBackendNotWired, Blocks: platform.BlocksNothing})
	}
	if port := servedDNSPort(cfg, prof); port > 0 && plat == platform.OpenWrt && !dnsmasqForwardsTo(s.dnsRunner(), port) {
		out = append(out, PlanFinding{ID: "dns.serve_clients.not_wired", Setting: "dns.serve_clients",
			Item: "127.0.0.1#" + strconv.Itoa(port), Requested: "on", Effective: "not used by dnsmasq",
			Severity: platform.SeverityDegraded, Reason: platform.ReasonBackendNotWired, Blocks: platform.BlocksNothing})
	}
	return out
}

// dnsmasqForwardsTo is whether OpenWrt's dnsmasq already names WayHop's loopback resolver, as the
// finding's remedy asks: then devices do reach it.
func dnsmasqForwardsTo(run nativedns.Runner, port int) bool {
	nd, err := nativedns.Adopt(run, "openwrt")
	if err != nil {
		return false
	}
	for _, r := range nd.Resolvers {
		if r.Address == "127.0.0.1" && r.Port == port {
			return true
		}
	}
	return false
}

// handleGetDNSNative adopts the router's OWN DNS stack (OpenWrt uci https-dns-proxy/dnsmasq, Keenetic
// dnsmasq.d) into the platform-agnostic NativeDNS, so the panel can show the DNS the device ACTUALLY
// serves — not just WayHop's sing-box plane. READ-ONLY: on KeeneticOS the chain is written by
// handleDNSChainSet, on OpenWrt not at all yet. Off a router (dev/demo) it returns available:false. See docs/DNS_NATIVE_INTEGRATION.md (development repository) in the
// development repository.
func (s *Server) handleGetDNSNative(w http.ResponseWriter, r *http.Request) {
	serveClients := s.serveClientsFact(r.Context(), nativedns.ProbeResolver)
	platform := s.dnsPlatform()
	if platform == "" {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "serve_clients": serveClients})
		return
	}
	run := s.dnsRunner()
	nd, err := nativedns.Adopt(run, platform)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "platform": platform, "error": err.Error(), "serve_clients": serveClients})
		return
	}
	// The EFFECTIVE runtime path (who really serves :53, whether LAN DNS is force-redirected through
	// the router, whether a client can still escape via DoT/DoH). The adopted CONFIG alone cannot answer
	// the leak question — a box can hold a perfect encrypted upstream chain while every LAN client
	// bypasses it over its own DoH. Best-effort: off a router this is a low-signal empty result.
	eff := nativedns.RunEffectivePath(run)
	// A bound upstream's tier depends on whether its interface is a tunnel, which only the profile knows.
	prof := s.store.Profile()
	ifaces := kernelIfaceByEndpoint(&prof, s.appliedKernelDevices())
	tunnels := make(map[string]bool, len(ifaces))
	for _, iface := range ifaces {
		tunnels[iface] = true
	}
	nd = nd.MarkTunnels(func(iface string) bool { return tunnels[iface] })
	// Redact secret path/query of any adopted DoH/DoT resolver URL (personal NextDNS/ControlD/AdGuard
	// tokens ride the URL). The panel only needs to display + preview the plane; the raw URLs stay in
	// the device config and never need to reach the browser. A write-back of a redacted address is
	// rejected by ValidateForWrite rather than corrupting the device config.
	resp := map[string]any{
		"available": true, "platform": platform, "native": nd.Redacted(), "effective": eff,
		"answering":     eff.Answering(), // which plane really answers clients: the page leads with this
		"serve_clients": serveClients,
	}
	if platform == "keenetic" {
		resp["chain"] = s.chainViewOf(nd, &prof)
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleDNSNativePlan renders (does NOT apply) the write-back plan for an edited NativeDNS: the uci
// command sequence (OpenWrt) or the dnsmasq.d file content (Keenetic), plus the SEPARATE user-gated
// apply commands (commit + service restart). Pure preview — no device is touched — so the panel can
// show exactly what a native write would change before anyone runs it on the router.
func (s *Server) handleDNSNativePlan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Native nativedns.NativeDNS `json:"native"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid native DNS JSON")
		return
	}
	nd := body.Native
	if err := nativedns.ValidateForWrite(nd); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var content string
	var apply []string
	switch nd.Platform {
	case "openwrt":
		content = strings.Join(nativedns.RenderUCI(nd), "\n")
		apply = nativedns.UCICommitCmds()
	case "keenetic":
		content = nativedns.RenderDnsmasqD(nd)
		apply = nativedns.KeeneticApplyCmds("/opt/etc/dnsmasq.d/00-upstream.conf")
	default:
		writeErr(w, http.StatusBadRequest, "unknown platform "+nd.Platform)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"platform": nd.Platform, "content": content, "apply": apply})
}

// detectDNSPlatform sniffs which native DNS stack this host runs via cheap file probes ("" off a router).
func detectDNSPlatform() string {
	if dnsFileExists("/sbin/uci") || dnsFileExists("/etc/config/dhcp") {
		return "openwrt"
	}
	if dnsDirExists("/opt/etc/dnsmasq.d") || dnsFileExists("/bin/ndmc") {
		return "keenetic"
	}
	return ""
}

// dnsExecRunner runs a fixed device command (uci show / cat dnsmasq.d — hardcoded, no user input) and
// returns combined output. Used only on a real router.
func dnsExecRunner(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func dnsFileExists(p string) bool { fi, err := os.Stat(p); return err == nil && !fi.IsDir() }
func dnsDirExists(p string) bool  { fi, err := os.Stat(p); return err == nil && fi.IsDir() }

// dnsPreset is one provider preset for the add-resolver picker: globally reachable secure resolvers, all
// IP-pinned DoH/DoT so no cleartext bootstrap is needed (the certs carry the IP in a SAN), leak-safe as-is.
//
// An operator a state owns, funds or has a way to read is not offered. Yandex, AliDNS, DNSPod and Shecan
// were here as a country-local last resort; anyone who needs one can still type its address.
type dnsPreset struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Server     string `json:"server,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`
	Path       string `json:"path,omitempty"`
	Note       string `json:"note,omitempty"`
}

var dnsPresets = []dnsPreset{
	{Name: "Cloudflare (DoH)", Type: "https", Server: "1.1.1.1", Path: "/dns-query"},
	{Name: "Cloudflare — malware+adult filter (DoH)", Type: "https", Server: "1.1.1.3", Path: "/dns-query", Note: "family filtering, no local lists"},
	{Name: "Quad9 (DoH, DNSSEC)", Type: "https", Server: "9.9.9.9", Path: "/dns-query"},
	{Name: "Google (DoH)", Type: "https", Server: "8.8.8.8", Path: "/dns-query"},
	{Name: "AdGuard (DoH, ad-block)", Type: "https", Server: "94.140.14.14", Path: "/dns-query"},
	{Name: "AdGuard Family (DoH)", Type: "https", Server: "94.140.14.15", Path: "/dns-query", Note: "family filtering"},
	{Name: "Cloudflare (DoT)", Type: "tls", Server: "1.1.1.1"},
	{Name: "Quad9 (DoT)", Type: "tls", Server: "9.9.9.9"},
	{Name: "Device resolver (local)", Type: "local", Note: "the on-device https-dns-proxy/dnsmasq behind the :53 hijack"},
	{Name: "FakeIP (domain routing, TUN only)", Type: "fakeip", Note: "synthetic IPs so domain rules match; requires gateway/TUN mode"},
}

var (
	dnsCatalogOnce sync.Once
	dnsCatalogBody []byte
	dnsCatalogETag string
)

func dnsCatalogCached() ([]byte, string) {
	dnsCatalogOnce.Do(func() {
		dnsCatalogBody, _ = json.Marshal(map[string]any{"presets": dnsPresets})
		sum := sha256.Sum256(dnsCatalogBody)
		dnsCatalogETag = "\"" + hex.EncodeToString(sum[:8]) + "\""
	})
	return dnsCatalogBody, dnsCatalogETag
}

// secureDNSTemplate builds the failover-aware secure default for a profile: IP-pinned DoH whose
// detour is the profile's primary route (a failover group ⇒ DoH rides the tunnel while up, falls to
// direct-DoH when all VPN are down — still encrypted), a `local` server for domestic/private names,
// leak-proof (encrypted-only, `local` never final), ipv4_only (tunnels are v4-only). Not persisted
// until the user hits "Apply secure defaults".
func secureDNSTemplate(p *model.Profile) *model.DNSSettings {
	det := dnsDetour(p)
	return &model.DNSSettings{
		Enabled: true,
		Servers: []model.DNSServer{
			{Tag: "dns_secure", Type: "https", Server: "1.1.1.1", Path: "/dns-query", Detour: det, Enabled: true},
			{Tag: "dns_secure_bk", Type: "https", Server: "9.9.9.9", Path: "/dns-query", Detour: det, Enabled: true},
			{Tag: "dns_local", Type: "local", Enabled: true},
		},
		Final:     "dns_secure",
		Strategy:  "ipv4_only",
		LeakProof: true,
	}
}

// dnsDetour picks the outbound the secure-default DoH rides. The DNS religion needs it WAN-TERMINAL —
// a failover group whose members include `direct` — so DNS rides the tunnel while a VPN tier is up
// (ISP blind) and gracefully falls to direct-DoH over the raw WAN when EVERY tunnel is down, instead of
// going dark. Prefer the default route's group if it already ends in direct; else any WAN-terminal
// group; else fall back to primaryDetour (Tier-1 hiding without the guaranteed WAN tail — e.g. a
// deliberately kill-switched setup, where "no DNS when all VPN down" is the user's own choice).
func dnsDetour(p *model.Profile) string {
	primary := primaryDetour(p)
	if groupWANTerminal(p, primary) {
		return primary
	}
	for i := range p.Groups {
		if groupHasDirect(&p.Groups[i]) {
			return p.Groups[i].ID
		}
	}
	return primary
}

// groupWANTerminal reports whether id names a group that includes `direct` (a WAN-fallback member).
func groupWANTerminal(p *model.Profile, id string) bool {
	for i := range p.Groups {
		if p.Groups[i].ID == id {
			return groupHasDirect(&p.Groups[i])
		}
	}
	return false
}

func groupHasDirect(g *model.Group) bool {
	for _, m := range g.Members {
		if m == model.OutboundDirect {
			return true
		}
	}
	return false
}

// primaryDetour picks the outbound DNS should ride: the default route's outbound (usually the main
// failover group) if any, else the first group (ideal — failover-aware), else the first enabled
// endpoint, else "" (direct).
func primaryDetour(p *model.Profile) string {
	for _, r := range p.Rules {
		if r.Default && r.Outbound != "" && r.Outbound != model.OutboundBlock {
			return r.Outbound
		}
	}
	if len(p.Groups) > 0 {
		return p.Groups[0].ID
	}
	for i := range p.Endpoints {
		if p.Endpoints[i].Enabled {
			return p.Endpoints[i].ID
		}
	}
	return ""
}
