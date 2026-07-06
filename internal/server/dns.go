package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"

	"wayhop/internal/model"
	"wayhop/internal/nativedns"
)

// handleGetDNS returns the profile's DNS plane. When the user has not configured DNS yet it returns
// a synthesized failover-aware secure-default TEMPLATE (never persisted) so the panel can prefill the
// "Apply secure defaults" form with a detour already pointed at this profile's primary route.
func (s *Server) handleGetDNS(w http.ResponseWriter, r *http.Request) {
	p := s.store.Profile()
	// ?template=1 always returns a freshly-computed secure-default template (detour pointed at the
	// current primary route), regardless of what is configured — this is what the panel's "Apply
	// secure defaults" button loads so it can re-seed even a profile that already has DNS.
	if r.URL.Query().Get("template") == "1" {
		writeJSON(w, http.StatusOK, map[string]any{"dns": secureDNSTemplate(&p), "configured": p.DNS != nil, "template": true})
		return
	}
	if p.DNS != nil {
		writeJSON(w, http.StatusOK, map[string]any{"dns": p.DNS, "configured": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"dns": secureDNSTemplate(&p), "configured": false})
}

// handleSetDNS replaces the DNS plane. It validates the DNS PLANE against the current profile's
// namespace first (so a bad detour/rule_set/final reference or a leak-protection violation is rejected
// with a precise 400 instead of bricking a later Apply), then persists copy-on-write. It deliberately
// validates only the DNS plane — not the whole profile — matching the per-plane CRUD writers (which
// never whole-validate); an unrelated pre-existing profile issue is Apply's gate to surface, not a
// reason to block a DNS edit. A null body clears the plane (back to the no-dns-block default).
func (s *Server) handleSetDNS(w http.ResponseWriter, r *http.Request) {
	var dns *model.DNSSettings
	if err := json.NewDecoder(r.Body).Decode(&dns); err != nil {
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
	if err := s.store.SetDNS(dns); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"dns": dns, "configured": dns != nil})
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

// handleGetDNSNative adopts the router's OWN DNS stack (OpenWrt uci https-dns-proxy/dnsmasq, Keenetic
// dnsmasq.d) into the platform-agnostic NativeDNS, so the panel can show the DNS the device ACTUALLY
// serves — not just WayHop's sing-box plane. READ-ONLY (native write-back is a later slice). Off a
// router (dev/demo) it returns available:false. See docs/DNS_NATIVE_INTEGRATION.md.
func (s *Server) handleGetDNSNative(w http.ResponseWriter, r *http.Request) {
	platform := detectDNSPlatform()
	if platform == "" {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	nd, err := nativedns.Adopt(dnsExecRunner, platform)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "platform": platform, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "platform": platform, "native": nd})
}

// handleDNSNativePlan renders (does NOT apply) the write-back plan for an edited NativeDNS: the uci
// command sequence (OpenWrt) or the dnsmasq.d file content (Keenetic), plus the SEPARATE user-gated
// apply commands (commit + service restart). Pure preview — no device is touched — so the panel can
// show exactly what a native write would change before anyone runs it on the router.
func (s *Server) handleDNSNativePlan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Native nativedns.NativeDNS `json:"native"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
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

// dnsPreset is one provider preset for the add-resolver picker.
//
//   - Category "" (recommended) = globally-reachable SECURE resolvers, all IP-pinned DoH/DoT so no
//     cleartext bootstrap is needed (the certs carry the IP in a SAN) — leak-safe as-is.
//   - Category "local" = COUNTRY-LOCAL resolvers ("geo-allowed, non-blocked"): the resilience
//     last-resort tier. In a censored region the global secure resolvers get DPI-blocked, so DNS must
//     fall to a resolver the local network never blocks. Encrypted locals (e.g. AliDNS DoH on its own
//     IP) stay leak-safe; PLAINTEXT locals are the deliberate availability-over-privacy fallback and are
//     rejected under leak protection — pick them only for the last tier, or their DoH variant.
type dnsPreset struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Server     string `json:"server,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`
	Path       string `json:"path,omitempty"`
	Note       string `json:"note,omitempty"`
	Category   string `json:"category,omitempty"` // "" = recommended (secure/global); "local" = country-local
}

var dnsPresets = []dnsPreset{
	// Recommended — secure, global, IP-pinned (leak-safe as-is).
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
	// Country-local — geo-allowed, non-blocked (the resilience last-resort tier for a censored WAN).
	{Name: "🇷🇺 Yandex (RU)", Type: "udp", Server: "77.88.8.8", Category: "local", Note: "Russia — unblocked over any RU ISP; plaintext geo-fallback"},
	{Name: "🇷🇺 Yandex Safe (RU)", Type: "udp", Server: "77.88.8.88", Category: "local", Note: "Russia — + malware/fraud filtering"},
	{Name: "🇨🇳 AliDNS (DoH, CN)", Type: "https", Server: "223.5.5.5", Path: "/dns-query", Category: "local", Note: "China — IP-pinned DoH: encrypted AND unblocked in CN"},
	{Name: "🇨🇳 DNSPod (CN)", Type: "udp", Server: "119.29.29.29", Category: "local", Note: "China — Tencent, plaintext geo-fallback"},
	{Name: "🇮🇷 Shecan (IR)", Type: "udp", Server: "178.22.122.100", Category: "local", Note: "Iran — anti-sanction resolver, unblocked in IR"},
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
