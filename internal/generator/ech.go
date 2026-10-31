package generator

import (
	"encoding/pem"
	"regexp"
	"strconv"
	"strings"

	"wayhop/internal/model"
)

// Encrypted Client Hello (sing-box outbound tls.ech).
//
// The model keeps the server's ECHConfigList as base64 (model.ECH); sing-box wants it as one "ECH
// CONFIGS" PEM block, as lines, and refuses raw base64 ("invalid ECH configs pem"). An empty config
// makes sing-box send an HTTPS (type 65) query for the name and take the record's "ech" parameter,
// kept for the record's TTL; with no record the dial fails, there is no fall back to a plain
// ClientHello. The query goes through the DNS router (its rules and final), not the outbound's
// resolver, so the DNS server those pick sees the name ECH hides (ECHLookupFor).
//
// What the cores do with it, measured with `sing-box check` on 1.12.17, 1.13.21, 1.14.4 and
// 1.15.0-alpha.13 (TestECHSingBoxCheck):
//
//   - query_server_name exists from 1.13; 1.12 refuses it as an unknown field even with ECH off.
//   - Reality with ECH is FATAL on every core ("Reality is conflict with ECH").
//   - 1.12 has ECH only when built with Go 1.24 or newer; otherwise every config holding it fails
//     ("ECH requires go1.24"). 1.13 needs Go 1.24.7 to build at all.
//   - Over QUIC (hysteria2, tuic) sing-quic dials with the plain TLS config, so only a static config
//     is used; the DNS lookup never runs there.
//
// And in a real handshake on each of those cores (a VLESS+TLS server with an ECH key on loopback, and
// the outbound this package renders): with no uTLS fingerprint, chrome or firefox the connection
// works; with any other every handshake fails, while the same connection without ECH works - safari,
// ios, edge, qq, random and randomized with "tls: malformed outer client hello", android and 360
// (whose ClientHello offers no TLS 1.3, which ECH needs) with "tls: handshake failure". random may
// draw a fingerprint that works, so it fails only most of the time. Share links keep their fp=, so
// such a connection is rendered with chrome (echFitFingerprint) and the Apply review says so
// (ECHFingerprintReplaced).

// echCarryingFingerprints are the uTLS fingerprints whose ClientHello carries ECH.
var echCarryingFingerprints = map[string]bool{"chrome": true, "firefox": true}

// echFitFingerprint sets a rendered tls block's uTLS fingerprint to chrome when the block carries ECH
// and the fingerprint is one that cannot (echCarryingFingerprints). No fingerprint stays none: Go's
// own ClientHello carries ECH.
func echFitFingerprint(tl map[string]any) {
	u, ok := tl["utls"].(map[string]any)
	if !ok || tl["ech"] == nil {
		return
	}
	if fp, _ := u["fingerprint"].(string); !echCarryingFingerprints[fp] {
		u["fingerprint"] = "chrome"
	}
}

// ECHFingerprintReplaced returns the uTLS fingerprint e asks for when the outbound Generate renders
// for it carries ECH with chrome in its place (echFitFingerprint), or "" when nothing is replaced.
func ECHFingerprintReplaced(e *model.Endpoint, coreVersion string) string {
	if !echEmitted(e) || echGoTooOld(coreVersion) {
		return ""
	}
	if fp := safeEnum(normalizeUTLSFinger(e.TLS.Fingerprint), knownUTLSFinger); fp != "" && !echCarryingFingerprints[fp] {
		return fp
	}
	return ""
}

// echQueryNameMinMinor is the first sing-box minor with tls.ech.query_server_name.
const echQueryNameMinMinor = 13

// echMinGoMinor is the Go minor a 1.12 core needs to have ECH compiled in (common/tls/ech.go is
// //go:build go1.24; the stub returns "ECH requires go1.24").
const echMinGoMinor = 24

// coreGoVersionRe reads the Go a core was built with from the raw `sing-box version` output
// ("Environment: go1.25.6 linux/amd64").
var coreGoVersionRe = regexp.MustCompile(`Environment:\s*go1\.(\d+)`)

// coreGoMinor returns the Go 1.x minor the core named by v was built with, or -1 when v does not say
// (a bare version, or no version at all).
func coreGoMinor(v string) int {
	m := coreGoVersionRe.FindStringSubmatch(v)
	if m == nil {
		return -1
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return -1
	}
	return n
}

// echGoTooOld reports a known 1.12 core built with a Go that has no ECH. An unknown version, or one
// that does not name its Go, keeps ECH: nothing changes until the caller passes what it detected.
func echGoTooOld(coreVersion string) bool {
	m, g := coreMinor(coreVersion), coreGoMinor(coreVersion)
	return m >= 0 && m <= 12 && g >= 0 && g < echMinGoMinor
}

// echJSON renders t's ECH for the 1.12 schema every core accepts, or nil when there is none to
// render: ECH off, Reality, or a config that is not an ECHConfigList (model.Validate refuses that at
// save; dropped here too, so it can never fail the shared config). query_server_name is the 1.13
// option echCoreExtras adds.
func echJSON(t *model.TLS) map[string]any {
	if !t.ECHActive() {
		return nil
	}
	if t.ECH.Config == "" {
		return map[string]any{"enabled": true}
	}
	b, err := model.ParseECHConfigList(t.ECH.Config)
	if err != nil {
		return nil
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: b})
	return map[string]any{"enabled": true, "config": strings.Split(strings.TrimRight(string(p), "\n"), "\n")}
}

// fitECHToProtocol drops a DNS-mode ECH from a QUIC outbound's tls block, where sing-box would never
// run the lookup and send the server name in the clear (model.Validate refuses it at save).
func fitECHToProtocol(p model.Protocol, tl map[string]any, t *model.TLS) {
	if p != model.ProtoHysteria2 && p != model.ProtoTUIC {
		return
	}
	if ech, ok := tl["ech"].(map[string]any); ok && ech["config"] == nil {
		dropECH(tl, t)
	}
}

// dropECH removes the ECH from a rendered tls block, and with it the chrome echFitFingerprint put in
// place of the fingerprint t asks for.
func dropECH(tl map[string]any, t *model.TLS) {
	delete(tl, "ech")
	if u, ok := tl["utls"].(map[string]any); ok && t != nil {
		if fp := safeEnum(normalizeUTLSFinger(t.Fingerprint), knownUTLSFinger); fp != "" {
			u["fingerprint"] = fp
		}
	}
}

// echCoreExtras fits ob's ECH to the core named by coreVersion: it removes it from a 1.12 core
// built without ECH, which would refuse the whole config, and adds the query server name where the
// core has the option (1.13+). An unknown version keeps the 1.12 form.
func echCoreExtras(e *model.Endpoint, ob map[string]any, coreVersion string) {
	tl, _ := ob["tls"].(map[string]any)
	ech, _ := tl["ech"].(map[string]any)
	if ech == nil {
		return
	}
	if echGoTooOld(coreVersion) {
		dropECH(tl, e.TLS)
		return
	}
	if _, static := ech["config"]; static || coreMinor(coreVersion) < echQueryNameMinMinor {
		return
	}
	if q := strings.TrimSpace(e.TLS.ECH.QueryServerName); q != "" {
		ech["query_server_name"] = q
	}
}

// echEmitted reports whether the outbound Generate renders for e carries ECH, before the core is
// considered: a sing-box connection with a tls block, ECH on, not Reality, a well-formed config or
// the DNS lookup, and the lookup only where it runs (not over QUIC).
func echEmitted(e *model.Endpoint) bool {
	if e.Engine != model.EngineSingBox || !tlsCapable(e.Protocol) {
		return false
	}
	ech := echJSON(e.TLS)
	if ech == nil {
		return false
	}
	tl := map[string]any{"ech": ech}
	fitECHToProtocol(e.Protocol, tl, nil)
	return tl["ech"] != nil
}

// ECHFromDNS reports a connection whose ECH config sing-box looks up in DNS (and keeps for the
// record's TTL).
func ECHFromDNS(e *model.Endpoint) bool {
	return echEmitted(e) && e.TLS.ECH.Config == ""
}

// ECHQueryNameNeedsNewerCore reports a connection that looks its ECH config up under a query server
// name on a known core older than 1.13, which has no such option: the name is left out and sing-box
// asks for the SNI's record instead. An unknown version says nothing.
func ECHQueryNameNeedsNewerCore(e *model.Endpoint, coreVersion string) bool {
	if !ECHFromDNS(e) || strings.TrimSpace(e.TLS.ECH.QueryServerName) == "" || echGoTooOld(coreVersion) {
		return false
	}
	m := coreMinor(coreVersion)
	return m >= 0 && m < echQueryNameMinMinor
}

// ECHDroppedByCore reports a connection with ECH on a 1.12 core built with Go older than 1.24, which
// has no ECH: it is applied without it.
func ECHDroppedByCore(e *model.Endpoint, coreVersion string) bool {
	return echEmitted(e) && echGoTooOld(coreVersion)
}

// ECHConfigOnReality reports a Reality connection that holds an ECH config, as a link that set both
// brings it: sing-box cannot combine the two, so the connection runs over Reality without ECH.
func ECHConfigOnReality(e *model.Endpoint) bool {
	t := e.TLS
	return e.Engine == model.EngineSingBox && tlsCapable(e.Protocol) && t != nil && t.Enabled &&
		t.Type == "reality" && t.ECH != nil && (t.ECH.Config != "" || t.ECH.Enabled)
}

// ECHLookup is where a connection's ECH lookup (ECHFromDNS) goes.
type ECHLookup struct {
	// Name is the name whose HTTPS record is asked for, the one ECH hides: the query server name where
	// the core carries it (1.13+), else the SNI, else the server.
	Name string
	// Server is the tag of the DNS server the profile's DNS rules give the query to, "reject" when a
	// rule refuses it, or "" when the profile has no DNS plane and sing-box asks the system resolver.
	Server string
	// Clear: that server sends the question unencrypted - plain udp or tcp, or the router's own
	// resolver ("local", or no DNS plane), which forwards it however the router is set up to.
	Clear bool
	// Through is the server's detour when that is this connection or a group holding it: the lookup
	// then needs the connection it is for.
	Through string
}

// ECHLookupFor returns where e's ECH lookup goes as the dns block Generate renders for p routes it, or
// nil when e looks nothing up (no ECH, a pasted config, a core without ECH). A rule is read by its
// domains, suffixes and manual list entries; a list fetched from a URL or a geosite category cannot be
// read here and is taken not to hold the name (they are categories, not one server's name).
func ECHLookupFor(p *model.Profile, e *model.Endpoint, coreVersion string) *ECHLookup {
	if !ECHFromDNS(e) || echGoTooOld(coreVersion) {
		return nil
	}
	l := &ECHLookup{Name: e.TLS.SNI}
	if l.Name == "" {
		l.Name = e.Server
	}
	if q := strings.TrimSpace(e.TLS.ECH.QueryServerName); q != "" && coreMinor(coreVersion) >= echQueryNameMinMinor {
		l.Name = q
	}
	d := p.DNS
	if d == nil || !d.Enabled {
		l.Clear = true
		return l
	}
	// The servers dnsFrom emits (a disabled one is dropped, and the rules naming it with it; so is a
	// VPN's pushed-resolver server on a core without that type).
	var first *model.DNSServer
	byTag := map[string]*model.DNSServer{}
	for i := range d.Servers {
		if s := &d.Servers[i]; s.Enabled && !VPNDNSNeedsNewerCore(s, coreVersion) {
			byTag[s.Tag] = s
			if first == nil {
				first = s
			}
		}
	}
	var srv *model.DNSServer
	for i := range d.Rules {
		r := &d.Rules[i]
		if r.Disabled || (r.Server != "reject" && byTag[r.Server] == nil) || !dnsRuleTakesHTTPS(p, r, l.Name) {
			continue
		}
		if r.Server == "reject" {
			l.Server = "reject"
			return l
		}
		srv = byTag[r.Server]
		break
	}
	if srv == nil {
		// sing-box answers what no rule takes with final, or with the first server when there is none.
		if srv = byTag[d.Final]; srv == nil {
			srv = first
		}
	}
	if srv == nil {
		l.Clear = true // no server at all: the system resolver
		return l
	}
	l.Server = srv.Tag
	// A VPN's pushed resolvers are asked inside that connection's tunnel, so the question is not on the
	// router's WAN, where the firewall ECH blinds sits; their path is the connection, not a detour.
	vpn := model.IsVPNDNSType(srv.Type)
	l.Clear = srv.Type != "fakeip" && !model.IsEncryptedDNSType(srv.Type) && !vpn
	path := srv.Detour
	if vpn {
		path = srv.Endpoint
	}
	if det := canonicalOutbound(strings.TrimSpace(path)); det == e.ID || groupHolds(p, det, e.ID, map[string]bool{}) {
		l.Through = det
	}
	return l
}

// dnsRuleTakesHTTPS reports whether the DNS rule dnsFrom renders for r takes an HTTPS query for name,
// as far as it can be read (ECHLookupFor).
func dnsRuleTakesHTTPS(p *model.Profile, r *model.DNSRule, name string) bool {
	if len(r.QueryType) > 0 {
		https := false
		for _, q := range r.QueryType {
			if q = strings.ToUpper(strings.TrimSpace(q)); q == "HTTPS" || q == "65" {
				https = true
			}
		}
		if !https {
			return false
		}
	}
	for _, g := range r.GeoSite {
		if strings.TrimSpace(g) != "" {
			return false // a category this cannot read (and ANDed with the rest)
		}
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	suffix := func(s string) bool {
		s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
		if strings.HasPrefix(s, ".") {
			return s != "." && strings.HasSuffix(name, s)
		}
		return s != "" && (name == s || strings.HasSuffix(name, "."+s))
	}
	named := false // the rule has a name matcher at all
	for _, s := range r.Domain {
		named = named || strings.TrimSpace(s) != ""
		if s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")); s != "" && s == name {
			return true
		}
	}
	for _, s := range r.DomainSuffix {
		named = named || strings.TrimSpace(s) != ""
		if suffix(s) {
			return true
		}
	}
	for _, id := range r.RuleSets {
		tags := dnsListTags(p, id, false)
		if len(tags) == 0 {
			continue
		}
		named = true
		for _, tag := range tags {
			if tag != "rsm-"+id {
				continue // fetched from a URL: not read here
			}
			for i := range p.RoutingLists {
				if rl := &p.RoutingLists[i]; rl.ID == id {
					dom, _ := listEntries(rl)
					for _, s := range dom {
						if suffix(s) {
							return true
						}
					}
				}
			}
		}
	}
	if len(r.RuleSets) > 0 && !named {
		return false // every list it names renders nothing: dnsFrom drops the rule
	}
	// No name matcher: a query-type rule, which takes every HTTPS query.
	return !named && len(r.QueryType) > 0
}

// groupHolds reports whether the group id has ep among its members, directly or through a group.
func groupHolds(p *model.Profile, id, ep string, seen map[string]bool) bool {
	g := p.GroupByID(id)
	if g == nil || seen[id] {
		return false
	}
	seen[id] = true
	for _, m := range g.Members {
		if m == ep || groupHolds(p, m, ep, seen) {
			return true
		}
	}
	return false
}
