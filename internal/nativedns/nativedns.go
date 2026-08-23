// Package nativedns adopts a router's OWN DNS resolver stack into one platform-agnostic model, so
// WayHop can read and (later) manage the DNS the device ACTUALLY serves — OpenWrt uci
// https-dns-proxy/dnsmasq, Keenetic dnsmasq.d — instead of a disconnected sing-box dns block. This is
// the "adopt, don't fight" native-integration layer; see docs/DNS_NATIVE_INTEGRATION.md (development repository) in the
// development repository. The readers are pure (parse device text → NativeDNS) and tolerant
// (unknown lines ignored), mirroring the native-first importers in internal/keenetic.
package nativedns

import (
	"net/url"
	"strings"
)

// Resolver transports.
const (
	KindDoH   = "doh"   // DNS-over-HTTPS
	KindDoT   = "dot"   // DNS-over-TLS
	KindPlain = "plain" // cleartext UDP/TCP :53
	KindLocal = "local" // defer to the on-device resolver
)

// Tiers of the resilience chain (see docs/DNS_RESILIENCE.md in the development repository).
// Derived, best-effort: encrypted resolvers are the hidden/primary tier, plaintext fallbacks are
// the geo-allowed last resort. Whether a resolver rides the tunnel (Tier 1) vs the raw WAN (Tier 2)
// is not knowable from the DNS config alone — the routing plane decides — so ViaTunnel is enriched
// later (N3) and Tier defaults by kind.
const (
	TierHidden   = 1 // encrypted DoH/DoT via the VPN
	TierWANEnc   = 2 // encrypted DoH/DoT over the raw WAN
	TierFallback = 3 // plaintext geo-allowed, non-blocked
)

// NativeResolver is one upstream in the device's native DNS chain.
type NativeResolver struct {
	Kind      string `json:"kind"`             // doh|dot|plain|local
	Address   string `json:"address"`          // resolver IP, or the DoH URL
	Port      int    `json:"port,omitempty"`   // 0 = protocol default
	ViaTunnel bool   `json:"via_tunnel"`       // routed through the VPN (enriched later); false = unknown/direct
	Tier      int    `json:"tier,omitempty"`   // 1 hidden(VPN) · 2 WAN-encrypted · 3 geo-fallback
	Source    string `json:"source,omitempty"` // provenance tag for write-back (e.g. "https-dns-proxy[0]")
}

// NativeDNS is the whole adopted native resolver stack, ordered by preference (the tier order the
// device applies — dnsmasq strict-order / https-dns-proxy instance order).
type NativeDNS struct {
	Resolvers   []NativeResolver `json:"resolvers"`
	StrictOrder bool             `json:"strict_order"` // try in listed order (fallback) vs fastest-wins
	NoResolv    bool             `json:"no_resolv"`    // ignore ISP-pushed upstreams
	Platform    string           `json:"platform"`     // "openwrt" | "keenetic"
}

// RedactAddress masks the secret path/query of a DoH/DoT resolver URL before it crosses the API/UI
// boundary. A personal resolver URL — NextDNS/ControlD/AdGuard-personal — carries an account token in
// its path or query (e.g. https://dns.nextdns.io/ab12cd), and NativeResolver.Address holds it verbatim;
// surfacing that to the browser, an API error, or a log is a credential leak. This keeps the scheme +
// host (so the resolver is still recognizable) and masks the rest. A plain IP, a bare host, the standard
// "/dns-query" path with no query, or an unparseable value is returned unchanged (nothing to hide).
// Redaction is display-only: callers keep the raw Address server-side for the actual write-back.
func RedactAddress(addr string) string {
	u, err := url.Parse(strings.TrimSpace(addr))
	if err != nil || u.Host == "" {
		return addr // plain IP / bare host / unparseable — no URL secret to mask
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "http", "tls", "dot", "quic", "h3", "doq":
	default:
		return addr // not a URL-transport resolver
	}
	// The only widely-used NON-secret DoH path is the canonical /dns-query with no query string or
	// userinfo. Anything else is treated as potentially token-bearing and masked.
	path := strings.TrimRight(u.Path, "/")
	if u.User == nil && u.RawQuery == "" && (path == "" || strings.EqualFold(path, "/dns-query")) {
		return addr
	}
	return strings.ToLower(u.Scheme) + "://" + u.Host + "/" + RedactionMark
}

// RedactionMark is the visible marker RedactAddress substitutes for a masked secret. A write-back
// must never accept an address containing it (ValidateForWrite rejects one): its presence means a
// display-only redacted value was posted back instead of the real resolver URL, which would bake the
// placeholder into the device config. The real URL stays on the device; faithful tokened-DoH
// write-back needs the server-side re-read path (not yet wired).
const RedactionMark = "•••"

// Redacted returns a copy of nd with every resolver Address run through RedactAddress — the safe form
// to serialize into an API response or the UI. The ORIGINAL nd (with real URLs) must be kept for
// write-back; this copy is display-only. Resolver slice is cloned so the original is untouched.
func (nd NativeDNS) Redacted() NativeDNS {
	out := nd
	out.Resolvers = make([]NativeResolver, len(nd.Resolvers))
	copy(out.Resolvers, nd.Resolvers)
	for i := range out.Resolvers {
		out.Resolvers[i].Address = RedactAddress(out.Resolvers[i].Address)
	}
	return out
}

// tierForKind is the default tier when the routing plane hasn't enriched ViaTunnel yet: encrypted =
// primary (hidden), plaintext = the geo-allowed last resort, local = the WAN-encrypted middle.
func tierForKind(kind string) int {
	switch kind {
	case KindDoH, KindDoT:
		return TierHidden
	case KindLocal:
		return TierWANEnc
	default: // plain
		return TierFallback
	}
}
