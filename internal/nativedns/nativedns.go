// Package nativedns adopts a router's OWN DNS resolver stack into one platform-agnostic model, so
// WayHop can read and (later) manage the DNS the device ACTUALLY serves — OpenWrt uci
// https-dns-proxy/dnsmasq, Keenetic dnsmasq.d — instead of a disconnected sing-box dns block. This is
// the "adopt, don't fight" native-integration layer; see docs/DNS_NATIVE_INTEGRATION.md. The readers
// are pure (parse device text → NativeDNS) and tolerant (unknown lines ignored), mirroring the
// native-first importers in internal/keenetic.
package nativedns

// Resolver transports.
const (
	KindDoH   = "doh"   // DNS-over-HTTPS
	KindDoT   = "dot"   // DNS-over-TLS
	KindPlain = "plain" // cleartext UDP/TCP :53
	KindLocal = "local" // defer to the on-device resolver
)

// Tiers of the resilience chain (see docs/DNS_RESILIENCE.md). Derived, best-effort: encrypted resolvers
// are the hidden/primary tier, plaintext fallbacks are the geo-allowed last resort. Whether a resolver
// rides the tunnel (Tier 1) vs the raw WAN (Tier 2) is not knowable from the DNS config alone — the
// routing plane decides — so ViaTunnel is enriched later (N3) and Tier defaults by kind.
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
