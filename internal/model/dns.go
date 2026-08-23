package model

import (
	"fmt"
	"net"
	"strings"
)

// DNSServer is one upstream resolver in the DNS plane. It maps 1:1 to a sing-box 1.12.x
// dns.servers[] entry ({tag,type,server,detour,...}). Encrypted types (https/tls/quic/h3 =
// DoH/DoT/DoQ/DoH3) keep the query CONTENT unreadable by the ISP regardless of path; "local" defers
// to the on-device resolver (the 127.0.0.1 https-dns-proxy behind the existing :53 hijack); "fakeip"
// hands out synthetic IPs so domain routing works in the TUN plane.
//
// Detour is the KEY to FAILOVER-AWARE DNS (the "hide while we can, degrade gracefully" model): point
// it at a failover GROUP whose last member is `direct` — then DNS rides the tunnel while a VPN tier
// is up (the ISP sees nothing) and falls to the raw WAN when every tier is down (a DoH query stays
// encrypted; only the provider metadata is exposed), so DNS never goes fully dark and the internet
// keeps working. "" = direct. This mirrors the ordered-urltest [vpn…, direct] WAN-fallback pattern
// documented in validate.go's group-member check.
type DNSServer struct {
	Tag            string `json:"tag"`
	Type           string `json:"type"`                      // https|tls|quic|h3|udp|tcp|local|fakeip
	Server         string `json:"server,omitempty"`          // IP literal or hostname; empty for local/fakeip
	ServerPort     int    `json:"server_port,omitempty"`     // 0 = protocol default (443 DoH/DoQ, 853 DoT, 53 plain)
	Path           string `json:"path,omitempty"`            // DoH path; "" = /dns-query
	SNI            string `json:"sni,omitempty"`             // TLS server_name (encrypted types)
	Detour         string `json:"detour,omitempty"`          // endpoint/group id, or "" = direct; a GROUP makes DNS failover-aware
	DomainResolver string `json:"domain_resolver,omitempty"` // bootstrap server tag; REQUIRED when Server is a hostname
	Inet4Range     string `json:"inet4_range,omitempty"`     // fakeip v4 pool (e.g. 198.18.0.0/15)
	Inet6Range     string `json:"inet6_range,omitempty"`     // fakeip v6 pool
	Enabled        bool   `json:"enabled"`
}

// DNSRule steers matching queries to a specific DNSServer (or rejects them for DNS-level adblock). It
// reuses the Routing plane's rule_set tags (RoutingList IDs) so DNS routing and traffic routing stay
// coherent — a domain routed to a tunnel resolves via that tunnel's server. Entries within a field
// are OR'd; fields are AND'd (sing-box dns.rules semantics).
type DNSRule struct {
	ID           string   `json:"id"`
	RuleSets     []string `json:"rule_sets,omitempty"` // RoutingList IDs (→ sing-box rule_set)
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	Domain       []string `json:"domain,omitempty"`
	GeoSite      []string `json:"geosite,omitempty"`
	QueryType    []string `json:"query_type,omitempty"` // A|AAAA|HTTPS|… (empty = any)
	Server       string   `json:"server"`               // DNSServer tag, or "reject" (DNS-level block)
	Disabled     bool     `json:"disabled,omitempty"`
}

// DNSSettings is the whole DNS plane, hung on Profile as a POINTER (nil ⇒ no dns block emitted ⇒
// byte-identical to a pre-DNS profile). A non-nil pointer with Enabled==false keeps the config
// (servers/rules) but suppresses emission.
type DNSSettings struct {
	Enabled  bool        `json:"enabled"`
	Servers  []DNSServer `json:"servers,omitempty"`
	Rules    []DNSRule   `json:"rules,omitempty"`
	Final    string      `json:"final,omitempty"`    // default server tag for unmatched queries
	Strategy string      `json:"strategy,omitempty"` // prefer_ipv4|prefer_ipv6|ipv4_only|ipv6_only
	// LeakProof = ENCRYPTED-ONLY: reject plaintext (udp/tcp) servers and forbid a plaintext/local
	// `final`, so query CONTENT can never reach the ISP in the clear — even on the WAN fallback a DoH
	// query stays encrypted. It deliberately does NOT force a tunnel detour (that would break graceful
	// degradation); pair it with a failover-group detour for the full "hide while we can, stay working
	// when we can't".
	LeakProof bool `json:"leak_proof,omitempty"`
	// Intercept answers clients' plain DNS from THIS router whatever server they addressed, so a
	// device with a hardcoded resolver stops walking past every rule on the DNS page. Measured on a
	// real LAN: a NAS configured with 1.1.1.1 resolved directly and no domain rule could ever apply
	// to it. Kernel-plane only (it is a netfilter redirect); the page states what it cannot cover.
	Intercept bool `json:"intercept,omitempty"`
	// InterceptRejectEncrypted additionally refuses DoT and the well-known public DoH addresses so a
	// client that hardcodes an ENCRYPTED resolver falls back to plain 53 and is then intercepted.
	// Off by default: it breaks those specific destinations by design, which is a choice to make
	// deliberately rather than inherit.
	InterceptRejectEncrypted bool   `json:"intercept_reject_encrypted,omitempty"`
	FakeIP                   bool   `json:"fakeip,omitempty"`
	DisableCache             bool   `json:"disable_cache,omitempty"`
	IndependentCache         bool   `json:"independent_cache,omitempty"` // forced on when FakeIP
	ClientSubnet             string `json:"client_subnet,omitempty"`     // ECS subnet
	ReverseMapping           bool   `json:"reverse_mapping,omitempty"`
}

// DNS server-type sets. Encrypted types keep the query unreadable by the ISP; plaintext types
// (udp/tcp) expose it and are forbidden under LeakProof. Network types carry a Server address (and
// may take a Detour); local/fakeip do not.
var (
	validDNSServerTypes = map[string]bool{
		"https": true, "tls": true, "quic": true, "h3": true,
		"udp": true, "tcp": true, "local": true, "fakeip": true,
	}
	encryptedDNSTypes  = map[string]bool{"https": true, "tls": true, "quic": true, "h3": true}
	plaintextDNSTypes  = map[string]bool{"udp": true, "tcp": true}
	networkDNSTypes    = map[string]bool{"https": true, "tls": true, "quic": true, "h3": true, "udp": true, "tcp": true}
	validDNSStrategies = map[string]bool{
		"": true, "prefer_ipv4": true, "prefer_ipv6": true, "ipv4_only": true, "ipv6_only": true,
	}
)

// isEncryptedDNSType reports whether a server type keeps the query content encrypted end-to-end.
func isEncryptedDNSType(t string) bool { return encryptedDNSTypes[t] }

// IsEncryptedDNSType is the exported form. Two places outside this package must ask the SAME question
// and had each written their own list: the Keenetic backend, deciding whether the DNS plane needs the
// proxy core (only the core speaks DoH/DoT/DoQ), and the components section, naming what an installed
// core is used for. A second copy of this set is a second thing to keep in step, and the first one to
// drift silently changes whether a router starts its core at all.
func IsEncryptedDNSType(t string) bool {
	return isEncryptedDNSType(strings.ToLower(strings.TrimSpace(t)))
}

// dnsNamespace builds the id→kind and id→enabled maps validateDNS resolves against — the same
// namespace Profile.Validate assembles, but WITHOUT the structural checks. It never errors: resolution
// only needs presence, so empty/duplicate ids simply collapse.
func (p *Profile) dnsNamespace() (map[string]string, map[string]bool) {
	ids := map[string]string{}
	enabled := map[string]bool{}
	for _, e := range p.Endpoints {
		if e.ID != "" {
			ids[e.ID] = "endpoint"
			enabled[e.ID] = e.Enabled
		}
	}
	for _, g := range p.Groups {
		if g.ID != "" {
			ids[g.ID] = "group"
			enabled[g.ID] = true
		}
	}
	for _, r := range p.Rules {
		if r.ID != "" {
			ids[r.ID] = "rule"
		}
	}
	for _, rl := range p.RoutingLists {
		if rl.ID != "" {
			ids[rl.ID] = "routing list"
		}
	}
	return ids, enabled
}

// ValidateDNS validates ONLY the DNS plane against this profile's namespace (endpoints/groups/routing
// lists), independent of the rest of the profile's structural validity. A nil DNS plane is always
// valid. The DNS-section save path uses this so a DNS edit is gated on DNS correctness — a bad
// detour/rule_set/final or a leak-protection violation is a precise error — WITHOUT being blocked by
// an unrelated, pre-existing profile issue (the per-plane CRUD writers never whole-validate; the full
// Validate at Apply, which also runs validateDNS, stays the final gate for the whole config).
func (p *Profile) ValidateDNS() error {
	if p.DNS == nil {
		return nil
	}
	ids, enabled := p.dnsNamespace()
	return validateDNS(p.DNS, ids, enabled)
}

// validateDNS checks the DNS plane: unique server tags, known types/strategy, a server address for
// network types, a bootstrap resolver for hostname servers (no cleartext bootstrap leak), FakeIP
// ranges + IndependentCache coupling, resolvable detours/final/rule targets, and the LeakProof
// (encrypted-only) invariant. ids/enabled come from Profile.Validate — Detour resolves against the
// endpoint/group namespace, rule_sets against RoutingLists. Fail-safe: a bricking value is rejected
// so Apply fails cleanly with a precise error rather than emitting a config sing-box would fatal.
// DNS is greenfield (nil for every existing profile), so a strict check here can't brick legacy data.
func validateDNS(dns *DNSSettings, ids map[string]string, enabled map[string]bool) error {
	if !validDNSStrategies[dns.Strategy] {
		return fmt.Errorf("dns: unknown strategy %q", dns.Strategy)
	}
	if dns.FakeIP && !dns.IndependentCache {
		return fmt.Errorf("dns: fakeip requires independent_cache (the panel enables it automatically)")
	}
	tags := map[string]bool{}
	serverEnabled := map[string]bool{}
	serverType := map[string]string{}
	for i := range dns.Servers {
		s := &dns.Servers[i]
		if strings.TrimSpace(s.Tag) == "" {
			return fmt.Errorf("dns server has empty tag")
		}
		if tags[s.Tag] {
			return fmt.Errorf("dns: duplicate server tag %q", s.Tag)
		}
		tags[s.Tag] = true
		serverEnabled[s.Tag] = s.Enabled
		serverType[s.Tag] = s.Type
		if !validDNSServerTypes[s.Type] {
			return fmt.Errorf("dns server %q: unknown type %q", s.Tag, s.Type)
		}
		if dns.LeakProof && plaintextDNSTypes[s.Type] {
			return fmt.Errorf("dns server %q: plaintext %s is not allowed with leak protection (use https/tls/quic)", s.Tag, s.Type)
		}
		if networkDNSTypes[s.Type] {
			if strings.TrimSpace(s.Server) == "" {
				return fmt.Errorf("dns server %q (%s): empty server address", s.Tag, s.Type)
			}
			// A hostname upstream needs a bootstrap resolver, else sing-box does a CLEARTEXT A-lookup
			// of the DoH/DoT hostname → the ISP sees which resolver you use. IP-literal upstreams
			// (the secure-default pins 1.1.1.1/9.9.9.9) need none.
			if encryptedDNSTypes[s.Type] && net.ParseIP(strings.TrimSpace(s.Server)) == nil && strings.TrimSpace(s.DomainResolver) == "" {
				return fmt.Errorf("dns server %q: hostname %q needs a bootstrap domain_resolver (or use an IP literal)", s.Tag, s.Server)
			}
			if s.ServerPort != 0 && (s.ServerPort < 1 || s.ServerPort > 65535) {
				return fmt.Errorf("dns server %q: server_port %d out of range", s.Tag, s.ServerPort)
			}
			if s.Detour != "" {
				// "block" is a route-rule ACTION (reject) in sing-box >=1.12, not an outbound: the
				// generator emits route-rule block as action=reject but a DNS detour verbatim, so a
				// block detour would be a dangling outbound reference `sing-box check` FATALs on —
				// and a "blocked" DNS server is a nonsense config anyway (disable it instead).
				// Mirror the group-member guard. isBuiltin would otherwise accept it below.
				if s.Detour == OutboundBlock {
					return fmt.Errorf("dns server %q: detour %q is a route action (reject), not an outbound — disable the server instead", s.Tag, s.Detour)
				}
				if !isResolvable(s.Detour, ids) {
					return fmt.Errorf("dns server %q: detour %q does not resolve", s.Tag, s.Detour)
				}
				if !isBuiltin(s.Detour) && !enabled[s.Detour] {
					return fmt.Errorf("dns server %q: detour %q targets a disabled endpoint", s.Tag, s.Detour)
				}
			}
		}
		if s.Type == "fakeip" {
			if strings.TrimSpace(s.Inet4Range) == "" {
				return fmt.Errorf("dns server %q: fakeip needs an inet4_range (e.g. 198.18.0.0/15)", s.Tag)
			}
			// A fakeip range MUST be a CIDR (sing-box fakeip needs a prefix), so require the '/'
			// via net.ParseCIDR — firstInvalidCIDR accepts a bare IP (fine for ip_cidr matchers,
			// wrong here), which sing-box then rejects at config load.
			if _, _, err := net.ParseCIDR(strings.TrimSpace(s.Inet4Range)); err != nil {
				return fmt.Errorf("dns server %q: fakeip inet4_range %q must be a CIDR (e.g. 198.18.0.0/15)", s.Tag, s.Inet4Range)
			}
			if strings.TrimSpace(s.Inet6Range) != "" {
				if _, _, err := net.ParseCIDR(strings.TrimSpace(s.Inet6Range)); err != nil {
					return fmt.Errorf("dns server %q: fakeip inet6_range %q must be a CIDR (e.g. fc00::/18)", s.Tag, s.Inet6Range)
				}
			}
		}
	}
	// A hostname upstream's bootstrap domain_resolver must reference a DEFINED and ENABLED DNS server
	// tag. The generator emits domain_resolver verbatim and DROPS disabled servers, so a typo'd or
	// disabled bootstrap tag becomes a dangling reference `sing-box check` FATALs on. Second pass: the
	// tags map is only complete now, since a bootstrap may be declared AFTER the server that cites it.
	// Gated to network servers + enabled citers, matching where the generator actually emits the field.
	for i := range dns.Servers {
		s := &dns.Servers[i]
		if !s.Enabled || !networkDNSTypes[s.Type] {
			continue
		}
		dr := strings.TrimSpace(s.DomainResolver)
		if dr == "" {
			continue
		}
		if !tags[dr] {
			return fmt.Errorf("dns server %q: domain_resolver %q is not a defined server tag", s.Tag, s.DomainResolver)
		}
		if !serverEnabled[dr] {
			return fmt.Errorf("dns server %q: domain_resolver %q targets a disabled server", s.Tag, s.DomainResolver)
		}
		// A bootstrap resolver must be able to resolve the hostname upstream: a fakeip server only
		// SYNTHESIZES addresses and a local server is the device stub — neither can bootstrap a real
		// A/AAAA lookup. Worse, a fakeip target is DROPPED by the generator in fast/mixed mode (no TUN),
		// leaving a dangling domain_resolver reference `sing-box check` FATALs on, taking down all
		// routing. Reject it here (mode-independent), mirroring dnsDefaultResolverTag's fakeip skip.
		if t := serverType[dr]; t == "fakeip" || t == "local" {
			return fmt.Errorf("dns server %q: domain_resolver %q targets a %s server, which cannot bootstrap a hostname (use an https/tls/quic/udp resolver)", s.Tag, s.DomainResolver, t)
		}
	}
	// client_subnet is emitted verbatim as sing-box dns.client_subnet (a netip prefix/addr); a
	// malformed value FATALs at config load. Accept an IP or a CIDR (sing-box promotes a bare IP to
	// /32 or /128), mirroring the fakeip range guard above.
	if cs := strings.TrimSpace(dns.ClientSubnet); cs != "" {
		if _, _, err := net.ParseCIDR(cs); err != nil && net.ParseIP(cs) == nil {
			return fmt.Errorf("dns: client_subnet %q must be an IP or CIDR", dns.ClientSubnet)
		}
	}
	// final + rule targets must reference a defined server tag (or "reject" for rules).
	if dns.Final != "" && !tags[dns.Final] {
		return fmt.Errorf("dns: final %q is not a defined server tag", dns.Final)
	}
	if dns.LeakProof && dns.Final != "" {
		for i := range dns.Servers {
			if dns.Servers[i].Tag == dns.Final && !isEncryptedDNSType(dns.Servers[i].Type) {
				return fmt.Errorf("dns: leak protection requires an ENCRYPTED final resolver, but %q is %q", dns.Final, dns.Servers[i].Type)
			}
		}
	}
	// The `final` must name an ENABLED server. The generator DROPS a disabled server and, with it, a
	// `final` that pointed at one (singbox.go: `if d.Final != "" && !dropped[d.Final]`), leaving the
	// DNS plane with NO default resolver and no error at all — the user's chosen default silently
	// vanishes and unmatched queries go nowhere (LOOP-029). Reject it at save instead. Checked after
	// the unknown-tag and leak-protection checks above so a more specific error still wins when both
	// apply; by here dns.Final is known to exist (the unknown-tag check returned otherwise).
	if dns.Final != "" && !serverEnabled[dns.Final] {
		return fmt.Errorf("dns: final %q targets a disabled server — enable it or choose an active default resolver", dns.Final)
	}
	for i := range dns.Rules {
		r := &dns.Rules[i]
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("dns rule has empty id")
		}
		if r.Disabled {
			continue
		}
		if r.Server != "reject" && !tags[r.Server] {
			return fmt.Errorf("dns rule %q: server %q is not a defined tag (or \"reject\")", r.ID, r.Server)
		}
		for _, rs := range r.RuleSets {
			if strings.TrimSpace(rs) == "" {
				continue
			}
			if ids[rs] != "routing list" {
				return fmt.Errorf("dns rule %q: rule_set %q is not a routing list", r.ID, rs)
			}
		}
		if dnsRuleHasNoMatcher(r) {
			return fmt.Errorf("dns rule %q: has no match condition (rule_set/domain/geosite/query_type)", r.ID)
		}
		// An ENABLED rule must route to an ENABLED server (or "reject"). A disabled target is dropped
		// by the generator along with the servers it names, so the rule's queries silently fall through
		// to `final` instead of the resolver the user aimed them at (LOOP-029). Checked last so a
		// missing matcher or an unknown rule_set is reported first when both apply; by here r.Server is
		// known to be "reject" or a defined tag.
		if r.Server != "reject" && !serverEnabled[r.Server] {
			return fmt.Errorf("dns rule %q: server %q is a disabled resolver — enable it or point the rule elsewhere", r.ID, r.Server)
		}
	}
	return nil
}

// dnsRuleHasNoMatcher reports whether a DNS rule carries no real matcher — a condition-less rule
// would match every query and shadow the rest (the same leak ruleHasNoMatcher guards against for
// routing rules). Blank entries do not count.
func dnsRuleHasNoMatcher(r *DNSRule) bool {
	return !hasNonBlank(r.RuleSets) && !hasNonBlank(r.DomainSuffix) && !hasNonBlank(r.Domain) &&
		!hasNonBlank(r.GeoSite) && !hasNonBlank(r.QueryType)
}
