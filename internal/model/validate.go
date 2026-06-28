package model

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"
)

// Sane bounds for the per-tunnel link MTU. The lower bound is the IPv4 minimum
// reassembly buffer (576); the upper is a generous jumbo-frame ceiling (9200)
// that still covers WG-over-jumbo links. A value outside this range is almost
// certainly a typo and the WG engine would reject it at link-up.
const (
	minMTU = 576
	maxMTU = 9200
)

// Validate checks structural integrity: unique IDs, resolvable members and
// rule targets, and sane ports. It returns the first problem found.
func (p *Profile) Validate() error {
	ids := map[string]string{}   // id -> kind, for duplicate + resolution checks
	enabled := map[string]bool{} // target id -> usable (endpoints honor Enabled; groups are always usable)

	for _, e := range p.Endpoints {
		if e.ID == "" {
			return fmt.Errorf("endpoint %q has empty id", e.Name)
		}
		if prev, ok := ids[e.ID]; ok {
			return fmt.Errorf("duplicate id %q (already used by %s)", e.ID, prev)
		}
		ids[e.ID] = "endpoint"
		enabled[e.ID] = e.Enabled
		// Per-tunnel link tunables are protocol-agnostic and opt-in: a 0/unset
		// value means "engine default" and is skipped. When SET they must be in a
		// sane range, otherwise the generator would emit a value the WG engine
		// rejects at link-up and take routing down. Checked before the external
		// short-circuit so an external endpoint with a stray bad value is caught too.
		if e.MTU != 0 && (e.MTU < minMTU || e.MTU > maxMTU) {
			return fmt.Errorf("endpoint %q: mtu %d out of range (%d-%d)", e.ID, e.MTU, minMTU, maxMTU)
		}
		if e.PersistentKeepalive != 0 && (e.PersistentKeepalive < 1 || e.PersistentKeepalive > 65535) {
			return fmt.Errorf("endpoint %q: persistent_keepalive %d out of range (1-65535)", e.ID, e.PersistentKeepalive)
		}
		if e.Engine == EngineExternal {
			// Routes via an existing OS interface, not a server — it needs only the
			// interface name; server/port/protocol do not apply.
			if s, _ := e.Params["interface"].(string); strings.TrimSpace(s) == "" {
				return fmt.Errorf("endpoint %q: external engine needs params.interface", e.ID)
			}
			continue
		}
		if e.Server == "" {
			return fmt.Errorf("endpoint %q: empty server", e.ID)
		}
		if e.Port < 1 || e.Port > 65535 {
			return fmt.Errorf("endpoint %q: port %d out of range", e.ID, e.Port)
		}
		if e.Protocol == "" {
			return fmt.Errorf("endpoint %q: empty protocol", e.ID)
		}
		// An ENABLED endpoint must carry the identity fields its protocol needs.
		// sing-box rejects an outbound/endpoint missing them ("missing private
		// key" / "invalid uuid" / "missing password"); since the whole profile
		// generates into ONE singbox.json loaded all-or-nothing, a single such
		// endpoint would fail the entire config on apply and take down all routing.
		// Catching it here (Generate calls Validate first) fails the apply safely,
		// leaving the last-good live config in place. Disabled endpoints aren't
		// emitted by the generator, so they're exempt (a half-edited draft is fine).
		if e.Enabled {
			if missing := missingProtoParam(&e); missing != "" {
				return fmt.Errorf("endpoint %q (%s): missing required %s", e.ID, e.Protocol, missing)
			}
			if bad := invalidProtoParam(&e); bad != "" {
				return fmt.Errorf("endpoint %q (%s): %s", e.ID, e.Protocol, bad)
			}
		}
	}

	for _, g := range p.Groups {
		if g.ID == "" {
			return fmt.Errorf("group %q has empty id", g.Name)
		}
		if prev, ok := ids[g.ID]; ok {
			return fmt.Errorf("duplicate id %q (already used by %s)", g.ID, prev)
		}
		ids[g.ID] = "group"
		enabled[g.ID] = true
		if len(g.Members) == 0 {
			return fmt.Errorf("group %q: no members", g.ID)
		}
	}

	// Members must resolve to a known, ENABLED endpoint or a group. A disabled
	// member isn't emitted by the generator, so the group would reference a
	// non-existent outbound tag and sing-box would reject the config.
	for _, g := range p.Groups {
		for _, m := range g.Members {
			// `direct` (WAN) is a valid, always-reachable sing-box outbound, so it may be a
			// failover/WAN-fallback member (e.g. an ordered urltest [vpn…, direct] that only
			// reaches WAN when every VPN tier is dead). `block` is a route ACTION (reject) in
			// sing-box ≥1.12, NOT an outbound — it cannot be a urltest/selector member.
			if m == OutboundDirect {
				continue
			}
			if m == OutboundBlock {
				return fmt.Errorf("group %q: member %q is a route action (reject), not an outbound", g.ID, m)
			}
			if _, ok := ids[m]; !ok {
				return fmt.Errorf("group %q: member %q does not resolve", g.ID, m)
			}
			if m == g.ID {
				return fmt.Errorf("group %q: cannot contain itself", g.ID)
			}
			if !enabled[m] {
				return fmt.Errorf("group %q: member %q is disabled", g.ID, m)
			}
		}
	}

	// Reject nested-group CYCLES (g1→g2→g1). The self-check above only catches the trivial
	// single-node case; an indirect cycle would emit mutually-referencing sing-box outbounds
	// that FATAL the config at load — failing the apply, or persisting an unappliable profile
	// when a crafted backup bundle is restored (Validate is the only gate there). DFS with a
	// visiting/done colouring over the group→group edges; a back-edge to a node on the stack
	// is a cycle.
	groupAdj := map[string][]string{}
	for _, g := range p.Groups {
		for _, m := range g.Members {
			if ids[m] == "group" { // only group-typed members can form a cycle
				groupAdj[g.ID] = append(groupAdj[g.ID], m)
			}
		}
	}
	const (
		colVisiting = 1
		colDone     = 2
	)
	color := map[string]int{}
	var dfs func(id string) error
	dfs = func(id string) error {
		color[id] = colVisiting
		for _, m := range groupAdj[id] {
			switch color[m] {
			case colVisiting:
				return fmt.Errorf("group %q is part of a cycle (via %q)", id, m)
			case colDone:
				continue
			default:
				if err := dfs(m); err != nil {
					return err
				}
			}
		}
		color[id] = colDone
		return nil
	}
	for _, g := range p.Groups {
		if color[g.ID] == 0 {
			if err := dfs(g.ID); err != nil {
				return err
			}
		}
	}

	// Rule targets must resolve to an enabled id or a builtin, and a non-default
	// rule must carry at least one matcher (a condition-less rule is invalid in
	// sing-box).
	defaults := 0
	for _, r := range p.Rules {
		// Rule ids share the endpoint/group/routing-list namespace. An empty or duplicate
		// id silently corrupts rule management (UpsertRule edits the FIRST match, DeleteRule
		// removes ALL matches → a same-id sibling is lost), and a hand-edited restored bundle
		// reaches the store via Replace without a per-item guard — so validate it here.
		if r.ID == "" {
			return fmt.Errorf("rule has empty id")
		}
		if prev, ok := ids[r.ID]; ok {
			return fmt.Errorf("duplicate id %q (already used by %s)", r.ID, prev)
		}
		ids[r.ID] = "rule"
		// A disabled rule is an inert no-op: skip its matcher / outbound / default-count
		// validation (it is never emitted on any plane), mirroring how a disabled endpoint
		// is exempt from its identity checks. The id-namespace checks above stay
		// unconditional — UpsertRule/DeleteRule key off the id even for a disabled rule.
		if r.Disabled {
			continue
		}
		if r.Default {
			defaults++
		} else {
			if ruleHasNoMatcher(r) {
				return fmt.Errorf("rule %q: has no match condition (domain/geosite/geoip/ip/port)", r.ID)
			}
			// A malformed ip_cidr entry FATALs sing-box at config-load
			// ("netip.ParsePrefix: no '/'"), bricking the whole shared singbox.json
			// on apply. sing-box accepts a bare IP or a CIDR; reject anything else
			// here so the apply fails safely with a precise error instead of bricking.
			// (Blank entries are handled by ruleHasNoMatcher / the generator.)
			if bad := firstInvalidCIDR(r.IPCIDR); bad != "" {
				return fmt.Errorf("rule %q: invalid ip_cidr %q (must be an IP or CIDR, e.g. 10.0.0.0/8)", r.ID, bad)
			}
			// sing-box route ports are uint16: a value <0 or >65535 FATALs the whole
			// config at decode ("cannot unmarshal number 70000 into uint16"), bricking
			// the shared singbox.json on apply. Range-check here so the apply fails
			// safely. (0 is valid — sing-box accepts it.)
			for _, port := range r.Port {
				if port < 0 || port > 65535 {
					return fmt.Errorf("rule %q: port %d out of range (must be 0-65535)", r.ID, port)
				}
			}
			// Source matchers (v1): same fail-safe checks as the destination matchers, so a
			// bad value fails the apply precisely instead of bricking the shared config.
			if bad := firstInvalidCIDR(r.SourceIPCIDR); bad != "" {
				return fmt.Errorf("rule %q: invalid source_ip_cidr %q (must be an IP or CIDR)", r.ID, bad)
			}
			for _, port := range r.SourcePort {
				if port < 0 || port > 65535 {
					return fmt.Errorf("rule %q: source_port %d out of range (must be 0-65535)", r.ID, port)
				}
			}
			for _, m := range r.SourceMAC {
				if s := strings.TrimSpace(m); s != "" {
					if _, err := net.ParseMAC(s); err != nil {
						return fmt.Errorf("rule %q: invalid source_mac %q (must be a MAC, e.g. aa:bb:cc:dd:ee:ff)", r.ID, m)
					}
				}
			}
			for _, ifn := range r.SourceIface {
				if s := strings.TrimSpace(ifn); s != "" && !validSourceIface(s) {
					return fmt.Errorf("rule %q: invalid source_iface %q (max 15 chars; letters/digits/.-_@ and an optional trailing *)", r.ID, ifn)
				}
			}
		}
		if !isResolvable(r.Outbound, ids) {
			return fmt.Errorf("rule %q: outbound %q does not resolve", r.ID, r.Outbound)
		}
		if !isBuiltin(r.Outbound) && !enabled[r.Outbound] {
			return fmt.Errorf("rule %q: outbound %q targets a disabled endpoint", r.ID, r.Outbound)
		}
	}
	if defaults > 1 {
		return fmt.Errorf("more than one default rule (%d)", defaults)
	}

	// Routing lists (the "Routing" page): unique id, some content, and an
	// outbound + download interface that resolve to an enabled target/builtin.
	for _, rl := range p.RoutingLists {
		if rl.ID == "" {
			return fmt.Errorf("routing list %q has empty id", rl.Name)
		}
		if prev, ok := ids[rl.ID]; ok {
			return fmt.Errorf("duplicate id %q (already used by %s)", rl.ID, prev)
		}
		ids[rl.ID] = "routing list"
		if rl.Source == "" && len(rl.Manual) == 0 && rl.CIDRSource == "" && len(rl.CIDRCache) == 0 {
			return fmt.Errorf("routing list %q: needs a source URL, a CIDR source, or manual entries", rl.ID)
		}
		if rl.CIDRSource != "" && !validCIDRSource(rl.CIDRSource) {
			return fmt.Errorf("routing list %q: cidr_source %q must be https://… , http://… , or asn:N,N", rl.ID, rl.CIDRSource)
		}
		if !isResolvable(rl.Outbound, ids) {
			return fmt.Errorf("routing list %q: outbound %q does not resolve", rl.ID, rl.Outbound)
		}
		if !isBuiltin(rl.Outbound) && !enabled[rl.Outbound] {
			return fmt.Errorf("routing list %q: outbound %q targets a disabled endpoint", rl.ID, rl.Outbound)
		}
		if rl.DownloadVia != "" {
			if !isResolvable(rl.DownloadVia, ids) {
				return fmt.Errorf("routing list %q: download_via %q does not resolve", rl.ID, rl.DownloadVia)
			}
			// A disabled endpoint isn't emitted as an outbound, so a download_detour
			// pointing at it would reference a missing tag and sing-box would reject
			// the config — same guard as Outbound above.
			if !isBuiltin(rl.DownloadVia) && !enabled[rl.DownloadVia] {
				return fmt.Errorf("routing list %q: download_via %q targets a disabled endpoint", rl.ID, rl.DownloadVia)
			}
		}
	}
	return nil
}

// validCIDRSource reports whether a RoutingList.CIDRSource has a supported scheme: an
// http(s) feed URL, or "asn:N[,N…]" (digit ASNs, optional AS prefix). It does NOT fetch —
// just a shape check so the API/UI rejects typos early (cidrfeed.Fetch is the real parser).
func validCIDRSource(s string) bool {
	if strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") {
		return true
	}
	if !strings.HasPrefix(s, "asn:") {
		return false
	}
	list := strings.TrimPrefix(s, "asn:")
	if strings.TrimSpace(list) == "" {
		return false
	}
	for _, a := range strings.Split(list, ",") {
		a = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(a)), "AS")
		if a == "" {
			return false
		}
		for _, r := range a {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// missingProtoParam returns the name of the first mandatory identity param the
// endpoint's protocol requires but is empty, or "" if all are present.
//
// Scope is deliberately the fields whose absence makes sing-box HARD-REJECT the
// generated config (verified against sing-box 1.12 on the live device): TUIC uuid
// ("invalid uuid: length 0"), Shadowsocks method/password ("unknown method" /
// "missing password"), and WireGuard/AmneziaWG private_key ("missing private
// key"). Those are the cases that fail the whole shared singbox.json and take
// down all routing. sing-box TOLERATES an empty vless/vmess uuid or trojan/
// hysteria2 password at load (the endpoint just won't authenticate — an isolated
// failure, not a config-bricking one), so they are intentionally not required
// here. socks/http (and external, handled earlier) carry no mandatory params.
func missingProtoParam(e *Endpoint) string {
	get := func(k string) string { s, _ := e.Params[k].(string); return strings.TrimSpace(s) }
	firstEmpty := func(keys ...string) string {
		for _, k := range keys {
			if get(k) == "" {
				return k
			}
		}
		return ""
	}
	switch e.Protocol {
	case ProtoTUIC:
		return firstEmpty("uuid")
	case ProtoShadowsocks:
		return firstEmpty("method", "password")
	case ProtoWireGuard, ProtoAmneziaWG:
		// peer_public_key is mandatory. An empty one is especially dangerous for
		// native WireGuard: it PASSES `sing-box check` (the peer public_key
		// base64-decodes "" to nil with no error at config-load) but then FATALs at
		// runtime when the endpoint starts (wireguard IpcSet rejects a 0-byte key),
		// bringing ALL routing down AFTER the pre-apply check already passed. Catch
		// it here, before Generate emits it, so the apply fails safely.
		return firstEmpty("private_key", "peer_public_key")
	}
	return ""
}

// knownSSMethods is the EXACT set of Shadowsocks methods sing-box 1.12.x accepts
// (enumerated against the live `sing-box check`): AEAD, AEAD-2022, the legacy
// stream ciphers it still ships, and "none". A method outside this set makes
// sing-box fail the whole shared singbox.json with "unknown method" — so a real
// old-server link using e.g. salsa20 / chacha20 (bare) / rc4 / camellia-*-cfb
// would take ALL routing down on apply. The method is mandatory and can't be
// degraded (no sane default for an arbitrary server), so it is rejected at
// Validate, which fails the apply safely and leaves the last-good config live.
// Erring narrow here only rejects a dead endpoint (sing-box would reject it too);
// it never lets a bricking value through.
var knownSSMethods = map[string]bool{
	"aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true, "2022-blake3-chacha20-poly1305": true,
	"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true,
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"rc4-md5": true, "chacha20-ietf": true, "xchacha20": true, "none": true,
}

// invalidProtoParam returns a message when a PRESENT mandatory param has a value
// sing-box hard-rejects (a different failure mode than missingProtoParam's empty
// fields, but the same all-or-nothing config-bricking consequence): a malformed
// TUIC uuid ("invalid uuid: incorrect UUID length"), an unsupported Shadowsocks
// method ("unknown method"), or a Shadowsocks-2022 PSK of the wrong length ("bad
// key length, required N"). None can be degraded — there is no sane default — so
// rejecting at Validate fails the apply safely instead of bricking the whole config.
func invalidProtoParam(e *Endpoint) string {
	get := func(k string) string { s, _ := e.Params[k].(string); return strings.TrimSpace(s) }
	switch e.Protocol {
	case ProtoTUIC:
		// TUIC authenticates with a uuid + password; sing-box parses the uuid
		// strictly (a non-canonical one fails the whole config load). vless/vmess
		// tolerate a bad uuid, so this guard is TUIC-only.
		if u := get("uuid"); u != "" && !isUUIDish(u) {
			return fmt.Sprintf("invalid uuid %q (want 8-4-4-4-12 hex)", u)
		}
	case ProtoShadowsocks:
		// An unsupported method bricks the shared config (sing-box "unknown method").
		// missingProtoParam already rejected an empty method, so a non-empty one here
		// must be in the set sing-box actually implements.
		if m := get("method"); m != "" && !knownSSMethods[m] {
			return fmt.Sprintf("unsupported method %q (sing-box rejects it, failing the whole config)", m)
		}
		// SS-2022 (2022-blake3-*) needs a base64 PSK of an exact byte length:
		// aes-128 -> 16, aes-256 / chacha20 -> 32. sing-box rejects a wrong one.
		if m := get("method"); strings.HasPrefix(m, "2022-blake3-") {
			want := 32
			if strings.Contains(m, "aes-128") {
				want = 16
			}
			if pw := get("password"); pw != "" && b64Len(pw) != want {
				return fmt.Sprintf("%s needs a %d-byte base64 key", m, want)
			}
		}
	}
	return ""
}

// isUUIDish reports whether s looks like a canonical 8-4-4-4-12 hex UUID.
func isUUIDish(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// b64Len returns the decoded byte length of a base64 string (std or raw-std,
// padded or not), or -1 if it does not decode.
func b64Len(s string) int {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return len(b)
		}
	}
	return -1
}

func isBuiltin(target string) bool {
	switch strings.ToLower(target) {
	case OutboundDirect, OutboundBlock:
		return true
	}
	return false
}

func isResolvable(target string, ids map[string]string) bool {
	if isBuiltin(target) {
		return true
	}
	_, ok := ids[target]
	return ok
}

func ruleHasNoMatcher(r Rule) bool {
	return !hasNonBlank(r.DomainSuffix) && !hasNonBlank(r.Domain) && !hasNonBlank(r.GeoSite) &&
		!hasNonBlank(r.GeoIP) && !hasNonBlank(r.IPCIDR) && len(r.Port) == 0 &&
		!hasNonBlank(r.SourceIPCIDR) && !hasNonBlank(r.SourceMAC) &&
		!hasNonBlank(r.SourceIface) && len(r.SourcePort) == 0
}

// HasSourceMatcher reports whether the rule carries any source matcher
// (source_ip_cidr / source_mac / source_iface / source_port). Blank string entries
// do not count (they impose no constraint). Shared so the kernel-PBR compiler and the
// sing-box generator agree on which rules are source-scoped.
func (r *Rule) HasSourceMatcher() bool {
	return hasNonBlank(r.SourceIPCIDR) || hasNonBlank(r.SourceMAC) ||
		hasNonBlank(r.SourceIface) || len(r.SourcePort) > 0
}

// hasNonBlank reports whether ss has at least one non-whitespace entry. A matcher
// slice of only blank strings (e.g. geosite:[""]) is NOT a real matcher: the
// generator trims blanks away, so such a rule would emit a CONDITION-LESS route
// rule that matches ALL traffic and shadows every later rule plus the
// block-default — a routing leak. Counting only non-blank entries lets
// ruleHasNoMatcher reject an all-blank rule at Validate, failing the apply safely
// instead of silently routing everything to that rule's outbound.
func hasNonBlank(ss []string) bool {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return true
		}
	}
	return false
}

// firstInvalidCIDR returns the first non-blank entry that sing-box would reject
// as an ip_cidr matcher — i.e. one that is neither a CIDR (net.ParseCIDR) nor a
// bare IP (net.ParseIP; sing-box accepts a bare address and treats it as /32 or
// /128). Returns "" when every entry is valid. Blank entries are skipped (they
// are handled by ruleHasNoMatcher and dropped by the generator's matcher build).
func firstInvalidCIDR(cidrs []string) string {
	for _, c := range cidrs {
		s := strings.TrimSpace(c)
		if s == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(s); err == nil {
			continue
		}
		if net.ParseIP(s) != nil {
			continue
		}
		return c
	}
	return ""
}

// validSourceIface reports whether s is a safe ingress-interface name for a source rule's
// kernel plane: 1..15 chars (IFNAMSIZ-1, counting an optional trailing "*" wildcard) made of
// [A-Za-z0-9._@-] (plus that trailing "*"). A whitelist keeps it both nft-safe (emitted
// quoted as `iifname "x"`) and shell-safe (the Keenetic iptables path interpolates `-i x`),
// so the name can never carry whitespace or an injection metacharacter. A bare "*" is
// rejected — it is match-anything, not a real source constraint.
func validSourceIface(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	if strings.HasSuffix(s, "*") {
		s = s[:len(s)-1]
	}
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '-' || c == '_' || c == '@') {
			return false
		}
	}
	return true
}
