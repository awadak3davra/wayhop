package model

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
)

// DisabledRefError marks the validation failures where a LIVE reference points at something that is
// switched OFF: a rule or routing list whose outbound is a disabled endpoint, a group holding a
// disabled member. They are worth telling apart from the rest because the rest describe a draft that
// is merely unfinished (a group whose members have not been added yet, a routing list with no source
// yet), which the panel fills in as the operator works, while these describe a profile that will be
// REJECTED at every Apply from now on — including applies that have nothing to do with the reference.
//
// The message is unchanged: the type carries the class, so nothing the operator reads moves.
type DisabledRefError struct {
	Kind   string // "group" | "rule" | "routing list" | "DNS server" — the object HOLDING the reference
	ID     string // its id
	Target string // what it points at
	msg    string
}

func (e *DisabledRefError) Error() string { return e.msg }

func disabledRef(kind, id, target, format string, a ...any) error {
	return &DisabledRefError{Kind: kind, ID: id, Target: target, msg: fmt.Sprintf(format, a...)}
}

// UnresolvedRefError marks the neighbouring class: a live reference naming something that is not in
// the profile AT ALL — a deleted group, a renamed endpoint, an id that never existed. Like
// DisabledRefError it blocks every Apply from now on, but the way out is different, and so is who
// can take it.
//
// It carries structure rather than only a sentence because the caller needs to know WHICH object
// holds the broken reference. Measured on the demo profile: the review said «The configuration is
// invalid — rule "st-rule-6": outbound "st-grp-0" does not resolve · Items: profile» and offered
// "Correct or disable the affected object". The panel has no rules editor — profile.rules is read in
// five places and rendered as an editable row in none — so the object named could not be reached
// from any page, and "Items: profile" pointed at the whole configuration instead of at the one rule.
//
// Kind/ID name the object to fix, Target names what it pointed at. The message is unchanged: the
// type carries the class, so nothing the operator reads moves.
type UnresolvedRefError struct {
	Kind   string // "group" | "rule" | "routing list" | "DNS server" — the object HOLDING the broken reference
	ID     string // its id, so a caller can name or act on it instead of saying "profile"
	Target string // the reference that did not resolve
	msg    string
}

func (e *UnresolvedRefError) Error() string { return e.msg }

func unresolvedRef(kind, id, target, format string, a ...any) error {
	return &UnresolvedRefError{Kind: kind, ID: id, Target: target, msg: fmt.Sprintf(format, a...)}
}

// Sane bounds for the per-tunnel link MTU. The lower bound is the IPv4 minimum
// reassembly buffer (576); the upper is a generous jumbo-frame ceiling (9200)
// that still covers WG-over-jumbo links. A value outside this range is almost
// certainly a typo and the WG engine would reject it at link-up.
const (
	minMTU = 576
	maxMTU = 9200
)

// Bounds for a routing list's CIDRSource auto-refresh cadence (RefreshHours). The floor protects the
// router flash overlay: even a churny feed can only rewrite the profile once per this many hours per
// list. 0 is always legal and means the built-in default (24h / once a day). The auto-refresh ticker
// clamps to these too, so a hand-edited profile.json can't drive refreshes faster than the floor.
const (
	MinCIDRRefreshHours = 6
	MaxCIDRRefreshHours = 720 // 30 days
)

// ValidRefreshHours reports whether a routing list's RefreshHours is acceptable for a NEW write.
// The bound only bites when the list has a CIDRSource (the flash-relevant kernel feed); a
// Source-only list's RefreshHours is just sing-box's rule_set update_interval, where any positive
// value is fine. Enforced at the CRUD boundary, NOT in Validate — see the note there (legacy data).
// ValidateDeviceGroup validates a single device group — a non-empty id and, per member, a valid MAC
// and/or IP (≥1 set). Used at the CRUD boundary (a 400 instead of a bricked Apply) AND by Validate
// (which adds the shared-namespace uniqueness check + wraps the error with the group name).
func ValidateDeviceGroup(g DeviceGroup) error {
	if strings.TrimSpace(g.ID) == "" {
		return fmt.Errorf("id is required")
	}
	for _, m := range g.Members {
		mac, ip := strings.TrimSpace(m.MAC), strings.TrimSpace(m.IP)
		if mac == "" && ip == "" {
			return fmt.Errorf("a member needs a MAC or an IP")
		}
		if mac != "" {
			// Require a 6-byte EUI-48: net.ParseMAC also accepts 8-byte EUI-64 and 20-byte InfiniBand
			// forms, but the kernel planes render `ether saddr`/`--mac-source` which only accept EUI-48,
			// so a longer address would fail the WHOLE nft/iptables apply device-wide. Reject it here.
			if hw, err := net.ParseMAC(mac); err != nil || len(hw) != 6 {
				return fmt.Errorf("invalid MAC %q (must be a 6-byte address, e.g. aa:bb:cc:dd:ee:ff)", m.MAC)
			}
		}
		if ip != "" && firstInvalidCIDR([]string{ip}) != "" {
			return fmt.Errorf("invalid IP/CIDR %q", m.IP)
		}
	}
	return nil
}

func ValidRefreshHours(rl RoutingList) bool {
	if rl.CIDRSource == "" || rl.RefreshHours == 0 {
		return rl.RefreshHours >= 0
	}
	return rl.RefreshHours >= MinCIDRRefreshHours && rl.RefreshHours <= MaxCIDRRefreshHours
}

// RuleSetURLKind is what a Source URL's file name says it is: "binary" for a .srs rule set, "source"
// for a .json one, "text" for any other extension (a plain-text .lst or .txt list, which sing-box
// cannot load as a rule set), and "" when the last path segment has no extension at all (a mirror or
// a query-string feed), which says nothing. The ?query and #fragment are not part of the name.
func RuleSetURLKind(source string) string {
	path := source
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if i := strings.Index(path, "://"); i >= 0 {
		path = path[i+3:]
		if j := strings.IndexByte(path, '/'); j >= 0 {
			path = path[j:]
		} else {
			path = ""
		}
	}
	name := path[strings.LastIndexByte(path, '/')+1:]
	dot := strings.LastIndexByte(name, '.')
	switch {
	case dot < 0:
		return ""
	case strings.EqualFold(name[dot:], ".srs"):
		return "binary"
	case strings.EqualFold(name[dot:], ".json"):
		return "source"
	}
	return "text"
}

// CarriedRuleSetFormat reports whether a rule-set format carried over from a list's old URL still
// holds for its new one (QA-150). A URL whose file name says nothing (a mirror with no extension, a
// query-string feed) keeps it: dropped, the generator would skip a list it has no way to read. A URL
// that names the same format keeps it too. One that names the other format, or a plain-text list,
// does not: kept, sing-box would read the file as what it is not, and a rule set that fails to load
// stops the whole core. The panel's form holds the same rule (page-routing.js rlKeepsFormat).
func CarriedRuleSetFormat(format, newSource string) bool {
	kind := RuleSetURLKind(newSource)
	return kind == "" || kind == format
}

// Validate checks structural integrity: unique IDs, resolvable members and
// rule targets, and sane ports. It returns the first problem found.
func (p *Profile) Validate() error {
	ids := map[string]string{}   // id -> kind, for duplicate + resolution checks
	enabled := map[string]bool{} // target id -> usable (endpoints honor Enabled; groups are always usable)
	// Reserve the builtin outbound tags. The generator ALWAYS emits {type:direct,tag:direct} PLUS one
	// outbound per enabled endpoint/group tagged by its raw id, so an id equal to a builtin tag would
	// produce a DUPLICATE outbound tag that FATALs `sing-box check` and fails every Apply (and for a
	// restored backup, persists an unappliable profile). Pre-seeding makes the duplicate-id checks
	// below reject it with a precise message instead.
	ids[OutboundDirect] = "builtin outbound"
	ids[OutboundBlock] = "builtin outbound"

	for _, e := range p.Endpoints {
		if e.ID == "" {
			return fmt.Errorf("endpoint %q has empty id", e.Name)
		}
		// The id becomes a filesystem path component for native plugins — the rendered <id>.conf /
		// <id>.yaml the (root) plugin manager writes and later deletes. A crafted id like
		// "../../etc/foo" would otherwise escape the plugin dir. Reject a path separator or a bare
		// traversal token; a legitimate id is a slug and never contains these.
		if strings.ContainsAny(e.ID, `/\`) || e.ID == "." || e.ID == ".." || strings.ContainsRune(e.ID, 0) {
			return fmt.Errorf("endpoint %q: invalid id %q (no path separators or '.'/'..')", e.Name, e.ID)
		}
		// isBuiltin folds case (Direct/DIRECT/Block…), but the reserved-tag seeding + duplicate check
		// below are exact-case, so a case-DIFFERING builtin id ("Direct") would slip past the dup
		// check yet still fold to the lowercase builtin at reference resolution (canonicalOutbound
		// lowercases it) — a rule targeting "Direct" would silently route to WAN while the endpoint
		// emits as an orphan outbound. Reject any id that case-insensitively matches a builtin tag.
		if isBuiltin(e.ID) {
			return fmt.Errorf("duplicate id %q (reserved builtin outbound tag, case-insensitive)", e.ID)
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
		if msg := QUICTuningProblem(&e); msg != "" {
			return fmt.Errorf("endpoint %q: %s", e.ID, msg)
		}
		// Only WayHop's own AmneziaWG engine can move a connection onto amneziawg-go. Refused rather
		// than ignored elsewhere: a flag the planner would never read is a setting that looks in force.
		if e.AWGUserspace && (e.Engine != EngineAmneziaWG || !e.OwnsResource()) {
			return fmt.Errorf("endpoint %q: awg_userspace applies only to an AmneziaWG connection WayHop runs itself", e.ID)
		}
		if e.Engine == EngineExternal {
			// Routes via an existing OS interface, not a server — it needs only the
			// interface name; server/port/protocol do not apply.
			ifn, _ := e.Params["interface"].(string)
			if strings.TrimSpace(ifn) == "" {
				return fmt.Errorf("endpoint %q: external engine needs params.interface", e.ID)
			}
			// This name is interpolated VERBATIM into the ROOT kernel plane — nft `oifname "x"` and
			// `ip route ... dev x` — so validate the RAW value (no trimming, so what passes is exactly
			// what renders) with the injection-safe iface whitelist, and reject wildcards (a concrete
			// egress dev, not a match). A trailing space/newline is thus rejected, not silently kept.
			if strings.Contains(ifn, "*") || !validSourceIface(ifn) {
				return fmt.Errorf("endpoint %q: invalid params.interface %q (plain interface name only)", e.ID, ifn)
			}
			continue
		}
		if e.Engine == EngineByeDPI {
			// A local proxy the daemon starts on loopback: no server, port or protocol of its own,
			// only the strategy, which must parse as ciadpi flags.
			if _, err := ByeDPIStrategy(e.Params); err != nil {
				return fmt.Errorf("endpoint %q (byedpi): %v", e.ID, err)
			}
			continue
		}
		// A Hysteria2 connection made through a realm has no server of its own: the rendezvous hands
		// out the server's addresses at connect time, and the generator emits neither field.
		if !e.UsesRealm() {
			if e.Server == "" {
				return fmt.Errorf("endpoint %q: empty server", e.ID)
			}
			if e.Port < 1 || e.Port > 65535 {
				return fmt.Errorf("endpoint %q: port %d out of range", e.ID, e.Port)
			}
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
			if p := endpointLoadProblem(&e); p != "" {
				return fmt.Errorf("endpoint %q (%s): %s", e.ID, e.Protocol, p)
			}
		}
	}

	for _, g := range p.Groups {
		if g.ID == "" {
			return fmt.Errorf("group %q has empty id", g.Name)
		}
		if isBuiltin(g.ID) { // case-insensitive builtin-tag collision — see the endpoint loop
			return fmt.Errorf("duplicate id %q (reserved builtin outbound tag, case-insensitive)", g.ID)
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
				return unresolvedRef("group", g.ID, m, "group %q: member %q does not resolve", g.ID, m)
			}
			if m == g.ID {
				return fmt.Errorf("group %q: cannot contain itself", g.ID)
			}
			if !enabled[m] {
				return disabledRef("group", g.ID, m, "group %q: member %q is disabled", g.ID, m)
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
					// Require a 6-byte EUI-48 (same guard as the device-group MAC check above):
					// net.ParseMAC also accepts 8-byte EUI-64 / 20-byte InfiniBand forms, but the kernel
					// planes render `ether saddr`/`--mac-source`, which only accept EUI-48, so a longer
					// address would fail the WHOLE nft/iptables apply device-wide, not just this rule.
					if hw, err := net.ParseMAC(s); err != nil || len(hw) != 6 {
						return fmt.Errorf("rule %q: invalid source_mac %q (must be a 6-byte address, e.g. aa:bb:cc:dd:ee:ff)", r.ID, m)
					}
				}
			}
			for _, ifn := range r.SourceIface {
				if s := strings.TrimSpace(ifn); s != "" && !validSourceIface(s) {
					return fmt.Errorf("rule %q: invalid source_iface %q (max 15 chars; letters/digits/.-_@ and an optional trailing *)", r.ID, ifn)
				}
			}
		}
		// Only a routing list can be handed to an NDM access policy: a rule's matchers (ports,
		// geosite, sources) have no kernel-plane form behind the policy's mark yet.
		if _, ok := NDMPolicyName(r.Outbound); ok {
			return fmt.Errorf("rule %q: outbound %q is a KeeneticOS access policy, which only a routing list can use", r.ID, r.Outbound)
		}
		if !isResolvable(r.Outbound, ids) {
			return unresolvedRef("rule", r.ID, r.Outbound, "rule %q: outbound %q does not resolve", r.ID, r.Outbound)
		}
		if !isBuiltin(r.Outbound) && !enabled[r.Outbound] {
			return disabledRef("rule", r.ID, r.Outbound, "rule %q: outbound %q targets a disabled endpoint", r.ID, r.Outbound)
		}
	}
	if defaults > 1 {
		return fmt.Errorf("more than one default rule (%d)", defaults)
	}

	// Device groups (named MAC/IP sets that a RoutingList can scope to). Unique id in the shared
	// namespace; each member needs a valid MAC and/or IP. Registered before the RoutingLists loop so a
	// list's scope_groups can be checked against them.
	devGroups := make(map[string]bool, len(p.DeviceGroups))
	for _, g := range p.DeviceGroups {
		if err := ValidateDeviceGroup(g); err != nil {
			return fmt.Errorf("device group %q: %w", g.Name, err)
		}
		if prev, ok := ids[g.ID]; ok {
			return fmt.Errorf("duplicate id %q (already used by %s)", g.ID, prev)
		}
		ids[g.ID] = "device group"
		devGroups[g.ID] = true
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
		if rl.Source == "" && len(rl.Manual) == 0 && rl.CIDRSource == "" && len(rl.CIDRCache) == 0 &&
			rl.DomainSource == "" && len(rl.DomainCache) == 0 {
			return fmt.Errorf("routing list %q: needs a source URL, a CIDR source, a domain source, or manual entries", rl.ID)
		}
		if err := ValidateManualEntries(rl); err != nil {
			return err
		}
		if rl.CIDRSource != "" && !validCIDRSource(rl.CIDRSource) {
			return fmt.Errorf("routing list %q: cidr_source %q must be https://… , http://… , or asn:N,N", rl.ID, rl.CIDRSource)
		}
		// A domain feed is fetched over HTTP(S) only: `asn:` names prefixes, which is the other
		// field's job, and there is nothing else this plane knows how to read.
		if rl.DomainSource != "" && !strings.HasPrefix(rl.DomainSource, "https://") &&
			!strings.HasPrefix(rl.DomainSource, "http://") {
			return fmt.Errorf("routing list %q: domain_source %q must be https://… or http://…", rl.ID, rl.DomainSource)
		}
		// RefreshHours bounds are deliberately NOT enforced here: Validate gates Apply/generate, so
		// hard-failing would brick Apply for a pre-existing profile whose refresh_hours predates the
		// bounds (they were legal before 0.4.1). The CRUD boundary (handleUpsertRoutingList) rejects
		// new out-of-range writes with a 400 via ValidRefreshHours, and the auto-refresh ticker
		// clamps whatever is persisted (cidrIntervalHours) — bad legacy data degrades, never bricks.
		// An NDM access policy is not an object of this profile, so there is nothing here to resolve
		// it against: only its shape is checked. Whether the router has it is the host-aware review's
		// question, asked again at every Apply because NDM owns the name.
		if name, ok := NDMPolicyName(rl.Outbound); ok {
			if !ValidNDMPolicyName(name) {
				return fmt.Errorf("routing list %q: outbound %q: an access policy name is letters, digits, '_' and '-' (e.g. %sPolicy1)", rl.ID, rl.Outbound, NDMPolicyPrefix)
			}
		} else {
			if !isResolvable(rl.Outbound, ids) {
				return unresolvedRef("routing list", rl.ID, rl.Outbound, "routing list %q: outbound %q does not resolve", rl.ID, rl.Outbound)
			}
			if !isBuiltin(rl.Outbound) && !enabled[rl.Outbound] {
				return disabledRef("routing list", rl.ID, rl.Outbound, "routing list %q: outbound %q targets a disabled endpoint", rl.ID, rl.Outbound)
			}
		}
		// Device scoping: mode enum + referenced groups must exist. "only"/"except" need a group.
		switch rl.ScopeMode {
		case "", "all", "only", "except":
		default:
			return fmt.Errorf("routing list %q: invalid scope_mode %q (all|only|except)", rl.ID, rl.ScopeMode)
		}
		for _, gid := range rl.ScopeGroups {
			if !devGroups[gid] {
				return fmt.Errorf("routing list %q: scope references unknown device group %q", rl.ID, gid)
			}
		}
		switch rl.TLSFragment {
		case "", TLSFragmentRecord, TLSFragmentHandshake:
		default:
			return fmt.Errorf("routing list %q: invalid tls_fragment %q (record|handshake)", rl.ID, rl.TLSFragment)
		}
		if (rl.ScopeMode == "only" || rl.ScopeMode == "except") && len(rl.ScopeGroups) == 0 {
			return fmt.Errorf("routing list %q: scope_mode %q needs at least one device group", rl.ID, rl.ScopeMode)
		}
		if rl.DownloadVia != "" {
			// The download is the core's own connection, and the core reaches a policy only through a
			// routed list's outbound; a detour into one is not offered.
			if _, ok := NDMPolicyName(rl.DownloadVia); ok {
				return fmt.Errorf("routing list %q: download_via %q is a KeeneticOS access policy, which can only carry the list's traffic", rl.ID, rl.DownloadVia)
			}
			if !isResolvable(rl.DownloadVia, ids) {
				return unresolvedRef("routing list", rl.ID, rl.DownloadVia, "routing list %q: download_via %q does not resolve", rl.ID, rl.DownloadVia)
			}
			// A disabled endpoint isn't emitted as an outbound, so a download_detour
			// pointing at it would reference a missing tag and sing-box would reject
			// the config — same guard as Outbound above.
			if !isBuiltin(rl.DownloadVia) && !enabled[rl.DownloadVia] {
				return disabledRef("routing list", rl.ID, rl.DownloadVia, "routing list %q: download_via %q targets a disabled endpoint", rl.ID, rl.DownloadVia)
			}
		}
	}

	// DNS plane (the "DNS" section) — greenfield, so a strict check can't brick a legacy profile.
	// Detours resolve against the endpoint/group namespace built above; rule_sets against RoutingLists.
	if p.DNS != nil {
		if err := validateDNS(p.DNS, ids, enabled, p.Endpoints); err != nil {
			return err
		}
	}
	return nil
}

// ValidateManualEntries refuses a manual entry with a line break or another control character inside
// it. On KeeneticOS the entries are written into dnsmasq's configuration
// (/opt/etc/dnsmasq.d/wayhop-policy.conf), so a line break inside one is a configuration line nobody
// reviewed: an extra upstream resolver, or a file dnsmasq refuses, leaving the LAN without DNS.
// Surrounding whitespace is not refused, because every consumer trims it and an entry pasted with a
// trailing "\r" has always worked; refusing it now would block Apply on a profile that runs.
func ValidateManualEntries(rl RoutingList) error {
	for _, entry := range rl.Manual {
		if strings.IndexFunc(strings.TrimSpace(entry), unicode.IsControl) >= 0 {
			return fmt.Errorf("routing list %q: manual entry %q contains a line break or another control character", rl.ID, entry)
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

// EndpointParamProblem names what would stop an enabled endpoint from loading (a missing identity
// param, or a value the core rejects) in Validate's words, or "" when nothing does. The bulk import
// stores such an endpoint disabled, since enabled it would fail Validate and with it every Apply.
// It also refuses a multiplex setting the core cannot take (muxProblem), which Validate does not:
// the generator leaves that out, so it costs one connection its multiplex rather than every Apply.
func EndpointParamProblem(e *Endpoint) string {
	if p := endpointLoadProblem(e); p != "" {
		return p
	}
	return muxProblem(e)
}

// endpointLoadProblem is EndpointParamProblem without the settings the generator drops on its own:
// what Validate refuses, because the core would fail the whole shared config over it.
func endpointLoadProblem(e *Endpoint) string {
	if e.Engine == EngineByeDPI {
		// The upsert, bulk import and subscription refresh ask this, not Validate: without it a
		// strategy Validate refuses was stored enabled and failed the next Apply instead (#89).
		if _, err := ByeDPIStrategy(e.Params); err != nil {
			return err.Error()
		}
		return ""
	}
	if missing := missingProtoParam(e); missing != "" {
		return "missing required " + missing
	}
	if p := invalidProtoParam(e); p != "" {
		return p
	}
	// TLS settings the protocol params do not cover: an ECH config sing-box would load and then fail
	// every handshake with, or an ECH pairing it refuses at load; a certificate pin that is not a
	// SHA-256 hash.
	if p := echProblem(e); p != "" {
		return p
	}
	return pinProblem(e)
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
	case ProtoSnell:
		// sing-box requires the pre-shared key, and Snell v6 one of 12 to 255 bytes.
		if k := get("psk"); k == "" {
			return "psk"
		} else if snellVersion(e.Params) == 6 && (len(k) < 12 || len(k) > 255) {
			return "psk (Snell v6 needs 12 to 255 bytes)"
		}
		return ""
	case ProtoSSH:
		// Not a load error, unlike the rest: an exit with no credential at all can never log in.
		if sshMissingAuth(e) {
			return "password or private_key"
		}
		return ""
	case ProtoOpenVPN:
		// sing-box refuses a TLS-mode client without a trust anchor, and a static-key one without
		// its key and both tunnel addresses.
		if get("mode") == "static_key" {
			return firstEmpty("static_key", "address", "peer_address")
		}
		return firstEmpty("ca")
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
	case ProtoHysteria2:
		// A malformed realm address leaves the generator no rendezvous or realm name to give the core,
		// and this connection no server; refused here so it is said at save, not at Apply.
		if _, err := Hy2RealmOf(e); err != nil {
			return err.Error()
		}
	case ProtoSSH:
		// A host key or private key sing-box cannot parse fails the shared config at load.
		return sshParamProblem(e)
	case ProtoShadowsocks:
		// An unsupported method bricks the shared config (sing-box "unknown method").
		// missingProtoParam already rejected an empty method, so a non-empty one here
		// must be in the set sing-box actually implements.
		if m := get("method"); m != "" && !knownSSMethods[m] {
			return fmt.Sprintf("unsupported method %q (sing-box rejects it, failing the whole config)", m)
		}
		// SS-2022 (2022-blake3-*) needs a base64 PSK of an exact byte length:
		// aes-128 -> 16, aes-256 / chacha20 -> 32. sing-box rejects a wrong one.
		// A multi-user server (sing-box `users`, the panels built on it) hands each client
		// "iPSK:uPSK": the server's identity key, then the user's. sing-box takes that form for
		// the AES ciphers (each part checked like a single key) and refuses it for chacha20
		// ("no EIH"), so only the AES ciphers may carry more than one key.
		if m := get("method"); strings.HasPrefix(m, "2022-blake3-") {
			want := 32
			if strings.Contains(m, "aes-128") {
				want = 16
			}
			if pw := get("password"); pw != "" {
				keys := strings.Split(pw, ":")
				if len(keys) > 1 && !strings.Contains(m, "-aes-") {
					return fmt.Sprintf("%s takes a single key (identity keys iPSK:uPSK need an AES 2022 method)", m)
				}
				for _, k := range keys {
					if b64Len(k) != want {
						return fmt.Sprintf("%s needs a %d-byte base64 key", m, want)
					}
				}
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
	s = strings.TrimSuffix(s, "*")
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

// snellVersion reads a Snell endpoint's version as the importers and the API store it: an int, a
// float64 after a JSON round-trip, or a string. 0 when absent or unreadable.
func snellVersion(p map[string]any) int {
	switch v := p["version"].(type) {
	case int:
		return v
	case float64:
		return int(v)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	}
	return 0
}
