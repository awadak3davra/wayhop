package generator

import (
	"regexp"
	"sort"
	"strconv"

	"wayhop/internal/model"
)

// Core-version gating.
//
// The generator targets the sing-box 1.12.x schema, and everything it emits is also accepted by
// `sing-box check` on 1.13.x and 1.14.x (CI runs the real check on each). Two fields it emits were
// deprecated in 1.14.0 with removal scheduled for 1.16.0, and sing-box treats a deprecation whose
// removal is the NEXT minor as fatal unless an ENABLE_DEPRECATED_* variable is set. So on 1.15:
//
//   - dns.independent_cache stops the core at startup ("set ENABLE_DEPRECATED_INDEPENDENT_DNS_CACHE");
//   - a remote rule-set's download_detour stops it the first time the set is fetched (not at
//     `check` time, so a passing check does not prove the config runs).
//
// Their replacements do not exist on 1.12/1.13, which reject unknown fields, so one config cannot be
// valid on both sides. Options.CoreVersion selects the 1.14+ form; empty (or unparseable) keeps the
// 1.12 form byte-for-byte, so nothing changes until the caller passes the version it detected.

// coreModernMinor is the first sing-box minor (1.x) whose schema replaces the two fields above.
const coreModernMinor = 14

// coreVersionRe finds the first x.y.z in either a bare version ("1.14.3", "v1.15.0-alpha.12") or
// the raw `sing-box version` output ("sing-box version 1.14.3\n\nEnvironment: go1.25.1 ...").
var coreVersionRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// coreMinor returns the 1.x minor of v, or -1 when v names no version or a major other than 1.
func coreMinor(v string) int {
	m := coreVersionRe.FindStringSubmatch(v)
	if m == nil || m[1] != "1" {
		return -1
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return -1
	}
	return n
}

// modernCore reports whether v is a sing-box that wants the 1.14+ schema. A pre-release counts as
// its own minor: 1.15.0-alpha.12 enforces the 1.15 deprecations.
func modernCore(v string) bool { return coreMinor(v) >= coreModernMinor }

// coreTUNStackLastMinor is the last sing-box minor that accepts a TUN inbound's `stack`. 1.15
// deprecated it - sing-tun now has its own TCP/IP stack, and the migration is to remove the option -
// with removal in 1.17, so by the next-minor rule above 1.16 refuses to start with it. WayHop keeps
// the stacks it has measured (system on OpenWrt, gvisor on KeeneticOS) wherever the option is still
// accepted, and drops it only where keeping it would stop the core; 1.15.0-alpha.13 only warns.
const coreTUNStackLastMinor = 15

// TUNStackAccepted reports whether the core named by v starts with a TUN `stack` option. An empty or
// unparseable version is taken as accepting it, like every other gate here: nothing changes until
// the caller passes the version it detected.
func TUNStackAccepted(v string) bool { return coreMinor(v) <= coreTUNStackLastMinor }

// FitTUNToCore removes `stack` from every TUN inbound of cfg when the core named by coreVersion
// would refuse it. Inbounds may be typed or decoded from JSON.
func FitTUNToCore(cfg map[string]any, coreVersion string) {
	if TUNStackAccepted(coreVersion) {
		return
	}
	switch inbounds := cfg["inbounds"].(type) {
	case []map[string]any:
		for _, in := range inbounds {
			if in["type"] == "tun" {
				delete(in, "stack")
			}
		}
	case []any:
		for _, v := range inbounds {
			if in, ok := v.(map[string]any); ok && in["type"] == "tun" {
				delete(in, "stack")
			}
		}
	}
}

// ruleSetHTTPClientPrefix tags the shared http_clients the 1.14+ form downloads rule-sets through.
// The http_clients namespace is separate from outbound tags, so the detour name is reused as is.
const ruleSetHTTPClientPrefix = "rs-dl-"

// applyModernCoreSchema rewrites a generated config into the 1.14+ form in place:
//
//   - dns.independent_cache is dropped. From 1.14 the DNS cache is always keyed per server, so the
//     flag no longer changes anything; the field exists only to be removed.
//   - each remote rule-set's download_detour becomes http_client, naming a top-level http_clients
//     entry with the same detour. `direct` maps to a client with NO detour, which dials from the
//     host: an http client whose detour is the (empty) direct outbound is refused by sing-box
//     ("detour to an empty direct outbound makes no sense"), a check the legacy field skipped.
func applyModernCoreSchema(cfg map[string]any) {
	if dns, ok := cfg["dns"].(map[string]any); ok {
		delete(dns, "independent_cache")
	}
	route, ok := cfg["route"].(map[string]any)
	if !ok {
		return
	}
	sets, _ := route["rule_set"].([]map[string]any)
	clients := map[string]map[string]any{}
	for _, s := range sets {
		d, ok := s["download_detour"].(string)
		if !ok {
			continue
		}
		delete(s, "download_detour")
		tag := ruleSetHTTPClientPrefix + d
		if _, seen := clients[tag]; !seen {
			c := map[string]any{"tag": tag}
			if d != "" && d != model.OutboundDirect {
				c["detour"] = d
			}
			clients[tag] = c
		}
		s["http_client"] = tag
	}
	if len(clients) == 0 {
		return
	}
	tags := make([]string, 0, len(clients))
	for t := range clients {
		tags = append(tags, t)
	}
	sort.Strings(tags) // deterministic output: the same profile always renders the same bytes
	list := make([]map[string]any, 0, len(tags))
	for _, t := range tags {
		list = append(list, clients[t])
	}
	cfg["http_clients"] = list
}
