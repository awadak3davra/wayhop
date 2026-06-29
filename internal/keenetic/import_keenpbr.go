package keenetic

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"velinx/internal/model"
)

// The subset of a keen-pbr config.json we convert.
type kpConfig struct {
	Lists map[string]kpList `json:"lists"`
	Route struct {
		Rules []kpRule `json:"rules"`
	} `json:"route"`
}

type kpList struct {
	URL     string   `json:"url,omitempty"`
	File    string   `json:"file,omitempty"`
	Domains []string `json:"domains,omitempty"`
	IPCIDRs []string `json:"ip_cidrs,omitempty"`
}

type kpRule struct {
	Enabled  bool     `json:"enabled"`
	Comment  string   `json:"comment,omitempty"`
	List     []string `json:"list"`
	Outbound string   `json:"outbound"`
}

// isCIDRFeedURL reports whether a list URL is a plain IP-CIDR feed (→ kernel plane) rather
// than a domain rule-set (→ sing-box). Heuristic over the known feed shapes (lord-alfred
// ipranges ipv4_merged, 1andrevich discord_ips). Domain lists (v2fly, itdoginfo `.lst`,
// re-filter domain feeds) do NOT match. This split is the red-team's #1 routing-correctness
// item: telegram/twitter/facebook/discord are IP feeds and MUST match by destination IP
// (MTProto, voice/UDP, IP-literal) — routing them as domains would leak them via WAN.
func isCIDRFeedURL(u string) bool {
	l := strings.ToLower(u)
	return strings.Contains(l, "ipv4") || strings.Contains(l, "ipranges") ||
		strings.Contains(l, "discord_ips") || strings.Contains(l, "_ips.")
}

// ImportKeenPBR converts a keen-pbr config.json into Velinx RoutingLists, preserving the
// IP-feed-vs-domain plane split:
//   - a URL CIDR feed → CIDRSource (kernel plane);
//   - a URL domain rule-set → Source (sing-box plane);
//   - inline ip_cidrs → Manual (kernel); inline domains → Manual (sing-box);
//   - a list with BOTH domains and ip_cidrs is split into two RoutingLists (`<id>` domains,
//     `<id>_ip` CIDRs) so each lands in the right plane.
//
// Each list's Outbound comes from the keen-pbr rule referencing it, mapped through outboundMap
// (keen-pbr outbound tag → Velinx group/endpoint id). `files` supplies the lines of any
// `file:` list (read by the caller — the converter stays pure / does no I/O). A list not
// referenced by any rule is emitted disabled. Generic: works on any keen-pbr config.
func ImportKeenPBR(configJSON []byte, files map[string][]string, outboundMap map[string]string) ([]model.RoutingList, error) {
	var cfg kpConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, fmt.Errorf("parse keen-pbr config: %w", err)
	}

	type asgn struct {
		outbound string
		enabled  bool
	}
	assign := map[string]asgn{}
	for _, r := range cfg.Route.Rules {
		ob := r.Outbound
		if m, ok := outboundMap[ob]; ok {
			ob = m
		}
		for _, id := range r.List {
			assign[id] = asgn{outbound: ob, enabled: r.Enabled}
		}
	}

	var out []model.RoutingList
	add := func(id, src, cidrSrc string, manual []string, a asgn) {
		out = append(out, model.RoutingList{
			ID: id, Name: id, Source: src, CIDRSource: cidrSrc, Manual: manual,
			Outbound: a.outbound, Enabled: a.enabled,
		})
	}

	ids := make([]string, 0, len(cfg.Lists))
	for id := range cfg.Lists {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic output

	for _, id := range ids {
		l := cfg.Lists[id]
		a := assign[id] // zero value = disabled, empty outbound, when unreferenced

		switch {
		case l.URL != "" && isCIDRFeedURL(l.URL):
			add(id, "", l.URL, nil, a) // kernel CIDR feed
		case l.URL != "":
			add(id, l.URL, "", nil, a) // sing-box domain rule_set
		case l.File != "":
			add(id, "", "", files[l.File], a) // inline lines from a file
		default:
			if len(l.Domains) > 0 {
				add(id, "", "", l.Domains, a) // sing-box (domains)
			}
			if len(l.IPCIDRs) > 0 {
				ipID := id
				if len(l.Domains) > 0 {
					ipID = id + "_ip" // split: keep the domain list as `id`, CIDRs as `id_ip`
				}
				add(ipID, "", "", l.IPCIDRs, a) // kernel (IP-CIDRs)
			}
		}
	}
	return out, nil
}
