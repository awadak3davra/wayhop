package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"wayhop/internal/cidrfeed"
	"wayhop/internal/importer"
	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// routingimport.go previews routing lists that something else on the router already keeps -
// KeeneticOS's own `object-group fqdn` groups, or a pasted HydraRoute Neo domain.conf / ip.list - as
// lists the Routing page can add. Both answers are read-only: nothing here writes the profile. The
// panel posts the suggestion the operator picks, with the exit they choose, through POST /api/routing
// like a list typed by hand.

// routingImportMaxBody bounds a pasted HydraRoute file: room for some forty thousand rule lines,
// which is a hand-kept list several times over, and far below the 16 MiB any POST may send.
const routingImportMaxBody = 1 << 20

// Where an import came from.
const (
	routingImportKeenetic   = "keenetic"
	routingImportHydraRoute = "hydraroute"
)

// routingImportSkip is one entry not carried, with why: importer.HydraSkip* reasons, which the
// Keenetic parser shares for the one it has ("invalid").
type routingImportSkip struct {
	Entry  string `json:"entry"`
	Reason string `json:"reason"`
	Line   int    `json:"line,omitempty"`
}

// routingImportList is a ready POST /api/routing body short of what only the operator can say: the
// id, the exit and whether it is enabled.
type routingImportList struct {
	Name   string   `json:"name"`
	Manual []string `json:"manual"`
}

type routingImportGroup struct {
	// Name is the NDM object-group ("domain-list7") or the HydraRoute target.
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Route is what the source itself routes the group by: the interface of NDM's `dns-proxy route`
	// line, or the policy or interface after HydraRoute's "/". Context for choosing an exit; WayHop
	// does not route by it.
	Route    string              `json:"route,omitempty"`
	Domains  []string            `json:"domains"`
	CIDRs    []string            `json:"cidrs"`
	Excludes []string            `json:"excludes,omitempty"`
	Skipped  []routingImportSkip `json:"skipped"`
	// Suggested is null when the group carries nothing a list could hold; Refused then says why.
	Suggested *routingImportList `json:"suggested"`
	Refused   string             `json:"refused,omitempty"`
	// SkippedTotal counts every entry not carried; Skipped lists the first routingImportMaxSkips.
	SkippedTotal int `json:"skipped_total"`
}

type routingImportAnswer struct {
	Source string `json:"source"`
	// Format is the HydraRoute file the paste was read as: "domain.conf" or "ip.list".
	Format  string               `json:"format,omitempty"`
	Demo    bool                 `json:"demo,omitempty"`
	Groups  []routingImportGroup `json:"groups"`
	Skipped []routingImportSkip  `json:"skipped"` // lines that belong to no group
	// SkippedTotal counts every such line; Skipped lists the first routingImportMaxSkips.
	SkippedTotal int `json:"skipped_total"`
}

// Reasons this file adds to the parsers' own (importer.HydraSkip*), for prefixes no routing list
// should be OFFERED. A router's list or a pasted ip.list can carry them - HydraRoute's own ip.list
// example has 10.0.0.0/8 and a single LAN address - and one such line, once the operator picks an exit,
// turns the list into a full tunnel or sends the LAN into it.
const (
	// routingImportSkipTooBroad: the default route, or a prefix covering a large share of the
	// internet (two /1 halves are the classic full tunnel).
	routingImportSkipTooBroad = "too_broad"
	// routingImportSkipNotRoutable: loopback, link-local, multicast, unspecified.
	routingImportSkipNotRoutable = "not_routable"
	// routingImportSkipPrivate: RFC 1918, ULA and CGNAT space - the LAN or the provider's own side.
	routingImportSkipPrivate = "private"
)

// routingImportMaxSkips keeps an answer proportionate to what it reports: measured in review, a
// 1 MiB paste of "a," became 524,272 skips and a 22 MB response built in the router's RAM.
const routingImportMaxSkips = 200

var routingImportCGNAT = netip.MustParsePrefix("100.64.0.0/10")

// importPrefixReason is why a prefix is not offered, or "" when it may be.
func importPrefixReason(cidr string) string {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return importer.HydraSkipInvalid
	}
	// A v4-mapped prefix is judged as the IPv4 prefix the kernel plane files it as: ::ffff:0.0.0.0/96
	// passed below as an IPv6 /96 and was routed as 0.0.0.0/0 (QA-111).
	p = cidrfeed.Unmap4In6(p.Masked())
	a := p.Addr()
	// The order matters: a short prefix inside a special range (fd00::/8, 224.0.0.0/4) is named by that
	// range, and only then is a prefix judged by its length; 0.0.0.0/1 is not "unspecified".
	switch {
	case p.Bits() == 0:
		return routingImportSkipTooBroad
	case a.IsPrivate(), routingImportCGNAT.Contains(a):
		return routingImportSkipPrivate
	case a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsMulticast():
		return routingImportSkipNotRoutable
	case cidrfeed.TooBroad(p): // the length a fetched feed is held to as well
		return routingImportSkipTooBroad
	case a.IsUnspecified():
		return routingImportSkipNotRoutable
	}
	return ""
}

// screenRoutingImport moves out of g's prefixes the ones importPrefixReason refuses, then bounds the
// skipped entries it reports. Run before the suggestion is built, so the list offered never holds them.
func screenRoutingImport(g *routingImportGroup) {
	kept := g.CIDRs[:0]
	for _, c := range g.CIDRs {
		if reason := importPrefixReason(c); reason != "" {
			g.Skipped = append(g.Skipped, routingImportSkip{Entry: c, Reason: reason})
			continue
		}
		kept = append(kept, c)
	}
	g.CIDRs = kept
	g.SkippedTotal = len(g.Skipped)
	g.Skipped = capImportSkips(g.Skipped)
}

func capImportSkips(s []routingImportSkip) []routingImportSkip {
	if len(s) > routingImportMaxSkips {
		return s[:routingImportMaxSkips]
	}
	return s
}

// handleRoutingImportKeenetic answers GET /api/routing/import/keenetic: the router's NDM FQDN
// object-groups, each with the list it would become. The running-config it reads also holds tunnel
// private keys; only the parsed groups leave this handler.
func (s *Server) handleRoutingImportKeenetic(w http.ResponseWriter, r *http.Request) {
	// Demo mode must not run host commands, and the panel's import dialog has to be buildable and
	// testable without a router, so the demo parses a fixed running-config instead.
	if s.demoMode() {
		writeJSONNoStore(w, http.StatusOK, keeneticImportAnswer(keenetic.ParseFQDNGroups(demoKeeneticFQDNConfig), true))
		return
	}
	if s.detectedPlatform() != platform.Keenetic {
		writeErr(w, http.StatusUnprocessableEntity, "object-groups are read from KeeneticOS's running-config, and this router is not running KeeneticOS")
		return
	}
	read := s.keeneticConfigReader
	if read == nil {
		read = readKeeneticRunningConfig
	}
	runningConfig, err := read(r.Context())
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "cannot read the router's running-config")
		return
	}
	writeJSONNoStore(w, http.StatusOK, keeneticImportAnswer(keenetic.ParseFQDNGroups(runningConfig), false))
}

func keeneticImportAnswer(groups []keenetic.FQDNGroup, demo bool) routingImportAnswer {
	ans := routingImportAnswer{Source: routingImportKeenetic, Demo: demo,
		Groups: make([]routingImportGroup, 0, len(groups)), Skipped: []routingImportSkip{}}
	for _, g := range groups {
		out := routingImportGroup{Name: g.Name, Description: g.Description, Route: g.Route,
			Domains: nonNilStrings(g.Domains), CIDRs: nonNilStrings(g.CIDRs), Excludes: g.Excludes,
			Skipped: make([]routingImportSkip, 0, len(g.Skipped))}
		for _, e := range g.Skipped {
			out.Skipped = append(out.Skipped, routingImportSkip{Entry: e, Reason: importer.HydraSkipInvalid})
		}
		name := g.Description
		if name == "" {
			name = g.Name
		}
		screenRoutingImport(&out)
		out.Suggested, out.Refused = suggestRoutingList(name, out.Domains, out.CIDRs)
		ans.Groups = append(ans.Groups, out)
	}
	return ans
}

// handleRoutingImportHydraRoute answers POST /api/routing/import/hydraroute {"text": "..."}: the
// pasted domain.conf or ip.list, one group per target.
func (s *Server) handleRoutingImportHydraRoute(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		writeErr(w, http.StatusBadRequest, `want {"text": "<domain.conf or ip.list>"}`)
		return
	}
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, routingImportMaxBody)).Decode(&body); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, "the pasted file is larger than 1 MiB")
			return
		}
		writeErr(w, http.StatusBadRequest, `want {"text": "<domain.conf or ip.list>"}`)
		return
	}
	if strings.TrimSpace(body.Text) == "" {
		writeErr(w, http.StatusBadRequest, "nothing to import: paste HydraRoute's domain.conf or ip.list")
		return
	}
	parsed := importer.ParseHydraRoute(body.Text)
	ans := routingImportAnswer{Source: routingImportHydraRoute, Format: parsed.Format,
		Groups: make([]routingImportGroup, 0, len(parsed.Targets)), Skipped: hydraImportSkips(parsed.Skipped),
		SkippedTotal: len(parsed.Skipped)}
	ans.Skipped = capImportSkips(ans.Skipped)
	for _, t := range parsed.Targets {
		description := strings.Join(t.Descriptions, ", ")
		out := routingImportGroup{Name: t.Target, Description: description, Route: t.Target,
			Domains: nonNilStrings(t.Domains), CIDRs: nonNilStrings(t.CIDRs), Skipped: hydraImportSkips(t.Skipped)}
		name := description
		if name == "" {
			name = t.Target
		}
		screenRoutingImport(&out)
		out.Suggested, out.Refused = suggestRoutingList(name, out.Domains, out.CIDRs)
		ans.Groups = append(ans.Groups, out)
	}
	writeJSON(w, http.StatusOK, ans)
}

func hydraImportSkips(in []importer.HydraSkip) []routingImportSkip {
	out := make([]routingImportSkip, 0, len(in))
	for _, s := range in {
		out = append(out, routingImportSkip{Entry: s.Entry, Reason: s.Reason, Line: s.Line})
	}
	return out
}

// suggestRoutingList builds the list a group would become and puts it to model.Validate - the check
// every Apply makes - in a profile of its own, so the panel is never offered a list that would make
// the profile unappliable. POST /api/routing itself accepts an unfinished list (it refuses only a
// reference to a disabled exit), which is why the question is asked here and not left to the write.
// The exit is a stand-in: the operator has not chosen one yet, and the list's content is the subject.
func suggestRoutingList(name string, domains, cidrs []string) (*routingImportList, string) {
	const probeID = "import-preview"
	// The bound a domain feed has (cidrfeed.MaxDomains), for the same reason: every name becomes a
	// resolver directive held in memory. Review measured a 1 MiB paste giving a 105,409-name list.
	if len(domains) > cidrfeed.MaxDomains {
		return nil, fmt.Sprintf("%d names is more than the %d a list may hold: the router's resolver keeps every one in memory; split the list", len(domains), cidrfeed.MaxDomains)
	}
	manual := make([]string, 0, len(domains)+len(cidrs))
	manual = append(append(manual, domains...), cidrs...)
	rl := model.RoutingList{ID: probeID, Name: name, Manual: manual, Outbound: model.OutboundDirect, Enabled: true}
	probe := model.Profile{RoutingLists: []model.RoutingList{rl}}
	if err := probe.Validate(); err != nil {
		// The probe's id is not the operator's; the reason after it is.
		return nil, strings.TrimPrefix(err.Error(), fmt.Sprintf("routing list %q: ", probeID))
	}
	return &routingImportList{Name: name, Manual: manual}, ""
}

// nonNilStrings keeps an empty list an empty JSON array: the panel iterates these, and null is not
// iterable.
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// demoKeeneticFQDNConfig is what the demo answers from: the shapes a live router prints (an escaped
// UTF-8 description, names and prefixes mixed, an exclude, an unusable include, a dns-proxy route),
// on documentation addresses.
const demoKeeneticFQDNConfig = `object-group fqdn domain-list0
    description Telegram
    include telegram.org
    include t.me
    include 192.0.2.0/24
    include 198.51.100.0/23
!
object-group fqdn domain-list1
    description "\xd0\x92\xd0\xb8\xd0\xb4\xd0\xb5\xd0\xbe"
    include youtube.com
    include googlevideo.com
    exclude www.youtube.com
!
object-group fqdn domain-list2
    include 203.0.113.0/24
    include not-a-name
!
dns-proxy
    route object-group domain-list0 Wireguard0 auto
!
`
