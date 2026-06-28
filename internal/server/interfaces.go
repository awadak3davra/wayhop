package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"

	"wakeroute/internal/model"
)

// ifaceInfo is one network interface as reported to the UI for the source_iface picker
// (source-based routing rules).
type ifaceInfo struct {
	Name  string   `json:"name"`
	Up    bool     `json:"up"`
	Addrs []string `json:"addrs,omitempty"`
}

// rawIface decouples filterInterfaces from net.Interface (whose Addrs() is an OS call), so the
// filtering/sorting is unit-testable with synthetic data.
type rawIface struct {
	name  string
	flags net.Flags
	addrs []string
}

// filterInterfaces drops loopback interfaces (never a traffic source for routing) and returns the
// rest sorted by name, each flagged up/down with its addresses — the payload for /api/interfaces.
func filterInterfaces(raw []rawIface) []ifaceInfo {
	out := make([]ifaceInfo, 0, len(raw))
	for _, r := range raw {
		if r.flags&net.FlagLoopback != 0 {
			continue
		}
		out = append(out, ifaceInfo{
			Name:  r.name,
			Up:    r.flags&net.FlagUp != 0,
			Addrs: r.addrs,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// handleInterfaces lists the host's network interfaces (loopback excluded) so the UI can offer a
// source_iface dropdown for source-based routing rules. Read-only host probe; captures no
// secrets. GET /api/interfaces.
func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := net.Interfaces()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list interfaces: "+err.Error())
		return
	}
	raw := make([]rawIface, 0, len(ifaces))
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		as := make([]string, 0, len(addrs))
		for _, a := range addrs {
			as = append(as, a.String())
		}
		raw = append(raw, rawIface{name: i.Name, flags: i.Flags, addrs: as})
	}
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": filterInterfaces(raw)})
}

// ifaceMatches reports whether a rule's source_iface pattern matches a real interface name. A
// trailing "*" is a prefix wildcard (e.g. "wg*" → any wg interface), mirroring nft's iifname
// wildcard and validSourceIface's accepted form; otherwise an exact name match.
func ifaceMatches(pattern string, names []string) bool {
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		for _, n := range names {
			if strings.HasPrefix(n, prefix) {
				return true
			}
		}
		return false
	}
	for _, n := range names {
		if n == pattern {
			return true
		}
	}
	return false
}

// checkSourceIfaces returns a finding per enabled rule whose source_iface references an interface
// not present on the host — a source rule with a wrong/typo'd interface silently never matches, so
// surfacing it is the source-routing analog of "why isn't my rule firing". Pure (host interface
// names passed in) for unit-testing.
func checkSourceIfaces(rules []model.Rule, names []string) []string {
	var bad []string
	for i := range rules {
		r := &rules[i]
		if r.Disabled {
			continue
		}
		for _, ifc := range r.SourceIface {
			ifc = strings.TrimSpace(ifc)
			if ifc == "" {
				continue
			}
			if !ifaceMatches(ifc, names) {
				bad = append(bad, fmt.Sprintf("rule %q: source interface %q not found", r.ID, ifc))
			}
		}
	}
	return bad
}

// sourceRuleCheck is a Diagnostics-battery probe: it flags source-routing rules whose
// source_iface doesn't exist on the router (the rule would never match). Read-only.
func (s *Server) sourceRuleCheck(_ context.Context) healthRow {
	row := healthRow{ID: "source-iface", Label: "Source-routing interfaces exist"}
	p := s.store.Profile()
	any := false
	for i := range p.Rules {
		if !p.Rules[i].Disabled && len(p.Rules[i].SourceIface) > 0 {
			any = true
			break
		}
	}
	if !any {
		row.Status, row.Summary = "pass", "no source-interface rules to check"
		return row
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		row.Status, row.Summary = "warn", "couldn't list interfaces"
		row.Detail = err.Error()
		return row
	}
	names := make([]string, 0, len(ifaces))
	for _, i := range ifaces {
		names = append(names, i.Name)
	}
	bad := checkSourceIfaces(p.Rules, names)
	if len(bad) == 0 {
		row.Status, row.Summary = "pass", "every source-rule interface exists"
		return row
	}
	row.Status = "warn"
	row.Summary = fmt.Sprintf("%d source rule(s) reference a missing interface", len(bad))
	row.Detail = strings.Join(bad, "; ")
	row.Fix = "fix the source interface name (or create/enable that interface); a source rule whose interface doesn't exist never matches any traffic"
	return row
}
