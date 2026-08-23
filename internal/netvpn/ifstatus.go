package netvpn

import "strings"

// NDMInterfaceStatus is the admin/link state of ONE interface as reported by
// `ndmc -c "show interface"` (or its RCI /rci/show/interface mirror). parseNDMInterfaces
// keeps only the identity fields for tunnel DISCOVERY and deliberately discards the state
// triple; this captures link/connected/state so a caller can report an interface's REAL
// up/down — the source of truth for the native managed-toggle, independent of any WayHop
// config flag (model.Endpoint.Enabled).
type NDMInterfaceStatus struct {
	Name        string `json:"ndm_name"`              // NDM interface-name, e.g. "Wireguard5"
	Type        string `json:"type,omitempty"`        // NDM type, e.g. "Wireguard"
	Description string `json:"description,omitempty"` // user label, e.g. "ND_NL"
	Link        string `json:"link,omitempty"`        // "up" | "down" (physical/link)
	Connected   string `json:"connected,omitempty"`   // "yes" | "no"
	State       string `json:"state,omitempty"`       // "up" | "down" (admin state; absent on some kinds)
	Up          bool   `json:"up"`                    // derived verdict (InterfaceStatusUp)
}

// InterfaceStatusUp derives a single REAL up/down verdict from the NDM state triple.
// KeeneticOS reports an explicit `state:` (admin state) for interfaces it can bring up/down —
// that is authoritative when present. When it is absent, fall back to the link+connected pair
// (physically up AND connected). Kept as a standalone pure func so the RCI-JSON reader can
// reuse the EXACT same verdict as the ndmc-text path (no divergence between the two sources).
func InterfaceStatusUp(link, connected, state string) bool {
	if state != "" {
		return strings.EqualFold(state, "up")
	}
	return strings.EqualFold(link, "up") && strings.EqualFold(connected, "yes")
}

// ParseNDMInterfaceStatus parses `ndmc -c "show interface"` into a per-interface status list,
// ALL interface kinds included (callers filter by Name/Type). Pure (no I/O), reusing the same
// splitNDMKV tokenizer parseNDMInterfaces trusts, so it stays in lockstep with the proven line
// format. Order follows the input; the Up verdict is computed per row via InterfaceStatusUp.
func ParseNDMInterfaceStatus(out string) []NDMInterfaceStatus {
	var res []NDMInterfaceStatus
	cur := -1
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		key, val, ok := splitNDMKV(trimmed)
		if !ok {
			continue
		}
		switch key {
		case "interface-name":
			res = append(res, NDMInterfaceStatus{Name: val})
			cur = len(res) - 1
		case "type":
			if cur >= 0 {
				res[cur].Type = val
			}
		case "description":
			if cur >= 0 {
				res[cur].Description = val
			}
		case "link":
			if cur >= 0 {
				res[cur].Link = val
			}
		case "connected":
			if cur >= 0 {
				res[cur].Connected = val
			}
		case "state":
			if cur >= 0 {
				res[cur].State = val
			}
		}
	}
	for i := range res {
		res[i].Up = InterfaceStatusUp(res[i].Link, res[i].Connected, res[i].State)
	}
	return res
}
