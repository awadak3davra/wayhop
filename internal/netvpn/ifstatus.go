package netvpn

import (
	"strconv"
	"strings"
)

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
	// PublicKey and ListenPort are the interface's own, from its `wireguard:` sub-block ("" / 0
	// for other kinds). Never a peer's: peers are nested a level deeper and come after.
	PublicKey  string `json:"public_key,omitempty"`
	ListenPort int    `json:"listen_port,omitempty"`
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
//
// Nesting is read from the layout. KeeneticOS right-aligns an interface's own keys on one colon
// column and a sub-block's keys further right, so a line whose colon sits right of the
// `interface-name:` colon belongs to a sub-block: a switch port's own `interface-name: 1` and
// `link:`, or a peer's empty `description:`. Read flat, those overwrote the interface's fields (a
// port could even start a bogus interface). The one sub-block read is `wireguard:`, for the
// interface's public key and listen port. A block whose `interface-name:` line is not indented
// has no layout to read and is taken flat, as before.
func ParseNDMInterfaceStatus(out string) []NDMInterfaceStatus {
	var res []NDMInterfaceStatus
	cur := -1
	top := -1      // colon column of the current interface's own keys; -1 = flat block
	inWG := false  // inside the current interface's `wireguard:` sub-block
	header := true // a new interface block may start at the next interface-name line
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "Interface, name =") {
			header, inWG = true, false
			continue
		}
		key, val, ok := splitNDMKV(trimmed)
		if !ok {
			continue
		}
		col := strings.Index(line, ":")
		nested := cur >= 0 && top >= 0 && col > top
		if key == "interface-name" && (header || !nested) {
			res = append(res, NDMInterfaceStatus{Name: val})
			cur = len(res) - 1
			top, inWG, header = -1, false, false
			if line[0] == ' ' || line[0] == '\t' {
				top = col
			}
			continue
		}
		if cur < 0 {
			continue
		}
		if nested {
			if !inWG {
				continue
			}
			switch key {
			case "public-key":
				if res[cur].PublicKey == "" {
					res[cur].PublicKey = val
				}
			case "listen-port":
				if res[cur].ListenPort == 0 {
					res[cur].ListenPort, _ = strconv.Atoi(val)
				}
			}
			continue
		}
		inWG = key == "wireguard"
		switch key {
		case "type":
			res[cur].Type = val
		case "description":
			res[cur].Description = val
		case "link":
			res[cur].Link = val
		case "connected":
			res[cur].Connected = val
		case "state":
			res[cur].State = val
		}
	}
	for i := range res {
		res[i].Up = InterfaceStatusUp(res[i].Link, res[i].Connected, res[i].State)
	}
	return res
}
