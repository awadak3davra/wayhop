package keenetic

import "fmt"

// This file adds the SINGLE-interface managed toggle: the reversible up/down primitive that
// lets the panel enable/disable one native Keenetic tunnel without touching the hand-written
// S89hy_failover stack or the routing plane. It renders commands only — the caller (a
// platform-gated handler) resolves the NDM name via ResolveNDMName, enforces the
// failover-interface deny-set, and submits the batch over RCIClient.ParseBatch.

// SaveCommand persists the running config to startup so a toggle survives a reboot. It is
// emitted ONLY when a caller explicitly opts in: the managed toggle runs UNSAVED by default,
// so a reboot reverts a bad flip (the same safety property SafeApply relies on).
func SaveCommand() string { return "system configuration save" }

// validNDMName reports whether s is a safe NDM interface name to interpolate into a command:
// non-empty and limited to the characters KeeneticOS uses for interface names (letters,
// digits, and . _ - /). This rejects whitespace, quotes, and command separators so a crafted
// endpoint can't inject extra NDM commands through the toggle.
func validNDMName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-', r == '/':
		default:
			return false
		}
	}
	return true
}

// ToggleCommands renders the NDM command batch that brings an EXISTING native interface
// administratively up or down WITHOUT redefining or deleting it — the reversible pair for the
// managed toggle. It uses the same proven in-block form as WireguardCommands (select the
// interface with `interface <name>`, then the admin verb), which ParseBatch applies as one
// unit — the NDM editing context is preserved across the batch. It NEVER emits `no interface`
// (that DELETES the definition, and the family tunnels' keys are not in our model) or any
// config/key line, so it can only flip admin state.
//
// PURE — no device I/O. The caller resolves <name> via ResolveNDMName and is responsible for
// the platform gate + the failover-interface deny-set before sending the batch over RCI.
func ToggleCommands(ndmName string, up bool) ([]string, error) {
	if !validNDMName(ndmName) {
		return nil, fmt.Errorf("keenetic: invalid NDM interface name %q", ndmName)
	}
	verb := "down"
	if up {
		verb = "up"
	}
	return []string{"interface " + ndmName, verb}, nil
}
