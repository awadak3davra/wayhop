package netvpn

import (
	"fmt"
	"strings"
)

// openwrt_plan.go assembles the pieces into the one thing the operator asked to see before anything
// is written: the exact commands, and what the router must look like for those commands to be safe.
//
// The shape follows the DNS write-back that already exists here — a plan is data, applying it is a
// separate, gated step — with one addition that the DNS path does not have and this one needs. A
// tunnel is edited from two sides: WayHop, and the operator in LuCI. So the plan carries the state
// it was BUILT against, and the write path re-reads and compares immediately before touching
// anything. If the two disagree, somebody changed the tunnel in between and applying the plan would
// discard their edit without a word.
//
// That is why Preconditions is a field rather than a doc comment. A rule written down is a rule
// somebody has to remember; a rule in the data is one the code can enforce.

// Plan is a proposed change to one AmneziaWG tunnel, ready to show and not yet applied.
type Plan struct {
	Iface string // the interface this plan is about

	// Commands is the full uci sequence, in order, with nothing that mutates the device: no commit,
	// no reload. Safe to print, safe to show, and impossible to apply by accident.
	Commands []string

	// Commit is the mutating tail, deliberately separate so a preview cannot apply itself.
	Commit []string

	// Expected is what the tunnel looked like when this plan was built — empty Name when it did not
	// exist yet. The write path compares the device against this and refuses on any difference.
	Expected AWGInterface

	// Intended is what the tunnel should look like afterwards; the post-write check compares the
	// device against this one.
	Intended AWGInterface

	// Zone is the firewall zone the interface will be attached to, and ZoneRef the section that held
	// it when the plan was built. Both are recorded because the reference is an index and the name is
	// the only stable handle — see openwrt_firewall.go.
	Zone, ZoneRef string

	// Warnings are things worth saying out loud that do not stop the plan.
	Warnings []string

	// Proto is the protocol this plan actually writes; RequestedProto is what the caller asked for.
	// They differ only on a fallback, and Fallback says so without the caller having to compare.
	//
	// Intended.Proto is set to Proto, NOT to RequestedProto, and that is not a detail: the post-write
	// check is DiffInterface(Intended, device). Leaving Intended at the requested value would make a
	// fallback plan write amneziawg, read back amneziawg, compare against wireguard, find a
	// difference and REVERT — every time, forever, on the only path the fallback exists for.
	Proto, RequestedProto Proto
	Fallback              bool

	// Orphans are peer sections of a protocol this interface no longer speaks, deleted by this plan.
	// Named from the parse, never derived, because the operator's own router carries an ANONYMOUS one.
	Orphans []string
}

// BuildPlan is retained for source compatibility, but intentionally fails closed because it has no
// router capability observation. Production and tests must call BuildPlanFor with a freshly probed,
// non-nil RouterProtos set.
//
// uciNetwork and uciFirewall are the raw outputs of `uci show network` and `uci show firewall` taken
// at the same moment. Passing them in rather than shelling out keeps this pure and testable, and
// makes the snapshot an explicit input — which is the whole point, since the plan is only valid
// against that snapshot.
//
// zoneName may be empty, in which case the firewall is left alone; the interface will exist but no
// zone policy will cover it, and that is said in Warnings rather than fixed by guessing a zone.
func BuildPlan(intended AWGInterface, zoneName, uciNetwork, uciFirewall string) (Plan, error) {
	return BuildPlanFor(intended, nil, zoneName, uciNetwork, uciFirewall)
}

// BuildPlanFor is BuildPlan with the router's netifd handler set in hand.
//
// protos must be a freshly observed, non-nil handler set. A nil set means the probe failed and is
// refused before anything is rendered. A non-nil set is authoritative: a protocol whose handler is
// absent is refused, or resolved to one the router does carry, BEFORE anything is rendered.
//
// Order matters and is the fix for a contradiction the review caught: resolution comes FIRST and the
// gate then applies to the RESOLVED protocol. Gating on the requested one would refuse the operator's
// WireGuard endpoint on a router that can carry it perfectly well as AmneziaWG, which is the whole
// case this exists for.
func BuildPlanFor(intended AWGInterface, protos RouterProtos, zoneName, uciNetwork, uciFirewall string) (Plan, error) {
	// The name is the one field that reaches the router UNQUOTED. Every VALUE this package renders
	// goes through q() — single-quoted with an escaped quote — but a section name is part of the uci
	// path itself ("uci set network.<name>.proto=..."), and those commands are handed to `sh -c`.
	// So a name carrying a quote, a space or a semicolon would not be a bad name, it would be a
	// second command.
	//
	// Nothing reaching here today is attacker-shaped: a created tunnel is named from its endpoint id
	// and an adopted one from the router's own uci. That is an argument about callers, and it has to
	// be re-made every time a caller is added. Checking the shape once, here, makes it an argument
	// about this function instead. Same alphabet as netdiag.ValidIface, which guards the interface
	// name passed to ping -I for exactly the same reason.
	if !validUCIName(intended.Name) {
		return Plan{}, fmt.Errorf("build plan: %q is not a usable interface name — letters, digits, "+
			"dot, dash and underscore only, up to 15 characters", intended.Name)
	}
	if len(intended.Peers) == 0 {
		return Plan{}, fmt.Errorf("build plan: %s has no peers, so it could never carry traffic", intended.Name)
	}

	requested := intended.Proto.resolve()
	resolved, fallback, err := resolveProto(requested, protos)
	if err != nil {
		return Plan{}, fmt.Errorf("build plan: %w", err)
	}
	sc, _ := schemaFor(resolved)
	// Silently dropping obfuscation is how an AmneziaWG profile becomes a plain-WireGuard tunnel that
	// the peer will not answer. If the resolved protocol has no namespace for these parameters, the
	// plan refuses rather than rendering an interface that looks right and cannot connect.
	if sc.ObfPrefix == "" && len(intended.Obfuscation) > 0 {
		return Plan{}, fmt.Errorf(
			"build plan: %s carries %d obfuscation parameter(s) and proto %q has nowhere to put them; "+
				"writing it would produce a tunnel the peer rejects", intended.Name, len(intended.Obfuscation), string(resolved))
	}
	// From here on the plan means the RESOLVED protocol. Intended carries it too — see Plan.Proto.
	intended.Proto = resolved

	p := Plan{
		Iface:          intended.Name,
		Intended:       intended,
		Commands:       nil, // filled below, once we know whether the interface already exists
		Commit:         CommitCmds(),
		Proto:          resolved,
		RequestedProto: requested,
		Fallback:       fallback,
	}
	if fallback {
		p.Warnings = append(p.Warnings, fmt.Sprintf(
			"%s is written as proto='%s' because this router has no netifd handler for it; no "+
				"obfuscation parameter is written, so this tunnel is plain %s on the wire — LuCI will "+
				"label it %s, and DPI can still fingerprint it as %s",
			string(requested), string(resolved), string(requested), string(resolved), string(requested)))
	}
	var existing *AWGInterface
	if cur, ok := ParseUCIShow(uciNetwork)[intended.Name]; ok {
		p.Expected = cur
		existing = &cur
	}

	// An interface that already exists under a DIFFERENT protocol needs its old shape taken off first.
	// `uci set` never removes an option it was not told about, and the peer sections carry the old
	// protocol in their TYPE, so a bare re-write would leave both behind: stale obfuscation in force
	// against a peer that does not expect it, and orphan peer sections pointing at an interface that
	// no longer speaks their protocol.
	//
	// The refs come from the parse. Never derived — the operator's own awg0 has an ANONYMOUS peer.
	if existing != nil && existing.Proto.resolve() != resolved {
		p.Orphans = PeerSectionsFor(uciNetwork, intended.Name)
		p.Commands = append(p.Commands, RemoveUCIRefs("", p.Orphans)...)
		// RemoveUCIRefs always appends the interface itself; this path must not delete it.
		p.Commands = p.Commands[:len(p.Commands)-1]
		oldSc, _ := schemaFor(existing.Proto)
		if oldSc.ObfPrefix != "" && oldSc.ObfPrefix != sc.ObfPrefix {
			var stale []string
			for _, k := range sortedKeys(existing.Obfuscation) {
				stale = append(stale, oldSc.ObfPrefix+k)
			}
			p.Commands = append(p.Commands, DeleteOptionCmds(intended.Name, stale)...)
		}
	}

	// The renderer only clears a list when there IS one — see RenderUCIFrom.
	p.Commands = append(p.Commands, RenderUCIFrom(intended, existing)...)

	// A parameter the device carries and the plan does not is DROPPED — but `uci set` does not remove
	// options, so saying so was not enough: the value stayed in force. Against a plain-WireGuard peer
	// a leftover junk or header parameter is a handshake that silently never completes.
	//
	// The delete list is read-derived (keys the parse actually found), which is also what makes it
	// safe: `uci -q delete` on an absent option exits 1 and would abort the batch.
	if sc.ObfPrefix != "" {
		var drop []string
		for _, k := range sortedKeys(p.Expected.Obfuscation) {
			if _, ok := intended.Obfuscation[k]; !ok {
				drop = append(drop, sc.ObfPrefix+k)
				p.Warnings = append(p.Warnings,
					fmt.Sprintf("%s%s is set on the router and absent from this plan; applying will delete it", sc.ObfPrefix, k))
			}
		}
		p.Commands = append(p.Commands, DeleteOptionCmds(intended.Name, drop)...)
	}

	if zoneName != "" {
		zones := ParseFirewallZones(uciFirewall)
		z, ok := FindZone(zones, zoneName)
		if !ok {
			return Plan{}, fmt.Errorf("build plan: firewall zone %q does not exist on this router "+
				"(zones present: %s) — attaching the tunnel to a different zone would silently apply "+
				"the wrong policy", zoneName, strings.Join(zoneNames(zones), ", "))
		}
		p.Zone, p.ZoneRef = z.Name, z.Ref
		p.Commands = append(p.Commands, ZoneAttachCmds(z, intended.Name)...)
		p.Commit = append(p.Commit, FirewallCommitCmds()...)
	} else {
		p.Warnings = append(p.Warnings,
			"no firewall zone was named, so the interface will exist with no zone policy covering it")
	}

	// Belt and braces on the one setting that decides who owns the route table. RenderUCI always
	// writes 0, but a plan that somehow carried a 1 must not be applied, and a check here costs
	// nothing next to the cost of finding out from a routing bug.
	for _, c := range p.Commands {
		if strings.Contains(c, "route_allowed_ips=") && !strings.Contains(c, "route_allowed_ips='0'") {
			return Plan{}, fmt.Errorf("build plan: refusing a plan that lets netifd own the routes (%s)", c)
		}
	}
	return p, nil
}

// PreflightAgainst is the check run immediately before writing, against a FRESH `uci show network`.
// It returns the differences between what the plan expected to find and what is actually there. A
// non-empty result means the plan is stale and must not be applied.
//
// Note what it does NOT do: it does not compare against Intended. Before the write the device is
// supposed to look like Expected, and confusing the two would make the check pass exactly when the
// change had already been applied by someone else.
func (p Plan) PreflightAgainst(freshUCINetwork string) []Difference {
	cur, exists := ParseUCIShow(freshUCINetwork)[p.Iface]
	if !exists && p.Expected.Name == "" {
		return nil // both agree the interface is not there yet
	}
	if !exists {
		return []Difference{{
			Field: "interface",
			Want:  "present (as when the plan was built)",
			Got:   "absent — it was removed after the plan was built",
		}}
	}
	if p.Expected.Name == "" {
		return []Difference{{
			Field: "interface",
			Want:  "absent (the plan creates it)",
			Got:   "present — something created " + p.Iface + " after the plan was built",
		}}
	}
	return DiffInterface(p.Expected, cur)
}

// VerifyAgainst is the check run AFTER writing, against a fresh `uci show network`. An empty result
// is the only evidence that the write did what it said; the commands exiting 0 is not.
func (p Plan) VerifyAgainst(freshUCINetwork string) []Difference {
	cur, ok := ParseUCIShow(freshUCINetwork)[p.Iface]
	if !ok {
		return []Difference{{Field: "interface", Want: "present after the write", Got: "absent"}}
	}
	return DiffInterface(p.Intended, cur)
}

// Preview renders the plan the way it should be shown to a person: the commands that will run, and
// then the commands that make them take effect, clearly apart.
func (p Plan) Preview() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s", p.Iface)
	if p.Zone != "" {
		fmt.Fprintf(&b, "  (firewall zone %s, currently %s)", p.Zone, p.ZoneRef)
	}
	b.WriteString("\n")
	for _, w := range p.Warnings {
		fmt.Fprintf(&b, "# warning: %s\n", w)
	}
	for _, c := range p.Commands {
		b.WriteString(c)
		b.WriteString("\n")
	}
	b.WriteString("\n# nothing above changes the running configuration; these do:\n")
	for _, c := range p.Commit {
		b.WriteString(c)
		b.WriteString("\n")
	}
	return b.String()
}

func zoneNames(zs []Zone) []string {
	out := make([]string, 0, len(zs))
	for _, z := range zs {
		out = append(out, z.Name)
	}
	return out
}

// validUCIName reports whether s is safe to interpolate into a uci path that will be run by a shell.
// Deliberately the same alphabet netdiag.ValidIface accepts for `ping -I`: Linux caps an interface
// name at 15 characters, and nothing outside this set can appear in one.
func validUCIName(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case (c == '.' || c == '-' || c == '_') && i > 0:
		default:
			return false
		}
	}
	return true
}
