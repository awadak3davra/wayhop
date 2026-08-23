package server

import (
	"sort"
	"strings"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// updaterusage.go answers the question that decides whether a component belongs on this router:
// does anything in the saved profile actually need it.
//
// The components section could say what an engine IS and what it would COST, and never whether it is
// USED. That left the two decisions it exists for unanswerable. An operator looking at an installed
// sing-box could not tell whether removing it frees 40 MB or kills their VLESS exit; an operator
// looking at an absent one could not tell whether "not installed" is the normal state (it is, on this
// router) or the reason a connection they configured does not work.
//
// Both answers come from the same place: the protocols the platform says have no native path, matched
// against what the profile is actually configured to use. Nothing is written down here — the protocol
// list is the capability probe's, so a router that gains a native path stops reporting a dependency
// it no longer has.

// coreDependents names the configured things that need the sing-box core on this platform, in
// display order. Empty means nothing in this profile uses it — the answer that makes "not installed"
// normal and makes removal safe.
func coreDependents(prof model.Profile, caps platform.Capabilities) []string {
	needs := make(map[string]bool, len(caps.SingboxRequired))
	for _, p := range caps.SingboxRequired {
		needs[strings.ToLower(p)] = true
	}
	var out []string
	for _, e := range prof.Endpoints {
		if !needs[strings.ToLower(string(e.Protocol))] {
			continue
		}
		name := e.Name
		if name == "" {
			name = e.ID
		}
		// A disabled endpoint is not carrying traffic, so it cannot be a reason to keep the core
		// installed — but it IS a reason the operator might be about to need it, so it is named with
		// its state rather than dropped. Silence here would read as "nothing uses this" one click
		// before enabling it does.
		if !e.Enabled {
			name += " (off)"
		}
		out = append(out, name)
	}
	sort.Strings(out)
	// Encrypted DNS is the other core-only feature, and it is easy to forget precisely because it is
	// not a connection: the DNS page offers DoH/DoT/DoQ, the capability probe marks them
	// MISSING_BINARY without the core, and nothing on the components page connected the two.
	if enc := encryptedDNSTags(prof); len(enc) > 0 {
		out = append(out, "encrypted DNS ("+strings.Join(enc, ", ")+")")
	}
	return out
}

// encryptedDNSTags lists the enabled DNS servers that speak an encrypted transport. Tags, not
// addresses: the tag is what the DNS page shows, and a resolver address is not something to repeat
// on an unrelated page.
func encryptedDNSTags(prof model.Profile) []string {
	if prof.DNS == nil || !prof.DNS.Enabled {
		return nil
	}
	var out []string
	for _, sv := range prof.DNS.Servers {
		if !sv.Enabled {
			continue
		}
		// The model owns this set; a copy here would be free to disagree with the predicate that
		// decides whether the core runs at all.
		if !model.IsEncryptedDNSType(sv.Type) {
			continue
		}
		tag := sv.Tag
		if tag == "" {
			tag = sv.Type
		}
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}
