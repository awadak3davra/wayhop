package model

import "errors"

// refproblems.go answers "what else is broken?" without writing a second validator.
//
// Validate returns the FIRST failure and stops, which is right for a gate — Apply either proceeds or
// it does not. It is wrong for a review: the panel showed one broken object at a time, so an operator
// fixed it, re-reviewed, and met the next one. Measured on the demo profile: rules st-rule-6,
// st-rule-7 and st-rule-12 were each a separate round trip, and nothing anywhere said how many were
// left.
//
// The enumeration asks the REAL validator repeatedly rather than re-implementing its rules. A second
// copy of "what counts as a broken reference" would be a second answer the day one of them learns
// about a new field, and this whole file exists because one answer was already too few.

// MaxRefProblems bounds the loop. A profile with more broken references than this is not a review
// problem any more, and an unbounded loop over a hostile file is not something a router should run.
const MaxRefProblems = 25

// RefProblem is one broken reference: which object holds it, what it points at, and which of the two
// ways it is broken. Missing and switched-off need different remedies, which is why they stay apart.
type RefProblem struct {
	Kind    string // "group" | "rule" | "routing list"
	ID      string
	Target  string
	Message string
	Missing bool // true = the target is not in the profile at all; false = it is there but disabled
}

// CollectRefProblems lists every broken reference in the profile, in the order Validate finds them.
//
// After recording one it NEUTRALISES that single reference in a working copy — pointing it at
// `direct`, which every profile resolves and which is never disabled — and asks again. Neutralising
// rather than deleting is deliberate: removing the object would change what OTHER objects resolve
// against and invent problems that are not in the operator's profile.
//
// It stops at the first failure that is not a reference problem, and returns what it has: the
// remaining error is a different kind of fault with a different remedy, and walking past it to keep
// counting references would report a profile as more broken in one way than it is.
func CollectRefProblems(p Profile) []RefProblem {
	work := cloneForRefScan(p)
	var out []RefProblem
	for len(out) < MaxRefProblems {
		err := work.Validate()
		if err == nil {
			return out
		}
		var missing *UnresolvedRefError
		var off *DisabledRefError
		var kind, id, target string
		switch {
		case errors.As(err, &missing):
			kind, id, target = missing.Kind, missing.ID, missing.Target
			out = append(out, RefProblem{Kind: kind, ID: id, Target: target, Message: err.Error(), Missing: true})
		case errors.As(err, &off):
			kind, id, target = off.Kind, off.ID, off.Target
			out = append(out, RefProblem{Kind: kind, ID: id, Target: target, Message: err.Error()})
		default:
			return out
		}
		if !neutralizeRef(&work, kind, id, target) {
			// The error named something this function cannot rewrite. Returning here rather than
			// looping is what keeps the bound honest: another pass would report the same problem again.
			return out
		}
	}
	return out
}

// neutralizeRef points ONE broken reference at `direct` so the next Validate finds the next problem.
// Reports whether it found the reference to rewrite — a false means the loop must stop rather than
// repeat itself.
func neutralizeRef(p *Profile, kind, id, target string) bool {
	switch kind {
	case "rule":
		for i := range p.Rules {
			if p.Rules[i].ID == id && p.Rules[i].Outbound == target {
				p.Rules[i].Outbound = OutboundDirect
				return true
			}
		}
	case "routing list":
		for i := range p.RoutingLists {
			rl := &p.RoutingLists[i]
			if rl.ID != id {
				continue
			}
			// Which FIELD is broken is not in the error, and does not need to be: the target value
			// identifies it. DownloadVia is cleared rather than pointed at direct because "" already
			// means the ordinary path there.
			if rl.Outbound == target {
				rl.Outbound = OutboundDirect
				return true
			}
			if rl.DownloadVia == target {
				rl.DownloadVia = ""
				return true
			}
		}
	case "group":
		for i := range p.Groups {
			g := &p.Groups[i]
			if g.ID != id {
				continue
			}
			for j := range g.Members {
				if g.Members[j] == target {
					// `direct` is accepted as a member and skipped by the member checks, so the group
					// keeps its shape (and its length) while this one name stops failing.
					g.Members[j] = OutboundDirect
					return true
				}
			}
		}
	}
	return false
}

// cloneForRefScan copies exactly what neutralizeRef writes to. The caller's profile is the store's
// published immutable value; mutating its backing arrays would rewrite the operator's configuration
// from a function whose whole job is to look at it.
func cloneForRefScan(p Profile) Profile {
	p.Rules = append([]Rule(nil), p.Rules...)
	p.RoutingLists = append([]RoutingList(nil), p.RoutingLists...)
	groups := make([]Group, len(p.Groups))
	copy(groups, p.Groups)
	for i := range groups {
		groups[i].Members = append([]string(nil), groups[i].Members...)
	}
	p.Groups = groups
	return p
}

// RefProblemError turns a collected problem back into the typed error its class carries, so callers
// that already choose a remedy from the error keep one code path for one and for many. Without it a
// caller would branch on RefProblem in one place and on the error in another, and the two would
// answer differently the first time either grew a case.
func RefProblemError(rp RefProblem) error {
	if rp.Missing {
		return &UnresolvedRefError{Kind: rp.Kind, ID: rp.ID, Target: rp.Target, msg: rp.Message}
	}
	return &DisabledRefError{Kind: rp.Kind, ID: rp.ID, Target: rp.Target, msg: rp.Message}
}
