package pbr

import "net/netip"

// Overlap is one pair of zones routing to different egresses whose static CIDRs overlap. The zone
// emitted later (orderZonesForEmit) is the Winner: its mark is the one the shared addresses get.
type Overlap struct {
	Loser, Winner string
	// Count is the loser's CIDRs that overlap the winner's (inside one of them or holding one).
	Count int
	// LoserFailClosed and WinnerFailClosed say which side is kill-switched; WinnerBlock that the
	// winner drops. A kill-switched loser with a winner that is neither is a leak.
	LoserFailClosed, WinnerFailClosed, WinnerBlock bool
}

// Leaks reports whether the overlap takes addresses from a kill switch to a path that may reach the WAN.
func (o Overlap) Leaks() bool { return o.LoserFailClosed && !o.WinnerFailClosed && !o.WinnerBlock }

// prefixSet answers containment questions over a set of prefixes by walking the candidate's parents.
type prefixSet map[netip.Prefix]bool

func newPrefixSet(cidrs ...[]string) prefixSet {
	s := prefixSet{}
	for _, list := range cidrs {
		for _, c := range list {
			if p, err := netip.ParsePrefix(c); err == nil {
				s[p.Masked()] = true
			}
		}
	}
	return s
}

// covers reports whether p lies inside a prefix of the set.
func (s prefixSet) covers(p netip.Prefix) bool {
	for bits := p.Bits(); bits >= 0; bits-- {
		if q, err := p.Addr().Prefix(bits); err == nil && s[q] {
			return true
		}
	}
	return false
}

// Overlaps lists the static overlaps between zones covering every source that route to different
// egresses. Domain zones overlap only at run time (their sets fill from answers) and are not here.
func (pl *Plan) Overlaps() []Overlap {
	kind := map[string]EgressKind{}
	fc := map[string]bool{}
	for _, e := range pl.Egresses {
		kind[e.Tag] = e.Kind
		fc[e.Tag] = e.Kind == EgressInterface && e.FailClosed
	}
	var out []Overlap
	for i, l := range pl.Zones {
		if l.SrcScoped || len(l.V4)+len(l.V6) == 0 {
			continue
		}
		ls := newPrefixSet(l.V4, l.V6)
		for _, w := range pl.Zones[i+1:] {
			if w.SrcScoped || w.Mark == l.Mark || len(w.V4)+len(w.V6) == 0 {
				continue
			}
			ws := newPrefixSet(w.V4, w.V6)
			// A loser prefix overlaps when it lies inside a winner prefix, or holds one.
			held := map[netip.Prefix]bool{}
			for p := range ws {
				for bits := p.Bits() - 1; bits >= 0; bits-- {
					if q, err := p.Addr().Prefix(bits); err == nil && ls[q] && !ws.covers(q) {
						held[q] = true
					}
				}
			}
			n := 0
			for p := range ls {
				if ws.covers(p) || held[p] {
					n++
				}
			}
			if n == 0 {
				continue
			}
			out = append(out, Overlap{Loser: l.Name, Winner: w.Name, Count: n,
				LoserFailClosed: fc[l.EgressTag], WinnerFailClosed: fc[w.EgressTag], WinnerBlock: kind[w.EgressTag] == EgressBlackhole})
		}
	}
	return out
}
