package keenetic

import (
	"fmt"
	"strings"
)

// wgasc.go reads KeeneticOS's AmneziaWG parameter line.
//
// OpenWrt names every obfuscation knob (`awg_jc`, `awg_s3`, `awg_i1`), so a writer there can set one
// and leave the rest alone. NDM does not: the whole set arrives as ONE positional line under the
// interface, and the arity varies. Both of these are live on the same device (KeeneticOS 5.01.C):
//
//	wireguard asc 4 10 34 10 34 103410341 034103410 341034103 410341034                       (9)
//	wireguard asc 3 41 03 41 03 <4 min-max ranges> 41 03 "" "" "" "" ""                       (16)
//
// The first five are Jc, Jmin, Jmax, S1, S2. That is not read off the protocol spec, it was measured
// across two firmwares: the Keenetic's tunnels to 203.0.113.10 carry `asc 5 49 998 17 110`, and the
// AX3000T's tunnel to the same host carries `awg_jc='5' awg_jmin='49' awg_jmax='998' awg_s1='17'
// awg_s2='110'` as NAMED uci options. Five values, same order, two independent config systems.
//
// The next four are the H values, as single numbers in the shorter form and as `min-max` RANGES in
// the longer one. Their position is structural — four H-ish arguments directly after S2, matching
// the four `awg_h1`..`awg_h4` on the other device — but their VALUES could not be cross-checked:
// the two routers reach that host on different ports (443 and 8443) and their H parameters differ,
// so they are separate tunnel instances that happen to share a J/S profile.
//
// What the long form's remaining seven arguments mean is NOT established here. It is tempting: 16 is
// exactly the size of the AmneziaWG parameter set measured on the AX3000T's uci (jc jmin jmax s1 s2
// h1..h4 s3 s4 i1..i5), and five empty strings sit precisely where i1..i5 would be. That is a good
// guess and it stays a guess — nothing consulted here says which position is which, and this file
// keeps them as raw tokens rather than writing the guess down as a fact.
//
// That restraint is the point. A positional line is exactly where a confident guess does damage: get
// the mapping wrong and a rewrite does not fail, it shifts every value one place and produces a
// tunnel that is configured, plausible, and not the one that was asked for. Preserving the tail
// verbatim is correct whether or not the guess would have been right.

// WGAsc is one `wireguard asc` line, split but not interpreted beyond the part that is certain.
type WGAsc struct {
	Raw  string   // the argument text exactly as NDM printed it
	Args []string // the arguments, whitespace-split, quotes preserved

	Jc, Jmin, Jmax string // args 0-2
	S1, S2         string // args 3-4
	H1, H2, H3, H4 string // args 5-8; a bare number or a "min-max" range

	// Tail is everything after H4. Present only in the longer form, and deliberately not named:
	// see the file comment.
	Tail []string
}

// ascFixedArgs is how many leading arguments have a meaning this code is willing to assert.
const ascFixedArgs = 9

// ParseWGAsc reads the argument text of a `wireguard asc` line.
//
// It refuses anything shorter than the nine arguments whose meaning is fixed, rather than filling
// the missing ones with zeros: a partially-read obfuscation set that looks complete is worse than a
// refusal, because the tunnel it produces negotiates and fails in a way that looks like a network
// problem.
func ParseWGAsc(args string) (WGAsc, error) {
	fields := strings.Fields(strings.TrimSpace(args))
	if len(fields) < ascFixedArgs {
		return WGAsc{}, fmt.Errorf("wireguard asc: %d argument(s), need at least %d (Jc Jmin Jmax S1 S2 H1 H2 H3 H4): %q",
			len(fields), ascFixedArgs, args)
	}
	a := WGAsc{
		Raw:  strings.TrimSpace(args),
		Args: fields,
		Jc:   fields[0], Jmin: fields[1], Jmax: fields[2],
		S1: fields[3], S2: fields[4],
		H1: fields[5], H2: fields[6], H3: fields[7], H4: fields[8],
	}
	if len(fields) > ascFixedArgs {
		a.Tail = append([]string(nil), fields[ascFixedArgs:]...)
	}
	return a, nil
}

// ParseWGAscLines pulls every `wireguard asc` out of a `show running-config`, keyed by the interface
// it appeared under. Interfaces without one are absent from the map rather than present-and-empty —
// no AmneziaWG obfuscation and unreadable obfuscation must not look alike.
func ParseWGAscLines(runningConfig string) map[string]WGAsc {
	out := map[string]WGAsc{}
	iface := ""
	for _, line := range strings.Split(runningConfig, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "interface "):
			iface = strings.TrimSpace(strings.TrimPrefix(t, "interface "))
		case iface != "" && strings.HasPrefix(t, "wireguard asc "):
			if a, err := ParseWGAsc(strings.TrimPrefix(t, "wireguard asc ")); err == nil {
				out[iface] = a
			}
		}
	}
	return out
}

// SameShape reports whether b could replace a without shifting any argument's meaning — same count,
// and the H arguments still ranges or still bare numbers.
//
// This is the check a future NDM writer needs before rewriting a line it did not author. Rewriting
// with a different arity is not a validation error on the device: NDM accepts it, and the tunnel
// simply obfuscates differently from what either side expects.
func (a WGAsc) SameShape(b WGAsc) bool {
	if len(a.Args) != len(b.Args) {
		return false
	}
	for i := 5; i <= 8; i++ {
		if strings.Contains(a.Args[i], "-") != strings.Contains(b.Args[i], "-") {
			return false
		}
	}
	return true
}

// NamedHead returns the nine positions whose names are established, keyed the way OpenWrt names
// them (`jc`, `jmin`, `jmax`, `s1`, `s2`, `h1`..`h4`) so a Keenetic tunnel and an OpenWrt one can be
// compared directly.
//
// It stops at nine. The tail is deliberately absent rather than given plausible keys: a map that
// silently answers "s3" with whatever sits in position 9 would be believed by every caller, and the
// only evidence for that position is that the argument count happens to match a 16-parameter set.
func (a WGAsc) NamedHead() map[string]string {
	if len(a.Args) < ascFixedArgs {
		return nil
	}
	return map[string]string{
		"jc": a.Jc, "jmin": a.Jmin, "jmax": a.Jmax,
		"s1": a.S1, "s2": a.S2,
		"h1": a.H1, "h2": a.H2, "h3": a.H3, "h4": a.H4,
	}
}

// HeadMatches reports whether this line's established parameters agree with a set of OpenWrt-named
// options — the comparison that let the head be identified in the first place, kept available so a
// future writer can check a tunnel it is about to rewrite against one that is known to work.
//
// Only keys present in named are compared; a caller passing a partial set gets a partial check.
// A set that shares NO key with the head returns false rather than true — asking whether `s3` and
// `i1` agree with a line whose s3 and i1 positions are not established compares nothing at all, and
// answering "they match" would be the most confident possible way of saying nothing.
func (a WGAsc) HeadMatches(named map[string]string) bool {
	head := a.NamedHead()
	if head == nil || len(named) == 0 {
		return false
	}
	compared := 0
	for k, v := range named {
		h, ok := head[k]
		if !ok {
			continue
		}
		compared++
		if h != v {
			return false
		}
	}
	return compared > 0
}
