package pbr

import (
	"fmt"
	"strconv"
	"strings"
)

// ruleguard.go keeps a re-run of the Keenetic program from rewriting ip rules that are already there.
// The netfilter.d hook re-runs the whole program after every NDM firewall rebuild, but
// ip rules survive a netfilter rebuild: the make-before-break rewrite of every table and backstop rule
// (up to six forks a rule, two rules per interface and family) only delayed the marking chain, which
// comes after it, by seconds on MIPS, in every rebuild. Now each family's rule list
// is read once per run, and a rule is rewritten only when its exact line is missing.
//
// The check can only skip work, never correctness: a line printed in a shape the patterns do not
// know (another ip build, a "[detached]" interface) is "missing" and rewritten as before. BusyBox and
// iproute2 print the mark with %#x ("0", "0x20000") and fwmark before iif; both orders and the "0x0"
// spelling of a zero mark are matched anyway.

// ruleDumpVar is the shell variable holding one family's `ip rule show`, framed by newlines so that a
// pattern can anchor a whole line.
func ruleDumpVar(ip string) string {
	if ip == "ip -6" {
		return "wr_r6"
	}
	return "wr_r4"
}

// writeRuleDump reads the rule list of each family once (one fork each).
func writeRuleDump(b *strings.Builder, v6 bool) {
	b.WriteString("# each family's rules, read once: a rule already in place is not rewritten.\n")
	b.WriteString("wr_r4=\"\n$(ip rule show 2>/dev/null)\n\"\n")
	if v6 {
		b.WriteString("wr_r6=\"\n$(ip -6 rule show 2>/dev/null)\n\"\n")
	}
}

// ruleDumpLines is how `ip rule show` prints the rule `spec` at priority pref, each line framed for a
// shell case pattern. nil when the spec has a selector the patterns do not model.
func ruleDumpLines(spec string, pref int) []string {
	f := strings.Fields(spec)
	var iif, to, action string
	var marks []string
	for i := 0; i < len(f); i++ {
		arg := ""
		if i+1 < len(f) {
			arg = f[i+1]
		}
		switch f[i] {
		case "type":
			// "type blackhole": the rule type BusyBox ip accepts (measured on KeeneticOS 1.37).
			if arg != "blackhole" {
				return nil
			}
			action = "blackhole"
			i++
			continue
		case "blackhole":
			action = "blackhole"
			continue
		case "iif":
			iif = arg
		case "to":
			to = arg
		case "table", "lookup":
			action = "lookup " + arg
		case "fwmark":
			v, m, hasMask := strings.Cut(arg, "/")
			mark, err := strconv.ParseUint(v, 0, 32)
			if err != nil {
				return nil
			}
			suffix := "" // a full mask is not printed
			if hasMask {
				mask, err := strconv.ParseUint(m, 0, 32)
				if err != nil {
					return nil
				}
				if mask != 0xffffffff {
					suffix = fmt.Sprintf("/%#x", mask)
				}
			}
			marks = append(marks, fmt.Sprintf("fwmark %#x%s", mark, suffix))
			if mark == 0 {
				marks = append(marks, "fwmark 0x0"+suffix)
			}
		default:
			return nil
		}
		if arg == "" {
			return nil
		}
		i++
	}
	if action == "" {
		return nil
	}
	head := fmt.Sprintf("\n%d:\tfrom all", pref)
	if to != "" {
		head += " to " + to
	}
	var out []string
	// BusyBox prints a blackhole rule with a table it does not use: "lookup main blackhole" for one
	// added without a table, "lookup unspec blackhole" for NDM's own; every form counts as present.
	add := func(mid string) {
		if action != "blackhole" {
			out = append(out, head+mid+" "+action)
			return
		}
		for _, a := range []string{"lookup main blackhole", "lookup unspec blackhole", "blackhole"} {
			out = append(out, head+mid+" "+a)
		}
	}
	switch {
	case len(marks) == 0 && iif == "":
		add("")
	case len(marks) == 0:
		add(" iif " + iif)
	default:
		for _, m := range marks {
			if iif == "" {
				add(" " + m)
				continue
			}
			add(" " + m + " iif " + iif)
			add(" iif " + iif + " " + m)
		}
	}
	return out
}

// guardRule writes body only when the rule spec at pref is not in the family's dump. A program that
// read no dump (an empty variable) rewrites every rule, as before.
func guardRule(b *strings.Builder, ip, spec string, pref int, body string) {
	lines := ruleDumpLines(spec, pref)
	if len(lines) == 0 {
		b.WriteString(body)
		return
	}
	pats := make([]string, len(lines))
	for i, l := range lines {
		pats[i] = "*\"" + l + "\"[!0-9]*"
	}
	fmt.Fprintf(b, "case \"$%s\" in %s) ;; *)\n", ruleDumpVar(ip), strings.Join(pats, "|"))
	b.WriteString(body)
	b.WriteString(";; esac\n")
}
