package pbr

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// retire.go replaces a Keenetic plane without taking the old one down first.
//
// A replaced plane used to run the old program's whole teardown and only then the new program: the
// PREROUTING jump, the marking chain, every ip rule and every table went, and until the new program
// ran nothing was marked, so listed traffic went by the main table, the WAN, kill switch or not
// (FIXES.md, "Kill switch audit"). Now the new program is installed over the old one (its chain is one
// restore commit, its rules are del-then-add) and only what the new program does NOT install is
// removed afterwards: the old teardown with every line spared that would undo something the new
// program has just put in place.

var (
	reRetireJump     = regexp.MustCompile(`^while (ip6?tables) -t mangle -D PREROUTING -j (\S+) 2>/dev/null; do :; done$`)
	reRetireChain    = regexp.MustCompile(`^(ip6?tables) -t mangle -[FX] (\S+) 2>/dev/null \|\| true$`)
	reRetireIptDel   = regexp.MustCompile(`^(ip6?tables)( -t \S+)? -D (\S+) (.+) 2>/dev/null \|\| true$`)
	reRetireRuleDel  = regexp.MustCompile(`^(ip(?: -6)?) rule del (.+?) 2>/dev/null \|\| true$`)
	reRetireRuleLoop = regexp.MustCompile(`^while (ip(?: -6)?) rule del (.+?) 2>/dev/null; do :; done$`)
	reRetireFlush    = regexp.MustCompile(`^(ip(?: -6)?) route flush table (\d+) 2>/dev/null \|\| true$`)
	reRetireDestroy  = regexp.MustCompile(`^ipset destroy (\S+) 2>/dev/null \|\| true$`)
	reRouteLine      = regexp.MustCompile(`^(ip(?: -6)?) route (?:add|replace) .*\btable (\d+)\b`)
)

// installs reports whether script runs `prefix` as a command of its own: at a line start, or after
// `|| `, `&& { ` or `; ` (the unpin guard's form), and ending the command there.
func installs(script, prefix string) bool {
	for _, lead := range []string{"\n", "|| ", "&& { ", "; "} {
		for _, tail := range []string{"\n", " 2>/dev/null", ";", " &&"} {
			if strings.Contains("\n"+script, lead+prefix+tail) {
				return true
			}
		}
	}
	return false
}

// usesTable reports whether script names routing table n (an ip rule or route with `table n`).
func usesTable(script, fam, n string) bool {
	for _, line := range strings.Split(script, "\n") {
		if !strings.HasPrefix(line, fam+" ") || (fam == "ip" && strings.HasPrefix(line, "ip -6 ")) {
			continue
		}
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if (f[i] == "table" || f[i] == "lookup") && f[i+1] == n {
				return true
			}
		}
	}
	return false
}

// RetireProgram is the part of the previous plane's teardown that the new plane does not undo: run
// AFTER the new program, it removes what only the old plane had. teardown is the old plane's whole
// teardown program (preamble included, which is kept), next the new program, nextSets the sets the new
// plane owns. A table both planes use is never flushed here: ReflushTables names the ones whose routes
// changed, to be flushed before the new program re-populates them.
func RetireProgram(teardown, next string, nextSets []string) string {
	keepSet := map[string]bool{}
	for _, n := range nextSets {
		keepSet[n] = true
	}
	var b strings.Builder
	for _, line := range strings.Split(teardown, "\n") {
		if line == "" {
			continue
		}
		if retireSpares(line, next, keepSet) {
			continue
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func retireSpares(line, next string, keepSet map[string]bool) bool {
	if m := reRetireJump.FindStringSubmatch(line); m != nil {
		return installs(next, m[1]+" -t mangle -A PREROUTING -j "+m[2]) || strings.HasSuffix(m[2], MangleStageSuffix) && installs(next, m[1]+" -t mangle -A PREROUTING -j "+strings.TrimSuffix(m[2], MangleStageSuffix))
	}
	if m := reRetireChain.FindStringSubmatch(line); m != nil {
		live := strings.TrimSuffix(m[2], MangleStageSuffix)
		// A chain the next program jumps to: from PREROUTING, or from OUTPUT behind a match (the
		// hand-off's return chain).
		return installs(next, m[1]+" -t mangle -A PREROUTING -j "+live) ||
			strings.Contains(next, "\n"+m[1]+" -t mangle -C OUTPUT ") && strings.Contains(next, " -t mangle -A OUTPUT "+handoffOutputJump(live)+"\n")
	}
	if m := reRetireIptDel.FindStringSubmatch(line); m != nil {
		return installs(next, m[1]+m[2]+" -A "+m[3]+" "+m[4]) || installs(next, m[1]+m[2]+" -I "+m[3]+" "+m[4])
	}
	if m := reRetireRuleDel.FindStringSubmatch(line); m != nil {
		return installs(next, m[1]+" rule add "+m[2])
	}
	if m := reRetireRuleLoop.FindStringSubmatch(line); m != nil {
		return installs(next, m[1]+" rule add "+m[2])
	}
	if m := reRetireFlush.FindStringSubmatch(line); m != nil {
		return usesTable(next, m[1], m[2])
	}
	if m := reRetireDestroy.FindStringSubmatch(line); m != nil {
		return keepSet[m[1]]
	}
	return false
}

// ReflushTables names the routing tables, per family, that both programs use but with different
// routes: they are flushed before the new program runs so its seed routes are not refused as already
// present and the old ones do not linger. A table whose route lines are the same keeps its routes,
// including the one the elector chose since. Returns "ip route flush table N" lines (ip -6 for v6).
func ReflushTables(previous, next string) []string {
	routes := func(script string) map[string][]string {
		out := map[string][]string{}
		for _, line := range strings.Split(script, "\n") {
			if m := reRouteLine.FindStringSubmatch(line); m != nil {
				k := m[1] + "|" + m[2]
				out[k] = append(out[k], line)
			}
		}
		for k := range out {
			sort.Strings(out[k])
		}
		return out
	}
	prev, nxt := routes(previous), routes(next)
	var out []string
	for k, lines := range prev {
		n, both := nxt[k]
		if !both || strings.Join(n, "\n") == strings.Join(lines, "\n") {
			continue
		}
		fam, table, _ := strings.Cut(k, "|")
		if table == strconv.Itoa(BackstopTable(Options{})) {
			continue // the daemon's blackhole routes live there: a flush would open the backstop
		}
		out = append(out, fam+" route flush table "+table+" 2>/dev/null || true")
	}
	sort.Strings(out)
	return out
}
