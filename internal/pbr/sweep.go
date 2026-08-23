package pbr

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// sweepTableSpan bounds the routing-table window the sweep may touch: TableBase..TableBase+span-1.
// WayHop allocates tables sequentially from TableBase (one per non-WAN egress), so 64 covers any
// realistic profile while keeping the window far from other software's ranges (mwan3 ~1001+,
// the pbr package ~40000+).
const sweepTableSpan = 64

// ruleLine is one parsed `ip rule` output line.
type ruleLine struct {
	pref     int
	fwmark   uint64 // 0 when absent
	fwmask   uint64 // 0 when absent
	toCIDR   string // "" when absent
	lookup   string // table name or number, "" when absent
	original string
}

var (
	rulePrefRe = regexp.MustCompile(`^(\d+):`)
	fwmarkRe   = regexp.MustCompile(`fwmark (0x[0-9a-fA-F]+)(?:/(0x[0-9a-fA-F]+))?`)
	toRe       = regexp.MustCompile(`\bto (\S+)`)
	lookupRe   = regexp.MustCompile(`\blookup (\S+)`)
)

func parseRuleLine(s string) (ruleLine, bool) {
	m := rulePrefRe.FindStringSubmatch(s)
	if m == nil {
		return ruleLine{}, false
	}
	pref, _ := strconv.Atoi(m[1])
	rl := ruleLine{pref: pref, original: strings.TrimSpace(s)}
	if fm := fwmarkRe.FindStringSubmatch(s); fm != nil {
		rl.fwmark, _ = strconv.ParseUint(fm[1], 0, 64)
		if fm[2] != "" {
			rl.fwmask, _ = strconv.ParseUint(fm[2], 0, 64)
		}
	}
	if tm := toRe.FindStringSubmatch(s); tm != nil {
		rl.toCIDR = tm[1]
	}
	if lm := lookupRe.FindStringSubmatch(s); lm != nil {
		rl.lookup = lm[1]
	}
	return rl, true
}

// SweepStrandedRules removes ip rules (v4 + v6) that an earlier wayhop plan installed but a later
// empty-plan teardown could not name — the boot-time mode-switch strand: the user switches
// hybrid/fast → tun/mixed without Applying, reboots, and the in-memory plan is nil, so
// SyncPlugins' stale-table cleanup deletes the nft table (nothing marks packets anymore) but the
// fwmark ip rules + per-egress tables stay behind.
//
// Safety contract — a rule is swept ONLY when it is unmistakably wayhop's:
//   - fwmark rules: the fwmark MASK equals opt.MarkMask (wayhop's 0x00ff0000 scheme) AND the
//     lookup table is NUMERIC within [TableBase, TableBase+sweepTableSpan). Both keys must match;
//     mwan3/pbr/user rules differ in mask, table range, or both. Swept tables also get their
//     routes flushed (the stale `default dev`/blackhole entries).
//   - private-exclude rules: a `to <CIDR> lookup main` rule whose priority sits in wayhop's
//     exclude band [RulePref-sweepTableSpan, RulePref). Stock systems place nothing there.
//
// Everything else — local/main/default, named-table lookups, foreign fwmark schemes — is never
// touched. Best-effort: keeps going on per-command errors and returns the first one with the
// count of rules actually deleted.
func SweepStrandedRules(r Runner, opt Options) (int, error) {
	opt.withDefaults()
	swept := 0
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, fam := range [][]string{{"rule"}, {"-6", "rule"}} {
		out, err := r.Run("", "ip", fam...)
		if err != nil {
			// `ip -6 rule` fails on v6-less kernels — that family simply has nothing to sweep.
			continue
		}
		famFlag := ""
		if fam[0] == "-6" {
			famFlag = "-6 "
		}
		tables := map[int]bool{}
		for _, line := range strings.Split(out, "\n") {
			rl, ok := parseRuleLine(line)
			if !ok {
				continue
			}
			// fwmark strand: wayhop mask + numeric table inside the wayhop window.
			if rl.fwmask != 0 && rl.fwmask == uint64(opt.MarkMask) {
				if n, err := strconv.Atoi(rl.lookup); err == nil && n >= opt.TableBase && n < opt.TableBase+sweepTableSpan {
					del := fmt.Sprintf("ip %srule del fwmark %s/%s table %d priority %d",
						famFlag, hexMark(uint32(rl.fwmark)), hexMark(uint32(rl.fwmask)), n, rl.pref)
					name, args := splitCmd(del)
					if _, err := r.Run("", name, args...); err != nil {
						note(err)
					} else {
						swept++
						tables[n] = true
					}
				}
				continue
			}
			// exclude strand: to-CIDR pinned to main inside wayhop's exclude priority band.
			if rl.toCIDR != "" && rl.lookup == "main" &&
				rl.pref >= opt.RulePref-sweepTableSpan && rl.pref < opt.RulePref {
				del := fmt.Sprintf("ip %srule del to %s lookup main priority %d", famFlag, rl.toCIDR, rl.pref)
				name, args := splitCmd(del)
				if _, err := r.Run("", name, args...); err != nil {
					note(err)
				} else {
					swept++
				}
			}
		}
		for n := range tables {
			name, args := splitCmd(fmt.Sprintf("ip %sroute flush table %d", famFlag, n))
			if _, err := r.Run("", name, args...); err != nil {
				note(err)
			}
		}
	}
	return swept, firstErr
}
