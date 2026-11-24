package pbr

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// The ordering invariant of the Keenetic plane: for every mark an iptables rule can set,
// the ip rule that routes it and its table (plus, for a kill-switched egress, the table's blackhole and
// the mark's blackhole rule) are installed BEFORE the first rule that sets it. A mark set before its
// rule exists matches no rule, skips the backstop (which only looks at unmarked packets) and leaves by
// the main table, the WAN. Removal goes the other way: nothing sets a mark when its rule goes.

var reSetMark = regexp.MustCompile(`--set-xmark (0x[0-9a-f]+)/(0x[0-9a-f]+)`)

// markSetters returns, per family ("4", "6") and mark, the byte offset of the first program line that
// can set it: a rule of a restore commit or an iptables append/insert.
func markSetters(script string) map[string]map[uint32]int {
	out := map[string]map[uint32]int{"4": {}, "6": {}}
	fam := ""
	off := 0
	for _, line := range strings.SplitAfter(script, "\n") {
		at := off
		off += len(line)
		switch {
		case strings.HasPrefix(line, "ip6tables_restore "):
			fam = "6"
			continue
		case strings.HasPrefix(line, "iptables_restore "):
			fam = "4"
			continue
		case strings.HasPrefix(line, "WR_MANGLE"):
			fam = ""
			continue
		}
		lf := fam
		switch {
		case strings.HasPrefix(line, "ip6tables "):
			lf = "6"
		case strings.HasPrefix(line, "iptables "):
			lf = "4"
		case !strings.HasPrefix(line, "-A "):
			continue
		}
		if lf == "" || strings.Contains(line, " -D ") || !strings.Contains(line, "-j MARK") {
			continue
		}
		m := reSetMark.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		var mark uint32
		fmt.Sscanf(m[1], "0x%x", &mark)
		if _, seen := out[lf][mark]; !seen {
			out[lf][mark] = at
		}
	}
	return out
}

// orderNeed is one line that must precede the first setter of a mark: re is matched against each
// program line after the family's `ip ` / `ip -6 ` prefix.
type orderNeed struct {
	what string
	re   *regexp.Regexp
}

func firstMatch(script, ip string, re *regexp.Regexp) int {
	off := 0
	for _, line := range strings.SplitAfter(script, "\n") {
		if strings.HasPrefix(line, ip) && re.MatchString(strings.TrimSuffix(strings.TrimPrefix(line, ip), "\n")) {
			return off
		}
		off += len(line)
	}
	return -1
}

// orderViolations checks the invariant for one rendered program.
func orderViolations(pl *Plan, script string) []string {
	mask := hexMark(pl.Mask)
	q := regexp.QuoteMeta
	needs := map[uint32][]orderNeed{}
	add := func(m uint32, what, re string) {
		needs[m] = append(needs[m], orderNeed{what, regexp.MustCompile(re)})
	}
	for _, e := range pl.nonWanEgresses() {
		m := hexMark(e.Mark)
		add(e.Mark, "table rule", fmt.Sprintf(`^rule add fwmark %s/%s table %d priority \d+$`, q(m), q(mask), e.Table))
		if e.Kind == EgressInterface && e.FailClosed {
			add(e.Mark, "table blackhole", fmt.Sprintf(`^route replace blackhole default metric \d+ table %d\b`, e.Table))
			add(e.Mark, "blackhole rule", fmt.Sprintf(`^rule add fwmark %s/%s type blackhole priority \d+$`, q(m), q(mask)))
		}
		if e.Kind == EgressBlackhole {
			add(e.Mark, "blackhole route", fmt.Sprintf(`^route replace blackhole default table %d$`, e.Table))
		}
	}
	for _, ps := range pl.NDMPolicySlots() {
		add(ps.Mark, "NDM policy backstop", fmt.Sprintf(`^rule add fwmark %s type blackhole priority \d+$`, q(hexMark(ps.Mark))))
	}
	bit := q(hexMark(HandoffBit))
	add(HandoffBit, "hand-off rule", fmt.Sprintf(`^rule add iif \S+ fwmark %s/%s table %d priority \d+$`, bit, bit, HandoffTable(Options{})))
	wan := map[uint32]bool{}
	for _, e := range pl.Egresses {
		if e.Kind == EgressWAN {
			wan[e.Mark] = true
		}
	}
	var out []string
	for fam, marks := range markSetters(script) {
		ip := "ip "
		if fam == "6" {
			ip = "ip -6 "
		}
		for mark, at := range marks {
			if wan[mark] {
				continue // the WAN egress is the main table: no rule of its own
			}
			ns, known := needs[mark]
			if !known {
				out = append(out, fmt.Sprintf("v%s mark %s is set and nothing routes it", fam, hexMark(mark)))
				continue
			}
			for _, n := range ns {
				if i := firstMatch(script, ip, n.re); i < 0 || i > at {
					out = append(out, fmt.Sprintf("v%s mark %s is set at %d, its %s at %d", fam, hexMark(mark), at, n.what, i))
				}
			}
		}
	}
	return out
}

func handoffOrderProfile() *model.Profile {
	p := backstopProfile()
	p.Groups[0].KillSwitch = false
	p.RoutingLists = append(p.RoutingLists,
		model.RoutingList{ID: "ipcheck", Enabled: true, Outbound: model.OutboundDirect, Manual: []string{"api.ipify.org"}})
	return p
}

func orderPlans(t *testing.T) map[string]*Plan {
	t.Helper()
	plans := map[string]*Plan{}
	for name, p := range map[string]*model.Profile{
		"kill switch":    backstopProfile(),
		"no kill switch": keeneticProfile(),
		"hand-off":       handoffOrderProfile(),
	} {
		pl, _, err := Compile(p, Options{CollectDomainZones: true, ListEgresses: true})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		plans[name] = pl
	}
	return plans
}

func orderOptions() IpsetOptions {
	io := bsOptions()
	io.HandoffIface = HandoffIfaceDefault
	return io
}

func TestOrderRulesBeforeMarks(t *testing.T) {
	for name, pl := range orderPlans(t) {
		script := pl.RenderKeeneticScript(Options{}, orderOptions())
		if len(markSetters(script)["4"]) == 0 {
			t.Fatalf("%s: the checker found no marks", name)
		}
		if v := orderViolations(pl, script); len(v) > 0 {
			t.Errorf("%s:\n%s", name, strings.Join(v, "\n"))
		}
	}
}

// A table rule is rewritten make-before-break: a copy at the staging priority holds the mark while the
// rule at its own priority is deleted and added again (the netfilter.d hook re-runs the program three
// times per NDM rebuild; a plain tunnel list went by the WAN in each del-then-add gap).
func TestOrderTableRuleMakeBeforeBreak(t *testing.T) {
	pl := orderPlans(t)["no kill switch"]
	script := pl.RenderKeeneticScript(Options{}, bsOptions())
	mask := hexMark(pl.Mask)
	stagePref := fmt.Sprint(tableRuleStagePref(Options{RulePref: 150}))
	for i, e := range pl.nonWanEgresses() {
		for _, ip := range []string{"ip", "ip -6"} {
			spec := fmt.Sprintf("fwmark %s/%s table %d priority ", hexMark(e.Mark), mask, e.Table)
			own := fmt.Sprint(150 + i)
			stage := strings.Index(script, ip+" rule add "+spec+stagePref+" 2>/dev/null || true\n")
			del := strings.Index(script, "while "+ip+" rule del "+spec+own+" 2>/dev/null; do :; done\n")
			add := strings.Index(script, "\n"+ip+" rule add "+spec+own+"\n")
			drop := strings.Index(script, "while "+ip+" rule del "+spec+stagePref+" 2>/dev/null; do :; done\n")
			if stage < 0 || !(stage < del && del < add && add < drop) {
				t.Fatalf("%s %s: stage@%d del@%d add@%d dropstage@%d", ip, spec, stage, del, add, drop)
			}
		}
	}
}

// Teardown: every mark-setting rule (the jumps into the chains) goes before any ip rule.
func TestOrderTeardownMarksFirst(t *testing.T) {
	for name, pl := range orderPlans(t) {
		td := pl.RenderTeardownScript(Options{}, orderOptions())
		lastMark := -1
		for _, p := range []string{" -D PREROUTING ", " -D OUTPUT ", " -t mangle -F "} {
			if i := strings.LastIndex(td, p); i > lastMark {
				lastMark = i
			}
		}
		firstRule := strings.Index(td, " rule del ")
		if lastMark < 0 || firstRule < 0 || firstRule < lastMark {
			t.Errorf("%s: last mark removal @%d, first rule removal @%d", name, lastMark, firstRule)
		}
	}
}
