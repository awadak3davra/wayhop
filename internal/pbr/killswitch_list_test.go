package pbr

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// Kill switch audit (review F3 and the operator's rule: with a kill switch on, the marked traffic of
// that group or list never leaves by the provider, in any state). These tests read the rendered
// Keenetic plane the way the kernel would and follow the marked packet through the ip rules.

type ksRule struct {
	pref      int
	mark      uint32
	mask      uint32
	table     int // 0 = blackhole rule
	blackhole bool
}

// ksRules parses the `ip [-6] rule add fwmark M/MASK (table N|blackhole) priority P` lines of a script.
func ksRules(script string, v6 bool) []ksRule {
	prefix := "ip rule add fwmark "
	if v6 {
		prefix = "ip -6 rule add fwmark "
	}
	var out []ksRule
	for _, line := range strings.Split(script, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		f := strings.Fields(strings.TrimPrefix(line, prefix))
		mm := strings.SplitN(f[0], "/", 2)
		if len(mm) != 2 {
			continue
		}
		m, _ := strconv.ParseUint(mm[0], 0, 32)
		k, _ := strconv.ParseUint(mm[1], 0, 32)
		r := ksRule{mark: uint32(m), mask: uint32(k)}
		for i := 1; i < len(f); i++ {
			switch f[i] {
			case "table":
				r.table, _ = strconv.Atoi(f[i+1])
			case "blackhole":
				r.blackhole = true
			case "priority":
				r.pref, _ = strconv.Atoi(f[i+1])
			}
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].pref < out[j].pref })
	return out
}

// ksVerdict follows a packet carrying mark through the rules with every table EMPTY (all routes gone:
// link down, the elector's all-down clear, a flush, a reinstall between del and add) and tells where
// it ends: "drop" (a blackhole rule) or "main" (the WAN).
func ksVerdict(rules []ksRule, mark uint32) string {
	for _, r := range rules {
		if mark&r.mask != r.mark {
			continue
		}
		if r.blackhole {
			return "drop"
		}
		// A table rule over an empty table: the lookup finds nothing and goes on.
	}
	return "main"
}

func killSwitchListProfile(onAllDown string) *model.Profile {
	p := fastestKeenetic()
	p.Groups[0].KillSwitch = true
	// A domain entry too: the list is dual-stack, so IPv6 must hold as well.
	p.RoutingLists[1].Manual = append(p.RoutingLists[1].Manual, "t.me")
	p.RoutingLists[1].Fastest = &model.FastestPolicy{Enabled: true, OnAllDown: onAllDown}
	return p
}

func TestKillSwitchListEgressNeverReachesMain(t *testing.T) {
	for _, mode := range []string{"", model.OnAllDownWAN, model.OnAllDownBlock, model.OnAllDownKeep} {
		t.Run("on_all_down="+mode, func(t *testing.T) {
			p := killSwitchListProfile(mode)
			pl, _, err := Compile(p, Options{CollectDomainZones: true, ListEgresses: true})
			if err != nil {
				t.Fatal(err)
			}
			le, ok := listEgressByTag(pl, model.ListEgressTag("iplist"))
			if !ok {
				t.Fatalf("no list egress: %+v", pl.Egresses)
			}
			if !le.FailClosed {
				t.Fatalf("list under a kill-switched group lost the kill switch: %+v", le)
			}
			script := pl.RenderIPScript(Options{})
			for _, v6 := range []bool{false, true} {
				if v := ksVerdict(ksRules(script, v6), le.Mark); v != "drop" {
					t.Fatalf("v6=%v: the list's marked traffic with an empty table ends in %s:\n%s", v6, v, script)
				}
			}
			// The group's own egress too (the other list still rides it).
			g, _ := listEgressByTag(pl, "failover_with_wan")
			if v := ksVerdict(ksRules(script, false), g.Mark); v != "drop" {
				t.Fatalf("group egress ends in %s", v)
			}
		})
	}
}

// The table's blackhole and the backstop rule are written before the table's rule is replaced, so
// the del-then-add of the rule never has a moment with neither.
func TestKillSwitchBackstopBeforeTableRule(t *testing.T) {
	pl, _, err := Compile(killSwitchListProfile(""), Options{CollectDomainZones: true, ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	le, _ := listEgressByTag(pl, model.ListEgressTag("iplist"))
	script := pl.RenderIPScript(Options{})
	for _, fam := range []string{"ip", "ip -6"} {
		hole := strings.Index(script, fmt.Sprintf("%s route replace blackhole default metric", fam))
		back := strings.Index(script, fmt.Sprintf("%s rule add fwmark 0x%08x/0x00ff0000 type blackhole priority 450", fam, le.Mark))
		del := strings.Index(script, fmt.Sprintf("%s rule del fwmark 0x%08x/0x00ff0000 table %d", fam, le.Mark, le.Table))
		if hole < 0 || back < 0 || del < 0 || !(hole < del && back < del) {
			t.Fatalf("%s: blackhole@%d backstop@%d rule-del@%d\n%s", fam, hole, back, del, script)
		}
	}
	// Teardown takes the backstop away with the plane (routing off is the operator's choice).
	td := pl.RenderTeardownScript(Options{}, IpsetOptions{})
	mustContain(t, td, fmt.Sprintf("ip rule del fwmark 0x%08x/0x00ff0000 type blackhole priority 450", le.Mark))
	mustContain(t, td, fmt.Sprintf("ip -6 rule del fwmark 0x%08x/0x00ff0000 type blackhole priority 450", le.Mark))
}

// Without a kill switch nothing changes: "wan" still falls through to the provider by design.
func TestNoKillSwitchListFallsThroughOnWAN(t *testing.T) {
	p := killSwitchListProfile(model.OnAllDownWAN)
	p.Groups[0].KillSwitch = false
	pl, _, err := Compile(p, Options{CollectDomainZones: true, ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	le, _ := listEgressByTag(pl, model.ListEgressTag("iplist"))
	if le.FailClosed {
		t.Fatal("on_all_down=wan without a kill switch must not fail closed")
	}
	if v := ksVerdict(ksRules(pl.RenderIPScript(Options{}), false), le.Mark); v != "main" {
		t.Fatalf("verdict %s", v)
	}
}
