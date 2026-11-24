package pbr

import (
	"strings"
	"testing"
)

// BusyBox ip 1.37 on KeeneticOS (measured): `ip rule add fwmark M/K type blackhole priority P` is the
// only accepted form (a bare "blackhole" is "invalid argument"), and `ip rule show` prints it as
// "P:\tfrom all fwmark M/K lookup main blackhole"; NDM's own print "lookup unspec blackhole". The guard
// must see each printed form as present, or every hook run rewrites the rule.
func TestRuleGuardKnowsBusyBoxBlackholePrints(t *testing.T) {
	lines := ruleDumpLines("fwmark 0x10000000/0x10ff0000 type blackhole", 143)
	want := []string{
		"\n143:\tfrom all fwmark 0x10000000/0x10ff0000 lookup main blackhole",
		"\n143:\tfrom all fwmark 0x10000000/0x10ff0000 lookup unspec blackhole",
	}
	joined := strings.Join(lines, "|")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Fatalf("guard misses the printed form %q in %q", w, lines)
		}
	}
}

func TestRuleCheckReadsTypeBlackhole(t *testing.T) {
	k, ok := parseRuleSpec(strings.Fields("fwmark 0x10000000/0x10ff0000 type blackhole priority 143"))
	if !ok || k.action != "blackhole" || k.pref != 143 {
		t.Fatalf("parsed %+v ok=%v", k, ok)
	}
	got := parseRuleDump("143:\tfrom all fwmark 0x10000000/0x10ff0000 lookup main blackhole \n")
	if len(got) != 1 || got[0].action != "blackhole" || got[0].pref != 143 || got[0].fwmark != 0x10000000 {
		t.Fatalf("dump parsed as %+v", got)
	}
}
