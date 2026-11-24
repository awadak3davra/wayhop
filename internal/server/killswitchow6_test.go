package server

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
)

// Once the bound of remembered source pairs is full a new rule is not told; that used
// to be silent. The log says so once, Diagnostics shows a warning and Review a line.
func TestSourcePairsOverTheBoundAreSaid(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	dump := ksSourceDump{rules4: ow5Rules, routes4: ow5Tables("awg1")}
	var fail error
	s := ow5Server(t, &dump, &fail)
	plan := ow4Plan(t, "198.18.5.0/24")
	s.noteGuardTunnels(plan)
	s.refreshGuardLocal(true)
	if got := s.sourceBoundFindings(); len(got) != 0 {
		t.Fatalf("under the bound: %+v", got)
	}
	if row := ow4Row(s, plan); row.Status == "warn" {
		t.Fatalf("under the bound the row warns: %+v", row)
	}

	rules := func(n int) string {
		var b strings.Builder
		b.WriteString("0:\tfrom all lookup local\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "30:\tfrom 10.9.%d.0/24 lookup 160\n", i)
		}
		return b.String()
	}
	dump = ksSourceDump{rules4: rules(ksSourceMax + 4), routes4: ow5Tables("awg1")}
	s.refreshGuardLocal(true)
	s.refreshGuardLocal(true) // a second reading over the bound does not log again
	if n := len(s.guardSources()); n != ksSourceMax {
		t.Fatalf("%d pairs told, the bound is %d", n, ksSourceMax)
	}
	over := 0
	s.ksLocal.mu.Lock()
	over = s.ksLocal.sourceOver
	s.ksLocal.mu.Unlock()
	// One pair of the first reading (the second segment) is remembered, so 16+4+1 rules leave 5 refused.
	if over != 5 {
		t.Fatalf("refused %d pairs, want 5", over)
	}
	if n := strings.Count(logged.String(), "are not told to the guard: it remembers at most 16"); n != 1 {
		t.Fatalf("logged %d times:\n%s", n, logged.String())
	}
	row := ow4Row(s, plan)
	if row.Status != "warn" || !strings.Contains(row.Summary, "5 source-routing rule(s)") || row.Fix == "" {
		t.Fatalf("Diagnostics: %+v", row)
	}
	f := s.sourceBoundFindings()
	if len(f) != 1 || f[0].ID != findingSourceBound || !strings.Contains(f[0].Effective, "at most 16") {
		t.Fatalf("Review: %+v", f)
	}

	// Back under the bound (the extra rules removed): no Review line, no warning.
	dump = ksSourceDump{rules4: ow5Rules, routes4: ow5Tables("awg1")}
	s.refreshGuardLocal(true)
	if got := s.sourceBoundFindings(); len(got) != 0 {
		t.Fatalf("after the extra rules are gone: %+v", got)
	}
}
