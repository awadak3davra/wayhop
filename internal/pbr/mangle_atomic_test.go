package pbr

import (
	"slices"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// Kill switch audit, "mangle window": the marking chain used to be flushed and refilled rule by rule,
// so between the -F and the last -A a listed destination went unmarked by the main table, the WAN.

func mangleTestPlan(t *testing.T) *Plan {
	t.Helper()
	p := killSwitchListProfile(model.OnAllDownBlock)
	pl, _, err := Compile(p, Options{CollectDomainZones: true, ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	return pl
}

// mangleSection returns the lines of one family's chain replacement: from the restore line to the
// closing brace of its fallback, plus the jump line after it.
func mangleSection(t *testing.T, script, ipt string) []string {
	t.Helper()
	lines := strings.Split(script, "\n")
	start := slices.Index(lines, strings.ReplaceAll(ipt, "-", "_")+"_restore --noflush <<'WR_MANGLE' || {")
	if start < 0 {
		t.Fatalf("%s: no restore commit in:\n%s", ipt, script)
	}
	for i := start; i < len(lines); i++ {
		if lines[i] == "}" {
			return lines[start : i+2]
		}
	}
	t.Fatalf("%s: unterminated fallback", ipt)
	return nil
}

// The restore input declares only our chain, inside the mangle table, and carries every rule; nothing
// flushes the live chain before the commit.
func TestMangleChainIsOneRestoreCommit(t *testing.T) {
	pl := mangleTestPlan(t)
	script := pl.RenderIptablesScript(IpsetOptions{})
	for _, ipt := range []string{"iptables", "ip6tables"} {
		sec := mangleSection(t, script, ipt)
		end := slices.Index(sec, "WR_MANGLE")
		body := sec[1:end]
		if body[0] != "*mangle" || body[1] != ":WR_PREROUTING - [0:0]" || body[len(body)-1] != "COMMIT" {
			t.Fatalf("%s restore input:\n%s", ipt, strings.Join(body, "\n"))
		}
		for _, l := range body[2 : len(body)-1] {
			if !strings.HasPrefix(l, "-A WR_PREROUTING ") {
				t.Fatalf("%s: restore input touches more than our chain: %q", ipt, l)
			}
		}
		if n := len(body) - 3; n < 4 {
			t.Fatalf("%s: %d rules in the commit", ipt, n)
		}
		before := script[:strings.Index(script, sec[0])]
		if strings.Contains(before, ipt+" -t mangle -F WR_PREROUTING\n") {
			t.Fatalf("%s: the live chain is flushed before the commit", ipt)
		}
	}
}

// mangleSim interprets the fallback's command forms over a model of the mangle table and checks after
// every command that a packet entering PREROUTING reaches a chain holding a whole rule set.
type mangleSim struct {
	chains  map[string][]string
	jumps   []string
	full    [][]string // rule sets that count as whole: the old one and the new one
	t       *testing.T
	checked bool
}

func (s *mangleSim) whole() bool {
	for _, j := range s.jumps {
		for _, f := range s.full {
			if slices.Equal(s.chains[j], f) {
				return true
			}
		}
	}
	return false
}

// run executes one simple command and reports its exit status.
func (s *mangleSim) run(cmd string) bool {
	f := strings.Fields(strings.ReplaceAll(cmd, "2>/dev/null", ""))
	if len(f) < 4 || f[1] != "-t" || f[2] != "mangle" {
		s.t.Fatalf("unmodelled command %q", cmd)
	}
	op, ch := f[3], f[4]
	ok := true
	switch op {
	case "-N":
		if _, exists := s.chains[ch]; exists {
			ok = false
		} else {
			s.chains[ch] = []string{}
		}
	case "-F":
		if _, exists := s.chains[ch]; !exists {
			ok = false
		} else {
			s.chains[ch] = []string{}
		}
	case "-X":
		if slices.Contains(s.jumps, ch) {
			ok = false
		} else {
			delete(s.chains, ch)
		}
	case "-A", "-C", "-D":
		spec := strings.Join(f[5:], " ")
		if ch == "PREROUTING" {
			target := f[len(f)-1]
			switch op {
			case "-A":
				s.jumps = append(s.jumps, target)
			case "-C":
				ok = slices.Contains(s.jumps, target)
			case "-D":
				i := slices.Index(s.jumps, target)
				if ok = i >= 0; ok {
					s.jumps = slices.Delete(s.jumps, i, i+1)
				}
			}
		} else if op == "-A" {
			s.chains[ch] = append(s.chains[ch], spec)
		} else {
			s.t.Fatalf("unmodelled %q", cmd)
		}
	}
	if s.checked && !s.whole() {
		s.t.Fatalf("after %q no whole chain is jumped to: jumps=%v chains=%v", cmd, s.jumps, s.chains)
	}
	return ok
}

// exec runs a line: `a || b`, `while a; do :; done`, `if a; then` ... `fi` handled by the caller.
func (s *mangleSim) exec(line string) bool {
	if strings.HasPrefix(line, "while ") {
		c := strings.TrimSuffix(strings.TrimPrefix(line, "while "), "; do :; done")
		for s.run(c) {
		}
		return true
	}
	parts := strings.Split(line, " || ")
	for i, p := range parts {
		if p == "true" {
			return true
		}
		if s.run(p) || i == len(parts)-1 {
			return true
		}
	}
	return false
}

func (s *mangleSim) fallback(sec []string, ipt string) {
	lines := sec[slices.Index(sec, "WR_MANGLE")+1:]
	skip := false
	for _, l := range lines {
		switch {
		case l == "}" || l == "":
			continue
		case strings.HasPrefix(l, "if ") && strings.HasSuffix(l, "; then"):
			skip = !s.run(strings.TrimSuffix(strings.TrimPrefix(l, "if "), "; then"))
		case l == "fi":
			skip = false
		case skip:
		case strings.HasPrefix(l, ipt+" ") || strings.HasPrefix(l, "while "+ipt+" "):
			s.exec(l)
		default:
			s.t.Fatalf("unmodelled line %q", l)
		}
	}
}

func specsOf(sec []string) []string {
	var out []string
	for _, l := range sec[1:slices.Index(sec, "WR_MANGLE")] {
		if strings.HasPrefix(l, "-A WR_PREROUTING ") {
			out = append(out, strings.TrimPrefix(l, "-A WR_PREROUTING "))
		}
	}
	return out
}

// The fallback (no restore, or the kernel refused the commit) never leaves PREROUTING without a whole
// chain: not on a replaced plane, not on a hook re-run over the same rules, not after a killed run left
// the staging chain behind. A first install ends with the chain whole and jumped to.
func TestMangleFallbackNeverEmpty(t *testing.T) {
	pl := mangleTestPlan(t)
	sec := mangleSection(t, pl.RenderIptablesScript(IpsetOptions{}), "iptables")
	newSpecs := specsOf(sec)
	old := []string{"-j CONNMARK --restore-mark --nfmask 0x00ff0000 --ctmask 0x00ff0000", "-m set --match-set wr_old_4 dst -j MARK --set-xmark 0x00020000/0x00ff0000"}

	for name, start := range map[string]func(*mangleSim){
		"replaced plane": func(s *mangleSim) { s.chains["WR_PREROUTING"] = old; s.jumps = []string{"WR_PREROUTING"} },
		"hook re-run":    func(s *mangleSim) { s.chains["WR_PREROUTING"] = newSpecs; s.jumps = []string{"WR_PREROUTING"} },
		"killed run left the stage": func(s *mangleSim) {
			s.chains["WR_PREROUTING"] = old
			s.chains["WR_PREROUTING_S"] = old[:1]
			s.jumps = []string{"WR_PREROUTING", "WR_PREROUTING_S"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := &mangleSim{chains: map[string][]string{}, full: [][]string{old, newSpecs}, t: t}
			start(s)
			s.checked = true
			s.fallback(sec, "iptables")
			s.exec(sec[len(sec)-1]) // the jump line after the section
			if !slices.Equal(s.chains["WR_PREROUTING"], newSpecs) || !slices.Equal(s.jumps, []string{"WR_PREROUTING"}) {
				t.Fatalf("end state: jumps=%v chains=%v", s.jumps, s.chains)
			}
			if _, left := s.chains["WR_PREROUTING_S"]; left {
				t.Fatal("staging chain left behind")
			}
		})
	}
	t.Run("first install", func(t *testing.T) {
		s := &mangleSim{chains: map[string][]string{}, full: [][]string{newSpecs}, t: t}
		s.fallback(sec, "iptables")
		s.exec(sec[len(sec)-1])
		if !slices.Equal(s.chains["WR_PREROUTING"], newSpecs) || !slices.Equal(s.jumps, []string{"WR_PREROUTING"}) {
			t.Fatalf("end state: jumps=%v chains=%v", s.jumps, s.chains)
		}
	})
}
