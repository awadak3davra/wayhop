package netvpn

import (
	"errors"
	"strings"
	"testing"
)

// planFor builds a plan to create awg9, which does not exist in the fixture — the ordinary create.
func planFor(t *testing.T) Plan {
	t.Helper()
	p, err := BuildPlanFor(newIface("awg9"), testRouterProtos, "vpn", liveUCIShow, liveFirewallShow)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	return p
}

// uciShowFromCmds turns a plan's commands into what `uci show` would print afterwards.
//
// The subtlety that broke this twice: uci prints a list as ONE line carrying every value, while the
// plan builds that list with one `add_list` per value. Emitting a line per command instead produces
// repeated keys, and a reader that takes the last one sees a single-element list — so the test fails
// on correct output and blames the code.
//
// It lives in one place now precisely because writing it a second time is what went wrong: the
// round-trip test had the merge and this one did not.
func uciShowFromCmds(cmds []string) []string {
	var lines []string
	for _, c := range cmds {
		var kv string
		switch {
		case strings.HasPrefix(c, "uci set "):
			lines = append(lines, strings.TrimPrefix(c, "uci set "))
			continue
		case strings.HasPrefix(c, "uci add_list "):
			kv = strings.TrimPrefix(c, "uci add_list ")
		default:
			continue // -q delete and anything else does not appear in `uci show`
		}
		i := strings.Index(kv, "=")
		key, val := kv[:i], kv[i+1:]
		merged := false
		for j, ln := range lines {
			if strings.HasPrefix(ln, key+"=") {
				lines[j] = ln + " " + val // uci prints list values space-separated on one line
				merged = true
				break
			}
		}
		if !merged {
			lines = append(lines, key+"="+val)
		}
	}
	return lines
}

// afterWrite is what `uci show network` returns once the plan has been staged: the fixture plus the
// interface the plan creates. Built from the plan's own commands so it cannot drift from them.
func afterWrite(p Plan) string {
	return liveUCIShow + strings.Join(uciShowFromCmds(p.Commands), "\n") + "\n"
}

func TestApply_HappyPathCommitsLast(t *testing.T) {
	p := planFor(t)
	rr := &RecordRunner{Responses: map[string]string{
		"uci changes":      "",
		"uci show network": liveUCIShow,
	}}
	// Once the writes have gone in, the next read must show them.
	rr.OnCommand = func(cmd string, r *RecordRunner) {
		if strings.HasPrefix(cmd, "uci add_list network.awg9_peer1.allowed_ips") {
			r.Responses["uci show network"] = afterWrite(p)
		}
	}

	res, err := p.Apply(rr)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Applied || res.Rollback != RollbackNone {
		t.Fatalf("applied=%v rollback=%q", res.Applied, res.Rollback)
	}
	// The commit must be the LAST thing that happens, after both reads.
	joined := strings.Join(rr.Cmds, "\n")
	iCommit := strings.Index(joined, "uci commit network")
	iRead := strings.LastIndex(joined, "uci show network")
	if iCommit < iRead {
		t.Errorf("the commit ran before the verification read:\n%s", joined)
	}
}

// The refusal that protects somebody else's work. `uci revert` discards the WHOLE staging buffer for
// a config, so running with foreign staged edits means our rollback would delete them.
func TestApply_RefusesWhenSomeoneElseHasStagedChanges(t *testing.T) {
	p := planFor(t)
	rr := &RecordRunner{Responses: map[string]string{
		"uci changes":      "network.lan.ipaddr='192.168.9.1'",
		"uci show network": liveUCIShow,
	}}
	res, err := p.Apply(rr)
	if err == nil {
		t.Fatal("Apply proceeded with foreign staged changes present")
	}
	if res.Applied {
		t.Fatal("Applied is set despite the refusal")
	}
	if !strings.Contains(err.Error(), "192.168.9.1") {
		t.Errorf("the error should show WHAT is staged so it can be judged: %v", err)
	}
	for _, c := range rr.Cmds {
		if strings.HasPrefix(c, "uci set") || strings.Contains(c, "commit") {
			t.Fatalf("something was written despite the refusal: %s", c)
		}
	}
}

// The stop switch: the router changed after the plan was built.
func TestApply_RefusesWhenTheConfigMovedUnderneath(t *testing.T) {
	p, err := BuildPlanFor(newIface("awg0"), testRouterProtos, "vpn", liveUCIShow, liveFirewallShow)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	moved := strings.Replace(liveUCIShow, "network.awg0.mtu='1280'", "network.awg0.mtu='1400'", 1)
	rr := &RecordRunner{Responses: map[string]string{
		"uci changes":      "",
		"uci show network": moved,
	}}

	res, err := p.Apply(rr)
	if err == nil {
		t.Fatal("Apply overwrote a configuration that had changed since the plan was built")
	}
	if len(res.Preflight) == 0 {
		t.Error("the differences that caused the refusal were not reported")
	}
	for _, c := range rr.Cmds {
		if strings.HasPrefix(c, "uci set") {
			t.Fatalf("a write was issued despite the preflight failing: %s", c)
		}
	}
}

// The case the staging buffer exists for: the write went in, the read-back does not match, and
// nothing must reach the disk.
func TestApply_RevertsRatherThanCommitOnAMismatch(t *testing.T) {
	p := planFor(t)
	rr := &RecordRunner{Responses: map[string]string{
		"uci changes": "",
		// Never updated after the writes: the read-back looks nothing like what was intended.
		"uci show network": liveUCIShow,
	}}

	res, err := p.Apply(rr)
	if err == nil {
		t.Fatal("Apply committed a configuration it had not verified")
	}
	if res.Rollback != RollbackDone {
		t.Errorf("the staging buffer was not reverted after the mismatch: %q %+v", res.Rollback, res.Reverts)
	}
	if res.Applied {
		t.Error("Applied is set although nothing was committed")
	}
	joined := strings.Join(rr.Cmds, "\n")
	if !strings.Contains(joined, "uci revert network") {
		t.Errorf("no revert was issued:\n%s", joined)
	}
	if strings.Contains(joined, "uci commit") {
		t.Errorf("a commit was issued despite the failed verification:\n%s", joined)
	}
	if len(res.Verify) == 0 {
		t.Error("the verification differences were not reported")
	}
}

// A failing uci command mid-batch leaves a half-written buffer; it has to be discarded, not left for
// the next person to find.
func TestApply_RevertsWhenACommandFails(t *testing.T) {
	p := planFor(t)
	boom := p.Commands[3]
	rr := &RecordRunner{
		Responses: map[string]string{"uci changes": "", "uci show network": liveUCIShow},
		Fail:      map[string]error{boom: errors.New("uci: entry not found")},
	}

	res, err := p.Apply(rr)
	if err == nil {
		t.Fatal("Apply reported success although a command failed")
	}
	if res.Rollback != RollbackDone {
		t.Errorf("a half-written staging buffer was left behind: %q %+v", res.Rollback, res.Reverts)
	}
	if !strings.Contains(err.Error(), boom) {
		t.Errorf("the error does not name the command that failed: %v", err)
	}
}

func TestApply_NeverReturnsPrivateKeyCommand(t *testing.T) {
	p := planFor(t)
	var privateCommand string
	for _, command := range p.Commands {
		if strings.Contains(command, "private_key=") {
			privateCommand = command
			break
		}
	}
	if privateCommand == "" {
		t.Fatal("fixture has no private-key command")
	}
	rr := &RecordRunner{
		Responses: map[string]string{"uci changes": "", "uci show network": liveUCIShow},
		Fail:      map[string]error{privateCommand: errors.New("uci rejected secret command")},
	}
	res, err := p.Apply(rr)
	if err == nil {
		t.Fatal("private-key write failure reported success")
	}
	secret := p.Intended.PrivateKey
	if secret == "" {
		t.Fatal("fixture has no private key")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(strings.Join(res.Ran, "\n"), secret) {
		t.Fatalf("private key leaked through result/error: %v / %#v", err, res.Ran)
	}
}

// The firewall buffer is only reverted when the plan touched it — reverting a config we never wrote
// to would discard whatever else was staged there.
func TestApply_RevertsFirewallOnlyWhenItWasInvolved(t *testing.T) {
	noZone, err := BuildPlanFor(newIface("awg9"), testRouterProtos, "", liveUCIShow, liveFirewallShow)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	rr := &RecordRunner{Responses: map[string]string{"uci changes": "", "uci show network": liveUCIShow}}
	_, _ = noZone.Apply(rr)

	joined := strings.Join(rr.Cmds, "\n")
	if !strings.Contains(joined, "uci revert network") {
		t.Error("the network buffer should still be reverted")
	}
	if strings.Contains(joined, "uci revert firewall") {
		t.Error("the firewall buffer was reverted although this plan never wrote to it")
	}
}
