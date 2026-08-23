package netvpn

import (
	"errors"
	"strings"
	"testing"
)

// Rollback fault injection.
//
// The defect these tests are the regression for: `revert` issued both `uci revert` commands, threw
// away both exit statuses, and set Reverted=true unconditionally. Every failure path therefore
// reported "reverted" — including the one where the revert itself failed and the router was left
// holding a staged change nobody could see. A rollback is only worth having if a failed one is
// distinguishable from a successful one.

// stagedRemoval builds a removal plan against the AX3000T-shaped fixture and a runner whose reads
// answer as a router with the interface still present would.
func stagedRemoval(t *testing.T) (RemovalPlan, *RecordRunner) {
	t.Helper()
	p, err := BuildRemovalPlan("wrprobe0", removeNetUCI, removeFwUCI)
	if err != nil {
		t.Fatal(err)
	}
	rr := &RecordRunner{
		Responses: map[string]string{
			"uci changes network":  "",
			"uci changes firewall": "",
			"uci show network":     removeNetUCI,
			"uci show firewall":    removeFwUCI,
		},
		Fail: map[string]error{},
	}
	return p, rr
}

// The read-back is answered with the unchanged config, so VerifyRemoved finds the interface still
// there and the applier rolls back. That is the trigger for every case below.
func revertOutcomes(t *testing.T, failing map[string]error) (ApplyResult, error) {
	t.Helper()
	p, rr := stagedRemoval(t)
	for cmd, err := range failing {
		rr.Fail[cmd] = err
	}
	res, err := p.Apply(rr)
	if err == nil {
		t.Fatal("the applier committed a removal whose read-back still showed the interface")
	}
	if res.Applied {
		t.Fatal("it reported the removal as applied")
	}
	return res, err
}

func outcome(t *testing.T, res ApplyResult, cfg string) RevertOutcome {
	t.Helper()
	for _, r := range res.Reverts {
		if r.Config == cfg {
			return r
		}
	}
	t.Fatalf("no rollback outcome was recorded for %q; got %+v", cfg, res.Reverts)
	return RevertOutcome{}
}

// Case 1: the network revert fails and the firewall revert succeeds. The firewall attempt must still
// happen — stopping at the first failure would strand a staged firewall change as well — and the
// result must not read as a completed rollback.
func TestRollback_NetworkFailsFirewallSucceeds(t *testing.T) {
	res, err := revertOutcomes(t, map[string]error{"uci revert network": errors.New("exit status 1")})

	if res.Rollback != RollbackPartial {
		t.Errorf("rollback state = %q, want %q: one buffer was discarded and one was not", res.Rollback, RollbackPartial)
	}
	if o := outcome(t, res, "network"); o.OK {
		t.Error("the network revert failed but was recorded as successful")
	}
	if o := outcome(t, res, "firewall"); !o.OK {
		t.Error("the firewall revert was never attempted after the network one failed")
	}
	if !strings.Contains(err.Error(), "uci revert network") {
		t.Errorf("the failed rollback is not in the error, so nothing reports it:\n%v", err)
	}
	if strings.Contains(err.Error(), ", and the staged changes were rolled back") {
		t.Errorf("the error claims a completed rollback after a half-failed one:\n%v", err)
	}
}

// Case 2: the mirror image. The network buffer is cleared, the firewall one is not — which is the
// state that leaves a zone naming an interface the removal was about to take away.
func TestRollback_NetworkSucceedsFirewallFails(t *testing.T) {
	res, err := revertOutcomes(t, map[string]error{"uci revert firewall": errors.New("exit status 1")})

	if res.Rollback != RollbackPartial {
		t.Errorf("rollback state = %q, want %q", res.Rollback, RollbackPartial)
	}
	if o := outcome(t, res, "network"); !o.OK {
		t.Error("the network revert succeeded but was not recorded as such")
	}
	if o := outcome(t, res, "firewall"); o.OK {
		t.Error("the firewall revert failed but was recorded as successful")
	}
	if !strings.Contains(err.Error(), "uci revert firewall") {
		t.Errorf("the failed rollback is not in the error:\n%v", err)
	}
}

// Case 3: both fail. Nothing was put back, and the result has to say exactly that rather than fall
// into the same "not reverted" bucket as a run where no rollback was ever needed.
func TestRollback_BothFail(t *testing.T) {
	res, err := revertOutcomes(t, map[string]error{
		"uci revert network":  errors.New("exit status 1"),
		"uci revert firewall": errors.New("exit status 1"),
	})

	if res.Rollback != RollbackFailed {
		t.Errorf("rollback state = %q, want %q", res.Rollback, RollbackFailed)
	}
	for _, cfg := range []string{"network", "firewall"} {
		if o := outcome(t, res, cfg); o.OK {
			t.Errorf("the %s revert failed but was recorded as successful", cfg)
		}
	}
	if !strings.Contains(err.Error(), "the rollback FAILED") {
		t.Errorf("a total rollback failure is not stated in the error:\n%v", err)
	}
}

// Case 4: both succeed. The honest-reporting change must not have made the good path stop reporting
// a rollback — a state nobody can reach is not a state.
func TestRollback_BothSucceed(t *testing.T) {
	res, err := revertOutcomes(t, nil)

	if res.Rollback != RollbackDone {
		t.Errorf("rollback state = %q, want %q", res.Rollback, RollbackDone)
	}
	if len(res.Reverts) != 2 {
		t.Fatalf("both configs must be reverted, got %+v", res.Reverts)
	}
	for _, r := range res.Reverts {
		if !r.OK || r.Err != "" {
			t.Errorf("%s: a successful revert carries a failure: %+v", r.Config, r)
		}
	}
	if !strings.Contains(err.Error(), "the staged changes were rolled back") {
		t.Errorf("a successful rollback is not stated in the error:\n%v", err)
	}
}

// Case 5: the verification failure is what triggers the rollback at all. Without this the four cases
// above could pass against a path that never reverts.
func TestRollback_VerifyFailureTriggersIt(t *testing.T) {
	res, err := revertOutcomes(t, nil)

	if len(res.Verify) == 0 {
		t.Fatal("the read-back showed the interface still present but no verification difference was recorded")
	}
	joined := strings.Join(res.Ran, "\n")
	for _, want := range []string{"uci revert network", "uci revert firewall"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%q was never issued:\n%s", want, joined)
		}
	}
	for _, c := range res.Ran {
		if strings.HasPrefix(c, "uci commit") || strings.Contains(c, "ifdown") {
			t.Errorf("it reached the mutating tail despite a failed verification: %q", c)
		}
	}
	if !strings.Contains(err.Error(), "not a clean removal") {
		t.Errorf("the rollback was not attributed to the verification:\n%v", err)
	}
}

// Case 6: the claim the whole change exists for. Nothing in the result or the error may say the
// router was put back while a buffer is still staged.
func TestRollback_NeverClaimsRevertedWhenItIsNot(t *testing.T) {
	cases := map[string]map[string]error{
		"network fails":  {"uci revert network": errors.New("exit status 1")},
		"firewall fails": {"uci revert firewall": errors.New("exit status 1")},
		"both fail": {
			"uci revert network":  errors.New("exit status 1"),
			"uci revert firewall": errors.New("exit status 1"),
		},
	}
	for name, failing := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := revertOutcomes(t, failing)
			if res.Rollback == RollbackDone {
				t.Errorf("state %q claims a completed rollback while a revert failed", res.Rollback)
			}
			if res.Rollback == RollbackNone {
				t.Errorf("state %q claims no rollback was attempted, but two were", res.Rollback)
			}
			// The API's `reverted` flag is derived from this comparison, so it is the exact expression
			// a consumer would use.
			if res.Rollback == RollbackDone {
				t.Error(`the API would report "reverted": true`)
			}
			if strings.Contains(err.Error(), ", and the staged changes were rolled back") {
				t.Errorf("the operator-facing error claims a rollback that did not happen:\n%v", err)
			}
		})
	}
}

// The apply path shares the rollback helper, so it must report the same way. It reverts firewall only
// when the plan touched it, so a failed network revert there is a total failure, not a partial one.
func TestRollback_ApplyPathReportsTheSameWay(t *testing.T) {
	noZone, err := BuildPlanFor(newIface("awg9"), testRouterProtos, "", liveUCIShow, liveFirewallShow)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	rr := &RecordRunner{
		Responses: map[string]string{"uci changes": "", "uci show network": liveUCIShow},
		Fail: map[string]error{
			"uci revert network": errors.New("exit status 1"),
		},
	}
	// A staged write that reads back unchanged fails verification and rolls back.
	res, err := noZone.Apply(rr)
	if err == nil {
		t.Fatal("the applier committed a plan whose read-back did not match")
	}
	if res.Rollback != RollbackFailed {
		t.Errorf("rollback state = %q, want %q: the only config this plan touched could not be reverted",
			res.Rollback, RollbackFailed)
	}
	if len(res.Reverts) != 1 || res.Reverts[0].Config != "network" {
		t.Errorf("a plan with no zone must not report a firewall rollback: %+v", res.Reverts)
	}
}

// A failed revert echoes the assignment uci rejected, and for this package's writes that assignment
// carries the interface's private key. It must not reach the result, the error or a log.
func TestRollback_FailureOutputIsScrubbed(t *testing.T) {
	const secret = "cHJpdmF0ZUtleU1hdGVyaWFs"
	p, rr := stagedRemoval(t)
	rr.Fail["uci revert network"] = errors.New("exit status 1")
	rr.Responses["uci revert network"] = "uci: cannot revert network.wrprobe0.private_key=" + secret

	res, err := p.Apply(rr)
	if err == nil {
		t.Fatal("the applier committed a removal whose read-back still showed the interface")
	}
	o := outcome(t, res, "network")
	if strings.Contains(o.Err, secret) {
		t.Errorf("the key material reached the result: %q", o.Err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the key material reached the error:\n%v", err)
	}
	// Scrubbed, not dropped: the operator still has to be able to see which option uci choked on.
	if !strings.Contains(o.Err, "private_key") || !strings.Contains(o.Err, "present") {
		t.Errorf("the failure was scrubbed into uselessness: %q", o.Err)
	}
}

// The refusal path prints somebody else's staged changes back at them, and those can carry a key
// belonging to a tunnel this removal never touched.
func TestRollback_StagedChangesRefusalIsScrubbed(t *testing.T) {
	const secret = "b3RoZXJUdW5uZWxLZXlNYXRlcmlhbA=="
	p, rr := stagedRemoval(t)
	rr.Responses["uci changes network"] = "network.other.private_key='" + secret + "'"

	_, err := p.Apply(rr)
	if err == nil {
		t.Fatal("the removal proceeded while somebody else had edits staged")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("another tunnel's key was echoed back in the refusal:\n%v", err)
	}
	if !strings.Contains(err.Error(), "uncommitted changes") {
		t.Errorf("it refused for some other reason than the staged edits: %v", err)
	}
}
