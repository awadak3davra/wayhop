package netvpn

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// openwrt_apply.go runs a Plan against a router, and refuses to more often than it agrees to.
//
// The sequence rests on a property of uci that was MEASURED on the AX3000T rather than assumed,
// because the whole safety argument depends on it: `uci set` writes to a staging buffer, `uci show`
// reflects that buffer, /etc/config is untouched until `uci commit`, and `uci revert` discards the
// buffer completely — verified by staging a probe section, seeing it in `uci show`, confirming
// /etc/config/network did not contain it, reverting, and finding no trace in either.
//
// So the order is: check nothing else is staged, compare the device against what the plan expected,
// write into the buffer, read the buffer back, compare against what was intended, and only then
// commit. A mismatch at the last step costs a revert and nothing has reached the disk.
//
// The first step exists because of the same experiment. `uci revert network` discards EVERYTHING
// staged for that config, not just ours — so if somebody has pending edits when we start, our
// rollback would destroy their work. Finding staged changes is therefore a refusal, not a warning.

// Runner executes commands on the router. Matching internal/pbr's shape (stdin, name, args) so the
// two native-write paths are driven the same way and a recording runner can stand in for a device.
type Runner interface {
	Run(stdin, name string, args ...string) (string, error)
}

// RollbackState says what a rollback achieved. It is an enum rather than a bool because "not
// reverted" has to distinguish three states an operator would act on differently: no rollback was
// needed, one was attempted and failed, or one half-worked and left a staging buffer behind.
type RollbackState string

const (
	RollbackNone    RollbackState = ""         // no rollback was attempted
	RollbackDone    RollbackState = "reverted" // every attempted revert was confirmed
	RollbackPartial RollbackState = "partial"  // some buffers were discarded, some were not
	RollbackFailed  RollbackState = "failed"   // nothing could be discarded
)

// RevertOutcome is what one `uci revert` achieved, per config. A rollback that cleared the network
// buffer and failed on firewall leaves the router in neither the old state nor the new one, and the
// only way to say which half is stranded is to record them separately.
type RevertOutcome struct {
	Config string // "network" | "firewall"
	OK     bool
	Err    string // scrubbed output of the failed command, empty when OK
}

// ApplyResult records what happened, including the case where nothing did.
type ApplyResult struct {
	Applied   bool            // the change reached /etc/config
	Rollback  RollbackState   // what discarding the staging buffer achieved, if it was tried
	Reverts   []RevertOutcome // per-config detail behind Rollback
	Preflight []Difference    // why it refused before writing, if it did
	Verify    []Difference    // why it reverted after writing, if it did
	Ran       []string        // the commands actually issued, in order
}

// Apply executes the plan. It returns an error for every path that did not end in a committed
// change, so a caller cannot mistake a refusal for success by ignoring the result struct.
func (p Plan) Apply(r Runner) (ApplyResult, error) {
	var res ApplyResult
	sh := func(cmd string) (string, error) {
		res.Ran = append(res.Ran, scrubUCI(cmd))
		return r.Run("", "sh", "-c", cmd)
	}

	// 1. Somebody else's staged edits make our rollback destructive.
	changes, err := sh("uci changes")
	if err != nil {
		return res, fmt.Errorf("apply %s: reading uci changes: %w", p.Iface, err)
	}
	if strings.TrimSpace(changes) != "" {
		return res, fmt.Errorf("apply %s: the router has uncommitted uci changes already staged, and "+
			"a rollback here would discard them — commit or revert them first:\n%s",
			p.Iface, scrubUCI(strings.TrimSpace(changes)))
	}

	// 2. The device must still look like the plan's snapshot.
	before, err := sh("uci show network")
	if err != nil {
		return res, fmt.Errorf("apply %s: reading network config: %w", p.Iface, err)
	}
	if d := p.PreflightAgainst(before); len(d) > 0 {
		res.Preflight = d
		return res, fmt.Errorf("apply %s: the configuration changed after this plan was built, so "+
			"applying it would discard that change (%d difference(s), first: %s)",
			p.Iface, len(d), d[0])
	}

	// 3. Write into the staging buffer. Nothing is on disk yet.
	for _, c := range p.Commands {
		if _, err := sh(c); err != nil {
			rb := p.revert(sh, &res)
			return res, errors.Join(fmt.Errorf("apply %s: %q failed%s: %w",
				p.Iface, scrubUCI(c), rollbackNote(res.Rollback), err), rb)
		}
	}

	// 4. Read the buffer back. "The commands exited 0" is not the claim being made.
	after, err := sh("uci show network")
	if err != nil {
		rb := p.revert(sh, &res)
		return res, errors.Join(fmt.Errorf("apply %s: re-reading after the write%s: %w",
			p.Iface, rollbackNote(res.Rollback), err), rb)
	}
	if d := p.VerifyAgainst(after); len(d) > 0 {
		res.Verify = d
		rb := p.revert(sh, &res)
		return res, errors.Join(fmt.Errorf("apply %s: the staged configuration does not match what was "+
			"intended, so nothing was committed (%d difference(s), first: %s)%s",
			p.Iface, len(d), d[0], rollbackNote(res.Rollback)), rb)
	}

	// 5. Only now does anything reach the disk.
	for _, c := range p.Commit {
		if _, err := sh(c); err != nil {
			return res, fmt.Errorf("apply %s: %q failed AFTER the configuration was verified — the "+
				"change may be half-applied, check `uci changes` and the interface state: %w",
				p.Iface, c, err)
		}
	}
	res.Applied = true
	return res, nil
}

// revert discards the staging buffer for every config the plan touched.
func (p Plan) revert(sh func(string) (string, error), res *ApplyResult) error {
	cfgs := []string{"network"}
	if p.Zone != "" {
		cfgs = append(cfgs, "firewall")
	}
	return revertConfigs(sh, res, cfgs...)
}

// revertConfigs discards the named staging buffers and records what that actually achieved.
//
// Every config is attempted even after one fails: stopping would leave a buffer staged that nobody
// asked for and nothing reports. The returned error is nil only when every attempt was confirmed, so
// a caller can never read silence as a successful rollback.
func revertConfigs(sh func(string) (string, error), res *ApplyResult, cfgs ...string) error {
	var errs []error
	for _, cfg := range cfgs {
		cmd := "uci revert " + cfg
		out, err := sh(cmd)
		oc := RevertOutcome{Config: cfg, OK: err == nil}
		if err != nil {
			oc.Err = scrubUCI(strings.TrimSpace(out))
			e := fmt.Errorf("rollback: %q failed, so the %s staging buffer may still hold this change: %w",
				cmd, cfg, err)
			if oc.Err != "" {
				e = fmt.Errorf("%w: %s", e, oc.Err)
			}
			errs = append(errs, e)
		}
		res.Reverts = append(res.Reverts, oc)
	}
	switch {
	case len(cfgs) == 0:
		res.Rollback = RollbackNone
	case len(errs) == 0:
		res.Rollback = RollbackDone
	case len(errs) == len(cfgs):
		res.Rollback = RollbackFailed
	default:
		res.Rollback = RollbackPartial
	}
	return errors.Join(errs...)
}

// rollbackNote states what the rollback achieved, so an operator-facing message never has to assume
// it worked. The alternative — a fixed ", reverted" — is a claim about a command whose exit status
// was never read.
func rollbackNote(st RollbackState) string {
	switch st {
	case RollbackDone:
		return ", and the staged changes were rolled back"
	case RollbackPartial:
		return ", and the rollback only partly succeeded — some staged changes are still in the buffer"
	case RollbackFailed:
		return ", and the rollback FAILED — the staged changes are still in the buffer"
	default:
		return ""
	}
}

// uciSecretRe matches the option assignments this package writes that carry key material, in both
// the `uci show` form (`network.wg0.private_key='…'`) and the command form uci echoes back when it
// rejects one (`uci set network.wg0.private_key=…`).
var uciSecretRe = regexp.MustCompile(`((?:private_key|preshared_key)\s*=\s*)('[^']*'|"[^"]*"|\S+)`)

// scrubUCI removes key material from raw router output before it reaches an error, a result or a
// log. uci quotes the assignment it choked on, and for this package's writes that assignment is the
// interface's private key.
func scrubUCI(s string) string {
	return uciSecretRe.ReplaceAllStringFunc(s, func(m string) string {
		i := strings.Index(m, "=")
		return m[:i+1] + redact(strings.Trim(m[i+1:], `'"`))
	})
}

// RecordRunner captures commands instead of running them, and answers reads from a script. It exists
// so the apply path can be tested at all: the alternative is a live router, and a test that needs one
// is a test nobody runs.
type RecordRunner struct {
	Cmds []string
	// Responses maps a command to what it should return. A command with no entry returns "".
	Responses map[string]string
	// Fail maps a command to an error it should produce.
	Fail map[string]error
	// OnCommand fires before each command, so a test can change what the next read will return —
	// which is how "the router changed underneath us" is simulated.
	OnCommand func(cmd string, rr *RecordRunner)
}

func (rr *RecordRunner) Run(stdin, name string, args ...string) (string, error) {
	cmd := name
	if len(args) > 0 {
		cmd = args[len(args)-1] // sh -c "<cmd>"
	}
	rr.Cmds = append(rr.Cmds, cmd)
	if rr.OnCommand != nil {
		rr.OnCommand(cmd, rr)
	}
	if err, ok := rr.Fail[cmd]; ok {
		// A failing command still prints: the two maps are not exclusive, so a test can give a command
		// both an error and the output the router would have written to stderr with it.
		return rr.Responses[cmd], err
	}
	return rr.Responses[cmd], nil
}
