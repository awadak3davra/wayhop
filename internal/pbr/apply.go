package pbr

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// Runner executes the apply/teardown commands. Abstracted so the apply logic is unit-
// tested with a recorder (and dry-run is free); ExecRunner runs them for real on the
// router. stdin is fed to the command (used for `nft -f -`).
type Runner interface {
	Run(stdin, name string, args ...string) (string, error)
}

// ExecRunner runs real commands (Linux router only — nft/ip don't exist elsewhere).
type ExecRunner struct{}

func (ExecRunner) Run(stdin, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// RecordRunner records calls instead of executing them (dry-run / tests). It fails any
// call whose "name args" line contains a key in Fail (value = the error to return).
type RecordRunner struct {
	Calls []string // "name args" per call, in order
	Stdin []string // stdin per call (parallel to Calls)
	Fail  map[string]error
}

func (r *RecordRunner) Run(stdin, name string, args ...string) (string, error) {
	line := strings.TrimSpace(name + " " + strings.Join(args, " "))
	r.Calls = append(r.Calls, line)
	r.Stdin = append(r.Stdin, stdin)
	for k, e := range r.Fail {
		if strings.Contains(line, k) {
			return "", e
		}
	}
	return "", nil
}

// splitCmd turns a rendered command string into (name, args). The rendered commands
// never contain quoted/spaced arguments, so whitespace splitting is safe.
func splitCmd(s string) (string, []string) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return "", nil
	}
	return f[0], f[1:]
}

// Apply installs the plan: the nft table loads in one atomic, self-flushing `nft -f -`
// transaction; then the ip rules/routes are removed-then-added so re-apply is idempotent.
// On the live router this MUST run inside the fail-safe window (see Phase 2 in the roadmap).
func (pl *Plan) Apply(r Runner, opt Options) error {
	opt.withDefaults()
	if _, err := r.Run(pl.RenderNft(), "nft", "-f", "-"); err != nil {
		return fmt.Errorf("nft load: %w", err)
	}
	for _, c := range pl.ipTeardown(opt) { // clear stale rules/routes first (ignore errors)
		name, args := splitCmd(c)
		_, _ = r.Run("", name, args...)
	}
	for _, c := range pl.RenderIP(opt) {
		name, args := splitCmd(c)
		if _, err := r.Run("", name, args...); err != nil {
			// A per-egress `default dev <iface>` route legitimately fails ONLY when the tunnel iface
			// is DOWN at apply time (it comes up later; and for a FailClosed kill-switch egress the
			// blackhole fallback in the SAME table catches the traffic meanwhile). Skip just that
			// missing-device failure so a single down tunnel can't tear out the WHOLE plane (every
			// carve-out + the kill-switch blackhole → failing OPEN). ANY OTHER failure — including a
			// generic apply error on that line — still aborts, so the caller rolls back / abstains
			// rather than commit a half-applied plane.
			if isDefaultDevRoute(c) && isMissingDeviceErr(err) {
				continue
			}
			return fmt.Errorf("%s: %w", c, err)
		}
	}
	// Flow-offload loads LAST, in its OWN best-effort transaction (added to the table the core
	// plane created above). A kernel/NIC that rejects the flowtable or `flags offload` must degrade
	// offload ONLY — the routing plane is already up — so this failure is logged and swallowed, never
	// returned (returning it would fail the whole apply and defeat the split).
	if off := pl.RenderOffload(); off != "" {
		if _, err := r.Run(off, "nft", "-f", "-"); err != nil {
			log.Printf("pbr: flow-offload not applied — routing plane is up, continuing without offload: %v", err)
		}
	}
	return nil
}

// isDefaultDevRoute reports whether c is a per-egress `… route replace default dev <iface> …` line
// (v4 or v6) — the only Apply command with a benign, recoverable failure mode (the tunnel iface is
// absent), and only then (see isMissingDeviceErr).
func isDefaultDevRoute(c string) bool {
	return strings.Contains(c, "route replace default dev ")
}

// isMissingDeviceErr reports whether err is iproute2's "device is absent" failure. ExecRunner wraps
// the command's stderr into the error (`%w: %s`), so a down tunnel surfaces as "... Cannot find
// device \"awgN\"" / "No such device"; a generic error (e.g. a real apply fault) does not match and
// stays fatal.
func isMissingDeviceErr(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "cannot find device") || strings.Contains(s, "no such device")
}

// TeardownResult is what a teardown actually achieved.
//
// Teardown is legitimately best-effort — removing an object that is already gone is a success, and
// `nft delete table` / `ip rule del` both exit non-zero in that case — but "the object was already
// absent" and "the command failed for some other reason" are not the same outcome. Collapsing them
// meant a teardown that could not remove a live ip-rule reported exactly like one that removed
// everything, while the rule kept steering traffic and WayHop had already forgotten the plan that
// created it.
type TeardownResult struct {
	Commands int      // how many teardown commands were issued
	Failed   []string // commands that failed for a reason OTHER than the object already being gone
}

// Clean reports whether the kernel is known to be free of this plan.
func (t TeardownResult) Clean() bool { return len(t.Failed) == 0 }

// Err returns a non-nil error when something is left behind, naming what.
func (t TeardownResult) Err() error {
	if t.Clean() {
		return nil
	}
	return fmt.Errorf("kernel plane not fully removed: %s", strings.Join(t.Failed, "; "))
}

// TeardownVerified removes everything Apply installed and reports what could not be removed.
// Prefer it over Teardown wherever the answer is shown to a user or drives a decision.
func (pl *Plan) TeardownVerified(r Runner, opt Options) TeardownResult {
	opt.withDefaults()
	var res TeardownResult
	for _, c := range pl.RenderTeardown(opt) {
		name, args := splitCmd(c)
		res.Commands++
		if _, err := r.Run("", name, args...); err != nil && !isAlreadyAbsentErr(err) {
			res.Failed = append(res.Failed, c)
		}
	}
	return res
}

// isAlreadyAbsentErr reports whether err means the object was not there to begin with — the normal,
// successful outcome of an idempotent teardown. Anything else is a real failure to remove.
func isAlreadyAbsentErr(err error) bool {
	s := strings.ToLower(err.Error())
	for _, m := range []string{
		"no such file or directory", // nft: table/chain absent
		"does not exist",            // nft: newer wording
		"no such process",           // ip rule del: RTNETLINK answers
		"cannot find device",        // ip route del on a vanished iface
		"no such device",
		"not found",
	} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// Teardown removes everything Apply installed; best-effort (errors ignored).
// Kept for callers that genuinely cannot act on the outcome; it always reports nil, which is why
// anything that REPORTS the result should use TeardownVerified instead.
func (pl *Plan) Teardown(r Runner, opt Options) error {
	pl.TeardownVerified(r, opt)
	return nil
}

// DryRun returns a human-readable preview of what Apply would execute: the full nft
// ruleset first, then each ip command. For the UI / diagnostics.
func (pl *Plan) DryRun(opt Options) []string {
	opt.withDefaults()
	out := append([]string{pl.RenderNft()}, pl.RenderIP(opt)...)
	if off := pl.RenderOffload(); off != "" { // best-effort second nft transaction (see Apply)
		out = append(out, off)
	}
	return out
}
