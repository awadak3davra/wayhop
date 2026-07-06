package pbr

import (
	"fmt"
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

// Teardown removes everything Apply installed; best-effort (errors ignored).
func (pl *Plan) Teardown(r Runner, opt Options) error {
	opt.withDefaults()
	for _, c := range pl.RenderTeardown(opt) {
		name, args := splitCmd(c)
		_, _ = r.Run("", name, args...)
	}
	return nil
}

// DryRun returns a human-readable preview of what Apply would execute: the full nft
// ruleset first, then each ip command. For the UI / diagnostics.
func (pl *Plan) DryRun(opt Options) []string {
	opt.withDefaults()
	return append([]string{pl.RenderNft()}, pl.RenderIP(opt)...)
}
