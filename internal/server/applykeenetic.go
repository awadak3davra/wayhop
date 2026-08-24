package server

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"wayhop/internal/keenetic"
	"wayhop/internal/nativeplan"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
)

var (
	errExactKeeneticUnavailable = errors.New("exact Keenetic native adapter is unavailable")
	errExactKeeneticPlan        = errors.New("exact Keenetic native plan is invalid")
	errExactKeeneticApply       = errors.New("exact Keenetic native operation failed")
)

const (
	exactKeeneticMaxCommands     = 4096
	exactKeeneticMaxCommandBytes = 8192
	exactKeeneticCleanupTimeout  = 20 * time.Second
	exactKeeneticSaveCommand     = "system configuration save"
	exactKeeneticNDMCPath        = "/bin/ndmc"
	exactKeeneticNDMCTimeout     = 20 * time.Second
	exactKeeneticNDMCOutputLimit = 1 << 20
	exactKeeneticCompatibilityIF = "wrtun0"
)

type exactKeeneticBatchRunner interface {
	ParseBatch(context.Context, []string) ([]byte, error)
}

type exactKeeneticCommandFunc func(context.Context, string, string, ...string) (string, error)

// exactKeeneticNDMCRunner is the on-router transport. It feeds one already-validated batch to one
// ndmc interactive process so NDM configuration context is preserved between commands.
type exactKeeneticNDMCRunner struct {
	run exactKeeneticCommandFunc
}

func newExactKeeneticNDMCRunner() *exactKeeneticNDMCRunner {
	return &exactKeeneticNDMCRunner{run: runExactKeeneticCommand}
}

func (runner *exactKeeneticNDMCRunner) ParseBatch(ctx context.Context, commands []string) ([]byte, error) {
	if runner == nil || runner.run == nil || len(commands) == 0 ||
		len(commands) > exactKeeneticMaxCommands || !validExactKeeneticCommands(commands, false) {
		return nil, errExactKeeneticPlan
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	// One `ndmc -c` per command, not a batch on stdin.
	//
	// Interactive ndmc needs a terminal: with stdin piped it reports "unable to update a window line
	// size", closes the NDM connection, and **exits 0 having executed nothing**. A daemon has no tty,
	// so the whole batch silently did nothing while the process reported success — the failure mode
	// that a postcondition check exists to catch, and did.
	//
	// `-c` accepts exactly one command, so a block has to be flattened: KeeneticOS takes the full
	// path in one line (`interface Wireguard0 description …` is accepted and saved), which is how the
	// context that the interactive session used to provide is carried instead.
	var out strings.Builder
	prefix := ""
	for _, command := range commands {
		line := command
		switch {
		case strings.HasPrefix(command, "interface "):
			prefix = command
		case prefix != "":
			line = prefix + " " + command
		}
		output, err := runner.run(ctx, "", exactKeeneticNDMCPath, "-c", line)
		if err != nil || exactKeeneticSemanticFailure(output) {
			return nil, errExactKeeneticApply
		}
		out.WriteString(output)
		out.WriteString("\n")
	}
	return []byte(out.String()), nil
}

// ndmc may exit zero even when NDM rejected one command. The interactive client can expose the
// rejection either as the same JSON status object returned by RCI or as diagnostic text. Treat
// both as a failed batch and never reflect the device response (which may contain credentials).
func exactKeeneticSemanticFailure(output string) bool {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return false
	}
	var decoded any
	if json.Unmarshal([]byte(trimmed), &decoded) == nil && exactKeeneticJSONError(decoded) {
		return true
	}
	lower := strings.ToLower(trimmed)
	for _, marker := range []string{
		"no such command", "unknown command", "invalid command", "syntax error",
		"command::base", "status: error", "status = error", "error:",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func exactKeeneticJSONError(value any) bool {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if exactKeeneticJSONError(item) {
				return true
			}
		}
	case map[string]any:
		for key, item := range typed {
			if strings.EqualFold(key, "status") {
				if status, ok := item.(string); ok && strings.EqualFold(status, "error") {
					return true
				}
			}
			if exactKeeneticJSONError(item) {
				return true
			}
		}
	}
	return false
}

func runExactKeeneticCommand(ctx context.Context, stdin, name string, args ...string) (string, error) {
	// The shape is fixed: `ndmc -c "<one command>"`, nothing on stdin. Interactive ndmc without a
	// terminal exits 0 without running anything, so accepting a stdin batch here would let a
	// no-op be reported as a successful Apply.
	if ctx == nil || name != exactKeeneticNDMCPath || stdin != "" ||
		len(args) != 2 || args[0] != "-c" ||
		args[1] == "" || len(args[1]) > exactKeeneticMaxCommandBytes {
		return "", errExactKeeneticPlan
	}
	runCtx, cancel := context.WithTimeout(ctx, exactKeeneticNDMCTimeout)
	defer cancel()
	output := newApplyHostCommandOutput(exactKeeneticNDMCOutputLimit, cancel)
	cmd := exec.CommandContext(runCtx, name, args...)
	cmd.Stdout = applyHostCommandWriter{output: output, retain: true}
	cmd.Stderr = applyHostCommandWriter{output: output}
	cmd.WaitDelay = applyHostCommandWaitDelay
	err := cmd.Run()
	switch {
	case output.exceededLimit():
		return "", errExactKeeneticApply
	case errors.Is(err, exec.ErrWaitDelay):
		return "", errExactKeeneticApply
	case errors.Is(ctx.Err(), context.Canceled):
		return "", context.Canceled
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(runCtx.Err(), context.DeadlineExceeded):
		return "", errExactKeeneticApply
	case err != nil:
		return "", errExactKeeneticApply
	default:
		return output.stdoutString(), nil
	}
}

// exactKeeneticNativeAdapter consumes only the authenticated NDM plan selected by the strict
// transaction. It never recompiles a Profile, discovers slots, or reads mutable Server config.
type exactKeeneticNativeAdapter struct {
	runner     exactKeeneticBatchRunner
	readConfig keeneticConfigReadFunc
}

func newExactKeeneticNativeAdapter(runner exactKeeneticBatchRunner) (*exactKeeneticNativeAdapter, error) {
	if runner == nil {
		return nil, errExactKeeneticUnavailable
	}
	return &exactKeeneticNativeAdapter{runner: runner, readConfig: readKeeneticRunningConfig}, nil
}

// prepare installs the target live but unsaved. Save belongs to commit, after every consumer plane
// has converged and obsolete authenticated resources have been removed.
func (adapter *exactKeeneticNativeAdapter) prepare(ctx context.Context, target nativeplan.Plan) error {
	if adapter == nil || adapter.runner == nil || adapter.readConfig == nil {
		return errExactKeeneticUnavailable
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if !validExactKeeneticTarget(target) {
		return errExactKeeneticPlan
	}
	plan := target.Keenetic
	// An adopted-only native plan has no interface mutation to prepare. Requiring an NDM
	// running-config read anyway makes compatibility recovery depend on the interactive CLI while
	// KeeneticOS is still booting, even though there is nothing this phase could verify or change.
	// External identities were already authenticated and checked before the executor lease; routes
	// and the complete native postcondition remain verified by commit/postcheck.
	if len(plan.Interfaces) == 0 {
		return nil
	}
	baseline, err := adapter.readConfig(ctx)
	if err != nil || strings.TrimSpace(baseline) == "" {
		return errExactKeeneticApply
	}
	attempted := &keenetic.Plan{}
	cleanup := func() {
		_ = adapter.cleanup(context.WithoutCancel(ctx), attempted)
	}
	for _, block := range plan.Interfaces {
		// A saved Keenetic interface is recreated by NDM before Entware starts. Re-sending its full
		// authenticated block during that early boot window is not idempotent: NDM can reject the
		// duplicate while the VPN subsystem is still settling, leaving recovery permanently blocked.
		// Exact sequence equality is sufficient proof that this block already materialized; skip
		// only that block and still verify the complete target below. Missing or partial blocks keep
		// the existing create-and-rollback path.
		if verifyExactKeeneticInterfaceBlocks([][]string{block}, baseline) {
			continue
		}
		attempted.Interfaces = append(attempted.Interfaces, append([]string(nil), block...))
		if err := context.Cause(ctx); err != nil {
			cleanup()
			return err
		}
		if _, err := adapter.runner.ParseBatch(ctx, append([]string(nil), block...)); err != nil {
			cleanup()
			return errExactKeeneticApply
		}
	}
	if len(plan.Interfaces) != 0 {
		running, err := adapter.readConfig(ctx)
		if err != nil || !verifyExactKeeneticInterfaceBlocks(plan.Interfaces, running) {
			cleanup()
			return errExactKeeneticApply
		}
	}
	return nil
}

func verifyExactKeeneticInterfaceBlocks(blocks [][]string, running string) bool {
	lines := normalizedNDMConfigLines(running)
	if len(blocks) == 0 || len(lines) == 0 {
		return false
	}
	for _, block := range blocks {
		if !containsExactNDMSequence(lines, normalizedNDMCommands(block)) {
			return false
		}
	}
	return true
}

// commit removes only the authenticated obsolete command identities and optionally persists the
// already-live candidate. OpenWrt removals are a type error, never silently ignored.
func (adapter *exactKeeneticNativeAdapter) commit(
	ctx context.Context,
	reconcile nativeplan.Reconciliation,
) error {
	if adapter == nil || adapter.runner == nil || adapter.readConfig == nil {
		return errExactKeeneticUnavailable
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if reconcile.Platform != platform.Keenetic ||
		reconcile.Target == nil || reconcile.Target.Platform != platform.Keenetic ||
		len(reconcile.OpenWrtRemovals) != 0 ||
		!validExactKeeneticTarget(*reconcile.Target) ||
		!validExactKeeneticTeardown(reconcile.KeeneticTeardown) {
		return errExactKeeneticPlan
	}
	target := *reconcile.Target
	teardown := reconcile.KeeneticTeardown
	restore := reconcile.KeeneticPriorityRestore
	// Adopted external interfaces are already identity-checked by the execution preflight and
	// postcondition adapter. When the authenticated native delta contains no NDM command at all,
	// waiting for the interactive running-config reader during early boot cannot prove or change
	// anything and can keep an otherwise healthy recovery journal open indefinitely.
	if exactKeeneticNativeMutationEmpty(target, teardown, restore) {
		return nil
	}
	cleanup := func() {
		_ = adapter.cleanup(context.WithoutCancel(ctx), target.Keenetic)
	}
	// The priority ladder goes in before the routes and as its own batch: each block carries its own
	// `interface X` context, and a default route that only half-lands is worse than one that does not
	// land at all.
	for _, block := range target.Keenetic.GlobalPriorityBlocks() {
		if _, err := adapter.runner.ParseBatch(ctx, append([]string(nil), block...)); err != nil {
			cleanup()
			return errExactKeeneticApply
		}
	}
	// Then the interfaces the previous plan raised and this one does not. AFTER the target ladder, so
	// the new top is already in place when the old one comes down: the reverse order would leave a
	// window with no tunnel above the WAN, and on a router carrying a family that window is a visible
	// drop. When the target has no ladder at all — the default rule went back to `direct` — this is
	// the only thing submitted, and handing the default back to the WAN is exactly what was asked.
	for _, block := range restore {
		if _, err := adapter.runner.ParseBatch(ctx, append([]string(nil), block...)); err != nil {
			cleanup()
			return errExactKeeneticApply
		}
	}
	if len(target.Keenetic.Routes) != 0 {
		if _, err := adapter.runner.ParseBatch(ctx, append([]string(nil), target.Keenetic.Routes...)); err != nil {
			cleanup()
			return errExactKeeneticApply
		}
	}
	if len(teardown) != 0 {
		if _, err := adapter.runner.ParseBatch(ctx, append([]string(nil), teardown...)); err != nil {
			cleanup()
			return errExactKeeneticApply
		}
	}
	running, err := adapter.readConfig(ctx)
	if err != nil || !verifyExactKeeneticRunningConfig(target, teardown, restore, running) {
		cleanup()
		return errExactKeeneticApply
	}
	return nil
}

func (adapter *exactKeeneticNativeAdapter) abort(ctx context.Context, target nativeplan.Plan) error {
	if adapter == nil || adapter.runner == nil || !validExactKeeneticTarget(target) {
		return errExactKeeneticPlan
	}
	return adapter.cleanup(ctx, target.Keenetic)
}

func (adapter *exactKeeneticNativeAdapter) cleanup(ctx context.Context, plan *keenetic.Plan) error {
	if adapter == nil || adapter.runner == nil || plan == nil {
		return errExactKeeneticUnavailable
	}
	commands := keenetic.TeardownCommands(plan)
	restore := plan.GlobalPriorityRestoreBlocks()
	if len(commands) == 0 && len(restore) == 0 {
		return nil
	}
	if len(commands) != 0 && !validExactKeeneticTeardown(commands) {
		return errExactKeeneticPlan
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, exactKeeneticCleanupTimeout)
	defer cancel()
	// The priority ladder goes back FIRST. It is the one edit here made to an interface the router
	// owns, and while it stands it decides which connection carries everything — an aborted apply
	// that removed our tunnels but left our ladder behind would point the default route at whatever
	// is left. Restoring is not a `no` command, so it cannot ride the teardown batch.
	for _, block := range restore {
		if _, err := adapter.runner.ParseBatch(cleanupCtx, append([]string(nil), block...)); err != nil {
			return errExactKeeneticApply
		}
	}
	if len(commands) == 0 {
		return nil
	}
	if _, err := adapter.runner.ParseBatch(cleanupCtx, append([]string(nil), commands...)); err != nil {
		return errExactKeeneticApply
	}
	return nil
}

// persist runs only after the global native/core/kernel postcheck, for a saving Apply or a Keep. A
// failed Apply never writes the candidate to startup-config; Test deliberately leaves the verified
// live state unsaved.
func (adapter *exactKeeneticNativeAdapter) persist(
	ctx context.Context,
	reconcile nativeplan.Reconciliation,
) error {
	if adapter == nil || adapter.runner == nil || adapter.readConfig == nil ||
		reconcile.Platform != platform.Keenetic || reconcile.Target == nil ||
		reconcile.Target.Platform != platform.Keenetic || len(reconcile.OpenWrtRemovals) != 0 ||
		!validExactKeeneticTarget(*reconcile.Target) ||
		!validExactKeeneticTeardown(reconcile.KeeneticTeardown) {
		return errExactKeeneticPlan
	}
	if exactKeeneticNativeMutationEmpty(*reconcile.Target, reconcile.KeeneticTeardown, reconcile.KeeneticPriorityRestore) {
		return nil
	}
	// Three distinct failures used to share one answer - tear the target down - and that answer
	// contradicted the caller: apply keeps the revision as a live unsaved window and tells the
	// operator "the configuration runs - use Keep to retry", and Keep retries THIS function. A
	// retry after a teardown cannot succeed (the re-read verifies against a target that is gone),
	// so the old behaviour made its own retry path unimplementable while the panel promised it.
	// persist runs only after the global postcheck proved the datapath, so:
	//   - a READ failure is transient plumbing: the target is live and carrying traffic; keep it,
	//     report the error, and let Keep retry the save;
	//   - a VERIFY mismatch means something else mutated NDM between postcheck and persist - that
	//     is drift, not a hiccup: fail closed and tear down, as before;
	//   - a failed `system configuration save` does not un-run the configuration: flash failed,
	//     the datapath did not; keep it, retryable.
	running, err := adapter.readConfig(ctx)
	if err != nil {
		return errExactKeeneticApply
	}
	if !verifyExactKeeneticRunningConfig(
		*reconcile.Target, reconcile.KeeneticTeardown, reconcile.KeeneticPriorityRestore, running) {
		_ = adapter.cleanup(context.WithoutCancel(ctx), reconcile.Target.Keenetic)
		return errExactKeeneticApply
	}
	if _, err := adapter.runner.ParseBatch(ctx, []string{exactKeeneticSaveCommand}); err != nil {
		return errExactKeeneticApply
	}
	return nil
}

// postcheck proves the live NDM state after the exact prepare/commit sequence. Transport success is
// not enough: an accepted-but-ignored command must not be reported as an applied native tunnel.
func (adapter *exactKeeneticNativeAdapter) postcheck(
	ctx context.Context,
	target nativeplan.Plan,
	teardown []string,
	restore [][]string,
) error {
	if adapter == nil || adapter.readConfig == nil || !validExactKeeneticTarget(target) ||
		!validExactKeeneticTeardown(teardown) {
		return errExactKeeneticUnavailable
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if exactKeeneticNativeMutationEmpty(target, teardown, restore) {
		return nil
	}
	running, err := adapter.readConfig(ctx)
	if err != nil || !verifyExactKeeneticRunningConfig(target, teardown, restore, running) {
		return errExactKeeneticApply
	}
	return nil
}

// restore is counted here because it is the ONLY change in the case that made it necessary: a
// profile whose default rule stops naming a tunnel produces no interfaces, no routes, no ladder and
// no teardown, and the previous version of this predicate then reported "nothing to do" and returned
// before anything ran — leaving the old ladder in place, still holding the default route.
// restoredPriorities reads an `interface X` / `ip global N` block pair back into a map, so the
// verification can compare what the router reports against what the restore asked for. Blocks that
// do not have that exact shape are ignored rather than guessed at — they cannot have come from
// priorityBlocks, and a verification must not invent an expectation.
func restoredPriorities(restore [][]string) map[string]int {
	out := map[string]int{}
	for _, block := range restore {
		if len(block) != 2 {
			continue
		}
		iface, ok := strings.CutPrefix(strings.TrimSpace(block[0]), "interface ")
		if !ok {
			continue
		}
		value, ok := strings.CutPrefix(strings.TrimSpace(block[1]), "ip global ")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			continue
		}
		out[strings.TrimSpace(iface)] = n
	}
	return out
}

func exactKeeneticNativeMutationEmpty(target nativeplan.Plan, teardown []string, restore [][]string) bool {
	return target.Keenetic != nil && len(target.Keenetic.Interfaces) == 0 &&
		len(target.Keenetic.Routes) == 0 && len(target.Keenetic.GlobalPriority) == 0 &&
		len(teardown) == 0 && len(restore) == 0
}

func verifyExactKeeneticRunningConfig(
	target nativeplan.Plan,
	teardown []string,
	restore [][]string,
	running string,
) bool {
	if !validExactKeeneticTarget(target) || !validExactKeeneticTeardown(teardown) ||
		strings.TrimSpace(running) == "" {
		return false
	}
	lines := normalizedNDMConfigLines(running)
	if len(lines) == 0 {
		return false
	}
	for _, block := range target.Keenetic.Interfaces {
		if !containsExactNDMSequence(lines, normalizedNDMCommands(block)) {
			return false
		}
	}
	// The ladder is verified by READING it back, not by matching command lines. `ip global` is only
	// the default route when it is read under the interface it belongs to, but it is not adjacent to
	// that interface line: the running config prints description, address and mtu in between, so an
	// exact-sequence match never finds it — measured as an Apply that submitted the ladder, failed its
	// own verification, and correctly rolled the router back.
	if len(target.Keenetic.GlobalPriority) != 0 || len(restore) != 0 {
		observed := keenetic.GlobalPriorities(running)
		for iface, want := range target.Keenetic.GlobalPriority {
			if observed[iface] != want {
				return false
			}
		}
		// The restored interfaces are read back the same way. An `ip global` the router accepted and
		// ignored looks exactly like one it applied, and here that difference is the whole default
		// route: a restore that silently failed leaves the old tunnel on top of the ladder while the
		// apply reports success.
		for iface, want := range restoredPriorities(restore) {
			if observed[iface] != want {
				return false
			}
		}
	}
	for _, route := range target.Keenetic.Routes {
		if !containsExactNDMLine(lines, normalizeNDMCommand(route)) {
			return false
		}
	}
	targetCommands := make(map[string]bool)
	for _, block := range target.Keenetic.Interfaces {
		for _, command := range block {
			targetCommands[normalizeNDMCommand(command)] = true
		}
	}
	for _, block := range target.Keenetic.GlobalPriorityBlocks() {
		for _, command := range block {
			targetCommands[normalizeNDMCommand(command)] = true
		}
	}
	for _, command := range target.Keenetic.Routes {
		targetCommands[normalizeNDMCommand(command)] = true
	}
	for _, command := range teardown {
		positive := normalizeNDMCommand(strings.TrimPrefix(command, "no "))
		if positive == "" || (!targetCommands[positive] && containsRetiredNDMIdentity(lines, positive)) {
			return false
		}
	}
	return true
}

func normalizedNDMConfigLines(config string) []string {
	result := make([]string, 0, strings.Count(config, "\n")+1)
	for _, line := range strings.Split(config, "\n") {
		if normalized := normalizeNDMCommand(line); normalized != "" && normalized != "!" {
			result = append(result, normalized)
		}
	}
	return result
}

func normalizedNDMCommands(commands []string) []string {
	result := make([]string, 0, len(commands))
	for _, command := range commands {
		normalized := normalizeNDMCommand(command)
		if normalized == "" {
			return nil
		}
		result = append(result, normalized)
	}
	return result
}

func normalizeNDMCommand(command string) string { return strings.Join(strings.Fields(command), " ") }

func containsExactNDMLine(lines []string, expected string) bool {
	for _, line := range lines {
		if line == expected {
			return true
		}
	}
	return false
}

func containsRetiredNDMIdentity(lines []string, identity string) bool {
	for _, line := range lines {
		if line == identity ||
			((strings.HasPrefix(identity, "ip route ") || strings.HasPrefix(identity, "ipv6 route ")) &&
				strings.HasPrefix(line, identity+" ")) {
			return true
		}
	}
	return false
}

func containsExactNDMSequence(lines, expected []string) bool {
	if len(expected) == 0 || len(expected) > len(lines) {
		return false
	}
	for start := 0; start+len(expected) <= len(lines); start++ {
		matched := true
		for offset := range expected {
			if lines[start+offset] != expected[offset] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func validExactKeeneticTarget(target nativeplan.Plan) bool {
	if target.Platform != platform.Keenetic || target.Keenetic == nil || len(target.OpenWrt) != 0 ||
		len(target.Decisions) > exactKeeneticMaxCommands {
		return false
	}
	plan := target.Keenetic
	if !isLowerHexRevision(plan.RunningConfigRev, reviewSHA256HexLen) {
		return false
	}
	seenEndpoints := make(map[string]bool, len(target.Decisions))
	managedIfaces := make(map[string]bool)
	allIfaces := make(map[string]nativeplan.Path)
	compatibility := 0
	for _, decision := range target.Decisions {
		routeTarget := plan.IfaceFor[decision.EndpointID]
		if decision.EndpointID == "" || seenEndpoints[decision.EndpointID] || decision.Interface == "" ||
			netvpn.ValidInterfaceName(decision.Interface) != nil ||
			routeTarget == "" || netvpn.ValidInterfaceName(routeTarget) != nil {
			return false
		}
		// For an interface WayHop creates, the decision names the same thing the routes target and
		// the two must agree. For an ADOPTED one they are deliberately different namespaces: the
		// decision holds the kernel link the capture probed (`nwg0`) while routes must name the NDM
		// interface that owns it (`Wireguard0`), because NDM rejects a netdev name outright.
		// Requiring equality here rejected every adopted plan as invalid.
		if decision.Path != nativeplan.PathNativeAdopt && routeTarget != decision.Interface {
			return false
		}
		seenEndpoints[decision.EndpointID] = true
		switch decision.Path {
		case nativeplan.PathNativeCreate, nativeplan.PathNativeManage, nativeplan.PathNativeUpdate:
			if managedIfaces[decision.Interface] {
				return false
			}
			managedIfaces[decision.Interface] = true
		case nativeplan.PathNativeAdopt, nativeplan.PathExternal:
		case nativeplan.PathCompatibility:
			compatibility++
			if plan.CompatibilityRouting && decision.Interface != exactKeeneticCompatibilityIF {
				return false
			}
		default:
			return false
		}
		if previous, duplicate := allIfaces[decision.Interface]; duplicate {
			if !plan.CompatibilityRouting || decision.Interface != exactKeeneticCompatibilityIF ||
				decision.Path != nativeplan.PathCompatibility || previous != nativeplan.PathCompatibility {
				return false
			}
		} else {
			allIfaces[decision.Interface] = decision.Path
		}
	}
	if len(plan.IfaceFor) != len(target.Decisions) {
		return false
	}
	if plan.CompatibilityRouting {
		marker, ok := plan.Singbox["wayhop_compatibility_routing"].(bool)
		if !ok || !marker || len(plan.Singbox) != 1 || len(plan.Routes) != 0 {
			return false
		}
	} else if (compatibility == 0) != (plan.Singbox == nil) {
		return false
	}
	blocks := make(map[string]bool, len(plan.Interfaces))
	commandCount := len(plan.Routes)
	for _, block := range plan.Interfaces {
		commandCount += len(block)
		if len(block) < 2 || !strings.HasPrefix(block[0], "interface Wireguard") ||
			block[len(block)-1] != "up" || blocks[block[0]] || !validExactKeeneticCommands(block, false) {
			return false
		}
		blocks[block[0]] = true
	}
	if commandCount > exactKeeneticMaxCommands || !validExactKeeneticCommands(plan.Routes, false) ||
		len(blocks) != len(managedIfaces) {
		return false
	}
	for iface := range managedIfaces {
		if !blocks["interface "+iface] {
			return false
		}
	}
	return true
}

func validExactKeeneticTeardown(commands []string) bool {
	return len(commands) <= exactKeeneticMaxCommands && validExactKeeneticCommands(commands, true)
}

func validExactKeeneticCommands(commands []string, teardown bool) bool {
	seen := make(map[string]bool, len(commands))
	for _, command := range commands {
		if command == "" || len(command) > exactKeeneticMaxCommandBytes ||
			strings.TrimSpace(command) != command || strings.ContainsAny(command, "\r\n\x00") ||
			seen[command] || (teardown && !strings.HasPrefix(command, "no ")) {
			return false
		}
		seen[command] = true
	}
	return true
}
