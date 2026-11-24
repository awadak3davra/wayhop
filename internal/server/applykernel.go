package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"wayhop/internal/pbr"
	"wayhop/internal/version"
)

var (
	errExactKernelUnavailable = errors.New("exact kernel adapter is unavailable")
	errExactKernelArtifact    = errors.New("exact kernel artifact is invalid")
)

// exactKernelRunner is deliberately context-aware. The legacy pbr.Runner cannot cancel a hung
// nft/ip process and therefore must not be wired into the strict transaction without an adapter
// that actually enforces the supplied context.
type exactKernelRunner interface {
	Run(context.Context, string, string, ...string) (string, error)
}

type exactKernelAdapter struct {
	runner exactKernelRunner
	// keep, when set, is asked before each install command; true skips it. It is how a reinstall
	// leaves a table the runtime elector re-pointed as it is (Server.electedRouteKeeper): RenderIP
	// seeds every table with `route replace default dev <first candidate>`, which would put the
	// compile-time pin back over an elected member on every Apply and every fw4 reload.
	keep func(command string) bool
	// hold, when set, is the names hold the kill-switch guard is rendered with for a plan
	// (Server.namesHold); nil renders the guard without one. Install and postcheck must be given the
	// same one, or the guard's marker would never match.
	hold func(plan *pbr.Plan) pbr.NamesHold
	// fallbackGuard is the guard of the plane this install replaces. A rollback loads it back before
	// it takes the plane down, so the lists the old plane kill-switched are held while nothing marks.
	fallbackGuard string
	// fallbackPlan is the plan fallbackGuard was rendered for (its learned addresses go back with it).
	fallbackPlan *pbr.Plan
	// learned, when set, is the program that puts the learned addresses of the plan's kill-switched
	// names back into a guard that has just been loaded (Server.learnedNamesProgram): a load replaces
	// the table, and the sets with it. Same transaction, so there is no moment without them.
	learned func(plan *pbr.Plan) string
	// guardTx, when set, is held over a load of the guard: the learned addresses are rendered and
	// loaded as one step against the loop that learns them (Server.ksGuardTx).
	guardTx sync.Locker
	// coreRunning, when set, says whether the core runs. A guard loaded while it does not takes over
	// what the names hold of the guard it replaces had left, instead of a fresh period.
	coreRunning func() bool
	// carry, when set, renders the program that puts the fast DNS plane's resolver-fed set elements
	// back into the table the nft load replaces (Server.dlistCarry). Loaded in the same transaction;
	// a load that fails with it is tried once more without, so the carry can never cost the plane.
	carry func(ctx context.Context, plan *pbr.Plan) string
	// mustLoad, when set, renders the program loaded right after the table that must succeed: the
	// remote lists' prefixes and the core pin's devices (Server.fastMustLoad).
	mustLoad func(ctx context.Context, plan *pbr.Plan) string
}

// guardProgram is the kill-switch guard for plan as this adapter loads it: the table and its marker
// in one transaction. "" when the plan has nothing to guard.
func (adapter *exactKernelAdapter) guardProgram(plan *pbr.Plan) string {
	if plan == nil {
		return ""
	}
	var hold pbr.NamesHold
	if adapter.hold != nil {
		hold = adapter.hold(plan)
	}
	return plan.RenderNftGuardWith(hold)
}

// loadGuard replaces the guard table with guard, rendered for plan: the table, its marker, the
// learned addresses of the plan's kill-switched names, and the names hold's remaining time when the
// core is down, all in one transaction.
func (adapter *exactKernelAdapter) loadGuard(ctx context.Context, guard string, plan *pbr.Plan) error {
	if adapter.guardTx != nil {
		adapter.guardTx.Lock()
		defer adapter.guardTx.Unlock()
	}
	program := guard + pbr.GuardProofProgram(guard)
	if adapter.learned != nil && plan != nil {
		program += adapter.learned(plan)
	}
	program += adapter.holdCarryOver(ctx, plan)
	_, err := adapter.runner.Run(ctx, program, "nft", "-f", "-")
	return err
}

// holdCarryOver keeps the names hold bounded across a reload. The hold is "at most
// one period without the core"; if every load of the table started that period again, then with the
// core down each Apply, each rollback and each list refresh that changed a guarded set would hold the
// LAN for another ten minutes. While the core is not running, the new table's hold gets what the
// old one had left: emptied when it had lapsed, shortened when it was counting down. With the core
// running, or with no hold in place to read (the boot, a table someone deleted), it is the full
// period, which the renewal keeps up anyway.
func (adapter *exactKernelAdapter) holdCarryOver(ctx context.Context, plan *pbr.Plan) string {
	if adapter.hold == nil || adapter.coreRunning == nil || plan == nil || adapter.coreRunning() {
		return ""
	}
	hold := adapter.hold(plan)
	if hold.Seconds <= 0 || len(hold.Pass) == 0 {
		return "" // no hold, or a strict one that never counts down
	}
	listing, err := adapter.runner.Run(ctx, "", "nft", "list", "set", "inet", pbr.GuardTable, pbr.GuardHoldSet)
	if err != nil {
		return ""
	}
	left, ok := pbr.GuardHoldRemaining(listing)
	switch {
	case !ok || left >= hold.Seconds:
		return ""
	case left <= 0:
		return pbr.RenderGuardHoldLift()
	}
	return pbr.RenderGuardHoldRenew(left)
}

// guardLoaded reports whether the guard in the kernel is this program with its rules in place: the
// marker is the last rule of the chain, so a flushed chain or table reads as absent.
func (adapter *exactKernelAdapter) guardLoaded(ctx context.Context, guard string) bool {
	listing, err := adapter.runner.Run(ctx, "", "nft", "list", "chain", "inet", pbr.GuardTable, pbr.GuardChain)
	return err == nil && pbr.GuardProofPresent(listing, guard)
}

// dropGuard removes the guard table; one that is not there is the state asked for.
func (adapter *exactKernelAdapter) dropGuard(ctx context.Context) error {
	command := "nft delete table inet " + pbr.GuardTable
	if err := adapter.runCommand(ctx, command); err != nil && !exactKernelAlreadyAbsent(command, err) {
		return err
	}
	return nil
}

const exactKernelRollbackTimeout = 10 * time.Second

const (
	exactKernelCommandTimeout = 15 * time.Second
	exactKernelOutputLimit    = 1 << 20
)

type exactKernelToolRunner struct {
	nft ExecutionToolIdentityV1
	ip  ExecutionToolIdentityV1
}

func (runner exactKernelToolRunner) Run(
	ctx context.Context,
	stdin string,
	name string,
	args ...string,
) (string, error) {
	identity := runner.ip
	if name == executionToolNFT {
		identity = runner.nft
	}
	if !validExecutionToolIdentity(identity, name) ||
		(name == executionToolIP && stdin != "") ||
		(name == executionToolNFT && stdin != "" && !slices.Equal(args, []string{"-f", "-"})) {
		return "", errExactKernelArtifact
	}
	runCtx, cancel := context.WithTimeout(ctx, exactKernelCommandTimeout)
	defer cancel()
	output := newApplyHostCommandOutput(exactKernelOutputLimit, cancel)
	commandArgs := append([]string(nil), args...)
	if name == executionToolIP && identity.Version == executionBusyBoxIPVersion {
		if filepath.Base(identity.ResolvedPath) != "busybox" {
			return "", errExactKernelArtifact
		}
		commandArgs = append([]string{"ip"}, commandArgs...)
	}
	cmd := exec.CommandContext(runCtx, identity.ResolvedPath, commandArgs...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	cmd.Stdout = applyHostCommandWriter{output: output, retain: true}
	// Retain bounded stderr too: BusyBox ip reports an idempotent delete miss only there. Without
	// that machine evidence the recovery adapter mistakes "No such process" for a fatal command
	// failure, rolls the authenticated PBR artifact back, and can never complete after a cold boot.
	cmd.Stderr = applyHostCommandWriter{output: output, retain: true}
	cmd.WaitDelay = applyHostCommandWaitDelay
	err := cmd.Run()
	if output.exceededLimit() || errors.Is(err, exec.ErrWaitDelay) || runCtx.Err() != nil {
		return "", errExactKernelArtifact
	}
	if err != nil {
		return output.stdoutString(), fmt.Errorf("%w: %s", err, output.stdoutString())
	}
	return output.stdoutString(), nil
}

func newExactKernelAdapter(runner exactKernelRunner) (*exactKernelAdapter, error) {
	if runner == nil {
		return nil, errExactKernelUnavailable
	}
	return &exactKernelAdapter{runner: runner}, nil
}

// apply installs or removes only an authenticated, already-rendered kernel artifact. Retire is
// copied from the authenticated ledger baseline; an empty target never grants delete authority.
func (adapter *exactKernelAdapter) apply(
	ctx context.Context,
	artifact executionKernelArtifactV1,
) error {
	if adapter == nil || adapter.runner == nil {
		return errExactKernelUnavailable
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	artifact = rerenderKernelArtifact(artifact)
	if !validExactKernelArtifact(artifact) {
		return errExactKernelArtifact
	}
	if artifact.Action == ExecutionEnsureAbsent {
		if len(artifact.Retire) == 0 {
			return nil
		}
		if err := adapter.teardown(ctx, artifact.Retire); err != nil {
			return fmt.Errorf("%w: retire baseline: %v", errExactKernelArtifact, err)
		}
		// The plane is gone because the operator switched kernel routing off: the guard goes with it,
		// after it. Left behind it would hold the kill-switched addresses with no tunnel route to take.
		if err := adapter.dropGuard(ctx); err != nil {
			return fmt.Errorf("%w: kill switch guard removal: %v", errExactKernelArtifact, err)
		}
		return nil
	}
	rollback := func(primary error) error {
		// The request may have been canceled after the first command changed the router. Cleanup must
		// not be skipped merely because the client disconnected, but it remains strictly bounded.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), exactKernelRollbackTimeout)
		defer cancel()
		// The guard is never part of a rollback's teardown: with the plane deleted it is the only
		// thing between a kill-switched list and the provider. The replaced plane's guard goes back
		// first, so what that plane held stays held until the baseline is installed again.
		// Not when it is already the one in place (the install changed nothing of the guard): a load
		// replaces the table, and with it the time the names hold has left.
		if adapter.fallbackGuard != "" && !adapter.guardLoaded(cleanupCtx, adapter.fallbackGuard) {
			if err := adapter.loadGuard(cleanupCtx, adapter.fallbackGuard, adapter.fallbackPlan); err != nil {
				log.Printf("apply: kernel plane rollback: the previous kill switch guard was not restored (the new one stays): %v", err)
			}
		}
		if rollbackErr := adapter.teardown(cleanupCtx, artifact.Teardown); rollbackErr != nil {
			return errors.Join(primary, fmt.Errorf("exact kernel rollback: %w", rollbackErr))
		}
		return primary
	}
	// The plane converges in place, make-before-break (RT-01). Nothing of the running plane is deleted
	// before the new one is complete: a deleted rule or a flushed table, the kill-switch blackhole
	// included, sent every packet marked for it out of the WAN until the matching add ran.
	//
	// 1. Rules and routes first, while the running nft table still marks as before: an add the kernel
	//    already holds is accepted, a replace overwrites. An egress whose mark (and so table) moves
	//    finds its new rule, route and blackhole in place before the nft load sends it there.
	// 2. The nft program, which replaces its own table atomically.
	// 3. Only then the deletions: the RenderIP lines that remove stale state from a table the plane
	//    keeps, and the retire list of rules and tables the new plane no longer names.
	//
	// 0. Before any of it, the kill-switch guard (pbr/guard_nft.go): its own table, replaced in one
	//    transaction, which holds the plan's kill-switched destinations whatever the steps below, a
	//    rollback or a later loss of a rule or route leave behind. A guard that does not load fails
	//    the install before anything of the plane was touched.
	//    A guard that is already this plan's (its marker is there) is left as it is: reloading it
	//    would start the names hold's timeouts again, and a plane that something keeps breaking, so
	//    that it is reinstalled every half minute, would then hold the LAN for as long as that
	//    lasts instead of for the hold's one period.
	guard := adapter.guardProgram(artifact.Plan)
	if guard != "" {
		if !adapter.guardLoaded(ctx, guard) {
			if err := adapter.loadGuard(ctx, guard, artifact.Plan); err != nil {
				return fmt.Errorf("%w: kill switch guard: %v", errExactKernelArtifact, err)
			}
		}
	}
	var cleanups []string
	for _, command := range artifact.IP {
		if err := context.Cause(ctx); err != nil {
			return rollback(err)
		}
		if exactKernelIPCleanupCommand(command) {
			cleanups = append(cleanups, command)
			continue
		}
		if adapter.keep != nil && adapter.keep(command) {
			continue
		}
		if err := adapter.runCommand(ctx, command); err != nil {
			if exactKernelRuleAlreadyPresent(command, err) {
				continue
			}
			if exactKernelDeviceRouteMissingDevice(command, err) {
				// The tunnel device is not there yet (boot before the endpoint resolves, amneziawg-go
				// being relaunched). Rolling back here deletes the nft table and the kill-switch
				// blackhole with every other egress's rules, which is the fail-open this plane exists
				// to prevent. Only this route is skipped: the blackhole in the same table still
				// installs, and restoreLostTableRoutes seeds the route once the device is up.
				log.Printf("apply: kernel plane: %q skipped, the device does not exist yet: %v", command, err)
				continue
			}
			return rollback(fmt.Errorf("%w: route install: %v", errExactKernelArtifact, err))
		}
	}
	if err := context.Cause(ctx); err != nil {
		return rollback(err)
	}
	carried := ""
	if adapter.carry != nil {
		carried = adapter.carry(ctx, artifact.Plan)
	}
	if carried != "" {
		if _, err := adapter.runner.Run(ctx, string(artifact.Nft)+carried, "nft", "-f", "-"); err != nil {
			log.Printf("apply: kernel plane: the resolver-fed set elements were not carried over (%v); loading without them", err)
		} else {
			carried = "loaded"
		}
	}
	if carried == "loaded" {
		// The table and its carried elements are in.
	} else if _, err := adapter.runner.Run(ctx, string(artifact.Nft), "nft", "-f", "-"); err != nil {
		// nft rejects a program as a whole, so the running table still marks as before; what step 1
		// changed is at most which tunnel a renumbered egress's table points at, and no blackhole was
		// removed. A rollback here would delete that running table and hand everything to the WAN; the
		// failed Apply re-runs its baseline over this instead.
		return fmt.Errorf("%w: nft load: %v", errExactKernelArtifact, err)
	}
	// The fast DNS plane's must-load part: the remote lists' prefixes and the
	// core pin's devices, a transaction of its own after the table, never dropped with the carry.
	if adapter.mustLoad != nil {
		if prog := adapter.mustLoad(ctx, artifact.Plan); prog != "" {
			if _, err := adapter.runner.Run(ctx, prog, "nft", "-f", "-"); err != nil {
				return rollback(fmt.Errorf("%w: fast path sets: %v", errExactKernelArtifact, err))
			}
		}
	}
	for _, command := range cleanups {
		if err := context.Cause(ctx); err != nil {
			return rollback(err)
		}
		if err := adapter.runCommand(ctx, command); err != nil && !exactKernelAlreadyAbsent(command, err) {
			return rollback(fmt.Errorf("%w: stale route cleanup: %v", errExactKernelArtifact, err))
		}
	}
	for _, command := range artifact.Retire {
		if err := context.Cause(ctx); err != nil {
			return rollback(err)
		}
		if err := adapter.runCommand(ctx, command); err != nil && !exactKernelAlreadyAbsent(command, err) {
			return rollback(fmt.Errorf("%w: previous-plane cleanup: %v", errExactKernelArtifact, err))
		}
	}
	if len(artifact.Offload) != 0 {
		if err := context.Cause(ctx); err != nil {
			return rollback(err)
		}
		if _, err := adapter.runner.Run(ctx, string(artifact.Offload), "nft", "-f", "-"); err != nil {
			// The strict transaction cannot report an exact materialization while silently dropping
			// a reviewed offload plane. Roll back and force a new review without offload instead.
			return rollback(fmt.Errorf("%w: offload load: %v", errExactKernelArtifact, err))
		}
	}
	proof, err := exactKernelProofProgram(artifact)
	if err != nil {
		return rollback(err)
	}
	if _, err := adapter.runner.Run(ctx, proof, "nft", "-f", "-"); err != nil {
		return rollback(fmt.Errorf("%w: verification marker: %v", errExactKernelArtifact, err))
	}
	if guard == "" {
		// The new plane kill-switches nothing: a guard an earlier plane left would go on dropping
		// what the operator has just released. Last, once the new plane routes.
		if err := adapter.dropGuard(ctx); err != nil {
			return fmt.Errorf("%w: stale kill switch guard: %v", errExactKernelArtifact, err)
		}
	}
	return nil
}

// postcheck verifies the transaction-specific marker installed only after the nft, route, retire,
// and optional offload steps all succeeded. A firewall reload that drops WayHop's table therefore
// cannot remain invisible to strict Apply or the authenticated-current reconciler.
func (adapter *exactKernelAdapter) postcheck(
	ctx context.Context,
	artifact executionKernelArtifactV1,
) error {
	if adapter == nil || adapter.runner == nil {
		return errExactKernelArtifact
	}
	if artifact = rerenderKernelArtifact(artifact); !validExactKernelArtifact(artifact) {
		return errExactKernelArtifact
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if artifact.Action == ExecutionEnsureAbsent {
		if len(artifact.Retire) == 0 {
			return nil
		}
		table, ok := exactKernelRetiredTable(artifact.Retire)
		if !ok {
			return errExactKernelArtifact
		}
		command := "nft delete table inet " + table
		if _, err := adapter.runner.Run(ctx, "", "nft", "list", "table", "inet", table); err == nil ||
			!exactKernelAlreadyAbsent(command, err) {
			return errExactKernelArtifact
		}
		return nil
	}
	proof, err := exactKernelProofSet(artifact)
	if err != nil {
		return err
	}
	if _, err := adapter.runner.Run(ctx, "", "nft", "list", "set", "inet", artifact.Plan.Table, proof); err != nil {
		return errExactKernelArtifact
	}
	// The kill-switch guard is a table of its own; its marker follows its program and is the last
	// rule of its chain, so an absent guard, another plan's guard and a flushed one all read as drift.
	if guard := adapter.guardProgram(artifact.Plan); guard != "" {
		if !adapter.guardLoaded(ctx, guard) {
			return fmt.Errorf("%w: the kill switch guard is not loaded", errExactKernelArtifact)
		}
	}
	return adapter.postcheckRoutes(ctx, artifact)
}

// postcheckRoutes reads back what the nft marker cannot vouch for: the plane's ip
// rules and the kill switch's blackhole routes live outside the nft table, so another script, an `ip
// rule flush` or an `ip route flush table N` removed them with the marker still in place, the panel
// still saying applied, and the marked traffic falling through to the main table. A missing rule or
// blackhole is drift, and the reconcile loop reinstalls the plane.
//
// A table's `default dev <tunnel>` route is deliberately not judged: the runtime elector owns it, an
// elected member is not drift, and it is rightly absent while a tunnel is down.
func (adapter *exactKernelAdapter) postcheckRoutes(ctx context.Context, artifact executionKernelArtifactV1) error {
	plan := artifact.Plan
	read := func(args ...string) (string, error) {
		out, err := adapter.runner.Run(ctx, "", "ip", args...)
		if err != nil {
			return "", fmt.Errorf("%w: ip %s: %v", errExactKernelArtifact, strings.Join(args, " "), err)
		}
		return out, nil
	}
	rules4, err := read("rule", "show")
	if err != nil {
		return err
	}
	var rules6, routes6 string
	if plan.HasV6() {
		if rules6, err = read("-6", "rule", "show"); err != nil {
			return err
		}
	}
	if missing := pbr.MissingIPRules(strings.Join(artifact.IP, "\n"), rules4, rules6, plan.HasV6()); len(missing) > 0 {
		return fmt.Errorf("%w: ip rules are missing: %s", errExactKernelArtifact, strings.Join(missing, "; "))
	}
	failClosed := false
	for _, e := range plan.Egresses {
		failClosed = failClosed || e.Kind == pbr.EgressBlackhole || e.Kind == pbr.EgressInterface && e.FailClosed
	}
	if !failClosed {
		return nil
	}
	routes4, err := read("route", "show", "table", "all")
	if err != nil {
		return err
	}
	if plan.HasV6() {
		if routes6, err = read("-6", "route", "show", "table", "all"); err != nil {
			return err
		}
	}
	if missing := plan.MissingFailClosedRoutes(routes4, routes6); len(missing) > 0 {
		return fmt.Errorf("%w: kill switch routes are missing: %s", errExactKernelArtifact, strings.Join(missing, "; "))
	}
	return nil
}

func exactKernelProofSet(artifact executionKernelArtifactV1) (string, error) {
	if !validExactKernelPresentArtifact(artifact) {
		return "", errExactKernelArtifact
	}
	hash := sha256.New()
	_, _ = hash.Write(artifact.Nft)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(strings.Join(artifact.IP, "\n")))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(artifact.Offload)
	return fmt.Sprintf("wh_proof_%x", hash.Sum(nil)[:16]), nil
}

func exactKernelProofProgram(artifact executionKernelArtifactV1) (string, error) {
	proof, err := exactKernelProofSet(artifact)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("add set inet %s %s { type inet_service; }\n", artifact.Plan.Table, proof), nil
}

func exactKernelRetiredTable(commands []string) (string, bool) {
	if len(commands) == 0 {
		return "", false
	}
	fields := strings.Fields(commands[0])
	if len(fields) != 5 || fields[0] != "nft" || fields[1] != "delete" ||
		fields[2] != "table" || fields[3] != "inet" || fields[4] == "" {
		return "", false
	}
	return fields[4], true
}

func validExactKernelArtifact(artifact executionKernelArtifactV1) bool {
	switch artifact.Action {
	case ExecutionEnsureAbsent:
		if artifact.Plan != nil || len(artifact.Nft) != 0 || len(artifact.IP) != 0 ||
			len(artifact.Offload) != 0 || len(artifact.Teardown) != 0 ||
			!validExactKernelCommands(artifact.Retire) {
			return false
		}
		if len(artifact.Retire) == 0 {
			return artifact.NFTTool == (ExecutionToolIdentityV1{}) &&
				artifact.IPTool == (ExecutionToolIdentityV1{})
		}
		return validExecutionToolIdentity(artifact.NFTTool, executionToolNFT) &&
			validExecutionToolIdentity(artifact.IPTool, executionToolIP)
	case ExecutionEnsurePresent:
		// Which plane the artifact carries decides which shape is valid. The nft checks below
		// require nft bytes, nft/ip identities and an `nft delete table` teardown; a Keenetic
		// artifact has none of those by construction, so running them against it rejects a
		// perfectly good ipset program as invalid.
		if artifact.Ipset != nil {
			return validExactKernelPresentIpsetArtifact(artifact) && validExactKernelCommands(artifact.Retire)
		}
		return validExactKernelPresentArtifact(artifact) && validExactKernelCommands(artifact.Retire)
	default:
		return false
	}
}

func (adapter *exactKernelAdapter) runCommand(ctx context.Context, command string) error {
	name, args, ok := exactKernelCommand(command)
	if !ok {
		return errExactKernelArtifact
	}
	_, err := adapter.runner.Run(ctx, "", name, args...)
	return err
}

func (adapter *exactKernelAdapter) teardown(ctx context.Context, commands []string) error {
	var failures []error
	for _, command := range commands {
		if err := context.Cause(ctx); err != nil {
			failures = append(failures, err)
			break
		}
		if err := adapter.runCommand(ctx, command); err != nil && !exactKernelAlreadyAbsent(command, err) {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func validExactKernelPresentArtifact(artifact executionKernelArtifactV1) bool {
	if artifact.Plan == nil || len(artifact.Nft) == 0 || len(artifact.Teardown) == 0 ||
		!validExecutionToolIdentity(artifact.NFTTool, executionToolNFT) ||
		!validExecutionToolIdentity(artifact.IPTool, executionToolIP) ||
		artifact.Teardown[0] != "nft delete table inet "+artifact.Plan.Table {
		return false
	}
	return bytes.Equal(artifact.Nft, []byte(artifact.Plan.RenderNft())) &&
		slices.Equal(artifact.IP, artifact.Plan.RenderIP(exactKernelOptions())) &&
		bytes.Equal(artifact.Offload, []byte(artifact.Plan.RenderOffload())) &&
		slices.Equal(artifact.Teardown, artifact.Plan.RenderTeardown(exactKernelOptions())) &&
		validExactKernelCommands(artifact.IP) && validExactKernelCommands(artifact.Teardown)
}

// rerenderKernelArtifact brings a stored nft artifact to this build's renderer (after a binary
// upgrade the nft program, ip commands and teardown stored by the previous build need not equal what
// the new one renders from the same plan, and the start converge would refuse it as "exact kernel
// artifact is invalid", leaving the router without its plane after a reboot). The plan is the
// reviewed, authenticated part of the record; the rendering is derived from it, so an artifact whose
// tools are still authenticated is re-rendered from its plan and then checked like any other. An
// artifact this build rendered (Renderer) is never re-rendered: a difference there is drift and is
// refused, as is one whose tools are not authenticated, and a Keenetic (ipset) artifact.
// The postcheck's marker follows the rendering, so the first reconcile after an upgrade reinstalls
// the plane once in the new form.
func rerenderKernelArtifact(artifact executionKernelArtifactV1) executionKernelArtifactV1 {
	if artifact.Action != ExecutionEnsurePresent || artifact.Ipset != nil || artifact.Plan == nil ||
		artifact.Renderer == kernelRendererID() || validExactKernelPresentArtifact(artifact) ||
		!validExecutionToolIdentity(artifact.NFTTool, executionToolNFT) ||
		!validExecutionToolIdentity(artifact.IPTool, executionToolIP) {
		return artifact
	}
	// Only plans whose shape every build renders alike are re-rendered: hybrid and
	// fast without the resolver plane. A fast plan with the resolver plane (routing mode fast, Phase 2,
	// never released) from another build carries choices this build may refuse (which lists are routed
	// by tables, which stay in nft): it is not re-rendered, and Diagnostics asks for one Apply.
	if fastPlanOfAnotherBuild(artifact) {
		log.Printf("apply: the stored fast-mode plane was planned by another build; it is not re-rendered: Apply once to plan it again")
		return artifact
	}
	// The stored bytes must still prove the stored plan: a plan changed beside an old
	// rendering is not made executable here; it takes a fresh Review and Apply.
	if why := renderingDisagrees(artifact); why != "" {
		log.Printf("apply: the stored kernel plane was rendered by another build and its plan does not match that rendering (%s); a new Review and Apply is needed", why)
		return artifact
	}
	out := artifact
	out.Nft = []byte(artifact.Plan.RenderNft())
	out.IP = artifact.Plan.RenderIP(exactKernelOptions())
	out.Offload = []byte(artifact.Plan.RenderOffload())
	out.Teardown = artifact.Plan.RenderTeardown(exactKernelOptions())
	out.Renderer = kernelRendererID()
	// What the old rendering installed and the new one does not is removed after the install
	// (an IPv6 blackhole at an older metric would otherwise outrank the tunnel's route and stay).
	out.Retire = append(append([]string(nil), artifact.Retire...), supersededKernelCommands(artifact.IP, out.IP)...)
	if validExactKernelPresentArtifact(out) {
		log.Printf("apply: the stored kernel plane was rendered by an older build; re-rendered from its plan")
	}
	return out
}

// staleFastPlan reports a stored fast plan of another build whose rendering this build would not run
// as stored (it renders differently now), so it waits for an Apply.
func staleFastPlan(a executionKernelArtifactV1) bool {
	return a.Action == ExecutionEnsurePresent && a.Ipset == nil && fastPlanOfAnotherBuild(a) && !validExactKernelPresentArtifact(a)
}

// fastPlanOfAnotherBuild reports a stored plan of the fast DNS plane (or one carrying its routed
// tables) that another build planned.
func fastPlanOfAnotherBuild(a executionKernelArtifactV1) bool {
	if a.Plan == nil || a.Renderer == kernelRendererID() {
		return false
	}
	if a.Plan.FastDNS {
		return true
	}
	for _, z := range a.Plan.Zones {
		if z.Routed || len(z.RouteV4)+len(z.RouteV6) > 0 || z.RemoteRouted {
			return true
		}
	}
	return false
}

// supersededKernelCommands is the inverse of every rule and route an old rendering added that the new
// one does not: `ip [-6] rule add X` -> `ip [-6] rule del X`, `ip [-6] route replace|add X` ->
// `ip [-6] route del X`. The executor takes an already absent one as done.
func supersededKernelCommands(oldIP, newIP []string) []string {
	// A route is the same object whether a rendering added or replaced it.
	same := func(c string) string { return strings.Replace(c, " route add ", " route replace ", 1) }
	now := map[string]bool{}
	for _, c := range newIP {
		now[same(c)] = true
	}
	var out []string
	for _, c := range oldIP {
		if now[same(c)] {
			continue
		}
		f := strings.Fields(c)
		i := 1
		if len(f) > 1 && f[1] == "-6" {
			i = 2
		}
		if len(f) < i+3 || f[0] != "ip" {
			continue
		}
		switch {
		case f[i] == "rule" && f[i+1] == "add":
			f[i+1] = "del"
		case f[i] == "route" && (f[i+1] == "replace" || f[i+1] == "add"):
			f[i+1] = "del"
		default:
			continue
		}
		if cmd := strings.Join(f, " "); validExactKernelCommands([]string{cmd}) {
			out = append(out, cmd)
		}
	}
	return out
}

// renderingDisagrees says how an older build's stored rendering fails to account for its stored plan
// ("" = it accounts for it): every egress's device, table and mark, and the address of every zone
// prefix kept in nft, must appear in the old nft program or ip commands, and the old teardown must
// delete the plan's table. A legacy record carries no authentication of its plan; this ties the plan
// to bytes an earlier build produced from it.
func renderingDisagrees(a executionKernelArtifactV1) string {
	nft, ip := string(a.Nft), strings.Join(a.IP, "\n")
	if len(a.Teardown) == 0 || a.Teardown[0] != "nft delete table inet "+a.Plan.Table {
		return "the teardown does not delete table " + a.Plan.Table
	}
	for _, e := range a.Plan.Egresses {
		if e.Kind == pbr.EgressWAN {
			continue
		}
		if !strings.Contains(ip, fmt.Sprintf("table %d", e.Table)) || !strings.Contains(nft+ip, fmt.Sprintf("0x%08x", e.Mark)) {
			return "egress " + e.Tag + " is not in the rendering"
		}
		if e.Kind == pbr.EgressInterface && e.Iface != "" && !strings.Contains(ip, "dev "+e.Iface+" ") {
			return "egress " + e.Tag + "'s device is not in the rendering"
		}
	}
	// Each prefix as a whole element of the old program, not a substring of one.
	tokens := map[string]bool{}
	for _, t := range strings.FieldsFunc(nft, func(r rune) bool { return strings.ContainsRune(" \t\n{},;", r) }) {
		tokens[t] = true
	}
	for _, z := range a.Plan.Zones {
		for _, c := range append(append([]string(nil), z.V4...), z.V6...) {
			if !tokens[c] {
				return "zone " + z.Name + "'s " + c + " is not in the rendering"
			}
		}
	}
	return ""
}

// kernelTeardownOf is what takes a stored plane down: its own teardown and, for an older build's
// rendering, this build's teardown of the same plan too (a table this build adds, such as
// the DNS table, is not in an older teardown).
func kernelTeardownOf(a executionKernelArtifactV1) []string {
	re := rerenderKernelArtifact(a)
	if re.Renderer == a.Renderer {
		return a.Teardown
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range append(append([]string(nil), a.Teardown...), re.Teardown...) {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// kernelRendererID names this build's renderer: the release and the commit it was built from.
func kernelRendererID() string { return version.Version + "+" + version.Commit }

// Keep the exact adapter's renderer comparison visibly pinned to the zero/default pbr.Options used
// by the review builder without importing mutable Server state.
func exactKernelOptions() pbr.Options { return pbr.Options{} }

func validExactKernelCommands(commands []string) bool {
	for _, command := range commands {
		if _, _, ok := exactKernelCommand(command); !ok {
			return false
		}
	}
	return true
}

func exactKernelCommand(command string) (string, []string, bool) {
	if command == "" || strings.TrimSpace(command) != command || strings.ContainsAny(command, "\r\n\x00") {
		return "", nil, false
	}
	fields := strings.Fields(command)
	if len(fields) < 2 || strings.Join(fields, " ") != command ||
		(fields[0] != "ip" && fields[0] != "nft") {
		return "", nil, false
	}
	return fields[0], fields[1:], true
}

func exactKernelAlreadyAbsent(command string, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		return false
	}
	message := strings.ToLower(err.Error())
	fragments := []string{"does not exist"}
	if strings.HasPrefix(command, "nft delete ") {
		fragments = append(fragments, "no such file or directory")
	}
	if strings.HasPrefix(command, "ip ") && exactKernelIPCleanupCommand(command) {
		// BusyBox uses both RTNETLINK spellings for an already-absent rule/route. A missing
		// executable remains fatal because the errors.Is checks above run before text matching.
		fragments = append(fragments, "no such process", "no such file or directory",
			"cannot find device", "no such device")
	}
	for _, fragment := range fragments {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}

// exactKernelDeviceRouteMissingDevice reports whether err is the one install failure that is not a
// fault of the plane: a per-egress `ip [-6] route replace default dev <iface> table <n>` answered
// with the device being absent. Any other command, and any other error on that command, stays fatal.
func exactKernelDeviceRouteMissingDevice(command string, err error) bool {
	if err == nil || errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		return false
	}
	name, args, ok := exactKernelCommand(command)
	if !ok || name != executionToolIP {
		return false
	}
	if len(args) != 0 && args[0] == "-6" {
		args = args[1:]
	}
	if len(args) != 7 || !slices.Equal(args[:4], []string{"route", "replace", "default", "dev"}) || args[5] != "table" {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "cannot find device") || strings.Contains(message, "no such device")
}

// exactKernelRuleAlreadyPresent reports whether err is an `ip [-6] rule add` refused because the
// identical rule is installed (RTNETLINK EEXIST, kernel 4.18+ with NLM_F_EXCL, which iproute2 and
// BusyBox both send). That is the converged state a re-apply asks for, not a fault. Any other command,
// and any other error, stays fatal.
func exactKernelRuleAlreadyPresent(command string, err error) bool {
	if err == nil || errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		return false
	}
	name, args, ok := exactKernelCommand(command)
	if !ok || name != executionToolIP {
		return false
	}
	if len(args) != 0 && args[0] == "-6" {
		args = args[1:]
	}
	if len(args) < 2 || args[0] != "rule" || args[1] != "add" {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "file exists")
}

func exactKernelIPCleanupCommand(command string) bool {
	name, args, ok := exactKernelCommand(command)
	if !ok || name != executionToolIP {
		return false
	}
	return slices.Contains(args, "del") || slices.Contains(args, "flush")
}
