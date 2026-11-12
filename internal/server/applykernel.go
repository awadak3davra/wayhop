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
	"time"

	"wayhop/internal/pbr"
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
		return nil
	}
	rollback := func(primary error) error {
		// The request may have been canceled after the first command changed the router. Cleanup must
		// not be skipped merely because the client disconnected, but it remains strictly bounded.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), exactKernelRollbackTimeout)
		defer cancel()
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
	var cleanups []string
	for _, command := range artifact.IP {
		if err := context.Cause(ctx); err != nil {
			return rollback(err)
		}
		if exactKernelIPCleanupCommand(command) {
			cleanups = append(cleanups, command)
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
	if _, err := adapter.runner.Run(ctx, string(artifact.Nft), "nft", "-f", "-"); err != nil {
		// nft rejects a program as a whole, so the running table still marks as before; what step 1
		// changed is at most which tunnel a renumbered egress's table points at, and no blackhole was
		// removed. A rollback here would delete that running table and hand everything to the WAN; the
		// failed Apply re-runs its baseline over this instead.
		return fmt.Errorf("%w: nft load: %v", errExactKernelArtifact, err)
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
	return nil
}

// postcheck verifies the transaction-specific marker installed only after the nft, route, retire,
// and optional offload steps all succeeded. A firewall reload that drops WayHop's table therefore
// cannot remain invisible to strict Apply or the authenticated-current reconciler.
func (adapter *exactKernelAdapter) postcheck(
	ctx context.Context,
	artifact executionKernelArtifactV1,
) error {
	if adapter == nil || adapter.runner == nil || !validExactKernelArtifact(artifact) {
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
