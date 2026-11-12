package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"

	"wayhop/internal/keenetic"
	"wayhop/internal/nativeplan"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
)

var (
	errExactKeeneticUnavailable = errors.New("exact Keenetic native adapter is unavailable")
	errExactKeeneticPlan        = errors.New("exact Keenetic native plan is invalid")
	errExactKeeneticApply       = errors.New("exact Keenetic native operation failed")
	// errExactKeeneticDrift is persist's refusal of a running config that changed after it was
	// verified: nothing was saved and nothing was removed.
	errExactKeeneticDrift = fmt.Errorf("%w: the router-native configuration changed after it was verified, so it was left as it is and not saved", errExactKeeneticApply)
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
	exactKeeneticPeerCommand     = "wireguard peer "
	// exactKeeneticPeerIndent is the one indentation a command may carry: what keenetic.
	// WireguardCommands puts before a peer's own settings, which belong to the `wireguard peer` line
	// above them (flattenExactKeeneticBatch).
	exactKeeneticPeerIndent = "    "
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
	if runner == nil || runner.run == nil {
		return nil, errExactKeeneticPlan
	}
	// Every line is checked and flattened before the first one runs, so a batch the transport cannot
	// carry is refused whole instead of failing halfway through the router.
	lines, ok := flattenExactKeeneticBatch(commands)
	if !ok {
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
	// context that the interactive session used to provide is carried instead. How a block nests,
	// including a peer's own settings one context deeper (QA-121), is flattenExactKeeneticBatch's
	// business.
	var out strings.Builder
	for _, line := range lines {
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
	// readInterfaces reads `show interface`, where NDM reports each WireGuard interface's own public
	// key. It is read only for blocks that carry a private key, which the running config never prints.
	readInterfaces keeneticConfigReadFunc
	// reportLeft receives, after each prepare, the interfaces WayHop created that it found changed
	// outside WayHop (none clears the report). nil drops it.
	reportLeft func(ifaces []string)

	// found holds, per target plan (exactKeeneticPlanKey), the interfaces prepare found already live
	// and therefore did not create: a kept slot, a saved interface NDM re-created at boot, one a
	// rollback finds still standing. The cleanups of commit, abort and persist spare them, as they
	// spare the plan's KeptInterfaces. left holds those of them a boot or rollback prepare found
	// changed and left as they were: the verifications of the same transaction do not hold them to
	// their blocks. Both live as long as the adapter, which is built for one transaction; a phase
	// run without that transaction's prepare (persist on a later Keep) falls back to KeptInterfaces.
	mu    sync.Mutex
	found map[string]map[string]bool
	left  map[string]map[string]bool
}

func newExactKeeneticNativeAdapter(runner exactKeeneticBatchRunner) (*exactKeeneticNativeAdapter, error) {
	if runner == nil {
		return nil, errExactKeeneticUnavailable
	}
	return &exactKeeneticNativeAdapter{runner: runner, readConfig: readKeeneticRunningConfig,
		readInterfaces: readKeeneticInterfaces}, nil
}

// exactNativeStrictKey marks the context of an Apply's own forward run (withStrictNativePrepare).
type exactNativeStrictKey struct{}

// withStrictNativePrepare marks ctx as the forward run of an Apply the operator started. There a
// WayHop-created interface found changed outside WayHop stops the Apply before anything is sent:
// the operator is there to read why. Everywhere else - boot, a rollback, routing switched back on -
// nobody is, and refusing would leave the whole datapath down (at boot sing-box would never start)
// over one tunnel, so that interface is left as it is, reported, and the rest goes ahead.
func withStrictNativePrepare(ctx context.Context) context.Context {
	return context.WithValue(ctx, exactNativeStrictKey{}, true)
}

func strictNativePrepare(ctx context.Context) bool {
	strict, _ := ctx.Value(exactNativeStrictKey{}).(bool)
	return strict
}

// readKeeneticInterfaces reads `show interface` the way the running config is read.
func readKeeneticInterfaces(ctx context.Context) (string, error) {
	if ctx == nil {
		return "", errExecutionCaptureUnavailable
	}
	output, err := runHostCommandBounded(ctx, keeneticRunningConfigTimeout, keeneticRunningConfigLimit,
		applyHostCommandWaitDelay, exactKeeneticNDMCPath, "-c", "show interface")
	if err != nil || strings.TrimSpace(output) == "" {
		return "", errExecutionCaptureUnavailable
	}
	return output, nil
}

// exactKeeneticBlockPublicKey is the public key of the interface block configures, derived from
// its `wireguard private-key` line (present reports that line exists). The running config never
// prints a private key, so this is how a key is verified at all: NDM reports each interface's own
// public key in `show interface`. "" when the line does not decode to a key.
func exactKeeneticBlockPublicKey(block []string) (public string, present bool) {
	for _, line := range block {
		encoded, ok := strings.CutPrefix(normalizeNDMCommand(line), "wireguard private-key ")
		if !ok {
			continue
		}
		private, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(private) != curve25519.ScalarSize {
			return "", true
		}
		derived, err := curve25519.X25519(private, curve25519.Basepoint)
		if err != nil {
			return "", true
		}
		return base64.StdEncoding.EncodeToString(derived), true
	}
	return "", false
}

// exactKeeneticKeysMatch reports whether every block that carries a private key is live with the
// public key that key derives, according to the `show interface` listing.
func exactKeeneticKeysMatch(blocks [][]string, listing string) map[string]bool {
	live := make(map[string]string)
	for _, status := range netvpn.ParseNDMInterfaceStatus(listing) {
		live["interface "+status.Name] = status.PublicKey
	}
	match := make(map[string]bool, len(blocks))
	for _, block := range blocks {
		public, present := exactKeeneticBlockPublicKey(block)
		match[block[0]] = !present || (public != "" && live[block[0]] == public)
	}
	return match
}

// listingFor reads `show interface` when any of blocks carries a private key; a block without one
// needs no listing, so none is read for it ("" and no error).
func listingFor(ctx context.Context, read keeneticConfigReadFunc, blocks [][]string) (string, error) {
	keyed := false
	for _, block := range blocks {
		if _, present := exactKeeneticBlockPublicKey(block); present {
			keyed = true
		}
	}
	if !keyed {
		return "", nil
	}
	if read == nil {
		return "", errExactKeeneticUnavailable
	}
	listing, err := read(ctx)
	if err != nil || strings.TrimSpace(listing) == "" {
		return "", errExactKeeneticApply
	}
	return listing, nil
}

// exactKeeneticDrift holds blocks whose interface is already on the router to what the router
// reports: their own lines, in order, in the running config (`ip global` is the ladder's), and their
// key against the public key `show interface` lists, when listed says that listing was read. changed
// names the interfaces that differ; unverified the ones whose key could not be checked because the
// listing could not be read. prepare and the Diagnostics row both judge by this.
func exactKeeneticDrift(blocks [][]string, running, listing string, listed bool) (changed, unverified []string) {
	var keys map[string]bool
	if listed {
		keys = exactKeeneticKeysMatch(blocks, listing)
	}
	for _, block := range blocks {
		name := strings.TrimPrefix(block[0], "interface ")
		_, keyed := exactKeeneticBlockPublicKey(block)
		switch {
		case !verifyExactKeeneticInterfaceBlock(block, running, true):
			changed = append(changed, name)
		case keyed && !listed:
			unverified = append(unverified, name)
		case keyed && !keys[block[0]]:
			changed = append(changed, name)
		}
	}
	return changed, unverified
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
		adapter.report(nil) // no interface of WayHop's is left to be changed
		return nil
	}
	strict := strictNativePrepare(ctx)
	baseline, err := adapter.readConfig(ctx)
	if err != nil || strings.TrimSpace(baseline) == "" {
		// Nothing has been sent. Said plainly, an Apply is not answered with a rollback that meets the
		// same unreadable router and then reports a restore that failed.
		return &applyStepUntouchedError{err: errExactKeeneticApply}
	}
	// An interface already in the running config predates this Apply: a slot the previous plan
	// created and this one keeps (QA-108), or a saved interface NDM re-created at boot before Entware
	// started, or one a rollback finds still standing. None is re-sent. NDM merges a re-sent block into
	// what is there, so it proves nothing, and the block's `ip global` would pull a tunnel the ladder
	// raised back down to the priority it was created with, moving the default route. During early
	// boot a re-send is not even idempotent: NDM can reject the duplicate while the VPN subsystem
	// settles. Nor is such an interface ever removed by this transaction's cleanups (see found): when
	// anything else fails, the answer must not be deleting a working tunnel this Apply did not create,
	// with whatever the operator attached to it.
	preexisting := make(map[string]bool, len(plan.Interfaces))
	var live [][]string
	for _, block := range plan.Interfaces {
		if _, found := ndmInterfaceSection(baseline, block[0]); found {
			preexisting[block[0]] = true
			live = append(live, block)
		}
	}
	adapter.noteFound(plan, preexisting)
	// Each of them is checked before anything is sent: its lines in the running config, and its key
	// against the public key NDM reports (one regenerated in the KeeneticOS web UI is a change too).
	// An Apply the operator started stops on anything it cannot vouch for, having sent nothing, and
	// says so: it is then not answered with a rollback, which would re-run the previous plan into the
	// same router, refuse the same way, and report a router "not fully restored" that nothing touched.
	listing, listErr := listingFor(ctx, adapter.readInterfaces, live)
	if listErr != nil && strict {
		return &applyStepUntouchedError{err: fmt.Errorf("%w: the router's interface list could not be read to check the keys of the tunnels WayHop created, so nothing was changed",
			errExactKeeneticApply)}
	}
	names, unverified := exactKeeneticDrift(live, baseline, listing, listErr == nil)
	adapter.report(names)
	changed := make(map[string]bool, len(names))
	for _, name := range names {
		changed["interface "+name] = true
	}
	if len(names) != 0 {
		if strict {
			return &applyStepUntouchedError{err: fmt.Errorf("%w: %s on the router no longer carries what WayHop created it with, so nothing was changed; undo the change made to it in KeeneticOS, or delete it there and Apply again to have it re-created",
				errExactKeeneticApply, strings.Join(names, ", "))}
		}
		// Anywhere else it is left exactly as it is, reported, and kept out of this transaction's
		// verifications, while everything else is brought up (see withStrictNativePrepare).
		log.Printf("apply: native: %s changed outside WayHop; left as it is", strings.Join(names, ", "))
		adapter.noteLeft(plan, changed)
	}
	// An unreadable listing outside an Apply leaves a key unverified, not changed: the tunnel's
	// lines did verify, nothing is sent to it, and the Diagnostics row checks it again when it runs.
	if len(unverified) != 0 {
		log.Printf("apply: native: the key of %s could not be verified (the interface list could not be read); left as it is",
			strings.Join(unverified, ", "))
	}
	attempted := &keenetic.Plan{}
	cleanup := func() {
		_ = adapter.cleanup(context.WithoutCancel(ctx), attempted)
	}
	for _, block := range plan.Interfaces {
		if preexisting[block[0]] {
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
	running, err := adapter.readConfig(ctx)
	if err != nil {
		cleanup()
		return errExactKeeneticApply
	}
	// What was just created is held to its key as well: an ignored `wireguard private-key` would
	// otherwise leave an interface that verifies line for line with a key nobody chose. An Apply that
	// cannot read the listing here takes back what it created; elsewhere the key stays unverified.
	created := make(map[string]bool, len(attempted.Interfaces))
	createdListing, err := listingFor(ctx, adapter.readInterfaces, attempted.Interfaces)
	switch {
	case err == nil:
		created = exactKeeneticKeysMatch(attempted.Interfaces, createdListing)
	case strict:
		cleanup()
		return errExactKeeneticApply
	default:
		var names []string
		for _, block := range attempted.Interfaces {
			created[block[0]] = true
			names = append(names, strings.TrimPrefix(block[0], "interface "))
		}
		log.Printf("apply: native: the key of %s could not be verified (the interface list could not be read)",
			strings.Join(names, ", "))
	}
	for _, block := range plan.Interfaces {
		if changed[block[0]] {
			continue
		}
		// A pre-existing interface's `ip global` is the ladder's to set and read back at commit.
		if !verifyExactKeeneticInterfaceBlock(block, running, preexisting[block[0]]) ||
			(!preexisting[block[0]] && !created[block[0]]) {
			cleanup()
			return errExactKeeneticApply
		}
	}
	return nil
}

// report hands the interfaces found changed outside WayHop to whoever shows them to the operator.
func (adapter *exactKeeneticNativeAdapter) report(ifaces []string) {
	if adapter.reportLeft != nil {
		adapter.reportLeft(ifaces)
	}
}

// exactKeeneticPlanKey identifies a target plan's interface set across the phases of one
// transaction: its NDM observation revision and every line of its blocks, hashed.
func exactKeeneticPlanKey(plan *keenetic.Plan) string {
	hash := sha256.New()
	hash.Write([]byte(plan.RunningConfigRev))
	for _, block := range plan.Interfaces {
		for _, line := range block {
			hash.Write([]byte{0})
			hash.Write([]byte(line))
		}
		hash.Write([]byte{1})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// noteFound records the interfaces prepare found already live for plan, for the cleanups of the
// same transaction (the rollback of a failed Apply runs through this same adapter).
func (adapter *exactKeeneticNativeAdapter) noteFound(plan *keenetic.Plan, live map[string]bool) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if adapter.found == nil {
		adapter.found = make(map[string]map[string]bool)
	}
	adapter.found[exactKeeneticPlanKey(plan)] = live
}

func (adapter *exactKeeneticNativeAdapter) foundLive(plan *keenetic.Plan) map[string]bool {
	if plan == nil {
		return nil
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.found[exactKeeneticPlanKey(plan)]
}

// noteLeft records the interfaces a boot or rollback prepare left as they were, changed.
func (adapter *exactKeeneticNativeAdapter) noteLeft(plan *keenetic.Plan, changed map[string]bool) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if adapter.left == nil {
		adapter.left = make(map[string]map[string]bool)
	}
	adapter.left[exactKeeneticPlanKey(plan)] = changed
}

func (adapter *exactKeeneticNativeAdapter) leftAsIs(plan *keenetic.Plan) map[string]bool {
	if plan == nil {
		return nil
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.left[exactKeeneticPlanKey(plan)]
}

// ndmSectionLine is one line of an `interface` section of running-config, whitespace-normalized,
// and whether it sits a level below the section's own commands (inside a `wireguard peer` group).
type ndmSectionLine struct {
	nested bool
	text   string
}

// ndmInterfaceSection returns the lines the running config prints inside the section header opens,
// normalized and without NDM's `!` context separators, and whether that section exists. A section
// runs to the `!` that closes it at the left margin, or to the next interface header. NDM prints a
// section's commands one level in and a peer's commands a level deeper; depth is read against the
// section's first line, so the width of the indent does not matter.
func ndmInterfaceSection(running, header string) ([]ndmSectionLine, bool) {
	want := normalizeNDMCommand(header)
	if want == "" {
		return nil, false
	}
	var section []ndmSectionLine
	found, base := false, -1
	for _, raw := range strings.Split(running, "\n") {
		normalized := normalizeNDMCommand(raw)
		margin := raw != "" && raw[0] != ' ' && raw[0] != '\t'
		if !found {
			found = margin && normalized == want
			continue
		}
		if margin && (normalized == "!" || strings.HasPrefix(normalized, "interface ")) {
			break
		}
		if normalized == "" || normalized == "!" {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		if base < 0 {
			base = indent
		}
		section = append(section, ndmSectionLine{nested: indent > base, text: normalized})
	}
	return section, found
}

// verifyExactKeeneticInterfaceBlock holds a block to its own lines, in their order and at their
// depth, inside the section its header opens, and every peer line inside the group its `wireguard
// peer` line opened. Lines printed between them do not count against it: NDM prints settings of its
// own, and on an interface that outlives an Apply the operator may have attached more in KeeneticOS
// (an `ip access-group`, between `ip mtu` and `ip tcp`). Requiring the block as one unbroken run of
// lines failed such an interface, and the failure path then deleted it. A line that is missing,
// reordered or moved out of its peer still fails: with the indentation normalized away, a peer's
// `connect` printed after its group closed, or found only under another peer, used to pass.
//
// A secret is never expected back (exactKeeneticPrintedLine): `show running-config` does not print it.
//
// skipGlobal leaves the block's `ip global` line out. That value belongs to the ladder wherever one
// governs the interface, and the ladder is verified by reading the priority back, not as a line of
// the block: a raised interface reads the ladder's number, never the one it was created with.
func verifyExactKeeneticInterfaceBlock(block []string, running string, skipGlobal bool) bool {
	if len(block) < 2 {
		return false
	}
	section, ok := ndmInterfaceSection(running, block[0])
	if !ok {
		return false
	}
	expected := make([]ndmSectionLine, 0, len(block)-1)
	for _, command := range block[1:] {
		want, printed := exactKeeneticPrintedLine(command, skipGlobal)
		if want.text == "" {
			return false
		}
		if printed {
			expected = append(expected, want)
		}
	}
	next := 0
	for _, line := range section {
		if next == len(expected) {
			break
		}
		if line == expected[next] {
			next++
			continue
		}
		// A peer's line is looked for only inside its peer group: reaching a line of the interface
		// itself means the group ended without it.
		if expected[next].nested && !line.nested {
			return false
		}
	}
	return next == len(expected)
}

// exactKeeneticPrintedLine is a block command as running-config shows it (normalized, at its depth),
// or false for a line NDM never prints back. KeeneticOS keeps the keys out of `show running-config`:
// KeeneticOS 5.1.8 prints no `wireguard private-key` for any of its five WireGuard interfaces, and the
// test Keenetic none for its six (2026-11-05). Neither prints a `preshared-key` under any peer;
// whether any of them has one cannot be told from that, so a pre-shared key is treated the same way.
// Expecting a key back failed every new tunnel after it was created (and the failure path then
// deleted it) and read every kept one as changed. Nothing can verify a key by reading the
// configuration (the key is checked against `show interface` instead); the block that carries it is
// still sent whole. Each is left out only at its own depth: the private key on the interface, the
// pre-shared key under its peer.
func exactKeeneticPrintedLine(command string, skipGlobal bool) (ndmSectionLine, bool) {
	sub, nested := strings.CutPrefix(command, exactKeeneticPeerIndent)
	line := ndmSectionLine{nested: nested, text: normalizeNDMCommand(sub)}
	switch {
	case !nested && strings.HasPrefix(line.text, "wireguard private-key "),
		nested && strings.HasPrefix(line.text, "preshared-key "),
		!nested && skipGlobal && strings.HasPrefix(line.text, "ip global "):
		return line, false
	}
	return line, true
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
		_ = adapter.cleanup(context.WithoutCancel(ctx), exactKeeneticRemovable(target.Keenetic, adapter.foundLive(target.Keenetic)))
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
	if err != nil || !verifyExactKeeneticRunningConfigLeaving(target, teardown, restore, running, adapter.leftAsIs(target.Keenetic)) {
		cleanup()
		return errExactKeeneticApply
	}
	return nil
}

func (adapter *exactKeeneticNativeAdapter) abort(ctx context.Context, target nativeplan.Plan) error {
	if adapter == nil || adapter.runner == nil || !validExactKeeneticTarget(target) {
		return errExactKeeneticPlan
	}
	plan := exactKeeneticRemovable(target.Keenetic, adapter.foundLive(target.Keenetic))
	// An abort is retried (Roll back, boot, switching routing on) after one that stopped part way, or
	// after the operator deleted a tunnel in KeeneticOS. How NDM answers a `no` for what is already
	// gone is not known here, so what the running config no longer carries is not asked for again (as
	// switching routing off removes only the routes still there), and each removal goes on its own: a
	// refused one does not keep the rest in place, and every refusal is reported.
	if adapter.readConfig != nil {
		if running, err := adapter.readConfig(ctx); err == nil && strings.TrimSpace(running) != "" {
			plan = exactKeeneticStillPresent(plan, running)
		}
	}
	return adapter.cleanupEach(ctx, plan, true)
}

// exactKeeneticStillPresent is plan without what running no longer carries: routes and interfaces
// already removed, and the ladder restore of an interface that is gone.
func exactKeeneticStillPresent(plan *keenetic.Plan, running string) *keenetic.Plan {
	if plan == nil {
		return nil
	}
	lines := normalizedNDMConfigLines(running)
	present := func(identity string) bool {
		return containsRetiredNDMIdentity(lines, normalizeNDMCommand(identity))
	}
	out := *plan
	out.Routes, out.Interfaces = nil, nil
	for _, route := range plan.Routes {
		if present(keenetic.RouteKey(route)) {
			out.Routes = append(out.Routes, route)
		}
	}
	for _, block := range plan.Interfaces {
		if len(block) != 0 && present(block[0]) {
			out.Interfaces = append(out.Interfaces, block)
		}
	}
	if plan.GlobalPriorityWas != nil {
		out.GlobalPriorityWas = make(map[string]int, len(plan.GlobalPriorityWas))
		for iface, was := range plan.GlobalPriorityWas {
			if present("interface " + iface) {
				out.GlobalPriorityWas[iface] = was
			}
		}
	}
	return &out
}

// exactKeeneticRemovable is what a failed Apply may take back down: the whole plan except the
// interfaces it keeps from the previous one (keenetic.Plan.KeptInterfaces) and the ones its prepare
// found already live (found, `interface X` headers). Those were there before this transaction
// began, so removing one undoes nothing it did; it only deletes a working tunnel, and what the
// operator attached to it in KeeneticOS, for a rollback to create again from scratch or, at boot,
// for nothing to put back. Their routes and ladder edits are still this transaction's and still go.
func exactKeeneticRemovable(plan *keenetic.Plan, found map[string]bool) *keenetic.Plan {
	if plan == nil || (len(plan.KeptInterfaces) == 0 && len(found) == 0) {
		return plan
	}
	spared := make(map[string]bool, len(plan.KeptInterfaces)+len(found))
	for _, iface := range plan.KeptInterfaces {
		spared["interface "+iface] = true
	}
	for header, live := range found {
		spared[header] = spared[header] || live
	}
	removable := *plan
	removable.Interfaces = nil
	removable.KeptInterfaces = nil
	for _, block := range plan.Interfaces {
		if len(block) != 0 && !spared[block[0]] {
			removable.Interfaces = append(removable.Interfaces, block)
		}
	}
	return &removable
}

func (adapter *exactKeeneticNativeAdapter) cleanup(ctx context.Context, plan *keenetic.Plan) error {
	return adapter.cleanupEach(ctx, plan, false)
}

// cleanupEach is cleanup; with each, the removals go one command at a time and every one is tried,
// the refused ones named in the error.
func (adapter *exactKeeneticNativeAdapter) cleanupEach(ctx context.Context, plan *keenetic.Plan, each bool) error {
	if adapter == nil || adapter.runner == nil || plan == nil {
		return errExactKeeneticUnavailable
	}
	commands := keenetic.TeardownCommands(plan)
	// An interface this cleanup removes gets no priority put back: the write would go to an
	// interface about to be deleted, and its recorded value is 0 when the interface did not exist
	// before, a write NDM may refuse, which would end the cleanup before the removal below.
	removed := make(map[string]bool, len(plan.Interfaces))
	for _, block := range plan.Interfaces {
		if len(block) != 0 {
			removed[block[0]] = true
		}
	}
	var restore [][]string
	for _, block := range plan.GlobalPriorityRestoreBlocks() {
		if !removed[block[0]] {
			restore = append(restore, block)
		}
	}
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
	if !each {
		if _, err := adapter.runner.ParseBatch(cleanupCtx, append([]string(nil), commands...)); err != nil {
			return errExactKeeneticApply
		}
		return nil
	}
	var refused []string
	for _, command := range commands {
		if _, err := adapter.runner.ParseBatch(cleanupCtx, []string{command}); err != nil {
			refused = append(refused, command)
		}
	}
	if len(refused) != 0 {
		return fmt.Errorf("%w: %d of %d removals were refused: %s", errExactKeeneticApply,
			len(refused), len(commands), strings.Join(refused, "; "))
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
	//   - a VERIFY mismatch means something else mutated NDM between postcheck and persist (a
	//     tunnel switched off in KeeneticOS during the window): fail closed by not saving, and
	//     leave the target as it is. Tearing it down left the core and the kernel plane on deleted
	//     interfaces while both callers kept the revision as running, and Keep could never succeed
	//     again (QA-141). Left alone, the window still judges it, and Roll back still undoes it;
	//   - a failed `system configuration save` does not un-run the configuration: flash failed,
	//     the datapath did not; keep it, retryable.
	running, err := adapter.readConfig(ctx)
	if err != nil {
		return errExactKeeneticApply
	}
	if !verifyExactKeeneticRunningConfigLeaving(*reconcile.Target, reconcile.KeeneticTeardown,
		reconcile.KeeneticPriorityRestore, running, adapter.leftAsIs(reconcile.Target.Keenetic)) {
		return errExactKeeneticDrift
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
	if err != nil || !verifyExactKeeneticRunningConfigLeaving(target, teardown, restore, running, adapter.leftAsIs(target.Keenetic)) {
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
	return verifyExactKeeneticRunningConfigLeaving(target, teardown, restore, running, nil)
}

// verifyExactKeeneticRunningConfigLeaving is verifyExactKeeneticRunningConfig without holding the
// blocks named in left (`interface X` headers) to their lines: the interfaces a boot or rollback
// prepare found changed outside WayHop and left as they were (see prepare).
func verifyExactKeeneticRunningConfigLeaving(
	target nativeplan.Plan,
	teardown []string,
	restore [][]string,
	running string,
	left map[string]bool,
) bool {
	if !validExactKeeneticTarget(target) || !validExactKeeneticTeardown(teardown) ||
		strings.TrimSpace(running) == "" {
		return false
	}
	lines := normalizedNDMConfigLines(running)
	if len(lines) == 0 {
		return false
	}
	// A block's `ip global` is checked as one of its lines only where nothing else owns it. The
	// ladder and the restore are read back below; a kept interface carries the priority the router
	// already gave it, because a kept block is never re-sent. Holding a raised interface to the
	// number in its block failed every native default route at commit.
	ladderOwned := make(map[string]bool)
	for iface := range target.Keenetic.GlobalPriority {
		ladderOwned[iface] = true
	}
	for iface := range restoredPriorities(restore) {
		ladderOwned[iface] = true
	}
	for _, iface := range target.Keenetic.KeptInterfaces {
		ladderOwned[iface] = true
	}
	for _, block := range target.Keenetic.Interfaces {
		if left[block[0]] {
			continue
		}
		if !verifyExactKeeneticInterfaceBlock(block, running, ladderOwned[strings.TrimPrefix(block[0], "interface ")]) {
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
	userspace := make(map[string]bool)
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
		case nativeplan.PathEnginePlugin:
			userspace[decision.Interface] = true
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
			block[len(block)-1] != "up" || blocks[block[0]] || !validExactKeeneticInterfaceBlock(block) {
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
	// A kept interface is spared by every cleanup, so it must name one of this plan's own blocks,
	// once: an entry naming anything else would shield an interface the plan does not describe.
	kept := make(map[string]bool, len(plan.KeptInterfaces))
	for _, iface := range plan.KeptInterfaces {
		if kept[iface] || !managedIfaces[iface] || !blocks["interface "+iface] {
			return false
		}
		kept[iface] = true
	}
	// A device WayHop's userspace AmneziaWG runs is not an NDM interface: no route and no ladder rung
	// may name it, or NDM refuses the batch at commit (or, worse, resolves the name to something else).
	for _, command := range plan.Routes {
		for _, field := range strings.Fields(command) {
			if userspace[field] {
				return false
			}
		}
	}
	for iface := range plan.GlobalPriority {
		if userspace[iface] {
			return false
		}
	}
	return true
}

// validExactKeeneticInterfaceBlock holds a block to the transport's rules (flattenExactKeeneticBatch)
// and to one interface: the first line opens its context and no later line switches to another.
func validExactKeeneticInterfaceBlock(block []string) bool {
	if _, ok := flattenExactKeeneticBatch(block); !ok {
		return false
	}
	for _, command := range block[1:] {
		if strings.HasPrefix(command, "interface ") {
			return false
		}
	}
	return true
}

// flattenExactKeeneticBatch checks one batch for the ndmc transport and renders each command as the
// single full-path line `ndmc -c` takes (see ParseBatch). It is the one place that knows how a block
// nests:
//
//   - `interface X` opens the context every following line is sent under;
//   - a line indented by exactly four spaces belongs to the `wireguard peer <key>` line above it and is
//     sent as `interface X wireguard peer <key> endpoint …`;
//   - any other line closes the peer.
//
// The indent is keenetic.WireguardCommands' own, and it is accepted here rather than dropped by the
// writer because it is the only thing in the list that says which lines belong to the peer: without
// it `endpoint …` flattens to `interface X endpoint …`, a command NDM does not have, unless this code
// learned NDM's grammar to put the peer back. It costs the verification nothing, since running-config
// prints the same lines one level deeper and both sides are compared with whitespace normalized away.
// The validator used to refuse any leading whitespace, so the block the compiler writes for an
// interface WayHop creates could never pass the exact adapter. (The one-level path form was verified
// on a device; the peer form is the same rule one level deeper and has not been run on one yet.)
//
// So the indent is allowed exactly where it carries that meaning: one level of four spaces, under a
// peer, inside an interface. A tab, any other width, trailing whitespace or an indented line with no
// peer above it is refused, and \r, \n and \x00 still are anywhere, so no value can smuggle in a second
// command. Duplicates are judged on the flattened line, which is the command NDM actually receives.
func flattenExactKeeneticBatch(commands []string) ([]string, bool) {
	if len(commands) == 0 || len(commands) > exactKeeneticMaxCommands {
		return nil, false
	}
	lines := make([]string, 0, len(commands))
	seen := make(map[string]bool, len(commands))
	iface, peer := "", ""
	for _, command := range commands {
		if command == "" || len(command) > exactKeeneticMaxCommandBytes ||
			strings.ContainsAny(command, "\r\n\x00") {
			return nil, false
		}
		line := command
		if sub, nested := strings.CutPrefix(command, exactKeeneticPeerIndent); nested {
			if peer == "" || sub == "" || strings.TrimSpace(sub) != sub {
				return nil, false
			}
			line = peer + " " + sub
		} else {
			if strings.TrimSpace(command) != command {
				return nil, false
			}
			peer = ""
			switch {
			case strings.HasPrefix(command, "interface "):
				iface = command
			case iface != "":
				line = iface + " " + command
				if strings.HasPrefix(command, exactKeeneticPeerCommand) {
					peer = line
				}
			}
		}
		// The flattened line is what ndmc gets, so it is the one held to the transport's limit; checking
		// only the parts let a block pass here and fail at the runner after earlier lines had run.
		if len(line) > exactKeeneticMaxCommandBytes || seen[line] {
			return nil, false
		}
		seen[line] = true
		lines = append(lines, line)
	}
	return lines, true
}

func validExactKeeneticTeardown(commands []string) bool {
	return len(commands) <= exactKeeneticMaxCommands && validExactKeeneticCommands(commands, true)
}

// validExactKeeneticCommands is the shape every NDM command must have before it is submitted: what
// the transport can carry (flattenExactKeeneticBatch: one bounded line, since a control character
// would smuggle a second command into it; no duplicates; no padding, since the runner reads
// `interface …` at the start of a line as the context every following line is flattened under and
// verification compares commands with whitespace collapsed), and only `no …` in a teardown. The single
// indentation allowed is the one keenetic.WireguardCommands emits for a peer's own settings, directly
// under the `wireguard peer` line of an interface block or under a sibling; refusing it refused every
// native WireGuard block the compiler produces (QA-121). An empty list is valid: a plan may carry no
// routes and a run may have nothing to tear down.
func validExactKeeneticCommands(commands []string, teardown bool) bool {
	if len(commands) == 0 {
		return true
	}
	if _, ok := flattenExactKeeneticBatch(commands); !ok {
		return false
	}
	for _, command := range commands {
		if teardown && !strings.HasPrefix(command, "no ") {
			return false
		}
	}
	return true
}
