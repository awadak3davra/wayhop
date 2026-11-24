package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"wayhop/internal/atomicfile"
	"wayhop/internal/core"
	"wayhop/internal/nativeplan"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
	"wayhop/internal/plugin"
	"wayhop/internal/updater"
)

// The executor installs one materialization in make-before-break order, calling the platform
// adapters directly. Everything it touches goes through applyExecOps so tests drive it with fakes.

var errExactProductionKernelApply = errors.New("kernel plane execution failed")

// applyExecOps is the narrow set of router mutations an Apply performs. Every op consumes the
// artifact it is handed verbatim; none re-reads the profile or config.
type applyExecOps struct {
	prepareNative   func(context.Context, nativeplan.Plan) error
	commitNative    func(context.Context, nativeplan.Reconciliation) error
	abortNative     func(context.Context, nativeplan.Plan) error
	persistNative   func(context.Context, nativeplan.Reconciliation) error
	postcheckNative func(context.Context, nativeplan.Reconciliation) error
	// core installs (ensure_present: write, reload/start, settle) or stops (ensure_absent) the core.
	core        func(context.Context, executionCoreArtifactV1) error
	coreRunning func() bool
	// checkCore validates config bytes with `sing-box check` on a staged file, touching nothing live.
	checkCore func(context.Context, []byte) error
	// kernel installs the target plane and retires what the previous one left behind.
	kernel          func(ctx context.Context, target executionKernelArtifactV1, previous *executionKernelArtifactV1) error
	kernelTeardown  func(context.Context, executionKernelArtifactV1) error
	kernelPostcheck func(context.Context, executionKernelArtifactV1) error
	// plugins syncs the engine plugins to specs and reports the ones that are not running.
	plugins func(context.Context, []executionPluginSpecV1) []map[string]any

	// The routing switch's own ops (routingswitch.go); no Apply calls them. nativeRoutingOff removes
	// what a native target routes with and keeps its interfaces; nativeRoutingSave makes the native
	// state the router's startup configuration; resolverReload restarts the router's resolver after
	// a kernel plane that fed it directives (Keenetic's dnsmasq ipset= file) was removed, so it stops
	// filling sets that no longer exist.
	nativeRoutingOff  func(context.Context, nativeplan.Plan) (changed bool, err error)
	nativeRoutingSave func(context.Context, nativeplan.Plan) error
	resolverReload    func(context.Context, executionKernelArtifactV1) error
}

// applyExecResult says what an execution did.
type applyExecResult struct {
	Mutated  bool             // at least one op ran (a failure after this needs a rollback)
	Steps    []string         // completed step names
	Problems []map[string]any // plugins that did not come up
}

// applyExecError names the step that failed.
type applyExecError struct {
	Step string
	Err  error
}

func (e *applyExecError) Error() string { return e.Step + ": " + e.Err.Error() }
func (e *applyExecError) Unwrap() error { return e.Err }

// applyStepUntouchedError marks a step that refused before it changed anything on the router. The
// executor then does not count that step as a mutation: a refusal that left everything as it was
// needs no rollback, and a rollback would run into the same refusal (re-executing the previous
// plan meets the same live state) and tell the operator the router was not fully restored when
// nothing on it had been touched.
type applyStepUntouchedError struct{ err error }

func (e *applyStepUntouchedError) Error() string { return e.err.Error() }
func (e *applyStepUntouchedError) Unwrap() error { return e.err }

const (
	stepNativePrepare = "native_prepare"
	stepPlugins       = "plugins"
	stepCore          = "core"
	stepKernel        = "kernel"
	stepPluginsRetire = "plugins_retire"
	stepNativeCommit  = "native_commit"
	stepPostcheck     = "postcheck"
	stepNativePersist = "native_persist"
)

// materializationIsDemo reports whether every plane is a demo no-op.
func materializationIsDemo(m *executionMaterializationV1) bool {
	return m != nil && m.Core.Action == ExecutionDemoNoop && m.Kernel.Action == ExecutionDemoNoop &&
		m.PluginAction == ExecutionDemoNoop
}

// executeMaterialization installs m. previous is what the router runs now (nil = nothing WayHop
// installed); it feeds the plugin make-before-break union and the kernel retire. progress is called
// with each step's name so a reloaded page can tell what is going on.
func executeMaterialization(
	ctx context.Context,
	ops applyExecOps,
	m *executionMaterializationV1,
	previous *executionMaterializationV1,
	progress func(string),
) (applyExecResult, error) {
	result := applyExecResult{Steps: []string{}, Problems: []map[string]any{}}
	if m == nil || !m.known() {
		return result, &applyExecError{Step: "program", Err: errors.New("nothing to execute: the materialization is unknown")}
	}
	if progress == nil {
		progress = func(string) {}
	}
	if materializationIsDemo(m) {
		return result, nil
	}
	for _, action := range []ExecutionActionV1{m.Core.Action, m.Kernel.Action, m.PluginAction} {
		if action != ExecutionEnsurePresent && action != ExecutionEnsureAbsent {
			return result, &applyExecError{Step: "program", Err: fmt.Errorf("plane action %q cannot be executed", action)}
		}
	}
	if m.Native != nil && (ops.prepareNative == nil || ops.commitNative == nil || ops.postcheckNative == nil) {
		return result, &applyExecError{Step: "program", Err: errors.New("this daemon has no native (UCI/NDM) adapter")}
	}
	if ops.core == nil || ops.kernel == nil || ops.plugins == nil || ops.coreRunning == nil {
		return result, &applyExecError{Step: "program", Err: errors.New("the execution adapters are incomplete")}
	}
	step := func(name string, run func() error) error {
		if err := context.Cause(ctx); err != nil {
			return &applyExecError{Step: name, Err: err}
		}
		progress(name)
		mutatedBefore := result.Mutated
		result.Mutated = true
		if err := run(); err != nil {
			var untouched *applyStepUntouchedError
			if errors.As(err, &untouched) {
				result.Mutated = mutatedBefore
			}
			return &applyExecError{Step: name, Err: err}
		}
		result.Steps = append(result.Steps, name)
		return nil
	}

	var previousKernel *executionKernelArtifactV1
	if previous.known() && previous.Kernel.Action == ExecutionEnsurePresent {
		k := previous.Kernel
		previousKernel = &k
	}
	var previousPlugins []executionPluginSpecV1
	if previous.known() {
		previousPlugins = previous.pluginSpecs()
	}
	targetPlugins := m.pluginSpecs()

	// 1. Native interfaces first: sing-box and the kernel plane may bind to them.
	if m.Native != nil {
		target := m.nativeTarget()
		if target == nil {
			return result, &applyExecError{Step: stepNativePrepare, Err: errors.New("the native program has no target plan")}
		}
		if err := step(stepNativePrepare, func() error { return ops.prepareNative(ctx, *target) }); err != nil {
			return result, err
		}
	}
	// 2. Plugins, make-before-break: bring the new set up while the old set keeps running; the old
	//    ones are retired after the consumer planes switched.
	if len(targetPlugins) != 0 || len(previousPlugins) != 0 {
		union := unionPluginSpecs(targetPlugins, previousPlugins)
		if err := step(stepPlugins, func() error { ops.plugins(ctx, union); return nil }); err != nil {
			return result, err
		}
	}
	// 3. Core, then kernel plane (the kernel catch must exist as the TUN stops capturing those
	//    destinations); when the core is being retired the kernel plane goes up first.
	if m.Core.Action == ExecutionEnsurePresent {
		if err := step(stepCore, func() error { return ops.core(ctx, m.Core) }); err != nil {
			return result, err
		}
	}
	if m.Kernel.Action == ExecutionEnsurePresent {
		if err := step(stepKernel, func() error { return ops.kernel(ctx, m.Kernel, previousKernel) }); err != nil {
			return result, err
		}
	}
	if m.Core.Action == ExecutionEnsureAbsent {
		if err := step(stepCore, func() error { return ops.core(ctx, m.Core) }); err != nil {
			return result, err
		}
	}
	if m.Kernel.Action == ExecutionEnsureAbsent {
		if err := step(stepKernel, func() error { return ops.kernel(ctx, m.Kernel, previousKernel) }); err != nil {
			return result, err
		}
	}
	// 4. Retire the plugins nothing references any more; what is still down after this is a
	//    problem the response names, not a refusal.
	if len(targetPlugins) != 0 || len(previousPlugins) != 0 {
		if err := step(stepPluginsRetire, func() error {
			result.Problems = ops.plugins(ctx, targetPlugins)
			return nil
		}); err != nil {
			return result, err
		}
	}
	// 5. Native commit: routes plus removal of the obsolete native resources.
	if m.Native != nil {
		if err := step(stepNativeCommit, func() error { return ops.commitNative(ctx, m.Native.Delta.Reconcile) }); err != nil {
			return result, err
		}
	}
	// 6. Postcheck: prove the router is in the state the record is about to claim.
	if err := step(stepPostcheck, func() error { return postcheckMaterialization(ctx, ops, m) }); err != nil {
		return result, err
	}
	return result, nil
}

// postcheckMaterialization proves the planes are in place: kernel plane present, core running as
// intended, native running-config verified.
func postcheckMaterialization(ctx context.Context, ops applyExecOps, m *executionMaterializationV1) error {
	if m.Native != nil && ops.postcheckNative != nil {
		if err := ops.postcheckNative(ctx, m.Native.Delta.Reconcile); err != nil {
			return fmt.Errorf("native state does not match the plan: %w", err)
		}
	}
	if m.Kernel.Action == ExecutionEnsurePresent && ops.kernelPostcheck != nil {
		if err := ops.kernelPostcheck(ctx, m.Kernel); err != nil {
			return fmt.Errorf("the kernel routing plane is not installed: %w", err)
		}
	}
	wantRunning := m.Core.Action == ExecutionEnsurePresent
	if running := ops.coreRunning(); running != wantRunning {
		if wantRunning {
			return errors.New("sing-box is not running after the apply")
		}
		return errors.New("sing-box is still running although this configuration does not use it")
	}
	return nil
}

// teardownMaterialization removes everything m installed. Used when there is no baseline to return
// to: stop the core, tear down the kernel plane, abort the native target, retire the plugins.
func teardownMaterialization(ctx context.Context, ops applyExecOps, m *executionMaterializationV1) error {
	if m == nil || !m.known() || materializationIsDemo(m) {
		return nil
	}
	var errs []error
	if ops.core != nil {
		absent := m.Core
		absent.Action = ExecutionEnsureAbsent
		if err := ops.core(ctx, absent); err != nil {
			errs = append(errs, fmt.Errorf("stop core: %w", err))
		}
	}
	if m.Kernel.Action == ExecutionEnsurePresent && ops.kernelTeardown != nil {
		if err := ops.kernelTeardown(ctx, m.Kernel); err != nil {
			errs = append(errs, fmt.Errorf("kernel plane teardown: %w", err))
		}
	}
	if target := m.nativeTarget(); target != nil && ops.abortNative != nil {
		if err := ops.abortNative(ctx, *target); err != nil {
			errs = append(errs, &nativeLeftoverError{err})
		}
	}
	if ops.plugins != nil {
		ops.plugins(ctx, nil)
	}
	return errors.Join(errs...)
}

// unionPluginSpecs is target plus every previous spec whose id target does not carry: the set that
// keeps the old tunnels up while the new ones come up.
func unionPluginSpecs(target, previous []executionPluginSpecV1) []executionPluginSpecV1 {
	out := append([]executionPluginSpecV1{}, target...)
	seen := make(map[string]bool, len(target))
	for _, spec := range target {
		seen[spec.ID] = true
	}
	for _, spec := range previous {
		if !seen[spec.ID] {
			out = append(out, spec)
			seen[spec.ID] = true
		}
	}
	return out
}

func toPluginSpecs(specs []executionPluginSpecV1) []plugin.Spec {
	out := make([]plugin.Spec, 0, len(specs))
	for _, spec := range specs {
		out = append(out, plugin.Spec{ID: spec.ID, Endpoint: spec.Endpoint, SOCKSPort: spec.SOCKSPort})
	}
	return out
}

// --- production composition -------------------------------------------------------------------

// productionExecOps binds the ops to the real core supervisor, plugin manager and platform
// adapters. Tests replace it through Server.execOps.
func (s *Server) productionExecOps() applyExecOps {
	if s.execOps != nil {
		return *s.execOps
	}
	openwrt, _ := newExactOpenWrtNativeAdapter(exactOpenWrtContextRunner{})
	keeneticRunner := newExactKeeneticNDMCRunner()
	keeneticAdapter, _ := newExactKeeneticNativeAdapter(keeneticRunner)
	if keeneticAdapter != nil && s.keeneticConfigReader != nil {
		keeneticAdapter.readConfig = s.keeneticConfigReader
	}
	if keeneticAdapter != nil {
		keeneticAdapter.reportLeft = s.noteKeeneticLeftAsIs
		if s.keeneticInterfacesReader != nil {
			keeneticAdapter.readInterfaces = s.keeneticInterfacesReader
		}
	}
	native, _ := newExactNativePlatformAdapter(openwrt, keeneticAdapter)
	ops := applyExecOps{
		core:        s.coreStep,
		coreRunning: func() bool { return s.singbox != nil && s.singbox.Running() },
		checkCore:   s.checkCoreConfig,
		kernel:      s.kernelStep,
		kernelTeardown: func(ctx context.Context, artifact executionKernelArtifactV1) error {
			return s.kernelTeardown(ctx, artifact)
		},
		kernelPostcheck: s.kernelPostcheck,
		resolverReload:  reloadResolverAfterTeardown,
		plugins: func(_ context.Context, specs []executionPluginSpecV1) []map[string]any {
			if s.plugins == nil {
				return []map[string]any{}
			}
			s.plugins.Sync(toPluginSpecs(specs))
			return failedPluginSummary(s.plugins.Status())
		},
	}
	if native != nil {
		ops.prepareNative = native.prepare
		ops.commitNative = native.commit
		ops.abortNative = native.abort
		ops.persistNative = native.persist
		ops.postcheckNative = native.postcheck
		ops.nativeRoutingOff = native.routingOff
		ops.nativeRoutingSave = native.routingSave
	}
	return ops
}

// reloadResolverAfterTeardown restarts Keenetic's dnsmasq once the plane that wrote its ipset=
// directives is gone (kernelTeardown deletes the file but the resolver keeps what it read). Nothing
// to do for a plane that fed the resolver nothing, or for the nft plane, whose sets dnsmasq never
// learned about.
func reloadResolverAfterTeardown(ctx context.Context, artifact executionKernelArtifactV1) error {
	if artifact.Ipset == nil || len(artifact.Ipset.DnsmasqConf) == 0 {
		return nil
	}
	adapter, err := newExactKeeneticKernelAdapter(*artifact.Ipset)
	if err != nil {
		return fmt.Errorf("%w: adapter: %v", errExactProductionKernelApply, err)
	}
	return reloadKeeneticDnsmasq(ctx, adapter.runner)
}

// singboxSettleWindow is how long an Apply waits after a (re)start to confirm the core STAYED up.
// Reload()/Start() only prove the process was SPAWNED — they return as soon as the fork succeeds.
// A config that passes `sing-box check` can still abort at runtime (TUN device busy, a listen port
// already taken, an unreachable required resource), and without this re-check Apply would report
// success over a core that is already dead.
const singboxSettleWindow = 2 * time.Second

// verifySingboxLive re-checks that sing-box is still alive singboxSettleWindow after a reload/start.
// Returns "" when the core stayed up, else a diagnostic carrying the tail of the core log (which
// holds the actual abort reason). Poll-based: a crash is caught within ~100ms, and the full window
// is only ever spent on the healthy path.
func (s *Server) verifySingboxLive() string {
	deadline := time.Now().Add(singboxSettleWindow)
	for {
		if !s.singbox.Running() {
			msg := "sing-box exited right after (re)start — the config was written but the core is NOT running"
			lines := s.singbox.LogLines()
			// Prefer a CLASSIFIED cause (which rule-sets failed, a port collision, a busy TUN) with a
			// remedy: the raw FATAL is a wall of nested errors, and the recurring ones are very fixable.
			// Fall back to the log tail when the abort isn't recognized — never invent a diagnosis.
			if f := core.ClassifyStartFailure(lines); f.Kind != "" {
				return msg + ": " + f.Summary()
			}
			if len(lines) > 0 {
				tail := lines
				if len(tail) > 6 {
					tail = tail[len(tail)-6:]
				}
				msg += ": " + strings.Join(tail, " | ")
			}
			return msg
		}
		if !time.Now().Before(deadline) {
			return ""
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// coreStep installs or stops the core. ensure_present writes the config atomically, reloads a
// running core (or starts a stopped one) and waits the settle window; ensure_absent stops it (which
// also clears the watchdog's desired flag so it does not fight the native datapath).
func (s *Server) coreStep(ctx context.Context, artifact executionCoreArtifactV1) error {
	if s.singbox == nil {
		return errors.New("core manager unavailable")
	}
	switch artifact.Action {
	case ExecutionEnsureAbsent:
		if err := s.singbox.Stop(); err != nil {
			return fmt.Errorf("stop sing-box: %w", err)
		}
		return nil
	case ExecutionEnsurePresent:
	default:
		return fmt.Errorf("core action %q cannot be executed", artifact.Action)
	}
	if len(artifact.Config) == 0 || artifact.ConfigPath == "" {
		return errors.New("the core artifact carries no config")
	}
	if !s.singbox.Available() {
		return fmt.Errorf("sing-box binary not found (%s) — the config was not written because nothing would run it", artifact.BinaryPath)
	}
	// Temp and rename, never the live file truncated in place: a kill or power cut before the fsync left
	// a zero-length or torn config, and an ENOSPC partway destroyed the only on-disk copy while the old
	// core ran on from memory, so the next scheduled restart read the broken file. The temp's name
	// (singbox.json.*.tmp) does not end in .json, so sing-box's directory mode never loads it.
	if err := atomicfile.Write(artifact.ConfigPath, artifact.Config, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", artifact.ConfigPath, err)
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if s.singbox.Running() {
		if err := s.singbox.Reload(); err != nil {
			return fmt.Errorf("reload sing-box: %w", err)
		}
	} else if err := s.singbox.Start(); err != nil {
		return fmt.Errorf("start sing-box: %w", err)
	}
	if msg := s.verifySingboxLive(); msg != "" {
		return errors.New(msg)
	}
	return nil
}

// checkCoreConfig runs `sing-box check` on the candidate staged next to the live config. It never
// touches the live file or process.
func (s *Server) checkCoreConfig(ctx context.Context, config []byte) error {
	if s.singbox == nil {
		return errors.New("core manager unavailable")
	}
	if !s.singbox.Available() {
		return fmt.Errorf("sing-box binary not found at %s", s.config().SingBox.Bin)
	}
	dir := filepath.Dir(s.config().SingBox.Config)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := coreConfigSpaceError(dir, len(config), coreDirAvail); err != nil {
		return err
	}
	staged, cleanup, err := stageExactCoreConfig(dir, config)
	if err != nil {
		return fmt.Errorf("stage config for check: %w", err)
	}
	defer cleanup()
	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return s.singbox.CheckConfig(checkCtx, staged)
}

// coreDirAvail reads the free space under the core's config directory; a var so tests decide it.
var coreDirAvail = updater.AvailBytes

// coreConfigSpaceReserve is left free on top of what an Apply writes: the overlay also holds UCI,
// the store and the logs, and a filesystem run to zero fails the next of those writes instead.
const coreConfigSpaceReserve = 1 << 20

// coreConfigSpaceError refuses an Apply whose core config would not fit where it is written. An Apply
// holds about three copies at its peak - the staged check copy here, the temp the live file is swapped
// in from, and the Apply record, which keeps the config base64-encoded for the committed and the
// tested revision - and since downloaded feeds reach the core, a large list sent to a proxy makes a
// config of megabytes, against perhaps 6 MB free on a small router's overlay. An unknown free
// space (off Linux, or statfs failing) skips the guard rather than blocking on it.
func coreConfigSpaceError(dir string, size int, avail func(string) (uint64, bool)) error {
	free, ok := avail(dir)
	if !ok {
		return nil
	}
	need := 3*uint64(size) + coreConfigSpaceReserve
	if free >= need {
		return nil
	}
	mb := func(n uint64) string { return fmt.Sprintf("%.1f MB", float64(n)/(1<<20)) }
	return fmt.Errorf("not enough free space in %s for the proxy core's config: an Apply needs about %s there "+
		"(the %s config, its check copy and the Apply record) and %s is free - make large routing lists "+
		"smaller or send them to a WireGuard/AmneziaWG connection in hybrid or fast mode, or free space on the router",
		dir, mb(need), mb(uint64(size)), mb(free))
}

// kernelStep installs the target kernel plane (nft/ip on OpenWrt, ipset/iptables + the netfilter.d
// hook on Keenetic) and retires what the previous plane left behind.
func (s *Server) kernelStep(ctx context.Context, target executionKernelArtifactV1, previous *executionKernelArtifactV1) error {
	if target.Action == ExecutionEnsureAbsent {
		// OpenWrt retires through the command list bound at materialization; Keenetic through the
		// previous plane's own teardown script.
		if previous != nil && previous.Ipset != nil {
			return s.kernelTeardown(ctx, *previous)
		}
		if len(target.Retire) == 0 {
			return nil
		}
		adapter, err := newExactKernelAdapter(exactKernelToolRunner{nft: target.NFTTool, ip: target.IPTool})
		if err != nil {
			return fmt.Errorf("%w: adapter: %v", errExactProductionKernelApply, err)
		}
		if err := adapter.apply(ctx, target); err != nil {
			return err
		}
		s.syncBootGuard(nil) // the guard went with the plane; so does its boot copy
		// The dlist sets went with the table (fast mode left): the snippet that fills them goes too,
		// and so does a watch of it.
		s.stopFastDNSWatch()
		if err := s.syncFastDNS(ctx, nil); err != nil {
			log.Printf("apply: kernel retire: %v", err)
		}
		return nil
	}
	if target.Action != ExecutionEnsurePresent {
		return fmt.Errorf("kernel action %q cannot be executed", target.Action)
	}
	if target.Ipset != nil {
		adapter, err := newExactKeeneticKernelAdapter(*target.Ipset)
		if err != nil {
			return fmt.Errorf("%w: adapter: %v", errExactProductionKernelApply, err)
		}
		// The kill switch backstop's routes go in before any rule or mark is (re)written, and the old
		// plane's stay until that plane is retired below (pbr/backstop.go).
		if err := s.syncKillSwitchBackstop(ctx, target.Plan, *target.Ipset, true, true, previous); err != nil {
			return fmt.Errorf("%w: kill switch backstop: %v", errExactProductionKernelApply, err)
		}
		// A replaced plane is NOT taken down first: that left nothing marked, and listed traffic on
		// the WAN, until the new program ran (kill switch audit). The new program goes in over it (its
		// chain is one commit, its rules del-then-add), then only what it does not install is retired.
		replaced := previous != nil && previous.Ipset != nil && string(previous.Ipset.Script) != string(target.Ipset.Script)
		if replaced {
			if flush := pbr.ReflushTables(string(previous.Ipset.Script), string(target.Ipset.Script)); len(flush) > 0 {
				if err := adapter.runProgram(ctx, *target.Ipset, strings.Join(flush, "\n")+"\n"); err != nil {
					log.Printf("apply: reflush the tables the new Keenetic plane re-seeds: %v", err)
				}
			}
		}
		if err := adapter.apply(ctx, *target.Ipset); err != nil {
			return err
		}
		if previous != nil && previous.Ipset != nil {
			if err := adapter.pruneRestore(ctx, previous.Ipset.Restore, target.Ipset.Restore); err != nil {
				return err
			}
		}
		// Fast mode guards dnsmasq's restart for the policy file the hook install writes (keeneticfast.go):
		// the file it replaces and whether DNS answered are read before it is written.
		fastPolicy := target.Ipset.DynamicDomainSets && len(target.Ipset.DnsmasqConf) != 0 && !s.config().Demo
		var pre keeneticFastPreInstall
		if fastPolicy {
			if pre, err = keeneticFastBeforeInstall(ctx); err != nil {
				return fmt.Errorf("%w: %v", errExactProductionKernelApply, err)
			}
		}
		// The hook goes in before the old plane is retired, and takes the plane with it if it fails.
		// A plane installed without one survives only until NDM's next firewall rebuild — minutes, on
		// a router where an interface flap triggers it — and would disappear with the panel still
		// reporting applied.
		if _, err := installKeeneticPBRHook(*target.Ipset); err != nil {
			_ = adapter.teardown(ctx, *target.Ipset)
			if replaced {
				if tdErr := s.kernelTeardown(ctx, *previous); tdErr != nil {
					log.Printf("apply: previous Keenetic plane teardown: %v", tdErr)
				}
			}
			return fmt.Errorf("install the netfilter.d re-assert hook: %w", err)
		}
		if replaced {
			if err := s.retireKeeneticPlane(ctx, *previous.Ipset, *target.Ipset); err != nil {
				log.Printf("apply: retire the previous Keenetic plane: %v", err)
			}
		}
		if previous != nil && previous.Ipset != nil {
			s.dropExtraIfaces(ctx, previous.Plan, *previous.Ipset, target.Ipset)
		}
		// From the kernel: the retire may have flushed the table.
		if err := s.syncKillSwitchBackstop(ctx, target.Plan, *target.Ipset, false, true, nil); err != nil {
			log.Printf("apply: kill switch backstop: drop the routes no plane needs: %v", err)
		}
		// The learned addresses of kill-switched domain sets, for the boot fill: written
		// when an Apply is saved, if they changed.
		s.saveLearnedNow()
		s.sweepLeakedFlows(ctx, target.Plan, *target.Ipset, true, "the Apply")
		// Domain zones are populated by the resolver, so they stay empty until it has read the
		// directives just written. A failure here is degraded, not wrong — the IP part of the plane
		// is installed and the domains start filling at the resolver's next start.
		// In fast mode the restart is guarded instead: a dnsmasq that refuses the file or stops answering
		// gets the previous file back, and the step fails so the Apply rolls back.
		if fastPolicy {
			return s.keeneticFastReload(ctx, adapter.runner.Run, *target.Ipset, target.Plan, pre)
		}
		s.keeneticFastLeft()
		if len(target.Ipset.DnsmasqConf) != 0 {
			if reloadErr := reloadKeeneticDnsmasq(ctx, adapter.runner); reloadErr != nil {
				log.Printf("apply: domain sets will fill only after the resolver restarts: %v", reloadErr)
			}
			// Also the rollback of a fast Apply to an earlier plane: a dnsmasq that did
			// not come back is restarted by the loop.
			if !s.config().Demo && waitKeeneticAlive(ctx) != nil {
				s.oweRestartIfSilent(ctx)
			}
		}
		return nil
	}
	if previous != nil && previous.Ipset != nil {
		// Platform switch inside one record is impossible in practice, but never leave a plane behind.
		if err := s.kernelTeardown(ctx, *previous); err != nil {
			log.Printf("apply: previous Keenetic plane teardown: %v", err)
		}
	}
	adapter, err := newExactKernelAdapter(exactKernelToolRunner{nft: target.NFTTool, ip: target.IPTool})
	if err != nil {
		return fmt.Errorf("%w: adapter: %v", errExactProductionKernelApply, err)
	}
	adapter.keep = s.electedRouteKeeper(ctx, target.Plan)
	// The guard is rendered with the router's routes as they are now; the postcheck that follows
	// reads the same ones (killswitchlocal.go).
	s.noteGuardTunnels(target.Plan)
	s.refreshGuardLocal(true)
	adapter.hold = s.namesHold
	adapter.learned = s.learnedNamesProgram
	adapter.guardTx = &s.ksGuardTx
	adapter.coreRunning = func() bool { return s.singbox != nil && s.singbox.Running() }
	if previous != nil && previous.Action == ExecutionEnsurePresent && previous.Ipset == nil && previous.Plan != nil {
		adapter.fallbackGuard, adapter.fallbackPlan = adapter.guardProgram(previous.Plan), previous.Plan
	}
	var prevPlan *pbr.Plan
	if previous != nil && previous.Action == ExecutionEnsurePresent && previous.Ipset == nil {
		prevPlan = previous.Plan
	}
	nftPath := target.NFTTool.ResolvedPath
	adapter.carry = func(ctx context.Context, plan *pbr.Plan) string {
		return s.fastInstallProgram(ctx, nftPath, plan, prevPlan)
	}
	adapter.mustLoad = s.fastMustLoad
	// dnsmasq answering on 127.0.0.1:53 before the install arms the watch after it.
	dnsWasUp := target.Plan != nil && len(target.Plan.DlistSets()) > 0 && !s.config().Demo &&
		s.detectedPlatform() == platform.OpenWrt && fastDNSAlive(ctx, false) == nil
	dnsAfter := s.fastDNSGuard(ctx, target.Plan)
	// A list moving from nft to a table gets its routes before the plane drops its set, so it has no
	// moment by the WAN; only tables the installed plane does not use.
	s.preloadRoutedTables(ctx, target.Plan, prevPlan)
	if err := adapter.apply(ctx, target); err != nil {
		return fmt.Errorf("%w: %v", errExactProductionKernelApply, err)
	}
	// The large lists' tables (fastdns_routed.go): their rules came with the plane; their routes now.
	// A table that cannot be filled fails the step, so the Apply rolls back rather than leave a list
	// unrouted.
	if err := s.syncRoutedTables(ctx, target.Plan); err != nil {
		return fmt.Errorf("%w: %v", errExactProductionKernelApply, err)
	}
	// The fast DNS plane's dnsmasq snippet follows the installed plan (fastdns.go). A dnsmasq that no
	// longer answers after the restart has had the snippet taken out again; the step fails so the
	// Apply rolls back rather than leave the LAN without DNS.
	if err := s.syncFastDNS(ctx, target.Plan); err != nil {
		return fmt.Errorf("%w: %v", errExactProductionKernelApply, err)
	}
	if err := dnsAfter(); err != nil {
		return fmt.Errorf("%w: %v", errExactProductionKernelApply, err)
	}
	// A plan without resolver-fed sets leaves no DNS table behind (the previous fast plan's).
	if target.Plan != nil && len(target.Plan.DlistSets()) == 0 {
		command := "nft delete table inet " + target.Plan.DNSTable()
		if err := adapter.runCommand(ctx, command); err != nil && !exactKernelAlreadyAbsent(command, err) {
			log.Printf("apply: the fast path's DNS table was not removed: %v", err)
		}
	}
	// The LAN's DNS is watched for a minute after the install (live 22.11: it stalled 10-20 s later).
	s.fastDNSInstalled()
	s.startFastDNSWatch(target.Plan, dnsWasUp)
	// The same guard on flash, for the boot before WayHop runs (killswitchnft.go), and the learned
	// addresses of its kill-switched names if they changed since the file was written.
	s.syncBootGuard(target.Plan)
	s.saveLearnedNamesNow(target.Plan)
	s.setLearnTarget(target.Plan, target.NFTTool, target.IPTool)
	return nil
}

// kernelTeardown removes an installed plane.
func (s *Server) kernelTeardown(ctx context.Context, artifact executionKernelArtifactV1) error {
	return s.kernelTeardownSparing(ctx, artifact, nil)
}

// kernelTeardownSparing is kernelTeardown that leaves in place the Keenetic DNS rules the program
// spare also installs; nil spares nothing.
func (s *Server) kernelTeardownSparing(ctx context.Context, artifact executionKernelArtifactV1, spare []byte) error {
	if artifact.Action != ExecutionEnsurePresent {
		return nil
	}
	if artifact.Ipset != nil {
		adapter, err := newExactKeeneticKernelAdapter(*artifact.Ipset)
		if err != nil {
			return fmt.Errorf("%w: adapter: %v", errExactProductionKernelApply, err)
		}
		hookErr := removeKeeneticPBRHook()
		if err := adapter.teardownSparing(ctx, *artifact.Ipset, spare); err != nil {
			return err
		}
		// The backstop's rules went with the program; its routes go after them.
		if spare == nil {
			s.dropExtraIfaces(ctx, artifact.Plan, *artifact.Ipset, nil)
			s.clearKillSwitchBackstop(ctx)
			s.keeneticFastLeft() // its policy file went with the hook; so does a watch of it
		}
		return hookErr
	}
	adapter, err := newExactKernelAdapter(exactKernelToolRunner{nft: artifact.NFTTool, ip: artifact.IPTool})
	if err != nil {
		return fmt.Errorf("%w: adapter: %v", errExactProductionKernelApply, err)
	}
	if err := adapter.teardown(ctx, kernelTeardownOf(artifact)); err != nil {
		return err
	}
	// The dlist sets went with the table: the snippet that fills them goes too, and a watch of it.
	s.stopFastDNSWatch()
	if err := s.syncFastDNS(ctx, nil); err != nil {
		log.Printf("apply: kernel teardown: %v", err)
	}
	// A plane taken down with nothing to replace it (routing switched off, an Apply with no baseline
	// to return to): the guard would hold the kill-switched addresses with no tunnel route left to
	// take. It goes after the plane, as the Keenetic backstop's routes do.
	s.syncBootGuard(nil)
	return adapter.dropGuard(ctx)
}

// kernelPostcheck proves the plane is in the kernel, not merely that a command succeeded: NDM
// rebuilds its firewall on its own schedule and fw4 reloads flush foreign tables.
func (s *Server) kernelPostcheck(ctx context.Context, artifact executionKernelArtifactV1) error {
	if artifact.Action != ExecutionEnsurePresent {
		return nil
	}
	if artifact.Ipset != nil {
		adapter, err := newExactKeeneticKernelAdapter(*artifact.Ipset)
		if err != nil {
			return err
		}
		return adapter.postcheck(ctx, *artifact.Ipset)
	}
	adapter, err := newExactKernelAdapter(exactKernelToolRunner{nft: artifact.NFTTool, ip: artifact.IPTool})
	if err != nil {
		return err
	}
	adapter.hold = s.namesHold
	return adapter.postcheck(ctx, artifact)
}

// renewKernelNamesHold is the reconcile tick's part in the nft guard: the boot copy follows the
// installed plan, and the names hold gets another period while the core runs.
func (s *Server) renewKernelNamesHold(ctx context.Context, artifact executionKernelArtifactV1, coreRunning bool) {
	if artifact.Action != ExecutionEnsurePresent || artifact.Ipset != nil || artifact.Plan == nil {
		return
	}
	s.noteGuardTunnels(artifact.Plan)
	if s.refreshGuardLocal(false) {
		s.reloadGuardForRoutes(ctx, artifact)
	}
	s.noteStoredPlan(artifact.Plan)
	s.syncBootGuard(artifact.Plan)
	s.setLearnTarget(artifact.Plan, artifact.NFTTool, artifact.IPTool)
	run := func(ctx context.Context, program string) error {
		_, err := exactKernelToolRunner{nft: artifact.NFTTool, ip: artifact.IPTool}.Run(ctx, program, "nft", "-f", "-")
		return err
	}
	s.renewNamesHold(ctx, artifact.Plan, coreRunning, run)
	s.coreReturned(artifact.Plan, coreRunning)
	// The addresses of kill-switched names are learned on a timer of their own (killswitchlearn.go).
}

// reloadGuardForRoutes loads the guard again when the router's own routes changed what it says (a
// new segment inside a private network a kill-switched list names). Only the guard:
// the plane does not read those routes. With the learned addresses and the hold's remaining time, as
// every load. A plan whose guard does not depend on the routes renders the same program and is left
// alone. A failed load is logged; the next tick's postcheck then finds the guard is not this one and
// reinstalls.
func (s *Server) reloadGuardForRoutes(ctx context.Context, artifact executionKernelArtifactV1) {
	adapter, err := newExactKernelAdapter(exactKernelToolRunner{nft: artifact.NFTTool, ip: artifact.IPTool})
	if err != nil {
		return
	}
	adapter.hold = s.namesHold
	adapter.learned = s.learnedNamesProgram
	adapter.guardTx = &s.ksGuardTx
	adapter.coreRunning = func() bool { return s.singbox != nil && s.singbox.Running() }
	guard := adapter.guardProgram(artifact.Plan)
	if guard == "" || adapter.guardLoaded(ctx, guard) {
		return
	}
	if err := adapter.loadGuard(ctx, guard, artifact.Plan); err != nil {
		log.Printf("kill switch: the guard was not reloaded for the router's changed routes: %v", strings.TrimSpace(err.Error()))
		return
	}
	log.Printf("kill switch: the guard was reloaded: the router's own routes into private addresses a kill-switched list covers changed")
}

// keeneticProductionNativeOperations names the exact NDM operations the Keenetic adapter implements,
// so the capability set can offer native adoption/creation on that platform.
func keeneticProductionNativeOperations() map[string]bool {
	operations := make(map[string]bool, 6)
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		for _, operation := range []platform.NativeOperation{
			platform.NativeAdopt, platform.NativeCreate, platform.NativeRemove,
		} {
			operations[platform.NativeOperationCapabilityID(protocol, operation)] = true
		}
	}
	return operations
}
