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
// tested revision - and since downloaded feeds reach the core (QA-066) a refilter-sized list sent to
// a proxy makes a config of megabytes, against 6.1 MB free on the test router's overlay. An unknown free
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
		return adapter.apply(ctx, target)
	}
	if target.Action != ExecutionEnsurePresent {
		return fmt.Errorf("kernel action %q cannot be executed", target.Action)
	}
	if target.Ipset != nil {
		if previous != nil && previous.Ipset != nil && string(previous.Ipset.Script) != string(target.Ipset.Script) {
			// A replaced plane: remove the old sets and marks first so nothing the new plan no longer
			// names lingers; the new program is installed right after. The DNS redirect and refusals
			// the new program keeps stay in place across the swap.
			if err := s.kernelTeardownSparing(ctx, *previous, target.Ipset.Script); err != nil {
				log.Printf("apply: previous Keenetic plane teardown: %v", err)
			}
		}
		adapter, err := newExactKeeneticKernelAdapter(*target.Ipset)
		if err != nil {
			return fmt.Errorf("%w: adapter: %v", errExactProductionKernelApply, err)
		}
		if err := adapter.apply(ctx, *target.Ipset); err != nil {
			return err
		}
		// The hook goes in last and takes the plane with it if it fails. A plane installed without
		// one survives only until NDM's next firewall rebuild — minutes, on a router where an
		// interface flap triggers it — and would disappear with the panel still reporting applied.
		if _, err := installKeeneticPBRHook(*target.Ipset); err != nil {
			_ = adapter.teardown(ctx, *target.Ipset)
			return fmt.Errorf("install the netfilter.d re-assert hook: %w", err)
		}
		// Domain zones are populated by the resolver, so they stay empty until it has read the
		// directives just written. A failure here is degraded, not wrong — the IP part of the plane
		// is installed and the domains start filling at the resolver's next start.
		if len(target.Ipset.DnsmasqConf) != 0 {
			if reloadErr := reloadKeeneticDnsmasq(ctx, adapter.runner); reloadErr != nil {
				log.Printf("apply: domain sets will fill only after the resolver restarts: %v", reloadErr)
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
	if err := adapter.apply(ctx, target); err != nil {
		return fmt.Errorf("%w: %v", errExactProductionKernelApply, err)
	}
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
		return hookErr
	}
	adapter, err := newExactKernelAdapter(exactKernelToolRunner{nft: artifact.NFTTool, ip: artifact.IPTool})
	if err != nil {
		return fmt.Errorf("%w: adapter: %v", errExactProductionKernelApply, err)
	}
	return adapter.teardown(ctx, artifact.Teardown)
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
	return adapter.postcheck(ctx, artifact)
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
