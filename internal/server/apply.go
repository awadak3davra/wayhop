package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/failsafe"
	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/netvpn"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// POST /api/apply is the one place the router is mutated for a configuration change. The pipeline
// (see docs/APPLY_REDESIGN.md in the development repository): rev check → plan (blockers, acknowledgements) → ONE host capture →
// materialize → `sing-box check` → execute make-before-break → postcheck → save (persist + commit)
// or Test (arm the fail-safe + record live). Every refusal names its cause; every failure after a
// mutation says whether the previous state was restored.

// applyLockWait bounds how long an Apply waits for a concurrent one before answering 503 BUSY.
const applyLockWait = 20 * time.Second

// applyRequest is the lenient POST /api/apply body. Everything is optional; a missing body is
// {save:false}. Unknown fields are ignored.
type applyRequest struct {
	Save   bool     `json:"save"`
	Rev    string   `json:"rev"`
	Ack    []string `json:"ack"`
	Detail bool     `json:"detail"`
}

// decodeApplyRequest reads the body leniently: empty → defaults, malformed JSON → an error the
// handler answers with 400.
func decodeApplyRequest(r io.Reader) (applyRequest, error) {
	var req applyRequest
	if r == nil {
		return req, nil
	}
	raw, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return req, fmt.Errorf("read body: %w", err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		return req, nil
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return applyRequest{}, fmt.Errorf("invalid JSON body: %w", err)
	}
	return req, nil
}

// Apply refusal/failure codes.
const (
	applyCodeInvalidRequest = "INVALID_REQUEST"
	applyCodeRevStale       = "REV_STALE"
	applyCodeAckRequired    = "ACK_REQUIRED"
	applyCodeBlocked        = "BLOCKED"
	applyCodeInvalidConfig  = "INVALID_CONFIG"
	applyCodeApplyFailed    = "APPLY_FAILED"
	applyCodeBusy           = "BUSY"
	// applyCodeRollbackOutstanding is Keep refused while a failed rollback of the Test is unfinished.
	applyCodeRollbackOutstanding = "ROLLBACK_OUTSTANDING"
	// applyCodeWindowChanged is Keep or Roll back of a named test Apply when a newer Test runs in its
	// place: it decides nothing, since nobody was asked about the newer one.
	applyCodeWindowChanged = "WINDOW_CHANGED"
)

// applyError is a refusal or failure with everything the operator needs to act on it.
type applyError struct {
	Status     int
	Code       string
	Message    string // human "error"
	Detail     string // tool output tail / adapter error
	Remedy     string
	Stage      string
	RolledBack *bool
	Plan       *Plan
	Findings   []Finding
}

func (e *applyError) Error() string { return e.Code + ": " + e.Message }

// body is the JSON the client receives.
func (e *applyError) body() map[string]any {
	out := map[string]any{"code": e.Code, "error": e.Message}
	if e.Detail != "" {
		out["detail"] = e.Detail
	}
	if e.Remedy != "" {
		out["remedy"] = e.Remedy
	}
	if e.Stage != "" {
		out["stage"] = e.Stage
	}
	if e.RolledBack != nil {
		out["rolled_back"] = *e.RolledBack
	}
	if e.Plan != nil {
		out["plan"] = e.Plan
	}
	if e.Findings != nil {
		out["findings"] = e.Findings
	}
	return out
}

// applySummary says, per plane, what the router now runs.
type applySummary struct {
	Core    string `json:"core"`
	Kernel  string `json:"kernel"`
	Native  string `json:"native"`
	Plugins string `json:"plugins"`
}

// applyResult is the 200 body.
type applyResult struct {
	Applied    bool             `json:"applied"`
	OK         bool             `json:"ok"`
	Saved      bool             `json:"saved"`
	Rev        string           `json:"rev"`
	DurationMS int64            `json:"duration_ms"`
	Failsafe   failsafe.Status  `json:"failsafe"`
	Summary    applySummary     `json:"summary"`
	Problems   []map[string]any `json:"problems"`
	Warnings   []string         `json:"warnings"`
}

// handleApply is POST /api/apply.
func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	req, err := decodeApplyRequest(r.Body)
	if err != nil {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"code": applyCodeInvalidRequest, "error": err.Error()})
		return
	}
	result, applyErr := s.runApply(r.Context(), req)
	if applyErr != nil {
		writeJSONNoStore(w, applyErr.Status, applyErr.body())
		return
	}
	writeJSONNoStore(w, http.StatusOK, result)
}

// lockApply takes applyMu, giving up after applyLockWait so a client is told the daemon is busy
// instead of hanging behind a long Apply.
func (s *Server) lockApply(ctx context.Context) bool {
	deadline := time.Now().Add(applyLockWait)
	for {
		if s.applyMu.TryLock() {
			return true
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// setStage publishes the current Apply step for GET /api/apply/status.
func (s *Server) setStage(stage string) {
	s.applyStage.Store(stage)
}

// currentStage returns the current Apply step ("" when idle).
func (s *Server) currentStage() string {
	if v, ok := s.applyStage.Load().(string); ok {
		return v
	}
	return ""
}

// runApply is the Apply pipeline. It returns either a result (200) or an applyError.
func (s *Server) runApply(ctx context.Context, req applyRequest) (*applyResult, *applyError) {
	started := time.Now()
	if !s.lockApply(ctx) {
		return nil, &applyError{Status: http.StatusServiceUnavailable, Code: applyCodeBusy,
			Message: "another Apply is still running", Remedy: "Wait for it to finish and try again."}
	}
	defer s.applyMu.Unlock()
	s.applyInProgress.Store(true)
	s.setStage("plan")
	defer func() {
		s.applyInProgress.Store(false)
		s.setStage("")
	}()

	// Routing switched off: an Apply would put WayHop's routing back without anyone deciding to.
	// Switching on restores the committed configuration; the change is applied after that.
	if s.routingIsOff() {
		return nil, &applyError{Status: http.StatusConflict, Code: routingCodeOff,
			Message: "WayHop's routing is switched off",
			Remedy:  "Switch routing on first (it restores the last applied configuration), then apply this change."}
	}
	desired, err := s.captureDesiredSnapshot()
	if err != nil {
		return nil, &applyError{Status: http.StatusServiceUnavailable, Code: applyCodeBusy,
			Message: "the saved configuration is changing", Detail: err.Error(), Remedy: "Try again in a moment."}
	}
	if req.Rev != "" && req.Rev != desired.DesiredRev {
		plan, planErr := s.buildPlan(ctx, false)
		e := &applyError{Status: http.StatusConflict, Code: applyCodeRevStale,
			Message: "the configuration changed since you reviewed it", Remedy: "Look at the updated review and apply again."}
		if planErr == nil {
			e.Plan = &plan
		}
		return nil, e
	}
	// An invalid profile cannot be generated: say what is wrong with it rather than which router
	// capability it would need.
	if err := desired.Profile.Validate(); err != nil {
		return nil, &applyError{Status: http.StatusBadRequest, Code: applyCodeInvalidConfig, Stage: "profile",
			Message: "the configuration is invalid", Detail: err.Error(),
			Remedy: "Correct or disable the object named in the detail."}
	}
	// Acknowledging and applying is one round trip: merge first, judge after.
	s.setAcks(req.Ack, true)
	plan, err := s.buildPlan(ctx, false)
	if err != nil {
		return nil, &applyError{Status: http.StatusServiceUnavailable, Code: applyCodeBusy,
			Message: "the plan could not be built", Detail: err.Error()}
	}
	if blockers := plan.blockers(); len(blockers) > 0 {
		return nil, &applyError{Status: http.StatusUnprocessableEntity, Code: applyCodeBlocked,
			Message: "this router cannot run the configuration as saved: " + strings.Join(findingTitles(blockers), "; "),
			Remedy:  "Change the setting; there is no override.", Findings: blockers}
	}
	if unacked := plan.unacked(); len(unacked) > 0 {
		return nil, &applyError{Status: http.StatusConflict, Code: applyCodeAckRequired,
			Message: "some settings will not take full effect and have not been acknowledged: " + strings.Join(findingTitles(unacked), "; "),
			Remedy:  "Tick the acknowledgements in the review and apply again.", Findings: unacked}
	}

	// ONE host capture, inside applyMu, used consistently for the rest of this Apply.
	s.setStage("capture")
	demo := desired.Config.Demo
	host, nativeCapture, captureErr := s.captureForApply(ctx, desired)
	if captureErr != nil {
		rolledBack := true // nothing was touched
		return nil, &applyError{Status: http.StatusInternalServerError, Code: applyCodeApplyFailed, Stage: "capture",
			Message: "the router state could not be read, nothing was changed", Detail: captureErr.Error(),
			Remedy: "Check the router tools named in the detail and try again.", RolledBack: &rolledBack}
	}

	// The marks every plane is compiled with are the ones THIS capture read: the review checked the
	// policies a moment ago, but NDM may have dropped or renumbered one since, and a list compiled
	// against a stale mark would route by a rule that is gone.
	ndmPolicies := applyNDMPolicies(desired.Config, nativeCapture)
	if missing := missingNDMPolicies(&desired.Profile, ndmPolicies); len(missing) > 0 {
		rolledBack := true // nothing was touched
		return nil, &applyError{Status: http.StatusUnprocessableEntity, Code: applyCodeBlocked, Stage: "capture",
			Message:    "routing lists are sent to access policies this router does not have: " + strings.Join(missing, ", "),
			Remedy:     "Review again: send each list to an existing access policy, or point it at a connection.",
			RolledBack: &rolledBack}
	}

	s.setStage("materialize")
	var kernelPlan *pbr.Plan
	var offloadWarning string
	if mode := desiredRoutingMode(desired.Config); mode == "hybrid" || mode == "fast" {
		kernelOpts := s.pbrCompileOptions(desired.Config)
		kernelOpts.NDMPolicies = ndmPolicies
		kernelOpts, offloadWarning = kernelOffloadForHost(kernelOpts, host.Host)
		kernelPlan, _, err = pbr.Compile(&desired.Profile, kernelOpts)
		if err != nil {
			return nil, &applyError{Status: http.StatusBadRequest, Code: applyCodeInvalidConfig, Stage: "kernel",
				Message: "the kernel routing plan could not be compiled", Detail: err.Error(),
				Remedy: "Fix the routing lists named in the detail, or switch to tun or mixed mode."}
		}
	}
	baseline := s.appliedBaseline()
	var previous *executionMaterializationV1
	if baseline != nil && baseline.Materialization.known() {
		previous = &baseline.Materialization
	}
	// A Test whose rollback failed part way is still the baseline (it is what the router has to be moved
	// off), but it is no configuration to go back to: a failure below rolls back to the committed one.
	outstanding := s.liveRollbackFailed()
	if outstanding != nil && previous != nil {
		// What the router carries is then part of each: the native objects to retire are those of both.
		if committed := s.committedRevision(); committed != nil {
			previous = ownershipBaseline(previous, &committed.Materialization, nativeCapture)
		}
	}
	m, warnings, err := materialize(materializeInput{
		desired: desired, host: host, native: nativeCapture, previous: previous, kernelPlan: kernelPlan,
		ndmPolicies: ndmPolicies,
	})
	if err != nil {
		stage, detail, remedy := materializeFailure(err)
		return nil, &applyError{Status: http.StatusBadRequest, Code: applyCodeInvalidConfig, Stage: stage,
			Message: "the configuration cannot be materialized on this router", Detail: detail, Remedy: remedy}
	}
	if warn := fastModeDomainWarning(&desired.Profile, desiredRoutingMode(desired.Config),
		keeneticKernelCarriesDomains(nativeCapture)); warn != "" {
		warnings = append(warnings, warn)
	}
	if offloadWarning != "" {
		warnings = append(warnings, offloadWarning)
	}
	ops := s.productionExecOps()
	if m.Core.Action == ExecutionEnsurePresent && ops.checkCore != nil {
		s.setStage("check")
		if err := ops.checkCore(ctx, m.Core.Config); err != nil {
			return nil, &applyError{Status: http.StatusBadRequest, Code: applyCodeInvalidConfig, Stage: "check",
				Message: "sing-box rejected the generated config", Detail: outputTail(err.Error(), 2048),
				Remedy: "Fix the connection or rule named in the output; the running configuration was not touched."}
		}
	}

	// From here on the router may change: mark the record so a crash converges to the committed
	// state on the next start.
	s.setInFlight(req.Save, desired.DesiredRev)
	// Only this forward run refuses a changed WayHop-created interface; the rollback below gets the
	// plain ctx and leaves such an interface as it is (withStrictNativePrepare).
	res, execErr := executeMaterialization(withStrictNativePrepare(ctx), ops, &m, previous, s.setStage)
	if execErr != nil {
		rolledBack := false
		if res.Mutated {
			s.setStage("rollback")
			target := baseline
			if outstanding != nil {
				// Rolling back to the Test put back the configuration whose own rollback was under way
				// (the one that had broken connectivity), reported it as "the previous configuration was
				// restored", and left the mark on it: the reconcile loop then kept the committed plane
				// under that Test's core and interfaces.
				target = s.committedRevision()
			}
			plane, rbErr := s.rollbackTo(ctx, ops, target, &m)
			if rbErr == nil && outstanding != nil {
				// That rollback undid this Apply only: its kernel retire list, its connection flush and its
				// native reconcile are computed from m. The Test whose rollback was outstanding has its own:
				// after an Apply that failed before its kernel step, the Test's ip rules stayed, the flush
				// was skipped when m's plan equalled the committed one, the native interfaces only the Test
				// had stayed, and recordRollback below dropped the Test, so nothing would ever retire them.
				// The same rollback from the Test finishes that; over the committed configuration just
				// restored it changes only what the Test left.
				if plane, rbErr = s.rollbackTo(ctx, ops, target, &baseline.Materialization); rbErr != nil && plane == rollbackPlaneTested {
					// Stopped before its kernel step: the plane is the committed one the first run installed.
					plane = rollbackPlaneCommitted
				}
			}
			if rbErr != nil {
				log.Printf("apply: rollback after a failed apply: %v", rbErr)
				// A rollback that stopped before its kernel step leaves the plane this Apply's own
				// execution left: unchanged unless that reached its kernel step.
				forwardPlane := kernelPlaneAfter(res, execErr)
				switch {
				case outstanding != nil:
					// Still outstanding, now over this Apply's leftovers too; a plane this Apply changed
					// is neither revision's.
					if plane == rollbackPlaneTested && forwardPlane != rollbackPlaneTested {
						plane = rollbackPlaneUnknown
					}
					s.noteRollbackFailed(baseline, plane, rbErr)
				case baseline != nil && sameRevision(baseline, s.liveRevision()):
					// The Test this Apply ran over could not be put back: it no longer runs as tested, and
					// Keep must not save it (QA-140). Its plane is as tested when the rollback restored
					// it, or when neither run got to the kernel step.
					if plane == rollbackPlaneCommitted || (plane == rollbackPlaneTested && forwardPlane == rollbackPlaneTested) {
						plane = rollbackPlaneTested
					} else {
						plane = rollbackPlaneUnknown
					}
					s.noteRollbackFailed(baseline, plane, rbErr)
				default:
					// The record named the committed configuration as running over this Apply's leftovers:
					// Roll back answered that it was, and the reconcile loop put the committed plane back
					// under this Apply's core (QA-140). This Apply becomes the live state with its rollback
					// outstanding, which Roll back undoes and Keep refuses. Its own plane is in when it
					// reached its kernel step; the committed one is when neither run did.
					if plane == rollbackPlaneTested {
						switch forwardPlane {
						case rollbackPlaneTested:
							plane = rollbackPlaneCommitted
						case rollbackPlaneUnknown:
							plane = rollbackPlaneUnknown
						}
					}
					s.noteLiveRollbackOutstanding(&appliedRevision{
						Rev: desired.DesiredRev, At: time.Now().Unix(),
						Desired:         &appliedDesired{Profile: desired.Profile, Config: desired.Config},
						Materialization: m,
					}, plane, rbErr)
				}
			} else {
				rolledBack = true
				if outstanding != nil {
					// The committed configuration is back: that also finished the rollback the record was
					// waiting on, so the Test and its mark go, and so does a window still held open for
					// it (it would close announcing a failed rollback for a router running the committed
					// configuration).
					s.recordRollback()
					if s.failsafe != nil {
						s.failsafe.MarkRolledBack()
					}
				}
			}
		}
		s.recordFailure(desired.DesiredRev, execErr)
		var stepErr *applyExecError
		stage := "execute"
		detail := execErr.Error()
		if errors.As(execErr, &stepErr) {
			stage, detail = stepErr.Step, stepErr.Err.Error()
		}
		msg := "the " + stageLabel(stage) + " could not be applied"
		if rolledBack && outstanding != nil {
			msg += "; the committed configuration was restored, which also completes the earlier rollback that had failed"
		} else if rolledBack {
			msg += "; the previous configuration was restored"
		} else if res.Mutated {
			msg += "; the previous configuration could NOT be fully restored"
		}
		return nil, &applyError{Status: http.StatusInternalServerError, Code: applyCodeApplyFailed, Stage: stage,
			Message: msg, Detail: outputTail(detail, 2048), RolledBack: &rolledBack,
			Remedy: "Read the detail, fix the cause and apply again."}
	}
	problems := res.Problems
	if problems == nil {
		problems = []map[string]any{}
	}
	if m.Kernel.Action == ExecutionEnsurePresent {
		s.markKernelPlane(kernelPlanePresent)
	} else {
		s.markKernelPlane(kernelPlaneUnknown)
	}
	// The plane restores each flow's saved mark first, so a flow the change moved would keep its old
	// exit - or none - until it ended (competitor gap 5). Before recordApplied: the baseline is still
	// the previous plan here.
	var prev *pbr.Plan
	if base := s.appliedBaseline(); base != nil {
		prev = base.Materialization.kernelPlan()
	}
	s.flushStaleFlows(prev, m.kernelPlan())

	rev := &appliedRevision{
		Rev: desired.DesiredRev, At: time.Now().Unix(),
		Desired:         &appliedDesired{Profile: desired.Profile, Config: desired.Config},
		Materialization: m,
	}
	saved := req.Save
	if req.Save {
		s.setStage(stepNativePersist)
		if m.Native != nil && !demo && ops.persistNative != nil {
			if err := ops.persistNative(ctx, m.Native.Delta.Reconcile); err != nil {
				// The configuration runs but is not saved: keep it as an unsaved window rather than
				// pretending it is committed, and say why.
				log.Printf("apply: native persist failed, keeping the configuration as an unsaved window: %v", err)
				problems = append(problems, map[string]any{"id": "native_persist", "engine": "native",
					"reason": "the router-native configuration could not be saved: " + err.Error() + " — use Keep to retry"})
				saved = false
			}
		}
	}
	if saved {
		s.recordApplied(true, rev)
		if s.failsafe != nil {
			s.failsafe.Confirm()
		}
	} else {
		s.recordApplied(false, rev)
		s.armFailSafe(rev)
	}

	result := &applyResult{
		Applied: true, OK: len(problems) == 0, Saved: saved, Rev: desired.DesiredRev,
		DurationMS: time.Since(started).Milliseconds(),
		Summary:    summarize(&m, res),
		Problems:   problems, Warnings: warnings,
	}
	if warnings == nil {
		result.Warnings = []string{}
	}
	if s.failsafe != nil {
		result.Failsafe = s.failsafe.Status()
	}
	return result, nil
}

// applyNDMPolicies is the access policies by name → mark an Apply compiles its planes with: the
// native capture's on a router, the demo's synthetic set in demo, none anywhere else.
func applyNDMPolicies(cfg config.Config, capture *executionNativeCaptureV1) map[string]uint32 {
	if cfg.Demo {
		return keenetic.PolicyMarks(demoNDMPolicies)
	}
	if capture == nil {
		return nil
	}
	return capture.NDMPolicies
}

// captureForApply is the ONE host capture of an Apply: host facts (platform, core identity, kernel
// tools, external interfaces) and the native (UCI/NDM) state. Demo synthesizes both.
func (s *Server) captureForApply(ctx context.Context, desired DesiredSnapshot) (ExecutionHostFactsV1, *executionNativeCaptureV1, error) {
	if desired.Config.Demo {
		host, err := s.captureHostSnapshot(ctx, desired)
		if err != nil {
			return ExecutionHostFactsV1{}, nil, fmt.Errorf("host snapshot: %w", err)
		}
		facts := ExecutionHostFactsV1{Host: host, ExternalBindings: []ExecutionExternalBindingV1{}}
		for _, e := range desired.Profile.Endpoints {
			if !e.Enabled || e.Engine != model.EngineExternal {
				continue
			}
			iface, _ := e.Params["interface"].(string)
			facts.ExternalBindings = append(facts.ExternalBindings, ExecutionExternalBindingV1{
				EndpointID: e.ID, Interface: iface, IfIndex: 1, AdminUp: true, Ready: true,
			})
		}
		return facts, nil, nil
	}
	host, err := s.captureExecutionHostFacts(ctx, desired)
	if err != nil {
		return ExecutionHostFactsV1{}, nil, err
	}
	switch platform.Platform(host.Host.Platform) {
	case platform.OpenWrt, platform.Keenetic:
		capture, err := s.captureExecutionNative(ctx, desired, host)
		if err != nil {
			return ExecutionHostFactsV1{}, nil, fmt.Errorf("router-native state (UCI/NDM) could not be read: %w", err)
		}
		return host, &capture, nil
	}
	return host, nil, nil
}

// nativeLeftoverError is a rollback whose only failure is the removal of the failed target's
// router-native tunnels, routes and ladder: everything else is back to the baseline.
type nativeLeftoverError struct{ err error }

func (e *nativeLeftoverError) Error() string {
	return "the router-native tunnels being rolled back could not be removed: " + e.err.Error()
}

func (e *nativeLeftoverError) Unwrap() error { return e.err }

// onlyNativeLeftover reports whether every failure in err is a nativeLeftoverError.
func onlyNativeLeftover(err error) bool {
	var leftover *nativeLeftoverError
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range joined.Unwrap() {
			if !errors.As(e, &leftover) {
				return false
			}
		}
		return len(joined.Unwrap()) != 0
	}
	return errors.As(err, &leftover)
}

// rollbackTo re-executes the baseline materialization over the failed/tested one, or tears
// everything WayHop installed down when there is no baseline. On failure plane says how far it got
// with the kernel plane (rollbackPlane*), which a caller that marks the rollback outstanding records
// with it; an error onlyNativeLeftover accepts means the baseline is back and only the failed
// target's router-native objects are left. Caller holds applyMu.
func (s *Server) rollbackTo(ctx context.Context, ops applyExecOps, base *appliedRevision, failed *executionMaterializationV1) (plane string, err error) {
	rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	if base == nil || !base.Materialization.known() {
		err = teardownMaterialization(rbCtx, ops, failed)
		s.markKernelPlane(kernelPlaneUnknown)
		if err == nil || onlyNativeLeftover(err) {
			s.flushStaleFlows(failed.kernelPlan(), nil)
			return rollbackPlaneCommitted, err
		}
		// The teardown goes on to every plane whatever failed before it, so the Test's plane is not as
		// tested whichever step failed; with no committed revision nothing is put back either way.
		return rollbackPlaneUnknown, err
	}
	target, abortErr := s.rollbackMaterialization(rbCtx, ops, &base.Materialization, failed)
	res, err := executeMaterialization(rbCtx, ops, target, failed, s.setStage)
	if err != nil {
		return kernelPlaneAfter(res, err), err
	}
	if target.Kernel.Action == ExecutionEnsurePresent {
		s.markKernelPlane(kernelPlanePresent)
	}
	// Flows the rolled-back plan marked would keep its marks - renumbered, or for an exit the
	// baseline does not have - until they end; a UDP flow with keepalives never does.
	s.flushStaleFlows(failed.kernelPlan(), target.kernelPlan())
	if abortErr != nil {
		// The baseline runs again, but the failed target's tunnels, routes and ladder are still on the
		// router. Reporting success made the record forget them and the API say rolled_back (QA-144);
		// as a failure the record keeps what is left to undo, and Roll back retries the abort.
		return rollbackPlaneCommitted, abortErr
	}
	return rollbackPlaneCommitted, nil
}

// rollbackMaterialization prepares the baseline for re-execution over failed: the kernel retire is
// recomputed against what failed installed, and the native delta is reconciled from failed's target
// to the baseline's (so the interfaces the failed apply created are removed and the baseline's are
// kept). When that reconciliation is impossible the failed native target is aborted first and the
// baseline is re-applied additively; an abort that fails is returned, for rollbackTo to report once the
// baseline is back.
func (s *Server) rollbackMaterialization(ctx context.Context, ops applyExecOps, base, failed *executionMaterializationV1) (*executionMaterializationV1, error) {
	var abortErr error
	target := *base
	target.Kernel = base.Kernel
	bindKernelRetire(&target.Kernel, failed)
	failedNative := failed.nativeTarget()
	baseNative := base.nativeTarget()
	switch {
	case failedNative == nil:
		// Nothing native to undo; the baseline's own removals were already applied when it went in.
		if target.Native != nil {
			native := *target.Native
			native.Delta.Reconcile.KeeneticTeardown = nil
			native.Delta.Reconcile.OpenWrtRemovals = nil
			target.Native = &native
		}
	case baseNative == nil:
		if ops.abortNative != nil {
			if err := ops.abortNative(ctx, *failedNative); err != nil {
				log.Printf("apply: rollback: native abort of the failed target: %v", err)
				abortErr = &nativeLeftoverError{err}
			}
		}
	default:
		networkUCI, firewallUCI := "", ""
		if baseNative.Platform == platform.OpenWrt {
			read := readUCI
			if s.uciReader != nil {
				read = s.uciReader
			}
			if n, f, err := read(); err == nil {
				networkUCI, firewallUCI = n, f
			}
		}
		delta, err := nativeplan.Reconcile(failedNative, baseNative, s.capabilitySet(ctx, false), networkUCI, firewallUCI)
		if err != nil {
			log.Printf("apply: rollback: native reconcile from the failed target: %v — aborting it and re-applying the baseline additively", err)
			if ops.abortNative != nil {
				if err := ops.abortNative(ctx, *failedNative); err != nil {
					log.Printf("apply: rollback: native abort of the failed target: %v", err)
					abortErr = &nativeLeftoverError{err}
				}
			}
			native := *target.Native
			native.Delta.Reconcile.KeeneticTeardown = nil
			native.Delta.Reconcile.OpenWrtRemovals = nil
			target.Native = &native
			break
		}
		if baseNative.Platform == platform.OpenWrt {
			delta.Target = rebaseOpenWrtRollback(baseNative, failedNative, networkUCI, firewallUCI)
		}
		target.Native = &executionNativeMaterializationV1{Delta: executionNativeDeltaV1{
			SchemaVersion: executionNativeDeltaSchemaV1, Reconcile: *delta,
		}, AWGKernel: cloneAWGKernelCapture(base.Native.AWGKernel)}
	}
	return &target, abortErr
}

// rebaseOpenWrtRollback rebuilds the baseline's write plan for each interface the failed apply left
// modified, against the UCI as it is now. A recorded plan's Expected is the interface as it was when
// the BASELINE was built — before the baseline itself, then the failed apply, changed it — so its
// preflight refused ("the configuration changed after this plan was built") and the rollback of a
// Test that edited an endpoint failed at native prepare, before the core step: rollback_failed in the
// window, and after a reboot mid-window no sing-box at all. The rebuild happens only when the
// interface is exactly what the failed plan wrote: anything else is someone else's edit, and the
// recorded plan's refusal stands. base is never modified.
func rebaseOpenWrtRollback(base, failed *nativeplan.Plan, networkUCI, firewallUCI string) *nativeplan.Plan {
	if networkUCI == "" {
		return base
	}
	tested := make(map[string]netvpn.Plan, len(failed.OpenWrt))
	for _, plan := range failed.OpenWrt {
		tested[plan.Iface] = plan
	}
	current := netvpn.ParseUCIShow(networkUCI)
	var out *nativeplan.Plan
	for i, plan := range base.OpenWrt {
		wrote, ok := tested[plan.Iface]
		if !ok || len(plan.PreflightAgainst(networkUCI)) == 0 {
			continue
		}
		if now, exists := current[plan.Iface]; !exists || len(netvpn.DiffInterface(wrote.Intended, now)) != 0 {
			continue
		}
		// The handler set is the one the baseline plan was resolved for: Intended carries the
		// resolved protocol, and the router ran it before the failed apply replaced it.
		rebuilt, err := netvpn.BuildPlanFor(plan.Intended, netvpn.RouterProtos{string(plan.Intended.Proto): true},
			plan.Zone, networkUCI, firewallUCI)
		if err != nil {
			log.Printf("apply: rollback: %s cannot be rebuilt against the current configuration: %v", plan.Iface, err)
			continue
		}
		if out == nil {
			clone := *base
			clone.OpenWrt = append([]netvpn.Plan(nil), base.OpenWrt...)
			out = &clone
		}
		out.OpenWrt[i] = rebuilt
	}
	if out == nil {
		return base
	}
	return out
}

// summarize describes the applied planes for the response.
func summarize(m *executionMaterializationV1, res applyExecResult) applySummary {
	out := applySummary{Core: "not used", Kernel: "not installed", Native: "not used", Plugins: "none"}
	switch m.Core.Action {
	case ExecutionEnsurePresent:
		out.Core = "running"
	case ExecutionDemoNoop:
		out.Core = "demo"
	}
	switch m.Kernel.Action {
	case ExecutionEnsurePresent:
		out.Kernel = "installed"
		if m.Kernel.Plan != nil {
			out.Kernel = fmt.Sprintf("installed (%d zones)", len(m.Kernel.Plan.Zones))
		}
	case ExecutionDemoNoop:
		out.Kernel = "demo"
	}
	if target := m.nativeTarget(); target != nil {
		n := 0
		for _, d := range target.Decisions {
			if d.Interface != "" {
				n++
			}
		}
		out.Native = fmt.Sprintf("%s: %d interface(s)", target.Platform, n)
	}
	if specs := m.pluginSpecs(); len(specs) != 0 {
		running := len(specs) - len(res.Problems)
		if running < 0 {
			running = 0
		}
		out.Plugins = fmt.Sprintf("%d of %d running", running, len(specs))
	} else if m.PluginAction == ExecutionDemoNoop {
		out.Plugins = "demo"
	}
	return out
}

func findingTitles(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		title := f.Title
		if len(f.Items) == 1 {
			title += " (" + f.Items[0] + ")"
		} else if len(f.Items) > 1 {
			title += fmt.Sprintf(" (%d affected)", f.Count)
		}
		out = append(out, title)
	}
	return out
}

func stageLabel(stage string) string {
	switch stage {
	case stepNativePrepare, stepNativeCommit, stepNativePersist:
		return "router-native tunnels"
	case stepPlugins, stepPluginsRetire:
		return "engine plugins"
	case stepCore:
		return "sing-box core"
	case stepKernel:
		return "kernel routing plane"
	case stepPostcheck:
		return "post-apply verification"
	default:
		return stage
	}
}

// outputTail keeps the last max bytes of a tool output, on a line boundary where possible.
func outputTail(text string, max int) string {
	text = strings.TrimSpace(text)
	if len(text) <= max {
		return text
	}
	cut := text[len(text)-max:]
	if i := strings.IndexByte(cut, '\n'); i >= 0 && i < len(cut)-1 {
		cut = cut[i+1:]
	}
	return "…" + cut
}

// --- status / confirm / rollback --------------------------------------------------------------

// handleApplyStatus (GET /api/apply/status): the fail-safe window plus the running Apply's stage.
func (s *Server) handleApplyStatus(w http.ResponseWriter, _ *http.Request) {
	st := failsafe.Status{Phase: "idle"}
	if s.failsafe != nil {
		st = s.failsafe.Status()
	}
	// Keep is refused while a rollback is outstanding (applyConfirm), so the panel must not offer it:
	// the banner showed "Keep & Save" over a Test that no longer ran as tested.
	rbErr, rbFailed := "", false
	if m := s.liveRollbackFailed(); m != nil {
		rbErr, rbFailed = m.Error, true
	}
	live := s.liveRevision()
	writeJSONNoStore(w, http.StatusOK, map[string]any{
		"rollback_failed": rbFailed,
		"rollback_error":  rbErr,
		"pending":         st.Pending,
		"phase":           st.Phase,
		"seconds_left":    st.SecondsLeft,
		"last_check_ok":   st.LastCheckOk,
		"last_check_at":   st.LastCheckAt,
		"last_error":      st.LastError,
		"in_progress":     s.applyInProgress.Load(),
		"stage":           s.currentStage(),
		"window_open":     live != nil,
		// The test Apply this window is about, to name in Keep and Roll back ({"window": ...}).
		"window": applyWindow(live),
	})
}

// applyDecisionWindow reads the optional {"window": "..."} of a Keep or Roll back: the test Apply the
// caller was shown, as /api/apply/status names it. An empty or absent body names none, which decides
// whatever runs unsaved (the panel's banner posts {}).
func applyDecisionWindow(r *http.Request) (string, error) {
	var body struct {
		Window string `json:"window"`
	}
	if r.Body == nil {
		return "", nil
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return body.Window, nil
}

// handleApplyConfirm (POST /api/apply/confirm) keeps a live (Test) configuration: the native state
// is persisted, the live record becomes committed and the fail-safe window closes.
func (s *Server) handleApplyConfirm(w http.ResponseWriter, r *http.Request) {
	window, err := applyDecisionWindow(r)
	if err != nil {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"code": applyCodeInvalidRequest, "error": "invalid JSON body"})
		return
	}
	code, resp := s.applyConfirm(r.Context(), window)
	writeJSONNoStore(w, code, resp)
}

// windowChanged is the refusal of a Keep or Roll back whose test Apply a newer one replaced.
func windowChanged() (int, map[string]any) {
	return http.StatusConflict, map[string]any{"code": applyCodeWindowChanged,
		"error": "a newer test Apply replaced the one this decision was for, so nothing was changed"}
}

// applyConfirm is Keep, for the panel and the Telegram bot alike: it answers with the HTTP status and
// body the panel expects. window, when not empty, names the test Apply the caller was asked about
// (applyWindow); a different one running unsaved is refused with WINDOW_CHANGED.
func (s *Server) applyConfirm(ctx context.Context, window string) (int, map[string]any) {
	s.applyMu.Lock()
	live := s.liveRevision()
	if live == nil {
		s.applyMu.Unlock()
		return http.StatusConflict, map[string]any{"code": "NO_WINDOW",
			"error": "there is no unsaved configuration to keep"}
	}
	// Compared under applyMu, which a Test Apply holds for its whole run. The bot's own check reads the
	// window before taking the lock: a Keep pressed on Test A's message while Test B ran from the panel
	// passed it (B was not recorded yet), waited here for B to finish and then committed B, untested
	// and never asked about.
	if window != "" && applyWindow(live) != window {
		s.applyMu.Unlock()
		return windowChanged()
	}
	if failed := s.liveRollbackFailed(); failed != nil {
		s.applyMu.Unlock()
		// The rollback got part way: the router runs neither the Test as tested nor the committed
		// configuration. Keeping it recorded a configuration that was not running as committed, and
		// during boot's retry wait it also made the retry skip, so nothing ever converged it (after an
		// OpenWrt reboot sing-box never started). Finishing the rollback, or applying again, is the
		// way out; both are open.
		return http.StatusConflict, map[string]any{"code": applyCodeRollbackOutstanding,
			"error":  "the rollback of this test configuration failed part way, so it no longer runs as tested and cannot be kept: roll back again to finish, or apply the configuration again",
			"detail": failed.Error}
	}
	ops := s.productionExecOps()
	if live.Materialization.Native != nil && !s.config().Demo && ops.persistNative != nil {
		if err := ops.persistNative(ctx, live.Materialization.Native.Delta.Reconcile); err != nil {
			s.applyMu.Unlock()
			// The window stays armed: the configuration runs and the user can retry.
			log.Printf("apply/confirm: native persist failed, keeping the window armed: %v", err)
			return http.StatusInternalServerError, map[string]any{"code": applyCodeApplyFailed,
				"stage": stepNativePersist, "error": "the router-native configuration could not be saved", "detail": err.Error()}
		}
	}
	s.recordCommit()
	s.applyMu.Unlock()
	// failsafe.Confirm must NOT run under applyMu: the rollback closure takes applyMu.
	if s.failsafe != nil {
		s.failsafe.Confirm()
	}
	resp := map[string]any{"committed": true}
	if s.failsafe != nil {
		resp["failsafe"] = s.failsafe.Status()
	}
	return http.StatusOK, resp
}

// handleApplyRollback (POST /api/apply/rollback) restores the committed configuration. It works
// whether or not a window is armed: with no live state there is nothing to roll back and it says so.
func (s *Server) handleApplyRollback(w http.ResponseWriter, r *http.Request) {
	window, err := applyDecisionWindow(r)
	if err != nil {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"code": applyCodeInvalidRequest, "error": "invalid JSON body"})
		return
	}
	code, resp := s.applyRollback(r.Context(), window)
	writeJSONNoStore(w, code, resp)
}

// applyRollback is Roll back, for the panel and the Telegram bot alike. window, when not empty, names
// the test Apply the caller was asked about, as for applyConfirm.
func (s *Server) applyRollback(ctx context.Context, window string) (int, map[string]any) {
	if s.failsafe != nil && s.failsafe.Status().Pending {
		rollbackNow := s.failsafe.RollbackNow
		if window != "" {
			// Checked under applyMu, which a Test Apply holds while it records its revision and arms its
			// window: a Roll back pressed on Test A's message while Test B ran waited for B and then rolled
			// back the window it found, B's. The epoch read with it keeps RollbackNowAt to the window
			// checked; the rollback itself takes applyMu, so it runs after the lock is let go.
			s.applyMu.Lock()
			cur, epoch := applyWindow(s.liveRevision()), s.failsafe.Epoch()
			s.applyMu.Unlock()
			if cur != "" && cur != window {
				return windowChanged()
			}
			rollbackNow = func() error { return s.failsafe.RollbackNowAt(epoch) }
		}
		if err := rollbackNow(); err != nil {
			// Pressed while an Apply held the lock, the rollback waits for it. When that Apply failed and its
			// rollback restored the committed configuration, it closed this window as rolled back, which
			// supersedes the press: the answer was "nothing was rolled back" (500) although the router had
			// just been returned to the committed configuration, the outcome the press asked for.
			if st := s.failsafe.Status(); errors.Is(err, failsafe.ErrSuperseded) && !st.Pending &&
				st.Phase == "rolled_back" && s.liveRevision() == nil {
				return http.StatusOK, map[string]any{"rolled_back": true, "failsafe": st,
					"message": "the Apply that was running failed and restored the committed configuration, which also rolled back this test"}
			}
			// A newer Test armed after the check: nothing was rolled back, and its window is not this
			// decision's.
			if cur := applyWindow(s.liveRevision()); window != "" && errors.Is(err, failsafe.ErrSuperseded) && cur != "" && cur != window {
				return windowChanged()
			}
			return http.StatusInternalServerError, map[string]any{"code": applyCodeApplyFailed,
				"rolled_back": false, "error": err.Error(), "failsafe": s.failsafe.Status()}
		}
		return http.StatusOK, map[string]any{"rolled_back": true, "failsafe": s.failsafe.Status()}
	}
	s.applyMu.Lock()
	live := s.liveRevision()
	if live == nil {
		s.applyMu.Unlock()
		resp := map[string]any{"rolled_back": false, "message": "no unsaved configuration to roll back — the committed configuration is running"}
		if s.failsafe != nil {
			resp["failsafe"] = s.failsafe.Status()
		}
		return http.StatusOK, resp
	}
	// After the window passed the Test runs unsaved, and a newer Test can replace it the same way.
	if window != "" && applyWindow(live) != window {
		s.applyMu.Unlock()
		return windowChanged()
	}
	plane, err := s.rollbackTo(ctx, s.productionExecOps(), s.committedRevision(), &live.Materialization)
	if err == nil {
		// Only a rollback that worked ends the live state: after a failure the record must still name
		// what is left to undo, or the next Roll back finds nothing and says the committed
		// configuration is running.
		s.recordRollback()
	} else {
		s.noteRollbackFailed(live, plane, err)
	}
	s.applyMu.Unlock()
	if err != nil {
		return http.StatusInternalServerError, map[string]any{"code": applyCodeApplyFailed,
			"rolled_back": false, "error": "the committed configuration could not be fully restored", "detail": err.Error()}
	}
	resp := map[string]any{"rolled_back": true}
	if s.failsafe != nil {
		resp["failsafe"] = s.failsafe.Status()
	}
	return http.StatusOK, resp
}
