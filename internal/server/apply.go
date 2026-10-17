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

	"wayhop/internal/failsafe"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
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

	s.setStage("materialize")
	var kernelPlan *pbr.Plan
	if mode := desiredRoutingMode(desired.Config); mode == "hybrid" || mode == "fast" {
		kernelPlan, _, err = pbr.Compile(&desired.Profile, s.pbrCompileOptions(desired.Config))
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
	m, warnings, err := materialize(materializeInput{
		desired: desired, host: host, native: nativeCapture, previous: previous, kernelPlan: kernelPlan,
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
	res, execErr := executeMaterialization(ctx, ops, &m, previous, s.setStage)
	if execErr != nil {
		rolledBack := false
		if res.Mutated {
			s.setStage("rollback")
			if rbErr := s.rollbackTo(ctx, ops, baseline, &m); rbErr != nil {
				log.Printf("apply: rollback after a failed apply: %v", rbErr)
			} else {
				rolledBack = true
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
		if rolledBack {
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

// rollbackTo re-executes the baseline materialization over the failed/tested one, or tears
// everything WayHop installed down when there is no baseline. Caller holds applyMu.
func (s *Server) rollbackTo(ctx context.Context, ops applyExecOps, base *appliedRevision, failed *executionMaterializationV1) error {
	rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	if base == nil || !base.Materialization.known() {
		err := teardownMaterialization(rbCtx, ops, failed)
		s.markKernelPlane(kernelPlaneUnknown)
		return err
	}
	target := s.rollbackMaterialization(rbCtx, ops, &base.Materialization, failed)
	_, err := executeMaterialization(rbCtx, ops, target, failed, s.setStage)
	if err == nil && target.Kernel.Action == ExecutionEnsurePresent {
		s.markKernelPlane(kernelPlanePresent)
	}
	return err
}

// rollbackMaterialization prepares the baseline for re-execution over failed: the kernel retire is
// recomputed against what failed installed, and the native delta is reconciled from failed's target
// to the baseline's (so the interfaces the failed apply created are removed and the baseline's are
// kept). When that reconciliation is impossible the failed native target is aborted first and the
// baseline is re-applied additively.
func (s *Server) rollbackMaterialization(ctx context.Context, ops applyExecOps, base, failed *executionMaterializationV1) *executionMaterializationV1 {
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
				if abortErr := ops.abortNative(ctx, *failedNative); abortErr != nil {
					log.Printf("apply: rollback: native abort of the failed target: %v", abortErr)
				}
			}
			native := *target.Native
			native.Delta.Reconcile.KeeneticTeardown = nil
			native.Delta.Reconcile.OpenWrtRemovals = nil
			target.Native = &native
			break
		}
		target.Native = &executionNativeMaterializationV1{Delta: executionNativeDeltaV1{
			SchemaVersion: executionNativeDeltaSchemaV1, Reconcile: *delta,
		}, AWGKernel: cloneAWGKernelCapture(base.Native.AWGKernel)}
	}
	return &target
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
	writeJSONNoStore(w, http.StatusOK, map[string]any{
		"pending":       st.Pending,
		"phase":         st.Phase,
		"seconds_left":  st.SecondsLeft,
		"last_check_ok": st.LastCheckOk,
		"last_check_at": st.LastCheckAt,
		"last_error":    st.LastError,
		"in_progress":   s.applyInProgress.Load(),
		"stage":         s.currentStage(),
		"window_open":   s.liveRevision() != nil,
	})
}

// handleApplyConfirm (POST /api/apply/confirm) keeps a live (Test) configuration: the native state
// is persisted, the live record becomes committed and the fail-safe window closes.
func (s *Server) handleApplyConfirm(w http.ResponseWriter, r *http.Request) {
	code, resp := s.applyConfirm(r.Context())
	writeJSONNoStore(w, code, resp)
}

// applyConfirm is Keep, for the panel and the Telegram bot alike: it answers with the HTTP status and
// body the panel expects.
func (s *Server) applyConfirm(ctx context.Context) (int, map[string]any) {
	s.applyMu.Lock()
	live := s.liveRevision()
	if live == nil {
		s.applyMu.Unlock()
		return http.StatusConflict, map[string]any{"code": "NO_WINDOW",
			"error": "there is no unsaved configuration to keep"}
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
	code, resp := s.applyRollback(r.Context())
	writeJSONNoStore(w, code, resp)
}

// applyRollback is Roll back, for the panel and the Telegram bot alike.
func (s *Server) applyRollback(ctx context.Context) (int, map[string]any) {
	if s.failsafe != nil && s.failsafe.Status().Pending {
		if err := s.failsafe.RollbackNow(); err != nil {
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
	err := s.rollbackTo(ctx, s.productionExecOps(), s.committedRevision(), &live.Materialization)
	s.recordRollback()
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
