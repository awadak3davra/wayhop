package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"wayhop/internal/atomicfile"
	"wayhop/internal/changeset"
	"wayhop/internal/config"
	"wayhop/internal/core"
	"wayhop/internal/model"
)

// The apply-state record is the one thing WayHop remembers about what it last applied: the desired
// snapshot (for the change review), the materialized artifacts (for boot converge, rollback and the
// reconcile loop) and the persisted acknowledgements. It lives next to the startup config so it
// survives a reboot on both platforms (DataDir may be tmpfs on OpenWrt).

// applyStateSchema is the on-disk schema of apply-state.json.
const applyStateSchema = 2

const applyStateFileName = "apply-state.json"

// appliedDesired is the saved configuration an Apply materialized: the change review diffs the
// current saved state against it. Only the apply-relevant subset matters (see DesiredInputsV1) but
// the whole config is stored so changeset.Diff has every field it reads.
type appliedDesired struct {
	Profile model.Profile `json:"profile"`
	Config  config.Config `json:"config"`
}

// appliedRevision is one applied state: what was asked for, when, and what was installed for it.
type appliedRevision struct {
	Rev string `json:"rev"`
	At  int64  `json:"at"`
	// Desired is nil when the record knows what was installed but not what was asked for (an
	// imported previous-stack ledger); the change review then reports no baseline.
	Desired         *appliedDesired            `json:"desired"`
	Materialization executionMaterializationV1 `json:"materialization"`
}

// applyInFlight marks an Apply that started mutating the router and has not recorded its result.
// A daemon that finds one at boot crashed mid-Apply: it converges to the committed state and logs.
type applyInFlight struct {
	At   int64  `json:"at"`
	Save bool   `json:"save"`
	Rev  string `json:"rev"`
}

type applyLastResult struct {
	At    int64  `json:"at"`
	OK    bool   `json:"ok"`
	Rev   string `json:"rev"`
	Error string `json:"error,omitempty"`
}

type applyStateRecord struct {
	Schema    int              `json:"schema"`
	Committed *appliedRevision `json:"committed"`
	Live      *appliedRevision `json:"live"`
	InFlight  *applyInFlight   `json:"in_flight"`
	Acks      map[string]int64 `json:"acks"`
	Last      applyLastResult  `json:"last"`
}

// applyStateStore holds the record in memory and mirrors every change to disk. The pointers it hands
// out are treated as immutable once published: mutations replace them, never edit them in place, so a
// reader that captured a baseline before an Apply keeps a consistent view.
type applyStateStore struct {
	mu      sync.Mutex
	path    string
	rec     applyStateRecord
	loaded  bool
	saveErr string // last persistence failure, surfaced by /api/state; cleared by the next good write
}

// known reports whether a materialization was actually recorded (as opposed to the zero value an
// imported pre-ledger baseline carries, which supplies a diff baseline and nothing to execute).
func (m *executionMaterializationV1) known() bool {
	return m != nil && m.SchemaVersion == ExecutionSnapshotSchemaV1
}

// applyStateFile is where the record lives: next to the startup config once StartApply told us
// where that is, else next to the sing-box config (the same directory on every real installation).
func (s *Server) applyStateFile() string {
	if s.applyStateDir != "" {
		return filepath.Join(s.applyStateDir, applyStateFileName)
	}
	dir := "."
	if s.cfg != nil && s.cfg.SingBox.Config != "" {
		dir = filepath.Dir(s.cfg.SingBox.Config)
	}
	return filepath.Join(dir, applyStateFileName)
}

// legacyAppliedSnapshotPath is where the pre-ledger stack kept the full applied inputs.
func (s *Server) legacyAppliedSnapshotPath() string {
	dir := ""
	if s.cfg != nil {
		dir = s.cfg.DataDir
		if dir == "" {
			dir = filepath.Dir(s.cfg.SingBox.Config)
		}
	}
	return filepath.Join(dir, "applied-snapshot.json")
}

// stateLocked returns the record, loading (and migrating) it on first use. Caller holds st.mu.
func (s *Server) stateLocked() *applyStateRecord {
	st := &s.applyState
	if st.loaded {
		return &st.rec
	}
	st.loaded = true
	st.path = s.applyStateFile()
	st.rec = applyStateRecord{Schema: applyStateSchema, Acks: map[string]int64{}}
	raw, err := os.ReadFile(st.path)
	switch {
	case err == nil:
		var rec applyStateRecord
		if jsonErr := json.Unmarshal(raw, &rec); jsonErr != nil || rec.Schema != applyStateSchema {
			// A corrupt record means "WayHop owns nothing it can prove". Apply still works; it will
			// simply not remove anything it did not create in this life. Never fatal.
			log.Printf("apply-state: %s is unreadable (%v, schema %d) — starting with an empty record", st.path, jsonErr, rec.Schema)
			return &st.rec
		}
		if rec.Acks == nil {
			rec.Acks = map[string]int64{}
		}
		st.rec = rec
	case errors.Is(err, os.ErrNotExist):
		s.migrateApplyStateLocked()
	default:
		log.Printf("apply-state: cannot read %s: %v — starting with an empty record", st.path, err)
	}
	return &st.rec
}

// persistLocked writes the record atomically. A failed write never fails an Apply — the datapath is
// in force — but it is recorded so /api/state can say the record will not survive a reboot.
func (s *Server) persistLocked() {
	st := &s.applyState
	b, err := json.Marshal(st.rec)
	if err == nil {
		err = atomicfile.Write(st.path, b, 0o600)
	}
	if err != nil {
		st.saveErr = err.Error()
		log.Printf("apply-state: could not persist %s (%v) — the datapath IS applied but this record will be lost on reboot", st.path, err)
		return
	}
	st.saveErr = ""
}

// appliedBaseline is what the router currently runs as far as WayHop knows: the live (Test) state
// while a window is open, else the committed state, else nil.
func (s *Server) appliedBaseline() *appliedRevision {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec := s.stateLocked()
	if rec.Live != nil {
		return rec.Live
	}
	return rec.Committed
}

// committedRevision is the rollback target of a Test window and what boot converges to.
func (s *Server) committedRevision() *appliedRevision {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	return s.stateLocked().Committed
}

// liveRevision is the unsaved (Test) state, nil when no window is open.
func (s *Server) liveRevision() *appliedRevision {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	return s.stateLocked().Live
}

// applyStateSnapshot returns a copy of the record's scalar parts for handlers.
func (s *Server) applyStateSnapshot() (rec applyStateRecord, saveErr string) {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec = *s.stateLocked()
	acks := make(map[string]int64, len(rec.Acks))
	for id, at := range rec.Acks {
		acks[id] = at
	}
	rec.Acks = acks
	return rec, s.applyState.saveErr
}

// recordApplied advances the record after a successful execution: a saving Apply becomes the
// committed state (and closes any window), a Test becomes the live state.
func (s *Server) recordApplied(save bool, rev *appliedRevision) {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec := s.stateLocked()
	if save {
		rec.Committed = rev
		rec.Live = nil
	} else {
		rec.Live = rev
	}
	rec.InFlight = nil
	rec.Last = applyLastResult{At: time.Now().Unix(), OK: true, Rev: rev.Rev}
	s.persistLocked()
}

// recordCommit keeps the live state: it becomes committed and the window closes.
func (s *Server) recordCommit() {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec := s.stateLocked()
	if rec.Live != nil {
		rec.Committed = rec.Live
		rec.Live = nil
	}
	s.persistLocked()
}

// recordRollback drops the live state: the router runs the committed state again.
func (s *Server) recordRollback() {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec := s.stateLocked()
	rec.Live = nil
	rec.InFlight = nil
	s.persistLocked()
}

// recordFailure notes a failed Apply without touching the applied revisions.
func (s *Server) recordFailure(rev string, err error) {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec := s.stateLocked()
	rec.InFlight = nil
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	rec.Last = applyLastResult{At: time.Now().Unix(), OK: false, Rev: rev, Error: msg}
	s.persistLocked()
}

func (s *Server) setInFlight(save bool, rev string) {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec := s.stateLocked()
	rec.InFlight = &applyInFlight{At: time.Now().Unix(), Save: save, Rev: rev}
	s.persistLocked()
}

// setAcks records (acked=true) or forgets (acked=false) acknowledgements by finding id.
func (s *Server) setAcks(ids []string, acked bool) {
	if len(ids) == 0 {
		return
	}
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec := s.stateLocked()
	now := time.Now().Unix()
	changed := false
	for _, id := range ids {
		if id == "" {
			continue
		}
		if acked {
			if _, ok := rec.Acks[id]; !ok {
				rec.Acks[id] = now
				changed = true
			}
		} else if _, ok := rec.Acks[id]; ok {
			delete(rec.Acks, id)
			changed = true
		}
	}
	if changed {
		s.persistLocked()
	}
}

func (s *Server) isAcked(id string) bool {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	_, ok := s.stateLocked().Acks[id]
	return ok
}

// ackedIDs lists the persisted acknowledgements, sorted.
func (s *Server) ackedIDs() []string {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec := s.stateLocked()
	out := make([]string, 0, len(rec.Acks))
	for id := range rec.Acks {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// discardLiveOnBoot drops a live (Test) state left by a previous process: the router booted from its
// saved configuration, so the unsaved state is gone. Returns whether there was one.
func (s *Server) discardLiveOnBoot() bool {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec := s.stateLocked()
	had := rec.Live != nil || rec.InFlight != nil
	if rec.Live != nil {
		log.Printf("apply-state: an unsaved (Test) state %s was left by the previous process — discarded, the router runs the saved configuration", rec.Live.Rev)
	}
	if rec.InFlight != nil {
		log.Printf("apply-state: an Apply of %s (save=%v) did not finish before the previous process stopped — converging to the committed state", rec.InFlight.Rev, rec.InFlight.Save)
	}
	rec.Live = nil
	rec.InFlight = nil
	if had {
		s.persistLocked()
	}
	return had
}

// --- migration from the previous stacks -------------------------------------------------------

// legacyLedgerCheckpoint / legacyLedgerManifest / legacyLedgerBlob are the pieces of the previous
// "strict ledger" persistence this loader still understands, without any HMAC check: the router
// runs what the ledger describes and the record only needs to know what that is.
type legacyLedgerRef struct {
	State       string `json:"state"`
	ManifestRev string `json:"manifest_rev"`
}

type legacyLedgerCheckpoint struct {
	SchemaVersion int             `json:"schema_version"`
	Current       legacyLedgerRef `json:"current"`
	Committed     legacyLedgerRef `json:"committed"`
}

type legacyLedgerManifest struct {
	Descriptor struct {
		DesiredRev string `json:"desired_rev"`
	} `json:"descriptor"`
	ExecutionBlobRev string `json:"execution_blob_rev"`
}

type legacyLedgerBlob struct {
	Payload []byte `json:"payload"`
}

// legacyAppliedSnapshot is the pre-ledger applied-snapshot.json shape.
type legacyAppliedSnapshot struct {
	Hash    string        `json:"hash"`
	Config  config.Config `json:"config"`
	Profile model.Profile `json:"profile"`
}

// migrateApplyStateLocked builds the first record from whatever the previous stacks left behind.
// Best-effort at every step: anything unreadable simply contributes nothing.
func (s *Server) migrateApplyStateLocked() {
	st := &s.applyState
	dir := filepath.Dir(st.path)
	imported := false
	if rev := importLegacyLedger(filepath.Join(dir, "apply-ledger-v1")); rev != nil {
		st.rec.Committed = rev
		imported = true
		log.Printf("apply-state: imported the previous ledger's committed materialization (rev %s)", rev.Rev)
	}
	if snap, ok := readLegacyAppliedSnapshot(s.legacyAppliedSnapshotPath()); ok {
		if st.rec.Committed == nil {
			desired, err := newDesiredSnapshot(snap.Config, snap.Profile, 0)
			if err == nil {
				st.rec.Committed = &appliedRevision{
					Rev: desired.DesiredRev, At: snap.at,
					Desired: &appliedDesired{Profile: snap.Profile, Config: snap.Config},
				}
				imported = true
				log.Printf("apply-state: imported the pre-ledger applied snapshot as the review baseline (rev %s); nothing is known about what it installed", desired.DesiredRev)
			}
		} else if st.rec.Committed.Desired == nil {
			st.rec.Committed.Desired = &appliedDesired{Profile: snap.Profile, Config: snap.Config}
			log.Printf("apply-state: the pre-ledger applied snapshot supplies the review baseline for the imported ledger state")
		}
	}
	if imported {
		s.persistLocked()
	}
}

// importLedgerRef names which ledger pointer to import: committed when known, else current.
func importLedgerRef(cp legacyLedgerCheckpoint) (string, bool) {
	for _, ref := range []legacyLedgerRef{cp.Committed, cp.Current} {
		if ref.State == "known" && isLowerHexRevision(ref.ManifestRev, reviewSHA256HexLen) {
			return ref.ManifestRev, true
		}
	}
	return "", false
}

// importLegacyLedger reads apply-ledger-v1/checkpoint.json → manifest → blob and decodes the
// materialization payload. nil when anything is missing or unreadable.
func importLegacyLedger(root string) *appliedRevision {
	raw, err := os.ReadFile(filepath.Join(root, "checkpoint.json"))
	if err != nil {
		return nil
	}
	var cp legacyLedgerCheckpoint
	if json.Unmarshal(raw, &cp) != nil {
		log.Printf("apply-state: previous ledger checkpoint is unreadable — not imported")
		return nil
	}
	manifestRev, ok := importLedgerRef(cp)
	if !ok {
		return nil
	}
	rawManifest, err := os.ReadFile(filepath.Join(root, "manifests", manifestRev+".json"))
	if err != nil {
		log.Printf("apply-state: previous ledger manifest %s is unreadable — not imported: %v", manifestRev, err)
		return nil
	}
	var manifest legacyLedgerManifest
	if json.Unmarshal(rawManifest, &manifest) != nil ||
		!isLowerHexRevision(manifest.Descriptor.DesiredRev, reviewSHA256HexLen) ||
		!isLowerHexRevision(manifest.ExecutionBlobRev, reviewSHA256HexLen) {
		log.Printf("apply-state: previous ledger manifest %s is malformed — not imported", manifestRev)
		return nil
	}
	rawBlob, err := os.ReadFile(filepath.Join(root, "blobs", manifest.ExecutionBlobRev+".json"))
	if err != nil {
		log.Printf("apply-state: previous ledger blob %s is unreadable — not imported: %v", manifest.ExecutionBlobRev, err)
		return nil
	}
	var blob legacyLedgerBlob
	if json.Unmarshal(rawBlob, &blob) != nil || len(blob.Payload) == 0 {
		log.Printf("apply-state: previous ledger blob %s is malformed — not imported", manifest.ExecutionBlobRev)
		return nil
	}
	materialization, err := decodeLegacyMaterialization(blob.Payload)
	if err != nil {
		log.Printf("apply-state: previous ledger materialization could not be decoded — not imported: %v", err)
		return nil
	}
	at := time.Now().Unix()
	if info, statErr := os.Stat(filepath.Join(root, "checkpoint.json")); statErr == nil {
		at = info.ModTime().Unix()
	}
	return &appliedRevision{Rev: manifest.Descriptor.DesiredRev, At: at, Materialization: materialization}
}

// decodeLegacyMaterialization decodes a previous-stack execution blob payload leniently: fields
// that no longer exist (input revisions, retire lists, AWG host facts) are ignored, and the plugin
// list — which the previous stack could not populate in production — is dropped when it does not
// decode into specs.
func decodeLegacyMaterialization(payload []byte) (executionMaterializationV1, error) {
	var m executionMaterializationV1
	if err := json.Unmarshal(payload, &m); err != nil {
		return executionMaterializationV1{}, fmt.Errorf("decode payload: %w", err)
	}
	if m.SchemaVersion != ExecutionSnapshotSchemaV1 {
		return executionMaterializationV1{}, fmt.Errorf("unsupported materialization schema %d", m.SchemaVersion)
	}
	plugins := m.Plugins[:0]
	for _, spec := range m.Plugins {
		if spec.ID != "" && spec.Endpoint.ID == spec.ID {
			plugins = append(plugins, spec)
		}
	}
	m.Plugins = plugins
	if len(m.Plugins) == 0 && m.PluginAction == ExecutionEnsurePresent {
		m.PluginAction = ExecutionEnsureAbsent
	}
	return m, nil
}

type legacyAppliedSnapshotFile struct {
	legacyAppliedSnapshot
	at int64
}

func readLegacyAppliedSnapshot(path string) (legacyAppliedSnapshotFile, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return legacyAppliedSnapshotFile{}, false
	}
	var snap legacyAppliedSnapshot
	if json.Unmarshal(raw, &snap) != nil || snap.Hash == "" {
		return legacyAppliedSnapshotFile{}, false
	}
	out := legacyAppliedSnapshotFile{legacyAppliedSnapshot: snap, at: time.Now().Unix()}
	if info, err := os.Stat(path); err == nil {
		out.at = info.ModTime().Unix()
	}
	return out, true
}

// --- pending / effective ---------------------------------------------------------------------

// applyPendingView is what /api/state and the plan agree on about saved vs applied.
type applyPendingView struct {
	SavedRev          string
	AppliedRev        string
	AppliedAt         int64
	Pending           bool
	NothingConfigured bool
	WindowOpen        bool
}

// pendingView computes the saved/applied relation from one desired snapshot and the baseline.
func (s *Server) pendingView(desired DesiredSnapshot) applyPendingView {
	view := applyPendingView{SavedRev: desired.DesiredRev}
	base := s.appliedBaseline()
	view.WindowOpen = s.liveRevision() != nil
	if base == nil {
		// Nothing applied yet. A profile that asks for no datapath has nothing an Apply would
		// change, so a fresh install is not greeted with "unapplied changes" over an empty config.
		view.NothingConfigured = desiredProfileRequestsNoDatapath(desired.Profile)
		view.Pending = !view.NothingConfigured
		return view
	}
	view.AppliedRev, view.AppliedAt = base.Rev, base.At
	view.Pending = base.Rev != desired.DesiredRev
	return view
}

// desiredProfileRequestsNoDatapath reports whether the saved profile asks WayHop to run nothing at
// all. Every field that can produce a router-visible artifact is listed: an endpoint or group is a
// tunnel, a rule or routing list is a route, a device group is a scope a routing list references,
// and a non-nil DNS plane emits a resolver block. Missing one here would under-report a real pending
// change, so this deliberately mirrors the Profile struct field for field rather than sampling a
// couple of them.
func desiredProfileRequestsNoDatapath(profile model.Profile) bool {
	return len(profile.Endpoints) == 0 && len(profile.Groups) == 0 && len(profile.Rules) == 0 &&
		len(profile.RoutingLists) == 0 && len(profile.DeviceGroups) == 0 && profile.DNS == nil
}

// Effective-state verdicts: whether the APPLIED revision is actually in force at runtime. Saved-vs-
// applied alone cannot answer this — the config can be written and recorded while nothing runs it.
const (
	effectiveApplied = "applied" // verified in force
	effectiveDrift   = "drift"   // verified NOT in force — runtime contradicts the applied revision
	effectiveUnknown = "unknown" // cannot be verified; NEVER assume success (spec: report unknown)
)

// effectiveState reports whether the applied revision is actually in force, plus a short reason.
// Deliberately conservative: it claims "applied" ONLY when WayHop can attribute the running datapath
// to its own record, and returns "unknown" whenever attribution is impossible — notably MONITOR MODE,
// where a sing-box the user (or an init script) started is serving traffic from a config WayHop does
// not drive. Cheap enough for UI polling: process-state predicates and the last reconcile verdict, no
// exec of the core and no device probes.
func (s *Server) effectiveState(base *appliedRevision) (verdict, reason string) {
	switch {
	case base == nil:
		return effectiveUnknown, "nothing applied yet"
	case s.config().Demo:
		return effectiveUnknown, "demo mode — no real datapath to verify"
	case s.singbox == nil:
		return effectiveUnknown, "core manager unavailable"
	case !base.Materialization.known():
		return effectiveUnknown, "the applied state predates this record — nothing is known about what it installed"
	}
	m := &base.Materialization
	if m.Core.Action != ExecutionEnsurePresent {
		// The core is intentionally down: the kernel plane (or the native tunnels) is the datapath.
		if s.singbox.Running() && s.singbox.Desired() {
			return effectiveDrift, "the applied configuration does not use sing-box, but WayHop's core is running"
		}
		if m.Kernel.Action == ExecutionEnsurePresent {
			switch s.kernelPlaneObserved() {
			case kernelPlanePresent:
				return effectiveApplied, "kernel routing plane verified in place"
			case kernelPlaneMissing:
				return effectiveDrift, "the kernel routing plane is missing — WayHop reinstalls it on its next reconcile"
			}
			return effectiveUnknown, "the kernel routing plane has not been verified yet"
		}
		return effectiveApplied, "native datapath applied — sing-box is intentionally not running"
	}
	v, reason := coreEffective(s.singbox.Available(), s.singbox.Desired(), s.singbox.Running())
	if v == effectiveDrift && s.singbox.Desired() && !s.singbox.Running() {
		// The core was asked to run and isn't. Classify WHY from its log tail so the UI can show an
		// actionable cause + remedy instead of a bare "not running" — this is the state a crash-restart
		// loop sits in, where the raw reason is otherwise never surfaced anywhere. Kept out of the pure
		// function because it reads the log, which is what makes the rest of the decision testable.
		if f := core.ClassifyStartFailure(s.singbox.LogLines()); f.Kind != "" {
			reason += ": " + f.Summary()
		}
	}
	return v, reason
}

// coreEffective is the sing-box half of the verdict, as a pure function of the three predicates it
// reads. Extracted because those predicates are unexported state on the core manager, so the rule
// below could not be exercised at all — and the one case nothing exercised was wrong.
//
// MONITOR MODE is the case: WayHop did not start the core, and one is running anyway. The function's
// own comment said "may be serving a completely different config — unverifiable by construction",
// the doc above effectiveState promises "unknown … notably MONITOR MODE", and the line underneath
// says "cannot attribute runtime to the applied config" — while the code returned APPLIED with the
// reason "core running the applied config". A panel reading that tells the operator their applied
// revision is in force on the strength of a process WayHop neither started nor can inspect.
func coreEffective(available, desired, running bool) (verdict, reason string) {
	switch {
	case !available:
		return effectiveDrift, "sing-box binary not present — the applied config cannot be running"
	case desired && running:
		// WayHop started the core, so its liveness IS attributable to the applied config.
		return effectiveApplied, "core running the applied config"
	case desired:
		return effectiveDrift, "core was started for the applied config but is not running"
	case running:
		return effectiveUnknown, "a core is running that WayHop did not start — it may be serving a different configuration, so nothing here can be attributed to the applied revision"
	default:
		return effectiveUnknown, "core not managed by WayHop (externally started or stopped) — cannot attribute runtime to the applied config"
	}
}

// handleState (GET /api/state) exposes the saved/applied/pending view for the UI's Apply banner, plus
// the EFFECTIVE verdict (is the applied revision actually in force?). It is a distinct endpoint from
// /api/apply/status (which carries the fail-safe countdown, whose own `pending` field means something
// else — the open rollback window, not unapplied config).
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	desired, err := s.captureDesiredSnapshot()
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "the saved configuration is changing — retry")
		return
	}
	view := s.pendingView(desired)
	base := s.appliedBaseline()
	verdict, reason := s.effectiveState(base)
	// §1.1 lifecycle: which of the five distinct states this configuration is in, with the label,
	// plain-language detail and the actions valid HERE — so the UI never shows an ambiguous
	// "Saved"/"Applied" that could mean stored-but-inactive, running-but-revertible, or verified.
	pendingCount := 0
	if view.Pending {
		pendingCount = 1 // at least one; the exact count comes from the plan's change set
	}
	failsafeArmed := view.WindowOpen
	if s.failsafe != nil && s.failsafe.Status().Pending {
		failsafeArmed = true
	}
	life := changeset.Describe(changeset.LifecycleInputs{
		PendingChanges: pendingCount, FailSafeArmed: failsafeArmed,
		Effective: verdict, EffectiveReason: reason,
		NothingConfigured: view.NothingConfigured,
	})
	_, saveErr := s.applyStateSnapshot()
	resp := map[string]any{
		"saved_hash":         view.SavedRev,
		"applied_hash":       view.AppliedRev,
		"applied_at":         view.AppliedAt,
		"pending":            view.Pending,
		"nothing_configured": view.NothingConfigured,
		"lifecycle":          life,
		// effective answers "is the applied revision REALLY in force?" — applied | drift | unknown.
		// The UI must not render success on "unknown"; that is the explicit not-verified signal.
		"effective":        verdict,
		"effective_reason": reason,
		"window_open":      view.WindowOpen,
	}
	// The datapath was applied, but the RECORD of it could not be written (a read-only or full
	// config dir). Surface it so the UI shows a recovery action instead of an unqualified success — a
	// reboot would otherwise reload nothing and report the applied revision "unknown". Present only
	// when set, so a healthy state stays byte-identical.
	if saveErr != "" {
		resp["state_persistence_error"] = saveErr
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}
