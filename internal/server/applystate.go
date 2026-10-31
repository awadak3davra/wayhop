package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
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
	// BootID is the kernel boot a Test (live) revision was applied in, empty when it could not be read.
	// The next process compares it to its own to tell a daemon restart, which leaves the Test running,
	// from a reboot, which on Keenetic leaves none of it (see liveNeedsRollbackOnBoot).
	BootID string `json:"boot_id,omitempty"`
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
	// RoutingOff is set while WayHop's routing is switched off (routingswitch.go). It lives here, not
	// in config.json, because it is a fact about what is installed on the router — the same thing this
	// record is about — and because config.json is rewritten wholesale by Settings, import, reset and
	// backup restore, any of which would silently flip routing back on without running anything.
	// omitempty keeps a record with routing on byte-identical to one written before the switch existed.
	RoutingOff *routingOffRecord `json:"routing_off,omitempty"`
	// RollbackOutstanding is set when a rollback of Live failed part way. Live stays recorded because
	// it is what the retry must undo, but the router no longer runs it as tested: the rollback may
	// already have installed the committed kernel plane before a later step (core stop, native commit,
	// postcheck) failed. Without the mark the reconcile loop read Live as the baseline, found its plane
	// missing and put it back: the plane that had broken connectivity, for good with auto-reboot off.
	// It is persisted so a restart still knows, and omitempty keeps a record without it byte-identical
	// to one written before it existed (an older record loads with it unset).
	RollbackOutstanding *rollbackOutstanding `json:"rollback_outstanding,omitempty"`
}

// rollbackOutstanding names the live revision whose rollback failed (by Rev and At, which together
// identify one Apply) and why. Naming it, rather than flagging the record, keeps a mark that some
// writer forgot to clear from pinning a later Test to the committed revision.
type rollbackOutstanding struct {
	Rev   string `json:"rev"`
	At    int64  `json:"at"`
	Error string `json:"error,omitempty"`
	// KernelPlane is how far the rollback got with the kernel plane (rollbackPlane*), which decides the
	// plane the supervision loops keep installed (supervisedBaseline).
	KernelPlane string `json:"kernel_plane,omitempty"`
}

// What a failed rollback left in the kernel plane. A rollback runs native prepare, plugins, core, then
// the kernel plane; marking every failure as "the committed plane is in" made the reconcile loop install
// the committed plane under the Test's core and native interfaces after a rollback that never got to
// the kernel step (a core that would not restart, a native prepare refusal), breaking a router that
// worked, with no window left to catch it after a Roll back past the window or a boot rollback.
const (
	// rollbackPlaneTested: the rollback stopped before its kernel step. The Test's plane, and the core
	// and native interfaces it pairs with, are as the Test installed them; the zero value, so a mark
	// that does not say keeps the plane the router has.
	rollbackPlaneTested = ""
	// rollbackPlaneCommitted: the kernel step completed: the committed revision's plane is installed,
	// or the Test's removed when the committed revision has none (or there is no committed revision).
	rollbackPlaneCommitted = "committed"
	// rollbackPlaneUnknown: the kernel step ran and failed, so neither plane can be assumed, and either
	// one put back could sit under a core it does not pair with.
	rollbackPlaneUnknown = "unknown"
)

// kernelPlaneAfter is how far one execution that failed with err got with the kernel plane.
func kernelPlaneAfter(res applyExecResult, err error) string {
	if slices.Contains(res.Steps, stepKernel) {
		return rollbackPlaneCommitted
	}
	var stepErr *applyExecError
	if errors.As(err, &stepErr) && stepErr.Step == stepKernel {
		return rollbackPlaneUnknown
	}
	return rollbackPlaneTested
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
	// Temps a crash left between persistLocked's create and rename; every write loads the record first
	// under st.mu, so none is in flight while it loads.
	atomicfile.RemoveStale(st.path)
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

// supervisedBaseline is the revision the supervision loops put back when the router drops part of it
// (the kernel-plane reconcile, the routing-table re-seed, and what they report as installed): the
// applied baseline, except while a rollback of Live is outstanding. Then it is the plane that rollback
// left: the committed revision once its kernel step completed (Live is the configuration being undone,
// and putting its plane back re-broke what the rollback had fixed), Live while the rollback never got
// to the kernel plane (the committed plane under the Test's core and interfaces is neither
// configuration), and nil — nothing put back — when the kernel step itself failed.
func (s *Server) supervisedBaseline() *appliedRevision {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec := s.stateLocked()
	if rec.Live == nil {
		return rec.Committed
	}
	switch mark := rollbackOutstandingLocked(rec); {
	case mark == nil || mark.KernelPlane == rollbackPlaneTested:
		return rec.Live
	case mark.KernelPlane == rollbackPlaneCommitted:
		return rec.Committed
	}
	return nil
}

// rollbackOutstandingLocked is the record's mark when it names the current Live, nil otherwise.
// Caller holds applyState.mu.
func rollbackOutstandingLocked(rec *applyStateRecord) *rollbackOutstanding {
	m := rec.RollbackOutstanding
	if m == nil || rec.Live == nil || m.Rev != rec.Live.Rev || m.At != rec.Live.At {
		return nil
	}
	return m
}

// liveRollbackFailed reports the failed rollback still outstanding for the live revision (a copy),
// nil when there is none.
func (s *Server) liveRollbackFailed() *rollbackOutstanding {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	m := rollbackOutstandingLocked(s.stateLocked())
	if m == nil {
		return nil
	}
	out := *m
	return &out
}

// noteRollbackFailed marks live's rollback outstanding after it failed. Only while live is still the
// record's Live: a Test, Keep or routing switch that replaced it since owns the record now. Matched by
// Rev and At because the window's closure holds the revision runApply built, of which the record keeps
// a copy. plane is how far this attempt got with the kernel plane (rollbackTo). Caller holds applyMu,
// as every rollback does.
func (s *Server) noteRollbackFailed(live *appliedRevision, plane string, err error) {
	if live == nil {
		return
	}
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec := s.stateLocked()
	if rec.Live == nil || rec.Live.Rev != live.Rev || rec.Live.At != live.At {
		return
	}
	// A retry that stopped before the kernel step did not touch the plane: it is still what the
	// earlier attempt left. Recording "tested" over a plane that attempt had already rolled back put
	// the reconcile loop back on the Test's plane.
	if prev := rollbackOutstandingLocked(rec); prev != nil && plane == rollbackPlaneTested {
		plane = prev.KernelPlane
	}
	msg := ""
	if err != nil {
		msg = outputTail(err.Error(), 512)
	}
	rec.RollbackOutstanding = &rollbackOutstanding{Rev: live.Rev, At: live.At, Error: msg, KernelPlane: plane}
	s.persistLocked()
}

// noteLiveRollbackOutstanding records rev as the live state with its rollback outstanding when the
// record has no live state to mark: an Apply whose execution and whose rollback both failed while no
// Test was live, or the Test left from before routing was switched off whose tunnels switching on
// could not remove. The router runs part of it, and the mark is what status, Roll back, the reconcile
// loop and Keep already read for a rollback that failed part way. plane is as for noteRollbackFailed,
// with rev as the tested revision. Caller holds applyMu.
func (s *Server) noteLiveRollbackOutstanding(rev *appliedRevision, plane string, err error) {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec := s.stateLocked()
	live := *rev
	live.BootID = s.bootID()
	rec.Live = &live
	msg := ""
	if err != nil {
		msg = outputTail(err.Error(), 512)
	}
	rec.RollbackOutstanding = &rollbackOutstanding{Rev: live.Rev, At: live.At, Error: msg, KernelPlane: plane}
	s.persistLocked()
}

// sameRevision reports whether a and b are the same Apply. Rev and At together identify one: the record
// keeps a copy of the revision runApply built, so pointers do not compare.
func sameRevision(a, b *appliedRevision) bool {
	return a != nil && b != nil && a.Rev == b.Rev && a.At == b.At
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
		live := *rev
		live.BootID = s.bootID()
		rec.Live = &live
	}
	rec.RollbackOutstanding = nil // whatever was left to undo, this Apply executed over it
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
	rec.RollbackOutstanding = nil
	s.persistLocked()
}

// recordRollback drops the live state: the router runs the committed state again.
func (s *Server) recordRollback() {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec := s.stateLocked()
	rec.Live = nil
	rec.RollbackOutstanding = nil
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

// discardLiveOnBoot drops what a previous process left half done: the in-flight marker always, and a
// live (Test) state unless keepLive — a Test that is still on the router stays recorded until boot has
// rolled it back, because the record is the only thing that says what to undo. Returns whether there
// was anything.
func (s *Server) discardLiveOnBoot(keepLive bool) bool {
	s.applyState.mu.Lock()
	defer s.applyState.mu.Unlock()
	rec := s.stateLocked()
	had := rec.Live != nil || rec.InFlight != nil
	if rec.Live != nil {
		if keepLive {
			log.Printf("apply-state: an unsaved (Test) state %s was left by the previous process and is still on the router — rolling it back to the committed configuration", rec.Live.Rev)
		} else {
			log.Printf("apply-state: an unsaved (Test) state %s was left by the previous process — discarded, the router runs the saved configuration", rec.Live.Rev)
			rec.Live = nil
			rec.RollbackOutstanding = nil
		}
	}
	if rec.InFlight != nil {
		log.Printf("apply-state: an Apply of %s (save=%v) did not finish before the previous process stopped — converging to the committed state", rec.InFlight.Rev, rec.InFlight.Save)
	}
	rec.InFlight = nil
	if had {
		s.persistLocked()
	}
	return had
}

// bootID is the kernel's id for the current boot, "" where it cannot be read.
func (s *Server) bootID() string {
	if s.bootIDOf != nil {
		return s.bootIDOf()
	}
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
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
	case s.routingIsOff():
		// Deliberately not "drift": nothing contradicts what the operator asked for. The applied
		// revision is simply not in force, and the switch's own banner says why.
		return effectiveUnknown, "WayHop's routing is switched off — the router routes on its own until it is switched back on"
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
	resp["routing"] = s.routingSwitchView()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}
