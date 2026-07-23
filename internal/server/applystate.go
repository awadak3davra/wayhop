package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"wayhop/internal/atomicfile"
	"wayhop/internal/config"
	"wayhop/internal/model"
)

// appliedState records the canonical revision last successfully pushed to the running engine —
// PLUS the revision that Apply replaced, so a fail-safe rollback can restore the truth. It is
// PERSISTED on disk: a frontend-only snapshot would reset to "all applied" on every reload,
// falsely hiding unapplied edits, and an in-memory prev would forget the rollback target across
// a daemon restart mid-window. Pending = the saved inputs' hash differs from the applied one.
type appliedState struct {
	Hash     string `json:"hash"`      // canonical hash of the applied inputs at the last successful Apply
	At       int64  `json:"at"`        // unix seconds of that Apply
	PrevHash string `json:"prev_hash"` // the revision that Apply replaced (a rollback restores this)
	PrevAt   int64  `json:"prev_at"`
}

// appliedInputs is the CANONICAL SNAPSHOT of everything an Apply materializes into the running
// engine: the profile (endpoints/groups/rules/routing lists/DNS) plus every config field that
// feeds generator.Generate, pbr.Compile or the native-only verdict. If ANY of these change, the
// running engine no longer reflects what is saved — so the hash changes and the UI shows
// "pending". The derived artifacts (singbox.json, the kernel plan) are pure functions of these
// inputs for a given binary, so hashing the inputs is equivalent to hashing the outputs without
// re-running a generate+compile on every GET /api/state.
type appliedInputs struct {
	Profile        model.Profile `json:"profile"`
	RoutingMode    string        `json:"routing_mode"`
	MixedPort      int           `json:"mixed_port"`
	ClashAddr      string        `json:"clash_addr"`
	ClashSecret    string        `json:"clash_secret"`
	Gateway        bool          `json:"gateway"`
	GatewayMTU     int           `json:"gateway_mtu"`
	GatewayAddr    string        `json:"gateway_addr"`
	Demo           bool          `json:"demo"`
	Offload        string        `json:"offload"`
	OffloadDevices []string      `json:"offload_devices"`
}

// canonicalHash is a deterministic content hash of the full applied-input snapshot: json.Marshal
// is stable here (struct fields in declaration order, map keys sorted), so unchanged inputs always
// hash the same across restarts, and any user edit — profile OR config (routing mode, ports, TUN,
// offload…) — changes it, flipping the UI to "pending".
func (s *Server) canonicalHash(c config.Config, p model.Profile) string {
	in := appliedInputs{
		Profile:        p,
		RoutingMode:    s.routingMode(c),
		MixedPort:      c.Ports.Mixed,
		ClashAddr:      c.Clash.Controller,
		ClashSecret:    c.Clash.Secret,
		Gateway:        c.Gateway,
		GatewayMTU:     c.GatewayMTU,
		GatewayAddr:    c.GatewayAddr,
		Demo:           c.Demo,
		Offload:        c.Offload,
		OffloadDevices: c.OffloadDevices,
	}
	b, err := json.Marshal(in)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (s *Server) appliedStatePath() string {
	dir := s.cfg.DataDir
	if dir == "" {
		dir = filepath.Dir(s.cfg.SingBox.Config)
	}
	return filepath.Join(dir, "applied.json")
}

// loadAppliedState reads the persisted applied revision on startup. If none exists yet (fresh
// install, demo, or an upgrade from before this feature), it bootstraps applied := the current
// saved inputs — i.e. "assume the running engine reflects the saved state at boot", which is true
// for a normally-running daemon. From then on, only a successful Apply advances the applied
// revision, so an edit-then-reload correctly reports pending.
func (s *Server) loadAppliedState() {
	s.applyStateMu.Lock()
	defer s.applyStateMu.Unlock()
	if b, err := os.ReadFile(s.appliedStatePath()); err == nil {
		var a appliedState
		if json.Unmarshal(b, &a) == nil && a.Hash != "" {
			s.appliedHash, s.appliedAt = a.Hash, a.At
			s.prevAppliedHash, s.prevAppliedAt = a.PrevHash, a.PrevAt
			return
		}
	}
	// bootstrap
	s.appliedHash = s.canonicalHash(s.config(), s.store.Profile())
	s.appliedAt = time.Now().Unix()
	s.prevAppliedHash, s.prevAppliedAt = "", 0
	s.persistAppliedLocked()
}

// recordApplied advances the applied revision to the (config, profile) snapshot the apply ACTUALLY
// materialized — passed in from handleApply, never re-read here, so a profile edit racing the apply
// can never be falsely marked applied. The replaced revision is kept as the rollback target. Called
// ONLY on a genuinely successful Apply (no reload/commit/PBR error) — a failed Apply leaves the
// previous applied revision, and the UI stays "pending".
func (s *Server) recordApplied(c config.Config, p model.Profile) {
	h := s.canonicalHash(c, p)
	s.applyStateMu.Lock()
	if h != s.appliedHash {
		s.prevAppliedHash, s.prevAppliedAt = s.appliedHash, s.appliedAt
	}
	s.appliedHash, s.appliedAt = h, time.Now().Unix()
	s.persistAppliedLocked()
	s.applyStateMu.Unlock()
}

// restorePrevApplied reverts the applied revision to the one the last Apply replaced, persisting
// the reversal. Called when the fail-safe rolls the engine back (automatic connectivity rollback
// or the manual RollbackNow endpoint — both drive the same closure): the engine now runs the
// PREVIOUS config, so keeping the new revision would make /api/state report "nothing pending"
// while the user's saved changes are in fact NOT active — the exact lie this file exists to
// prevent. No-op when there is nothing recorded to restore.
func (s *Server) restorePrevApplied() {
	s.applyStateMu.Lock()
	defer s.applyStateMu.Unlock()
	if s.prevAppliedHash == "" {
		return
	}
	s.appliedHash, s.appliedAt = s.prevAppliedHash, s.prevAppliedAt
	s.prevAppliedHash, s.prevAppliedAt = "", 0
	s.persistAppliedLocked()
	log.Printf("applystate: rollback — applied revision restored to the pre-apply snapshot")
}

// persistAppliedLocked writes applied.json. Caller holds applyStateMu. Best-effort (a failed write
// just means the state is recomputed/bootstrapped next boot — never fatal to an Apply).
func (s *Server) persistAppliedLocked() {
	if b, err := json.Marshal(appliedState{Hash: s.appliedHash, At: s.appliedAt, PrevHash: s.prevAppliedHash, PrevAt: s.prevAppliedAt}); err == nil {
		_ = atomicfile.Write(s.appliedStatePath(), b, 0o600)
	}
}

// handleState (GET /api/state) exposes the saved/applied/pending view for the UI's Apply banner. It
// is a distinct endpoint from /api/apply/status (which carries the fail-safe countdown, whose own
// `pending` field means something else — the open rollback window, not unapplied config).
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	saved := s.canonicalHash(s.config(), s.store.Profile())
	s.applyStateMu.Lock()
	applied, at := s.appliedHash, s.appliedAt
	s.applyStateMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"saved_hash":   saved,
		"applied_hash": applied,
		"applied_at":   at,
		"pending":      applied != "" && saved != applied,
	})
}
