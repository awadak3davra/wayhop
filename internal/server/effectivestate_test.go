package server

import (
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/core"
)

// TestEffectiveState covers the spec rule "report unknown rather than assuming success when runtime
// state cannot be verified". The dangerous case is a false "applied": a config recorded as applied
// while nothing actually runs it.
func TestEffectiveState(t *testing.T) {
	newSrv := func(cfg config.Config, sb *core.SingBox) *Server {
		return &Server{singbox: sb, cfg: &cfg}
	}
	// A recorded revision whose materialization runs the core.
	applied := &appliedRevision{Rev: "abc123", Materialization: executionMaterializationV1{
		SchemaVersion: ExecutionSnapshotSchemaV1,
		Core:          executionCoreArtifactV1{Action: ExecutionEnsurePresent},
		Kernel:        executionKernelArtifactV1{Action: ExecutionEnsureAbsent},
		PluginAction:  ExecutionEnsureAbsent,
	}}

	t.Run("nothing applied yet => unknown", func(t *testing.T) {
		s := newSrv(config.Config{}, core.New(t.TempDir()+"/nope", t.TempDir()+"/c.json"))
		v, reason := s.effectiveState(nil)
		if v != effectiveUnknown {
			t.Errorf("verdict = %q, want unknown (reason %q)", v, reason)
		}
	})

	t.Run("demo => unknown, never applied", func(t *testing.T) {
		s := newSrv(config.Config{Demo: true}, core.New(t.TempDir()+"/nope", t.TempDir()+"/c.json"))
		v, _ := s.effectiveState(applied)
		if v != effectiveUnknown {
			t.Errorf("demo verdict = %q, want unknown", v)
		}
	})

	t.Run("no sing-box binary => drift, not applied", func(t *testing.T) {
		// A revision is recorded but the core binary is absent: the applied config provably is not
		// running. This must NOT report applied.
		s := newSrv(config.Config{}, core.New(t.TempDir()+"/no-such-bin", t.TempDir()+"/c.json"))
		v, reason := s.effectiveState(applied)
		if v != effectiveDrift {
			t.Errorf("verdict = %q, want drift (reason %q)", v, reason)
		}
		if v == effectiveApplied {
			t.Fatal("must never claim applied when nothing can be running it")
		}
	})

	t.Run("nil core manager => unknown", func(t *testing.T) {
		s := newSrv(config.Config{}, nil)
		if v, _ := s.effectiveState(applied); v != effectiveUnknown {
			t.Errorf("verdict = %q, want unknown", v)
		}
	})
}
