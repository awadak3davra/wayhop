package server

import (
	"context"
	"errors"
	"testing"

	"wayhop/internal/config"
)

// Installing an engine the committed plan expects must bring the router back in line by itself.
//
// It did not, and the panel could not help either: installing a binary changes neither profile nor
// config, so nothing is pending, no Apply control exists, and the page's "Open Review & Apply" line
// pointed at something that was not there. Measured on a live Keenetic after removing and
// reinstalling sing-box — the binary was back, the core stayed down, encrypted DNS stayed dark, and
// only restarting the daemon fixed it, because a restart converges to the committed materialization.
//
// These are the REFUSALS: the cases where converging would be pointless work rather than a fix. The
// success path executes a real materialization and is covered on hardware (the router logs
// "installed 1.13.19; converged to the committed configuration" and the core comes back).
func TestConvergeAfterInstallRefusesWhenThereIsNothingToConvergeTo(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*Server)
	}{
		{"nothing applied before", func(s *Server) {}},
		{"a demo instance materializes nothing", func(s *Server) {
			cfg := config.Default()
			cfg.Demo = true
			s.cfg = cfg
			s.applyState.rec = applyStateRecord{Committed: &appliedRevision{
				Rev: "r1", Materialization: executionMaterializationV1{SchemaVersion: ExecutionSnapshotSchemaV1},
			}}
			s.applyState.loaded = true
		}},
		{"the committed plan runs no core", func(s *Server) {
			s.applyState.rec = applyStateRecord{Committed: &appliedRevision{
				Rev: "r1", Materialization: executionMaterializationV1{SchemaVersion: ExecutionSnapshotSchemaV1},
			}}
			s.applyState.loaded = true
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{cfg: config.Default()}
			c.setup(s)
			did, err := s.convergeAfterInstall(context.Background())
			if err != nil {
				t.Fatalf("refusal reported an error: %v", err)
			}
			if did {
				t.Fatalf("converged when there was nothing to converge to")
			}
		})
	}
}

// QA-142: while a Test runs unsaved, what was applied is the Test. Installing sing-box converged the
// committed revision instead: its core and kernel plane ran under a record and a panel that named the
// Test, and Keep then saved the Test as if it ran.
func TestConvergeAfterInstallConvergesTheLiveTest(t *testing.T) {
	setup := func(t *testing.T, testedCore ExecutionActionV1) (*Server, *applytest_ops, *appliedRevision, func() []string) {
		t.Helper()
		s, fake := applytest_server(t)
		committed := applyboot_kernelMaterialization()
		committed.Core.Config = []byte(`{"rev":"committed"}`)
		s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, Materialization: committed})
		tested := applyboot_kernelMaterialization()
		tested.Core.Action, tested.Core.Config = testedCore, []byte(`{"rev":"tested"}`)
		live := &appliedRevision{Rev: "tested", At: 2, Materialization: tested}
		s.recordApplied(false, live)
		var configs []string
		ops := fake.ops()
		inner := ops.core
		ops.core = func(ctx context.Context, artifact executionCoreArtifactV1) error {
			configs = append(configs, string(artifact.Config))
			return inner(ctx, artifact)
		}
		s.execOps = &ops
		fake.reset()
		return s, fake, s.liveRevision(), func() []string { return configs }
	}

	t.Run("a Test that runs no core is left alone", func(t *testing.T) {
		s, fake, _, _ := setup(t, ExecutionEnsureAbsent)
		if ok, err := s.convergeAfterInstall(context.Background()); ok || err != nil || len(fake.snapshot()) != 0 {
			t.Fatalf("converged = %v, %v; ops %v, want nothing run under the Test", ok, err, fake.snapshot())
		}
	})

	t.Run("a Test that runs one is what converges", func(t *testing.T) {
		s, _, live, configs := setup(t, ExecutionEnsurePresent)
		ok, err := s.convergeAfterInstall(context.Background())
		if !ok || err != nil {
			t.Fatalf("converged = %v, %v", ok, err)
		}
		if got := configs(); len(got) != 1 || got[0] != `{"rev":"tested"}` {
			t.Fatalf("core configs = %v, want the Test's", got)
		}
		if s.liveRevision() != live {
			t.Error("converging must not change the record")
		}
	})

	t.Run("a Test whose rollback is outstanding is left to Roll back", func(t *testing.T) {
		s, fake, live, _ := setup(t, ExecutionEnsurePresent)
		s.noteRollbackFailed(live, rollbackPlaneTested, errors.New("sing-box did not stop"))
		if ok, err := s.convergeAfterInstall(context.Background()); ok || err != nil || len(fake.snapshot()) != 0 {
			t.Fatalf("converged = %v, %v; ops %v, want nothing run", ok, err, fake.snapshot())
		}
	})
}
