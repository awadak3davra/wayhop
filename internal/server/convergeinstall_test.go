package server

import (
	"context"
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
