package server

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"wayhop/internal/clash"
	"wayhop/internal/pbr"
)

// A load of the guard rendered the learned addresses and then replaced the table; an
// address a learn pass added in between was in the old table and in RAM, and in neither the replay
// nor the new table.
func TestALearnPassDoesNotFallBetweenTheTwoHalvesOfAGuardLoad(t *testing.T) {
	namesPaths(t)
	s, plan := openwrtServer(t, namedProfile(), &fakeTables{})
	s.cfg.RoutingMode = "hybrid"
	s.uciReader = houseUCI
	ctx := context.Background()

	// The kernel's sets: a load replaces the table, a learn pass adds to the one in place.
	var mu sync.Mutex
	kernel := map[string]bool{}
	put := func(program string) {
		for _, ln := range strings.Split(program, "\n") {
			if f := strings.Fields(ln); len(f) > 6 && f[0] == "add" && f[1] == "element" && strings.HasPrefix(f[4], "kn_") {
				kernel[f[6]] = true
			}
		}
	}
	const addr = "93.184.216.34"
	passed := make(chan struct{})
	adapter := &exactKernelAdapter{guardTx: &s.ksGuardTx}
	adapter.learned = func(p *pbr.Plan) string {
		replay := s.learnedNamesProgram(p)
		// The pass arrives here: the replay is rendered, the table is not replaced yet.
		go func() {
			s.learnNames(ctx, plan, []clash.Conn{connTo(addr, "grp-auto")}, func(_ context.Context, program string) error {
				mu.Lock()
				defer mu.Unlock()
				put(program)
				return nil
			})
			close(passed)
		}()
		select {
		case <-passed:
		case <-time.After(300 * time.Millisecond):
		}
		return replay
	}
	adapter.runner = exactKernelRunnerFunc(func(_ context.Context, stdin, _ string, _ ...string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		kernel = map[string]bool{}
		put(stdin)
		return "", nil
	})
	if err := adapter.loadGuard(ctx, plan.RenderNftGuardWith(s.namesHold(plan)), plan); err != nil {
		t.Fatal(err)
	}
	<-passed
	s.ksn.mu.Lock()
	_, inRAM := s.ksn.sets["kn_tg_calls"][netip.MustParseAddr(addr)]
	s.ksn.mu.Unlock()
	mu.Lock()
	defer mu.Unlock()
	if !inRAM || !kernel[addr] {
		t.Fatalf("the address is in RAM (%v) and not in the table that was loaded (%v)", inRAM, kernel)
	}
}
