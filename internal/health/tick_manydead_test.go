package health

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wayhop/internal/clash"
	"wayhop/internal/model"
)

// manyDeadClash is a Clash API whose "dead-*" proxies answer 504 after deadDelay, as a delay test
// that timed out does, and whose other proxies answer at once. up=false makes every proxy dead (the
// uplink is away). It counts the delay tests it was asked for.
type manyDeadClash struct {
	up        atomic.Bool
	asked     atomic.Int64
	deadDelay time.Duration
}

func (f *manyDeadClash) client(t *testing.T) *clash.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/proxies/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/delay") {
			http.NotFound(w, r)
			return
		}
		f.asked.Add(1)
		if !f.up.Load() || strings.Contains(r.URL.Path, "dead-") {
			select {
			case <-time.After(f.deadDelay):
			case <-r.Context().Done():
				return
			}
			w.WriteHeader(http.StatusGatewayTimeout)
			_, _ = w.Write([]byte(`{"message":"An error occurred in the delay test"}`))
			return
		}
		_, _ = w.Write([]byte(`{"delay":50}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c, err := clash.New(strings.TrimPrefix(ts.URL, "http://"), "")
	if err != nil {
		t.Fatalf("clash.New: %v", err)
	}
	return c
}

// manyDeadProfile is dead exits first, then live ones: the order a subscription that kept its stale
// entries has them in.
func manyDeadProfile(dead, live int) model.Profile {
	var p model.Profile
	for i := 0; i < dead; i++ {
		p.Endpoints = append(p.Endpoints, model.Endpoint{ID: fmt.Sprintf("dead-%d", i), Name: "d", Protocol: model.ProtoVLESS,
			Server: "198.51.100.1", Port: 443, Enabled: true})
	}
	for i := 0; i < live; i++ {
		p.Endpoints = append(p.Endpoints, model.Endpoint{ID: fmt.Sprintf("live-%d", i), Name: "l", Protocol: model.ProtoVLESS,
			Server: "198.51.100.2", Port: 443, Enabled: true})
	}
	return p
}

func stateOf(m *Monitor, id string) State {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.stats[id]; s != nil {
		return s.state
	}
	return Unknown
}

// A profile where most exits time out still gets its live exits measured, and a local-fault flag
// left by an earlier tick is taken down by the exits that answer.
//
// The dead probes here take 20 rounds of deadDelay in all, several times one probe's budget
// (timeout + headroom = 500 ms). A deadline over the whole tick instead of each probe ends such a
// tick with nothing recorded: every exit stays unmeasured and the flag stays up, on every tick.
func TestTickRecordsLiveExitsBesideManyDead(t *testing.T) {
	f := &manyDeadClash{deadDelay: 60 * time.Millisecond}
	f.up.Store(true)
	const dead, live = 160, 10
	m := NewMonitor(f.client(t), health_newStore(t, manyDeadProfile(dead, live)), nil, false)
	m.timeoutMS, m.probeHeadroom = 100, 400*time.Millisecond
	m.localFault = true // an earlier tick, before the uplink came up

	m.tick(context.Background())

	for i := 0; i < live; i++ {
		if st := stateOf(m, fmt.Sprintf("live-%d", i)); st != Alive {
			t.Fatalf("live-%d = %v after a tick beside %d dead exits, want alive", i, st, dead)
		}
	}
	if m.LocalFault() {
		t.Error("local fault still raised though live exits answered")
	}
	if got := f.asked.Load(); got != dead+live {
		t.Errorf("first tick asked for %d delay tests, want all %d", got, dead+live)
	}

	// The second Down probe confirms the dead ones (flapThreshold).
	m.tick(context.Background())
	if st := stateOf(m, "dead-0"); st != Down {
		t.Errorf("dead-0 = %v after two failed probes, want down", st)
	}
}

// Dead exits past coldAfter failed probes are probed coldPerTick at a time, in rotation, while the
// live ones are probed on every tick; each cold exit still gets its turn.
func TestTickRotatesColdExits(t *testing.T) {
	f := &manyDeadClash{deadDelay: time.Millisecond}
	f.up.Store(true)
	const dead, live = 20, 3
	m := NewMonitor(f.client(t), health_newStore(t, manyDeadProfile(dead, live)), nil, false)
	m.timeoutMS, m.probeHeadroom = 100, 2*time.Second

	for i := 0; i < coldAfter; i++ {
		m.tick(context.Background())
	}
	if got := f.asked.Load(); got != int64(coldAfter*(dead+live)) {
		t.Fatalf("the first %d ticks asked for %d delay tests, want every exit each time (%d)",
			coldAfter, got, coldAfter*(dead+live))
	}

	seen := map[string]int{}
	rounds := (dead + coldPerTick - 1) / coldPerTick
	for i := 0; i < rounds; i++ {
		before := f.asked.Load()
		picked := m.pickProbes(m.targetsFrom(m.store.Profile()))
		for _, tg := range picked {
			seen[tg.id]++
		}
		if len(picked) != live+coldPerTick {
			t.Fatalf("tick %d picks %d exits, want the %d live and %d cold", i, len(picked), live, coldPerTick)
		}
		// pickProbes moved the rotation on; put it back so the tick itself picks the same share.
		m.mu.Lock()
		m.coldCursor = (m.coldCursor - coldPerTick + dead) % dead
		m.mu.Unlock()
		m.tick(context.Background())
		if got := f.asked.Load() - before; got != int64(live+coldPerTick) {
			t.Fatalf("tick %d asked for %d delay tests, want %d", i, got, live+coldPerTick)
		}
	}
	for i := 0; i < dead; i++ {
		if seen[fmt.Sprintf("dead-%d", i)] == 0 {
			t.Errorf("dead-%d was never probed in %d ticks of the rotation", i, rounds)
		}
	}
	for i := 0; i < live; i++ {
		if n := seen[fmt.Sprintf("live-%d", i)]; n != rounds {
			t.Errorf("live-%d probed on %d of %d ticks, want every tick", i, n, rounds)
		}
	}
}

// No more than coldPerTick cold exits: every one of them is probed on every tick.
func TestTickProbesFewColdExitsEveryTick(t *testing.T) {
	f := &manyDeadClash{deadDelay: time.Millisecond}
	f.up.Store(true)
	const dead, live = coldPerTick, 2
	m := NewMonitor(f.client(t), health_newStore(t, manyDeadProfile(dead, live)), nil, false)
	m.timeoutMS, m.probeHeadroom = 100, 2*time.Second
	const ticks = coldAfter + 3
	for i := 0; i < ticks; i++ {
		m.tick(context.Background())
	}
	if got := f.asked.Load(); got != int64(ticks*(dead+live)) {
		t.Errorf("%d ticks asked for %d delay tests, want every exit each time (%d)", ticks, got, ticks*(dead+live))
	}
}

// An outage of the uplink makes no live exit cold, however long it lasts: every tick of it asks all
// of them, so the first tick after the uplink is back ends the local fault. Were the live exits put
// in the rotation with the dead ones, that tick could fall on a share of dead exits and the flag
// would stay up until the rotation reached a live one.
func TestTickKeepsLiveExitsHotThroughAnOutage(t *testing.T) {
	f := &manyDeadClash{deadDelay: time.Millisecond}
	f.up.Store(true)
	const dead, live = 40, 4
	m := NewMonitor(f.client(t), health_newStore(t, manyDeadProfile(dead, live)), nil, false)
	m.timeoutMS, m.probeHeadroom = 100, 2*time.Second
	for i := 0; i < coldAfter+1; i++ { // the dead ones go cold
		m.tick(context.Background())
	}

	f.up.Store(false)
	for i := 0; i < coldAfter+3; i++ {
		before := f.asked.Load()
		m.tick(context.Background())
		if got := f.asked.Load() - before; got != live+coldPerTick {
			t.Fatalf("outage tick %d asked for %d delay tests, want the %d live and %d cold", i+1, got, live, coldPerTick)
		}
		if !m.LocalFault() {
			t.Fatalf("outage tick %d: every exit down at once did not raise the local fault", i+1)
		}
		for j := 0; j < live; j++ {
			if st := stateOf(m, fmt.Sprintf("live-%d", j)); st != Alive {
				t.Fatalf("outage tick %d: live-%d = %v, want it held alive", i+1, j, st)
			}
		}
	}

	f.up.Store(true)
	m.tick(context.Background())
	if m.LocalFault() {
		t.Error("local fault still raised one tick after the uplink came back")
	}
	for j := 0; j < live; j++ {
		if st := stateOf(m, fmt.Sprintf("live-%d", j)); st != Alive {
			t.Errorf("live-%d = %v once the uplink is back, want alive", j, st)
		}
	}
	if st := stateOf(m, "dead-0"); st != Down {
		t.Errorf("dead-0 = %v after the outage, want it still down", st)
	}
}

// noteProbes: Unknown leaves a count alone, Alive clears it, a Down the local-fault gate held back is
// not counted, and an exit that left the profile takes its count with it.
func TestNoteProbesCounts(t *testing.T) {
	m := NewMonitor(nil, health_newStore(t, model.Profile{}), nil, false)
	tgs := []target{{id: "a", kind: "endpoint"}, {id: "b", kind: "endpoint"}, {id: "c", kind: "endpoint"}}
	m.noteProbes(tgs, tgs, []State{Down, Down, Down}, false)
	m.noteProbes(tgs, tgs, []State{Down, Unknown, Alive}, false)
	if got := fmt.Sprint(m.probeFails); got != "map[a:2 b:1]" {
		t.Errorf("counts = %s, want map[a:2 b:1]", got)
	}
	m.noteProbes(tgs, tgs, []State{Down, Down, Down}, true)
	if got := fmt.Sprint(m.probeFails); got != "map[a:2 b:1]" {
		t.Errorf("counts after a gated tick = %s, want them unchanged (map[a:2 b:1])", got)
	}
	m.noteProbes(tgs[:1], nil, nil, false)
	if got := fmt.Sprint(m.probeFails); got != "map[a:2]" {
		t.Errorf("counts after b left the profile = %s, want map[a:2]", got)
	}
}
