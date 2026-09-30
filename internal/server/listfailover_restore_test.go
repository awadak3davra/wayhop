package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/health"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/store"
)

// restorePlan is an applied kernel plan with one endpoint egress (table 1001, the userspace device
// wr_u), one group egress (1002) and a blackhole (1003); v6 says whether it also marks IPv6.
func restorePlan(v6 bool) *pbr.Plan {
	plan := &pbr.Plan{
		Table: "wayhop",
		Egresses: []pbr.Egress{
			{Tag: model.OutboundDirect, Kind: pbr.EgressWAN, Mark: 0x10000, Table: 150},
			{Tag: "u", Kind: pbr.EgressInterface, Iface: "wr_u", Mark: 0x20000, Table: 1001},
			{Tag: "g", Kind: pbr.EgressInterface, Iface: "wr_g1", Mark: 0x30000, Table: 1002},
			{Tag: "blk", Kind: pbr.EgressBlackhole, Mark: 0x40000, Table: 1003},
		},
		Zones: []pbr.Zone{{Name: "z", EgressTag: "u", Mark: 0x20000, V4: []string{"203.0.113.0/24"}}},
	}
	if v6 {
		plan.Zones[0].V6 = []string{"2001:db8::/32"}
	}
	return plan
}

func restoreProfile() model.Profile {
	return model.Profile{Groups: []model.Group{{ID: "g", Members: []string{"m1", "m2"}}}}
}

// fakeTables records what the loop writes and answers reads from a map of family -> `ip route show`.
type fakeTables struct {
	mu      sync.Mutex
	show    map[bool]string
	readErr map[bool]error
	up      map[string]bool
	writes  []string
}

func (f *fakeTables) io() *routeTableIO {
	return &routeTableIO{
		read: func(_ context.Context, v6 bool) (string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.show[v6], f.readErr[v6]
		},
		write: func(_ context.Context, v6 bool, iface string, table int) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			family := "4"
			if v6 {
				family = "6"
			}
			f.writes = append(f.writes, fmt.Sprintf("v%s %s %d", family, iface, table))
			return nil
		},
		up: func(iface string) bool { return f.up[iface] },
	}
}

func restoreServer(t *testing.T, plan *pbr.Plan, tables *fakeTables) *Server {
	t.Helper()
	s := &Server{cfg: config.Default(), routeTables: tables.io()}
	profile := restoreProfile()
	s.applyState.rec = applyStateRecord{Committed: &appliedRevision{
		Rev: "r1", Desired: &appliedDesired{Profile: profile},
		Materialization: executionMaterializationV1{
			SchemaVersion: ExecutionSnapshotSchemaV1,
			Kernel:        executionKernelArtifactV1{Action: ExecutionEnsurePresent, Plan: plan},
		},
	}}
	s.applyState.loaded = true
	return s
}

// `ip -6 route show table all` reads the same way as v4: a device default per table; a blackhole,
// a kernel-local route and the main table are not ours.
func TestParseTableDefaultsReadsIPv6(t *testing.T) {
	got := parseTableDefaults("default dev wr_u table 1001 metric 1024 pref medium\n" +
		"blackhole default dev lo table 1003 metric 4000 pref medium\n" +
		"local ::1 dev lo table local proto kernel metric 0 pref medium\n" +
		"default via fe80::1 dev eth3 proto ra metric 1024 pref medium\n")
	if want := map[int]string{1001: "wr_u"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTableDefaults = %v, want %v", got, want)
	}
}

// The rule: an endpoint's table that lost its device route gets it back once the device is up; a
// group's table is the election's, a route to another device is somebody's choice, and a device that
// is not back yet waits for the next tick.
func TestLostTableRoutes(t *testing.T) {
	plan, profile := restorePlan(false), restoreProfile()
	up := func(iface string) bool { return iface == "wr_u" || iface == "wr_g1" }
	if got := lostTableRoutes(plan, &profile, map[int]string{}, up); !reflect.DeepEqual(got, []tableRestore{{Table: 1001, Iface: "wr_u"}}) {
		t.Errorf("empty tables: %+v", got)
	}
	for name, live := range map[string]map[int]string{
		"route still there":              {1001: "wr_u"},
		"route to someone else's device": {1001: "nwg3"},
	} {
		if got := lostTableRoutes(plan, &profile, live, up); len(got) != 0 {
			t.Errorf("%s: restored %+v", name, got)
		}
	}
	if got := lostTableRoutes(plan, &profile, map[int]string{}, func(string) bool { return false }); len(got) != 0 {
		t.Errorf("device down: restored %+v", got)
	}
}

// The loop puts back what the applied plan installed - the v4 route, and the v6 one when the plane
// seeds v6 - and nothing while an Apply runs, in the demo, or for a family it could not read.
func TestRestoreLostTableRoutes(t *testing.T) {
	run := func(t *testing.T, plan *pbr.Plan, tables *fakeTables, setup func(*Server)) []string {
		t.Helper()
		s := restoreServer(t, plan, tables)
		if setup != nil {
			setup(s)
		}
		live, _ := s.liveTableDefaults(context.Background(), false)
		s.restoreLostTableRoutes(context.Background(), live)
		return tables.writes
	}
	fresh := func() *fakeTables { return &fakeTables{up: map[string]bool{"wr_u": true}} }

	if got := run(t, restorePlan(true), fresh(), nil); !reflect.DeepEqual(got, []string{"v4 wr_u 1001", "v6 wr_u 1001"}) {
		t.Errorf("both families lost: writes %v", got)
	}
	if got := run(t, restorePlan(false), fresh(), nil); !reflect.DeepEqual(got, []string{"v4 wr_u 1001"}) {
		t.Errorf("a v4-only plane got v6 writes: %v", got)
	}
	unreadable := fresh()
	unreadable.readErr = map[bool]error{true: errors.New("ip -6: not supported")}
	if got := run(t, restorePlan(true), unreadable, nil); !reflect.DeepEqual(got, []string{"v4 wr_u 1001"}) {
		t.Errorf("an unreadable v6 family was written: %v", got)
	}
	present := fresh()
	present.show = map[bool]string{false: "default dev wr_u scope link table 1001\n", true: "default dev wr_u table 1001 metric 1024\n"}
	if got := run(t, restorePlan(true), present, nil); len(got) != 0 {
		t.Errorf("routes that are there were written: %v", got)
	}
	for name, setup := range map[string]func(*Server){
		"an Apply in progress":  func(s *Server) { s.applyInProgress.Store(true) },
		"Apply holds the lock":  func(s *Server) { s.applyMu.Lock() },
		"the demo":              func(s *Server) { cfg := config.Default(); cfg.Demo = true; s.cfg = cfg },
		"no kernel plane":       func(s *Server) { s.applyState.rec.Committed.Materialization.Kernel.Action = ExecutionEnsureAbsent },
		"no record of the plan": func(s *Server) { s.applyState.rec.Committed.Desired = nil },
	} {
		if got := run(t, restorePlan(true), fresh(), setup); len(got) != 0 {
			t.Errorf("%s: writes %v", name, got)
		}
	}
}

// A restore is logged each time it happens; a refusal once per change, not every tick.
func TestTableRestoreLogging(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	s := &Server{}
	lost := tableRestore{Table: 1001, Iface: "wr_u"}
	boom := errors.New("Cannot find device \"wr_u\"")
	s.noteTableRestore(false, lost, boom)
	s.noteTableRestore(false, lost, boom)
	s.noteTableRestore(true, lost, boom)
	if n := strings.Count(buf.String(), "cannot restore table 1001's IPv4"); n != 1 {
		t.Errorf("the same IPv4 refusal was logged %d times:\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "cannot restore table 1001's IPv6") {
		t.Errorf("the IPv6 refusal was folded into the IPv4 one:\n%s", buf.String())
	}
	s.noteTableRestore(false, lost, nil)
	if !strings.Contains(buf.String(), "table 1001 lost its IPv4 route through wr_u") {
		t.Errorf("the restore was not logged:\n%s", buf.String())
	}
	s.noteTableRestore(false, lost, boom)
	if n := strings.Count(buf.String(), "cannot restore table 1001's IPv4"); n != 2 {
		t.Errorf("a refusal after a recovery was not logged again:\n%s", buf.String())
	}
}

// The tick reads the tables once, and an unreadable read stops it whole: without that the restore
// half would see every table as empty and re-seed routes that are there.
func TestListFailoverTickWritesNothingOnAnUnreadableTable(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	tables := &fakeTables{up: map[string]bool{"wr_u": true}, readErr: map[bool]error{false: errors.New("ip: exit 1")}}
	s := restoreServer(t, restorePlan(false), tables)
	s.store = st
	s.monitor = health.NewMonitor(nil, st, nil, true)
	s.listFailoverTick(context.Background())
	if len(tables.writes) != 0 {
		t.Fatalf("an unreadable table was written: %v", tables.writes)
	}
	tables.readErr = nil
	s.listFailoverTick(context.Background())
	if !reflect.DeepEqual(tables.writes, []string{"v4 wr_u 1001"}) {
		t.Fatalf("with the tables readable the lost route was not restored: %v", tables.writes)
	}
}
