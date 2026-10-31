package server

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/health"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/store"
)

// nativeEndpoint is an adopted kernel tunnel: the loop elects it by its interface.
func nativeEndpoint(id, iface string) model.Endpoint {
	return model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineExternal,
		Params: map[string]any{"interface": iface}}
}

// failoverProfile is a group of two native tunnels [m1 (nwg3), m2 (nwg5)] behind one routing list,
// plus a second list through a single endpoint nl (awg0). extra is appended to the list's CIDRs.
func failoverProfile(extra ...string) model.Profile {
	return model.Profile{
		Endpoints: []model.Endpoint{nativeEndpoint("m1", "nwg3"), nativeEndpoint("m2", "nwg5"), nativeEndpoint("nl", "awg0")},
		Groups:    []model.Group{{ID: "grp", Name: "Main", Type: "fallback", Members: []string{"m1", "m2"}}},
		RoutingLists: []model.RoutingList{
			{ID: "tg", Name: "TG", Outbound: "grp", Enabled: true, Manual: append([]string{"203.0.113.0/24"}, extra...)},
			{ID: "yt", Name: "YT", Outbound: "nl", Enabled: true, Manual: []string{"198.51.100.0/24"}},
		},
	}
}

// appliedFailoverServer is a server whose committed (applied) kernel plan was compiled from applied,
// while the store holds saved: what the router runs and what the operator has saved but not applied.
func appliedFailoverServer(t *testing.T, applied, saved model.Profile, tables *fakeTables) (*Server, *pbr.Plan) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Replace(saved); err != nil {
		t.Fatalf("seed saved profile: %v", err)
	}
	cfg := config.Default()
	cfg.RoutingMode = "fast"
	s := &Server{cfg: cfg, store: st, routeTables: tables.io()}
	plan, _, err := pbr.Compile(&applied, s.pbrCompileOptions(*cfg))
	if err != nil {
		t.Fatalf("compile the applied profile: %v", err)
	}
	s.applyState.rec = applyStateRecord{Committed: &appliedRevision{
		Rev: "r1", Desired: &appliedDesired{Profile: applied},
		Materialization: executionMaterializationV1{
			SchemaVersion: ExecutionSnapshotSchemaV1,
			Kernel:        executionKernelArtifactV1{Action: ExecutionEnsurePresent, Plan: plan},
		},
	}}
	s.applyState.loaded = true
	s.monitor = health.NewMonitor(nil, st, nil, false) // never ticked: every member Unknown
	return s, plan
}

// healthWith is a monitor that has measured every id in alive as Alive and down as Down. It runs one
// demo tick over its own store, which marks the LAST endpoint Down and every other one Alive.
func healthWith(t *testing.T, alive []string, down string) *health.Monitor {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "health.json"))
	if err != nil {
		t.Fatal(err)
	}
	var p model.Profile
	for i, id := range append(append([]string{}, alive...), down) {
		p.Endpoints = append(p.Endpoints, nativeEndpoint(id, "probe"+string(rune('a'+i))))
	}
	if err := st.Replace(p); err != nil {
		t.Fatalf("seed health profile: %v", err)
	}
	m := health.NewMonitor(nil, st, nil, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.Run(ctx) // ticks once, then sees the cancelled context
	return m
}

func egressTable(t *testing.T, plan *pbr.Plan, tag string) int {
	t.Helper()
	for _, e := range plan.Egresses {
		if e.Tag == tag {
			return e.Table
		}
	}
	t.Fatalf("the plan has no egress %q: %+v", tag, plan.Egresses)
	return 0
}

// QA-091. The loop elected tables from the SAVED profile, recompiled on every tick, while the router
// holds the tables of the APPLIED plan. A pending edit that adds a list through an endpoint sorting
// before the group renumbers the group into the table the applied plan gave another egress: the tick
// then wrote the group's member into that egress's table (its list left through the wrong tunnel), and
// the group's real table was watched by nobody, so when its member died the list fell through to the
// provider until the next Apply.
func TestListFailoverElectsIntoTheAppliedTables(t *testing.T) {
	applied := failoverProfile()
	saved := failoverProfile()
	saved.Endpoints = append(saved.Endpoints, nativeEndpoint("de", "nwg7"))
	saved.RoutingLists = append(saved.RoutingLists, model.RoutingList{ID: "x", Name: "X", Outbound: "de",
		Enabled: true, Manual: []string{"192.0.2.0/24"}})

	tables := &fakeTables{}
	s, plan := appliedFailoverServer(t, applied, saved, tables)
	grpTable, nlTable := egressTable(t, plan, "grp"), egressTable(t, plan, "nl")
	pending, _, err := pbr.Compile(&saved, s.pbrCompileOptions(*s.cfg))
	if err != nil {
		t.Fatal(err)
	}
	if egressTable(t, pending, "grp") != nlTable {
		t.Fatalf("the fixture no longer renumbers: the saved profile must give the group the applied table of nl")
	}
	tables.show = map[bool]string{false: "default dev nwg3 scope link table " + itoa(grpTable) +
		"\ndefault dev awg0 scope link table " + itoa(nlTable) + "\n"}

	// m1 alive: the group's applied table already holds it, and nl's table is nobody's to touch.
	s.monitor = healthWith(t, []string{"m1", "m2"}, "spare")
	s.listFailoverTick(context.Background())
	if len(tables.writes) != 0 {
		t.Fatalf("with the elected member in place the tick wrote %v (table %d is nl's)", tables.writes, nlTable)
	}

	// m1 down: the group's APPLIED table moves to m2.
	s.monitor = healthWith(t, []string{"m2"}, "m1")
	s.listFailoverTick(context.Background())
	if want := []string{"v4 nwg5 " + itoa(grpTable)}; !reflect.DeepEqual(tables.writes, want) {
		t.Fatalf("writes %v, want %v", tables.writes, want)
	}
}

// QA-091. An Apply renumbers the tables; a tick that read the old plan and wrote after the new one was
// installed would put a member into another egress's table. The tick steps aside like the reconcile
// loop.
func TestListFailoverStepsAsideWhileApplyRuns(t *testing.T) {
	for name, setup := range map[string]func(*Server){
		"an Apply in progress": func(s *Server) { s.applyInProgress.Store(true) },
		"Apply holds the lock": func(s *Server) { s.applyMu.Lock() },
	} {
		tables := &fakeTables{}
		s, plan := appliedFailoverServer(t, failoverProfile(), failoverProfile(), tables)
		tables.show = map[bool]string{false: "default dev nwg3 scope link table " + itoa(egressTable(t, plan, "grp")) + "\n"}
		s.monitor = healthWith(t, []string{"m2"}, "m1")
		setup(s)
		s.listFailoverTick(context.Background())
		if len(tables.writes) != 0 {
			t.Errorf("%s: the tick wrote %v", name, tables.writes)
		}
	}
}

// QA-092. Apply seeds a v6 default next to the v4 one in every table of a plan that marks v6, but the
// loop moved only v4: when the elected member died, marked v6 stayed on the dead tunnel and, once its
// device went down and the kernel flushed the route, fell through to the main v6 table - the WAN. When
// the member came back nothing re-seeded the group's v6 table either, so v6 leaked until the next Apply.
func TestListFailoverRepointsIPv6Too(t *testing.T) {
	profile := failoverProfile("2001:db8:4e8::/48")
	newServer := func(t *testing.T, tables *fakeTables) (*Server, string) {
		t.Helper()
		s, plan := appliedFailoverServer(t, profile, profile, tables)
		if !plan.HasV6() {
			t.Fatal("the fixture's plan must mark v6")
		}
		return s, itoa(egressTable(t, plan, "grp"))
	}

	t.Run("the elected member dies", func(t *testing.T) {
		tables := &fakeTables{}
		s, table := newServer(t, tables)
		tables.show = map[bool]string{
			false: "default dev nwg3 scope link table " + table + "\n",
			true:  "default dev nwg3 table " + table + " metric 1024 pref medium\n",
		}
		s.monitor = healthWith(t, []string{"m2"}, "m1")
		s.listFailoverTick(context.Background())
		if want := []string{"v4 nwg5 " + table, "v6 nwg5 " + table}; !reflect.DeepEqual(tables.writes, want) {
			t.Fatalf("writes %v, want %v", tables.writes, want)
		}
	})

	t.Run("it comes back to a flushed v6 table", func(t *testing.T) {
		tables := &fakeTables{}
		s, table := newServer(t, tables)
		tables.show = map[bool]string{false: "default dev nwg5 scope link table " + table + "\n", true: ""}
		s.monitor = healthWith(t, []string{"m1", "m2"}, "spare")
		s.listFailoverTick(context.Background())
		if want := []string{"v4 nwg3 " + table, "v6 nwg3 " + table}; !reflect.DeepEqual(tables.writes, want) {
			t.Fatalf("writes %v, want %v", tables.writes, want)
		}
	})

	t.Run("an unreadable v6 family is not an empty one", func(t *testing.T) {
		tables := &fakeTables{}
		s, table := newServer(t, tables)
		tables.show = map[bool]string{false: "default dev nwg3 scope link table " + table + "\n"}
		tables.readErr = map[bool]error{true: errString("ip -6: not supported")}
		s.monitor = healthWith(t, []string{"m2"}, "m1")
		s.listFailoverTick(context.Background())
		if want := []string{"v4 nwg5 " + table}; !reflect.DeepEqual(tables.writes, want) {
			t.Fatalf("writes %v, want %v", tables.writes, want)
		}
	})

	t.Run("a v4-only plan writes no v6", func(t *testing.T) {
		tables := &fakeTables{}
		s, plan := appliedFailoverServer(t, failoverProfile(), failoverProfile(), tables)
		table := itoa(egressTable(t, plan, "grp"))
		tables.show = map[bool]string{false: "default dev nwg3 scope link table " + table + "\n", true: ""}
		s.monitor = healthWith(t, []string{"m2"}, "m1")
		s.listFailoverTick(context.Background())
		if want := []string{"v4 nwg5 " + table}; !reflect.DeepEqual(tables.writes, want) {
			t.Fatalf("writes %v, want %v", tables.writes, want)
		}
	})
}

// QA-093. self_switching_groups was built from the loop's ELECTION, so a group whose members were all
// down (or not measured yet) dropped out of it exactly during the outage, and the Failover card said the
// group does not switch by itself while the daemon stood ready to re-point it the moment a member came
// back. It is a capability: the group's table in the applied plan and a member the kernel can route to.
func TestSelfSwitchingGroupsIgnoresHealth(t *testing.T) {
	tables := &fakeTables{}
	s, _ := appliedFailoverServer(t, failoverProfile(), failoverProfile(), tables)

	s.monitor = healthWith(t, []string{"m1", "m2"}, "spare")
	if got := s.selfSwitchingGroups(); !reflect.DeepEqual(got, []string{"grp"}) {
		t.Fatalf("members alive: %v", got)
	}
	s.monitor = health.NewMonitor(nil, s.store, nil, false) // nothing measured: no member is alive
	if got := s.selfSwitchingGroups(); !reflect.DeepEqual(got, []string{"grp"}) {
		t.Fatalf("no member alive: %v", got)
	}
	s.applyState.rec.RoutingOff = &routingOffRecord{At: 1, By: routingByPanel}
	if got := s.selfSwitchingGroups(); len(got) != 0 {
		t.Fatalf("routing off, the loop switches nothing, yet: %v", got)
	}
	s.applyState.rec.RoutingOff = nil

	// A group whose members the kernel cannot route to has nothing the loop could elect.
	proxyOnly := failoverProfile()
	proxyOnly.Endpoints = []model.Endpoint{
		{ID: "m1", Enabled: true, Engine: model.EngineSingBox, Protocol: "socks", Server: "198.51.100.7", Port: 1080},
		{ID: "m2", Enabled: true, Engine: model.EngineSingBox, Protocol: "socks", Server: "198.51.100.8", Port: 1080},
		nativeEndpoint("nl", "awg0"),
	}
	s2, _ := appliedFailoverServer(t, proxyOnly, proxyOnly, &fakeTables{})
	if got := s2.selfSwitchingGroups(); len(got) != 0 {
		t.Fatalf("a group with no kernel member was reported: %v", got)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
