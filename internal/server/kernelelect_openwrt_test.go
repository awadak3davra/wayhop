package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/failover"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// The OpenWrt half of the kernel elector (owrt-1122). The router these shapes come from is an
// reference router on OpenWrt 25.12: adopted AmneziaWG links awg0/awg1/awg2, an engine-carried exit beside
// them, the nft plane `inet wayhop_pbr`, and sing-box's auto_redirect over everything else.

// refrouterProfile is that router's shape: a urltest group over three adopted links and one exit that
// lives only inside the proxy core, behind two address lists.
func refrouterProfile() model.Profile {
	return model.Profile{
		Endpoints: []model.Endpoint{nativeEndpoint("nl", "awg0"), nativeEndpoint("ru", "awg1"), nativeEndpoint("fi", "awg2"),
			{ID: "gw", Name: "keenetic-gw", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoSOCKS, Server: "198.51.100.7", Port: 1080}},
		Groups: []model.Group{{ID: "grp-auto", Name: "Auto", Type: model.GroupURLTest, Members: []string{"nl", "ru", "fi", "gw"}}},
		RoutingLists: []model.RoutingList{
			{ID: "tg-calls", Name: "Telegram calls", Outbound: "grp-auto", Enabled: true, Manual: []string{"149.154.160.0/20", "91.108.4.0/22"}},
			{ID: "list-heavy", Name: "RU heavy", Outbound: "ru", Enabled: true, Manual: []string{"5.45.192.0/18"}},
		},
	}
}

// openwrtTableDump is `ip -4 route show table all` on that router: WayHop's tables, then the main
// table as the router prints it (static default with a source, the tunnels' connected routes, the
// core's TUN), then the local table. Only the first kind is the elector's.
func openwrtTableDump(defaults map[int]string) string {
	var b strings.Builder
	for table, iface := range defaults {
		b.WriteString("default dev " + iface + " table " + itoa(table) + " scope link \n")
	}
	b.WriteString("default via 192.168.50.254 dev wan proto static src 192.168.50.70 \n" +
		"10.77.0.0/24 dev awg1 scope link \n" +
		"198.51.100.14 via 192.168.50.254 dev wan proto static \n" +
		"172.31.3.0/30 dev tun0 proto kernel scope link src 172.31.3.1 \n" +
		"192.168.1.0/24 dev wan proto kernel scope link src 192.168.50.70 \n" +
		"192.168.2.0/24 dev br-lan proto kernel scope link src 192.168.2.1 \n" +
		"default dev tun0 table 2022 \n" +
		"local 10.77.0.10 dev awg1 table local proto kernel scope host src 10.77.0.10 \n" +
		"broadcast 192.168.2.255 dev br-lan table local proto kernel scope link src 192.168.2.1 \n")
	return b.String()
}

// openwrtServer is a router whose applied plane is OpenWrt's (no ipset artifact), compiled the way
// this daemon compiles it.
func openwrtServer(t *testing.T, profile model.Profile, tables *fakeTables) (*Server, *pbr.Plan) {
	t.Helper()
	s, plan := appliedFailoverServer(t, profile, profile, tables)
	s.platformOf = func() platform.Platform { return platform.OpenWrt }
	if s.applyState.rec.Committed.Materialization.Kernel.Ipset != nil {
		t.Fatal("setup: the plane is KeeneticOS's")
	}
	return s, plan
}

// The live fault on OpenWrt: every group type was elected "first member the monitor calls alive", so a
// urltest group stayed on its first tunnel while that answered its own ping. The elector now runs on
// the nft plane too: the group's table follows the fastest member that completes a handshake to the
// group's target through its own link, the engine-carried member is never a candidate for the table,
// and the Failover page names the member the table holds.
func TestOpenWrtURLTestGroupElectsTheFastestWorkingLink(t *testing.T) {
	profile := refrouterProfile()
	tables := &fakeTables{}
	s, plan := openwrtServer(t, profile, tables)
	table := egressTable(t, plan, "grp-auto")
	solo := egressTable(t, plan, "ru")
	tables.show = map[bool]string{false: openwrtTableDump(map[int]string{table: "awg0", solo: "awg1"})}
	tables.probes = handshakes("cp.cloudflare.com:80", map[string]int{"awg0": -1, "awg1": 95, "awg2": 38})
	s.monitor = healthWith(t, []string{"nl", "ru", "fi", "gw"}, "spare")

	units := kernelUnitsFrom(plan, &profile, kernelIfaceByEndpoint(&profile, s.appliedKernelDevices()))
	if len(units) != 1 || units[0].Policy != failover.PolicyLatency {
		t.Fatalf("units %+v", units)
	}
	if units[0].Accepts("tun0") || units[0].Accepts("wan") || units[0].Iface["gw"] != "" {
		t.Fatalf("a link that is no member's is accepted, or the core's exit got a link: %+v", units[0].Iface)
	}
	for _, link := range []string{"awg0", "awg1", "awg2"} {
		if !units[0].Accepts(link) {
			t.Fatalf("%s is a member's link and must verify", link)
		}
	}
	s.listFailoverTick(context.Background())
	if want := []string{"v4 awg2 " + itoa(table)}; !reflect.DeepEqual(tables.writes, want) {
		t.Fatalf("writes %v, want %v (the single-endpoint table and tun0's are not the elector's)", tables.writes, want)
	}

	rec := httptest.NewRecorder()
	s.handleFailoverState(rec, httptest.NewRequest(http.MethodGet, "/api/failover/state", nil))
	var body struct {
		Elected map[string]string `json:"elected"`
		Self    []string          `json:"self_switching_groups"`
		Members map[string][]string
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Elected["grp-auto"] != "fi" || !reflect.DeepEqual(body.Self, []string{"grp-auto"}) {
		t.Fatalf("CURRENT must be the member table %d holds (fi): %+v", table, body)
	}
}

// A fastest list gets its own mark and table on the nft plane, and the elector points that table at
// the fastest of the list's kernel links by the list's own targets. The exit inside the proxy core is
// shown as having no link and takes no part.
func TestOpenWrtFastestListElectsIntoItsOwnTable(t *testing.T) {
	profile := refrouterProfile()
	profile.RoutingLists[0].Outbound = "nl"
	profile.RoutingLists[0].Candidates = []string{"nl", "ru", "gw"}
	profile.RoutingLists[0].Fastest = &model.FastestPolicy{Enabled: true, Targets: []string{"149.154.167.51:443"}}
	tables := &fakeTables{}
	s, plan := openwrtServer(t, profile, tables)
	list := egressTable(t, plan, model.ListEgressTag("tg-calls"))
	solo := egressTable(t, plan, "ru")
	if list == solo {
		t.Fatal("the list shares its second tunnel's table")
	}
	if !s.fastestRuns("tg-calls") {
		t.Fatal("the applied nft plan gave the list a table, so the router runs its choice")
	}
	tables.show = map[bool]string{false: openwrtTableDump(map[int]string{list: "awg0", solo: "awg1"})}
	tables.probes = handshakes("149.154.167.51:443", map[string]int{"awg0": 140, "awg1": 60})
	s.monitor = healthWith(t, []string{"nl", "ru", "fi", "gw"}, "spare")
	s.listFailoverTick(context.Background())
	if want := []string{"v4 awg1 " + itoa(list)}; !reflect.DeepEqual(tables.writes, want) {
		t.Fatalf("writes %v, want %v", tables.writes, want)
	}
	st := s.fastestStates()["tg-calls"]
	if st.Current != "ru" || !reflect.DeepEqual(st.Targets, []string{"149.154.167.51:443"}) {
		t.Fatalf("state %+v", st)
	}
	sum := s.fastestSummaryOf(&profile, profile.RoutingLists[0], st, true)
	noLink := map[string]bool{}
	for _, c := range sum.Candidates {
		noLink[c.ID] = c.NoLink
	}
	if noLink["nl"] || noLink["ru"] || !noLink["gw"] {
		t.Fatalf("no_link %v: only the core's exit has none", noLink)
	}
}

// The elector's handshakes carry the proxy core's bypass mark on OpenWrt, and only there: its
// auto_redirect sends every unmarked TCP connection the router opens into the core.
func TestUnitProbeMarkIsTheEngineBypassOnOpenWrtOnly(t *testing.T) {
	profile := refrouterProfile()
	s, _ := openwrtServer(t, profile, &fakeTables{})
	if got := s.unitProbeMark(); got != 0x2024 {
		t.Fatalf("OpenWrt probe mark %#x, want 0x2024 (sing-tun's auto_redirect_output_mark)", got)
	}
	keeneticPlane(s)
	if got := s.unitProbeMark(); got != 0 {
		t.Fatalf("KeeneticOS probe mark %#x: its probes must stay unmarked", got)
	}
	s.applyState.rec.Committed.Materialization.Kernel = executionKernelArtifactV1{Action: ExecutionEnsureAbsent}
	if got := s.unitProbeMark(); got != 0 {
		t.Fatalf("no plane, mark %#x", got)
	}
}

// A reinstall of the plane (an Apply, or the reconcile loop after a fw4 reload) seeds every table with
// `ip route replace default dev <first candidate>`. For a table the elector re-pointed, that seed is
// skipped while the table still holds the elected link; everything else of the program runs.
func TestOpenWrtReinstallKeepsTheElectedMember(t *testing.T) {
	profile := refrouterProfile()
	tables := &fakeTables{}
	s, plan := openwrtServer(t, profile, tables)
	table := egressTable(t, plan, "grp-auto")
	solo := egressTable(t, plan, "ru")
	tables.show = map[bool]string{false: openwrtTableDump(map[int]string{table: "awg0", solo: "awg1"})}
	tables.probes = handshakes("cp.cloudflare.com:80", map[string]int{"awg0": -1, "awg1": 95, "awg2": 38})
	s.monitor = healthWith(t, []string{"nl", "ru", "fi", "gw"}, "spare")
	if keep := s.electedRouteKeeper(context.Background(), plan); keep != nil {
		t.Fatal("before the elector chose anything every seed must run")
	}
	s.listFailoverTick(context.Background())
	tables.show = map[bool]string{false: openwrtTableDump(map[int]string{table: "awg2", solo: "awg1"})}
	s.listFailoverTick(context.Background()) // the elector reads what it wrote

	nftTool, ipTool := executionTestKernelTools()
	artifact := executionKernelArtifactV1{
		Action: ExecutionEnsurePresent, Plan: plan, NFTTool: nftTool, IPTool: ipTool,
		Nft: []byte(plan.RenderNft()), IP: plan.RenderIP(pbr.Options{}),
		Offload: []byte(plan.RenderOffload()), Teardown: plan.RenderTeardown(pbr.Options{}),
	}
	seedGroup := "ip route replace default dev awg0 table " + itoa(table)
	seedSolo := "ip route replace default dev awg1 table " + itoa(solo)
	install := func() []string {
		runner := &exactKernelRecordRunner{}
		adapter, err := newExactKernelAdapter(runner)
		if err != nil {
			t.Fatal(err)
		}
		adapter.keep = s.electedRouteKeeper(context.Background(), plan)
		if err := adapter.apply(context.Background(), artifact); err != nil {
			t.Fatalf("apply: %v", err)
		}
		return runner.calls
	}
	has := func(calls []string, want string) bool {
		for _, c := range calls {
			if c == want {
				return true
			}
		}
		return false
	}
	calls := install()
	if has(calls, seedGroup) {
		t.Fatalf("the reinstall put the compile-time pin back over the elected awg2:\n%s", strings.Join(calls, "\n"))
	}
	if !has(calls, seedSolo) || !has(calls, "nft -f -") {
		t.Fatalf("the rest of the program must run:\n%s", strings.Join(calls, "\n"))
	}
	rule := false
	for _, c := range calls {
		rule = rule || strings.HasPrefix(c, "ip rule add fwmark ") && strings.HasSuffix(c, " table "+itoa(table)+" priority 150")
	}
	if !rule {
		t.Fatalf("the group's fwmark rule is part of every install:\n%s", strings.Join(calls, "\n"))
	}

	// The table lost the elected route (the tunnel went down and the kernel flushed it), or holds a
	// link nobody elected: the plan's seed runs.
	for name, dump := range map[string]map[int]string{"emptied": {solo: "awg1"}, "foreign": {table: "wan", solo: "awg1"}} {
		tables.show = map[bool]string{false: openwrtTableDump(dump)}
		if !has(install(), seedGroup) {
			t.Errorf("%s table: the seed must run", name)
		}
	}
	// Unreadable tables are not "as the elector left them".
	tables.readErr = map[bool]error{false: errString("ip: timed out")}
	if !has(install(), seedGroup) {
		t.Error("unreadable tables: the seed must run")
	}
	tables.readErr = nil
	// A plan that gives the table to another owner keeps nothing.
	other := *plan
	other.Egresses = append([]pbr.Egress(nil), plan.Egresses...)
	for i := range other.Egresses {
		if other.Egresses[i].Tag == "grp-auto" {
			other.Egresses[i].Tag = "grp-other"
		}
	}
	if s.electedRouteKeeper(context.Background(), &other) != nil {
		t.Error("the table belongs to another egress in the new plan: nothing to keep")
	}
}

// The keeper's two readers, on the shapes iproute2 prints and RenderIP emits.
func TestTableDefaultCommandAndV6Refusal(t *testing.T) {
	for cmd, want := range map[string][3]any{
		"ip route replace default dev awg1 table 152":                     {false, "awg1", 152},
		"ip -6 route replace default dev wr_95bb4df7 table 151":           {true, "wr_95bb4df7", 151},
		"ip route replace blackhole default metric 1000 table 152":        nil3,
		"ip rule add fwmark 0x00020000/0x00ff0000 table 151 priority 150": nil3,
		"ip route del blackhole default metric 1000 table 151":            nil3,
		"ip route replace default dev awg1 table main":                    nil3,
	} {
		v6, iface, table, ok := tableDefaultCommand(cmd)
		if want == nil3 {
			if ok {
				t.Errorf("%q read as a table seed", cmd)
			}
			continue
		}
		if !ok || v6 != want[0] || iface != want[1] || table != want[2] {
			t.Errorf("%q -> %v %q %d %v", cmd, v6, iface, table, ok)
		}
	}
	dump := "default dev awg1 table 151 metric 1024 pref medium\n" +
		"unreachable default dev lo table 152 metric 1024 error -113 pref medium\n" +
		"blackhole default dev lo table 152 metric 2048 error -22 pref medium\n" +
		"fe80::/64 dev br-lan proto kernel metric 256 pref medium\n"
	if !tableRefusesV6(dump, 152) || tableRefusesV6(dump, 151) || tableRefusesV6(dump, 15) {
		t.Fatal("the unreachable default is table 152's alone; the kill switch's blackhole is not a refusal")
	}
}

var nil3 = [3]any{nil, nil, nil}

// IPv6 follows the kept IPv4 member: its own seed is skipped while the v6 table holds the same link,
// or the refusal the elector installs for a link without IPv6. A list the elector emptied because
// every tunnel is down stays empty through a reinstall.
func TestOpenWrtReinstallKeepsIPv6AndAnAllDownClear(t *testing.T) {
	profile := refrouterProfile()
	profile.RoutingLists[0].Manual = append(profile.RoutingLists[0].Manual, "2001:67c:4e8::/48")
	profile.RoutingLists[0].Outbound = "nl"
	profile.RoutingLists[0].Candidates = []string{"nl", "ru"}
	profile.RoutingLists[0].Fastest = &model.FastestPolicy{Enabled: true, Targets: []string{"149.154.167.51:443"}, OnAllDown: model.OnAllDownBlock}
	// External links are v4-only by posture; WayHop's own AmneziaWG carries v6, so use two of those.
	for i, id := range []string{"nl", "ru"} {
		e := executionAWGEndpoint(id)
		e.Params["local_address"] = []string{"10.8.0.2/32", "fd00:8::2/128"}
		profile.Endpoints[i] = e
	}
	tables := &fakeTables{noV6: map[string]bool{}}
	s, plan := openwrtServer(t, profile, tables)
	if !plan.HasV6() {
		t.Fatal("setup: the plan must mark IPv6")
	}
	ifaceOf := kernelIfaceByEndpoint(&profile, nil)
	nl, ru := ifaceOf["nl"], ifaceOf["ru"]
	list := egressTable(t, plan, model.ListEgressTag("tg-calls"))
	for _, eg := range plan.Egresses {
		if eg.Table == list && !eg.FailClosed {
			t.Fatal("on_all_down block: the list's table must carry the blackhole")
		}
	}
	v6dump := func(iface string) string {
		s := "blackhole default dev lo table " + itoa(list) + " metric 2048 error -22 pref medium\n"
		if iface != "" {
			s = "default dev " + iface + " table " + itoa(list) + " metric 1024 pref medium\n" + s
		}
		return s
	}
	tables.show = map[bool]string{false: openwrtTableDump(map[int]string{list: nl}), true: v6dump(nl)}
	tables.probes = handshakes("149.154.167.51:443", map[string]int{nl: 140, ru: 60})
	s.monitor = healthWith(t, []string{"nl", "ru", "fi", "gw"}, "spare")
	s.listFailoverTick(context.Background())
	if want := []string{"v4 " + ru + " " + itoa(list), "v6 " + ru + " " + itoa(list)}; !reflect.DeepEqual(tables.writes, want) {
		t.Fatalf("writes %v, want both families on %s", tables.writes, ru)
	}
	tables.show = map[bool]string{false: openwrtTableDump(map[int]string{list: ru}), true: v6dump(ru)}
	s.requestFastestProbe("tg-calls")
	s.listFailoverTick(context.Background())
	keep := s.electedRouteKeeper(context.Background(), plan)
	if keep == nil {
		t.Fatal("the elector holds the list's table")
	}
	for _, cmd := range []string{"ip route replace default dev " + nl + " table " + itoa(list), "ip -6 route replace default dev " + nl + " table " + itoa(list)} {
		if !keep(cmd) {
			t.Errorf("%q would undo the election", cmd)
		}
	}
	if keep("ip route replace blackhole default metric 1000 table "+itoa(list)) || keep("ip -6 route replace blackhole default metric 2048 table "+itoa(list)) {
		t.Fatal("the kill switch's blackhole is installed on every reinstall, never skipped")
	}

	// Every tunnel down, "block": the elector empties the table; the blackhole stays and drops.
	var clears []string
	s.routeTables.clear = func(_ context.Context, v6 bool, iface string, table int) error {
		clears = append(clears, iface+" "+itoa(table))
		return nil
	}
	for i := 0; i < 2; i++ { // dead after two cycles without one success
		tables.probes = handshakes("149.154.167.51:443", map[string]int{nl: -1, ru: -1})
		tables.probes[failover.ProbeKey{Iface: failover.ReferenceIface, Target: "149.154.167.51:443"}] = failover.ProbeResult{Ran: true, Attempts: 3, Successes: 3, MedianMs: 20}
		s.requestFastestProbe("tg-calls")
		s.listFailoverTick(context.Background())
	}
	if len(clears) == 0 {
		t.Fatalf("all tunnels dead, on_all_down block: the table must be emptied (writes %v)", tables.writes)
	}
	tables.show = map[bool]string{false: openwrtTableDump(map[int]string{}), true: v6dump("")}
	s.listFailoverTick(context.Background())
	keep = s.electedRouteKeeper(context.Background(), plan)
	if keep == nil || !keep("ip route replace default dev "+nl+" table "+itoa(list)) || !keep("ip -6 route replace default dev "+nl+" table "+itoa(list)) {
		t.Fatal("a reinstall must not seed a dead tunnel back into a table emptied for an outage")
	}
}

// What the panel and the review are told on OpenWrt: the option runs where the kernel plane exists,
// between tunnels with a link of their own, over the list's addresses.
func TestOpenWrtFastestSupportAndFindings(t *testing.T) {
	profile := refrouterProfile()
	profile.RoutingLists[0].Outbound = "nl"
	profile.RoutingLists[0].Candidates = []string{"nl", "ru", "gw"}
	profile.RoutingLists[0].Manual = append(profile.RoutingLists[0].Manual, "telegram.org")
	profile.RoutingLists[0].Fastest = &model.FastestPolicy{Enabled: true}
	profile.RoutingLists = append(profile.RoutingLists,
		model.RoutingList{ID: "core-only", Name: "Core only", Enabled: true, Outbound: "nl", Candidates: []string{"nl", "gw"},
			Manual: []string{"203.0.113.0/24"}, Fastest: &model.FastestPolicy{Enabled: true}},
		model.RoutingList{ID: "names", Name: "Names", Enabled: true, Outbound: "nl", Candidates: []string{"nl", "ru"},
			Manual: []string{"instagram.com"}, Fastest: &model.FastestPolicy{Enabled: true}})
	s, _ := openwrtServer(t, profile, &fakeTables{})
	if err := s.store.Replace(profile); err != nil {
		t.Fatal(err)
	}
	for mode, want := range map[string]bool{"hybrid": true, "fast": true, "tun": false, "mixed": false} {
		s.cfg.RoutingMode = mode
		ok, why := s.fastestSupported()
		if ok != want || (!ok && !strings.Contains(why, "hybrid or fast")) {
			t.Errorf("mode %s: supported=%v (%q), want %v", mode, ok, why, want)
		}
	}
	s.cfg.RoutingMode = "hybrid"
	type key struct{ id, item string }
	got := map[key]PlanFinding{}
	for _, f := range s.fastestFindings(&profile) {
		got[key{f.ID, f.Item}] = f
	}
	if f, ok := got[key{"routing_list.fastest_no_link", "tg-calls"}]; !ok || f.Effective != "fastest of nl, ru" || !strings.Contains(f.Detail, "keenetic-gw") {
		t.Errorf("tg-calls: the core's exit must be named as left out: %+v", f)
	}
	if f, ok := got[key{"routing_list.fastest_no_link", "core-only"}]; !ok || f.Effective != "first tunnel" || f.Remedy == "" {
		t.Errorf("core-only: one kernel link is nothing to choose between: %+v", f)
	}
	if f, ok := got[key{"routing_list.fastest_names", "tg-calls"}]; !ok || f.Effective != "addresses by the fastest tunnel, names by nl" {
		t.Errorf("tg-calls: names keep the first tunnel on the nft plane: %+v", f)
	}
	if f, ok := got[key{"routing_list.fastest_names", "names"}]; !ok || !strings.HasPrefix(f.Effective, "first tunnel") {
		t.Errorf("names: a list of names only is not steered by the nft plane: %+v", f)
	}
	if _, ok := got[key{"routing_list.fastest_names", "core-only"}]; ok {
		t.Error("core-only does not run at all: one finding says so, not two")
	}
	if _, ok := got[key{"routing_list.fastest_platform", "tg-calls"}]; ok {
		t.Error("hybrid mode on OpenWrt runs the option")
	}

	rec := httptest.NewRecorder()
	s.handleFastestLists(rec, httptest.NewRequest(http.MethodGet, "/api/lists/fastest", nil))
	var body struct {
		Supported bool     `json:"supported"`
		Note      string   `json:"note"`
		Linked    []string `json:"linked"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Supported || !strings.Contains(body.Note, "Names in the list") || !reflect.DeepEqual(body.Linked, []string{"nl", "ru", "fi"}) {
		t.Fatalf("GET /api/lists/fastest: %+v", body)
	}
	// KeeneticOS carries names in the list's own set: no note, no names finding.
	s.platformOf = func() platform.Platform { return platform.Keenetic }
	if s.fastestNamesNote() != "" {
		t.Fatal("KeeneticOS steers names too")
	}
	for _, f := range s.fastestFindings(&profile) {
		if f.ID == "routing_list.fastest_names" {
			t.Fatalf("KeeneticOS: %+v", f)
		}
	}
}
