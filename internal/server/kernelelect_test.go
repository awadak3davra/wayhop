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
)

// keeneticPlane marks the applied kernel plane as KeeneticOS's (its ipset artifact).
func keeneticPlane(s *Server) {
	s.applyState.rec.Committed.Materialization.Kernel.Ipset = &executionKernelIpsetArtifactV1{}
}

// awg31Profile is the router's shape: a urltest group whose FIRST member is a server on WayHop's
// userspace AmneziaWG (awg1), then three NDM WireGuard tunnels, behind the Telegram and Instagram lists.
func awg31Profile() model.Profile {
	return model.Profile{
		Endpoints: []model.Endpoint{nativeEndpoint("ca", "awg1"), nativeEndpoint("nl1", "nwg1"),
			nativeEndpoint("nl4", "nwg4"), nativeEndpoint("nl5", "nwg5")},
		Groups: []model.Group{{ID: "grp-awg31", Name: "AWG31", Type: model.GroupURLTest,
			Members: []string{"ca", "nl1", "nl4", "nl5"}}},
		RoutingLists: []model.RoutingList{
			{ID: "tg", Name: "Telegram", Outbound: "grp-awg31", Enabled: true, Manual: []string{"149.154.160.0/20", "91.108.4.0/22"}},
			{ID: "ig", Name: "Instagram", Outbound: "grp-awg31", Enabled: true, Manual: []string{"157.240.0.0/16"}},
		},
	}
}

// keeneticTableDump is `ip -4 route show table all` as the router prints it: the owned tables next to
// the main and local tables, which the parser must step over.
func keeneticTableDump(groupTable string) string {
	return "default dev awg1 table " + groupTable + " scope link \n" +
		"default via 192.168.50.1 dev eth3 \n" +
		"10.0.1.0/24 dev nwg1 proto kernel scope link src 10.0.1.2 \n" +
		"192.168.1.0/24 dev eth3 proto kernel scope link src 192.168.1.33 \n" +
		"local 10.0.1.2 dev nwg1 table local proto kernel scope host src 10.0.1.2 \n" +
		"broadcast 192.168.1.255 dev eth3 table local proto kernel scope link src 192.168.1.33 \n"
}

func handshakes(target string, ms map[string]int) map[failover.ProbeKey]failover.ProbeResult {
	out := map[failover.ProbeKey]failover.ProbeResult{}
	for iface, v := range ms {
		r := failover.ProbeResult{Ran: true, Attempts: 3}
		if v >= 0 {
			r.Successes, r.MedianMs = 3, v
		}
		out[failover.ProbeKey{Iface: iface, Target: target}] = r
	}
	return out
}

// End to end through the tick: Apply pinned the urltest group's table to the first member, which answers
// its own ping target so the monitor calls every member alive, but a handshake to the group's target
// through awg1 fails. The tick must re-point the table at the fastest member that completed one, and
// the Failover page must name that member, not the core's or the plan's.
func TestListFailoverURLTestElectsTheFastestWorkingMember(t *testing.T) {
	profile := awg31Profile()
	tables := &fakeTables{}
	s, plan := appliedFailoverServer(t, profile, profile, tables)
	keeneticPlane(s)
	table := egressTable(t, plan, "grp-awg31")
	tables.show = map[bool]string{false: keeneticTableDump(itoa(table))}
	tables.probes = handshakes("cp.cloudflare.com:80", map[string]int{"awg1": -1, "nwg1": 95, "nwg4": 38, "nwg5": 61})
	s.monitor = healthWith(t, []string{"ca", "nl1", "nl4", "nl5"}, "spare")

	units := kernelUnitsFrom(plan, &profile, kernelIfaceByEndpoint(&profile, s.appliedKernelDevices()))
	if len(units) != 1 || units[0].Policy != failover.PolicyLatency || !reflect.DeepEqual(units[0].Targets, []string{"cp.cloudflare.com:80"}) {
		t.Fatalf("units %+v", units)
	}
	s.listFailoverTick(context.Background())
	if want := []string{"v4 nwg4 " + itoa(table)}; !reflect.DeepEqual(tables.writes, want) {
		t.Fatalf("writes %v, want %v", tables.writes, want)
	}

	rec := httptest.NewRecorder()
	s.handleFailoverState(rec, httptest.NewRequest(http.MethodGet, "/api/failover/state", nil))
	var body struct {
		Elected map[string]string `json:"elected"`
		Units   []struct {
			ID      string `json:"id"`
			Current string `json:"current"`
			Events  []struct {
				Reason string `json:"reason"`
				From   string `json:"from"`
			} `json:"events"`
		} `json:"kernel_units"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Elected["grp-awg31"] != "nl4" {
		t.Fatalf("the page names %q, the kernel uses nl4", body.Elected["grp-awg31"])
	}
	if len(body.Units) != 1 || body.Units[0].Current != "nl4" || len(body.Units[0].Events) != 1 ||
		body.Units[0].Events[0].Reason != failover.ReasonDead || body.Units[0].Events[0].From != "ca" {
		t.Fatalf("kernel_units %+v", body.Units)
	}

	// A member that keeps answering faster within the deadband does not move the table.
	tables.show = map[bool]string{false: strings.Replace(keeneticTableDump(itoa(table)), "dev awg1", "dev nwg4", 1)}
	tables.probes = handshakes("cp.cloudflare.com:80", map[string]int{"awg1": -1, "nwg1": 95, "nwg4": 38, "nwg5": 20})
	s.listFailoverTick(context.Background())
	if len(tables.writes) != 1 {
		t.Fatalf("a 18 ms gain moved the table: %v", tables.writes)
	}
}

// Before the elector has read a table the page does not fall back to the core's pick for a group the
// kernel steers: unknown is not "the core's member". Either kernel plane is the elector's; a router
// with no applied plane is nobody's.
func TestFailoverStateDropsTheCorePickForAKernelGroup(t *testing.T) {
	profile := awg31Profile()
	s, _ := appliedFailoverServer(t, profile, profile, &fakeTables{})
	for _, plane := range []string{"OpenWrt nft", "KeeneticOS ipset"} {
		if plane == "KeeneticOS ipset" {
			keeneticPlane(s)
		}
		elected, owned, _ := s.kernelElected()
		if !owned["grp-awg31"] || elected["grp-awg31"] != "" {
			t.Fatalf("%s: owned %v elected %v", plane, owned, elected)
		}
	}
	s.applyState.rec.Committed.Materialization.Kernel = executionKernelArtifactV1{Action: ExecutionEnsureAbsent}
	if _, owned, _ := s.kernelElected(); len(owned) != 0 {
		t.Fatalf("no kernel plane applied, yet the elector claims %v", owned)
	}
}

func TestGroupProbeTarget(t *testing.T) {
	for in, want := range map[string]string{
		"":                                      "cp.cloudflare.com:80",
		"http://cp.cloudflare.com/generate_204": "cp.cloudflare.com:80",
		"https://www.google.com/generate_204":   "www.google.com:443",
		"8.8.8.8":                               "8.8.8.8:443",
		"http://1.1.1.1:8080/x":                 "1.1.1.1:8080",
	} {
		g := model.Group{}
		if in != "" {
			g.Test = &model.Health{URL: in}
		}
		if got := groupProbeTarget(g); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

// A runtime re-point must not read as drift. The Keenetic postcheck — which the reconcile loop runs
// and whose failure starts a reinstall or a rollback — reads sets, mangle rules and ip rules, never a
// table's routes; and the plane's install program seeds a table with `ip route add … || true`, so a
// reinstall leaves an elected member in place instead of restoring the compile-time pin.
func TestKeeneticPostcheckIgnoresTheElectedMember(t *testing.T) {
	art := keeneticDNSArtifact(t, keeneticPBRTestTools(), true, true)
	r := healthyKeeneticRouter(art)
	if err := keeneticPlanePostcheck(context.Background(), *art, r.run); err != nil {
		t.Fatalf("postcheck: %v", err)
	}
	for _, call := range r.calls {
		if strings.Contains(call, " route") {
			t.Fatalf("the postcheck reads routes (%q): an elected member would be drift", call)
		}
	}
	if strings.Contains(string(art.Script), "route replace default dev") {
		t.Fatal("the install program replaces table defaults: a reinstall would undo the election")
	}
}
