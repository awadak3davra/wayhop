package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

func routedTestPlan(t *testing.T) *pbr.Plan {
	t.Helper()
	var big []string
	for i := 0; i < 300; i++ {
		big = append(big, fmt.Sprintf("198.18.%d.0/24", i%256))
		if i >= 256 {
			big[len(big)-1] = fmt.Sprintf("198.19.%d.0/24", i-256)
		}
	}
	p := &model.Profile{
		Endpoints: []model.Endpoint{{ID: "awg2", Engine: model.EngineExternal, Enabled: true, Server: "198.51.100.2", Params: map[string]any{"interface": "awg2"}}},
		RoutingLists: []model.RoutingList{
			{ID: "ai", Manual: []string{"openai.com"}, Outbound: "awg2", Enabled: true},
			{ID: "geo", Manual: big, Outbound: "awg2", Enabled: true},
		},
	}
	plan, _, err := pbr.Compile(p, pbr.Options{FastDNS: true, LANIfaces: []string{"br-lan"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.RoutedZones(pbr.Options{})) != 1 {
		t.Fatalf("no routed zone: %+v", plan.Zones)
	}
	return plan
}

// TestSyncRoutedTables: the table is brought to its prefixes by one batch of replaces and deletes,
// nothing flushed; an unchanged table costs a read only; a device that is not up waits.
func TestSyncRoutedTables(t *testing.T) {
	s := &Server{cfg: &config.Config{RoutingMode: "fast"}, platformOf: func() platform.Platform { return platform.OpenWrt }}
	plan := routedTestPlan(t)
	table := plan.RoutedZones(pbr.Options{})[0].Table
	live := "198.18.0.0/24 dev awg2 scope link\n203.0.113.0/24 dev awg2 scope link\n198.18.1.0/24 dev wan scope link\n"
	var batches []string
	oldIP, oldUp := routedIP, routedDevUp
	t.Cleanup(func() { routedIP, routedDevUp = oldIP, oldUp })
	up := true
	routedDevUp = func(string) bool { return up }
	routedIP = func(_ context.Context, stdin string, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case fmt.Sprintf("-4 route show table %d", table):
			return live, nil
		case fmt.Sprintf("-6 route show table %d", table):
			return "", nil
		case "-4 -force -batch -":
			batches = append(batches, stdin)
			return "", nil
		}
		return "", fmt.Errorf("unexpected ip %v", args)
	}
	if err := s.syncRoutedTables(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 1 {
		t.Fatalf("batches %d", len(batches))
	}
	b := batches[0]
	if strings.Contains(b, "flush") || strings.Contains(b, "route replace 198.18.0.0/24 ") ||
		!strings.Contains(b, fmt.Sprintf("route replace 198.18.1.0/24 dev awg2 table %d\n", table)) ||
		!strings.Contains(b, fmt.Sprintf("route del 203.0.113.0/24 table %d\n", table)) || strings.Count(b, "route replace") != 299 {
		t.Errorf("batch:\n%.400s...", b)
	}
	// In step: a read, no write.
	var all []string
	for i := 0; i < 300; i++ {
		v4, _ := plan.RoutedZones(pbr.Options{})[0].RoutedPrefixes(nil)
		all = append(all, v4[i]+" dev awg2 scope link")
	}
	live, batches = strings.Join(all, "\n")+"\n", nil
	if err := s.syncRoutedTables(context.Background(), plan); err != nil || len(batches) != 0 {
		t.Errorf("an unchanged table was rewritten: %v %d", err, len(batches))
	}
	up = false
	if err := s.syncRoutedTables(context.Background(), plan); err != nil {
		t.Errorf("a device not up yet failed the sync: %v", err)
	}
}

// TestRoutedExitAttribution: an unmarked flow to a large list's address is that list's egress in the
// trace and the Dashboard; a marked one keeps its mark.
func TestRoutedExitAttribution(t *testing.T) {
	plan := routedTestPlan(t)
	idx := newRoutedIndex(plan, nil)
	labels := traceLabels{markExit: markExitResolverFrom(plan, nil), routed: idx}
	unmarked := Conn{Src: "192.168.77.5", Dst: "198.18.7.9", ReplySrc: "198.18.7.9"}
	if got := labels.exitOf(&unmarked); got != "awg2" {
		t.Errorf("unmarked flow to a routed prefix: %q", got)
	}
	other := Conn{Src: "192.168.77.5", Dst: "198.51.100.9", ReplySrc: "198.51.100.9"}
	if got := labels.exitOf(&other); got != "direct" {
		t.Errorf("unlisted address: %q", got)
	}
	if idx.lookup("198.18.7.9", 0x00010000) != "" {
		t.Error("a marked flow was attributed to the routed table")
	}
}

// TestSyncRoutedTablesNewTable (live 22.11): a table never filled does not exist yet, and ip-tiny
// (iproute2 6.18) answers its dump with "FIB table does not exist", exit 2. That is an empty table:
// every prefix is added. The teardown's flush of such a table counts as already done.
func TestSyncRoutedTablesNewTable(t *testing.T) {
	s := &Server{cfg: &config.Config{RoutingMode: "fast"}, platformOf: func() platform.Platform { return platform.OpenWrt }}
	plan := routedTestPlan(t)
	table := plan.RoutedZones(pbr.Options{})[0].Table
	var batch string
	oldIP, oldUp := routedIP, routedDevUp
	t.Cleanup(func() { routedIP, routedDevUp = oldIP, oldUp })
	routedDevUp = func(string) bool { return true }
	routedIP = func(_ context.Context, stdin string, args ...string) (string, error) {
		if strings.Join(args, " ") == "-4 -force -batch -" {
			batch = stdin
			return "", nil
		}
		return "", fmt.Errorf("ip %s: exit status 2: Error: ipv4: FIB table does not exist.\nDump terminated", strings.Join(args, " "))
	}
	if err := s.syncRoutedTables(context.Background(), plan); err != nil {
		t.Fatalf("a table not created yet failed the sync: %v", err)
	}
	if strings.Count(batch, "route replace") != 300 {
		t.Errorf("not every prefix added to the new table:\n%.300s", batch)
	}
	flush := fmt.Sprintf("ip route flush table %d", table)
	if !exactKernelAlreadyAbsent(flush, errors.New("exit status 2: Error: ipv4: FIB table does not exist.")) {
		t.Error("the teardown's flush of a never-filled table is not taken as done")
	}
}

// TestRoutedRemoteContentInForce: a routed remote list's refresh that names private
// space is not taken; the tables are filled from the content in force, never from a refreshed copy the
// reload has not taken; the loop's repair stands aside while an Apply holds applyMu.
func TestRoutedRemoteContentInForce(t *testing.T) {
	s := &Server{cfg: &config.Config{RoutingMode: "fast"}, platformOf: func() platform.Platform { return platform.OpenWrt }}
	var big []string
	for i := 0; i < 300; i++ {
		big = append(big, fmt.Sprintf("198.%d.%d.0/24", 18+i/256, i%256))
	}
	plan := &pbr.Plan{Table: "wayhop_pbr", Mask: 0x00ff0000, FastDNS: true, LANIfaces: []string{"br-lan"},
		Egresses: []pbr.Egress{{Tag: "direct", Kind: pbr.EgressWAN, Mark: 0x10000, Table: 254},
			{Tag: "awg2", Kind: pbr.EgressInterface, Iface: "awg2", Mark: 0x20000, Table: 151}},
		Zones: []pbr.Zone{{Name: "list_geo", EgressTag: "awg2", Mark: 0x20000, RemoteList: "geo", RemoteSource: "u",
			Routed: true, RemoteRouted: true, RouteList: "geo", DNSNoV6: true}}}
	inForce := pbr.RemoteSet{Source: "u", CIDRs: big}
	s.markRemoteLive(map[string]pbr.RemoteSet{"geo": inForce})
	refreshed := pbr.RemoteSet{Source: "u", CIDRs: append([]string{"10.77.0.0/16"}, big[1:]...)}
	s.fastDNS.remote = map[string]fastRemoteEntry{"geo": {fetched: time.Now(), set: refreshed}}
	if _, sets, _ := s.planRemote(plan); len(sets["geo"].CIDRs) != 300 || sets["geo"].CIDRs[0] != big[0] ||
		!strings.Contains(s.fastDNS.rejected["geo"], "private") {
		t.Fatalf("a private-space refresh of a routed list was taken: %v", s.fastDNS.rejected)
	}
	table := plan.RoutedZones(pbr.Options{})[0].Table
	var batch string
	oldIP, oldUp := routedIP, routedDevUp
	t.Cleanup(func() { routedIP, routedDevUp = oldIP, oldUp })
	routedDevUp = func(string) bool { return true }
	routedIP = func(_ context.Context, stdin string, args ...string) (string, error) {
		if strings.Join(args, " ") == "-4 -force -batch -" {
			batch = stdin
		}
		return "", nil
	}
	// A refreshed copy the reload has not taken (public, so it is not refused) does not reach the table.
	s.fastDNS.remote["geo"] = fastRemoteEntry{fetched: time.Now(), set: pbr.RemoteSet{Source: "u", CIDRs: []string{"203.0.113.0/24"}}}
	if err := s.syncRoutedTables(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(batch, "203.0.113.0/24") || !strings.Contains(batch, fmt.Sprintf("route replace %s dev awg2 table %d", big[0], table)) {
		t.Errorf("the table was not filled from the content in force:\n%.200s", batch)
	}
	batch = ""
	s.applyMu.Lock()
	s.repairRoutedTables(context.Background())
	s.applyMu.Unlock()
	if batch != "" {
		t.Error("the repair ran while an Apply held applyMu")
	}
}

// TestPreloadRoutedTables: before an install, a table the installed plane does
// not use is filled, so a list moving out of nft never goes by the WAN; one the installed plane uses
// is left to the install's own sync.
func TestPreloadRoutedTables(t *testing.T) {
	s := &Server{cfg: &config.Config{RoutingMode: "fast"}, platformOf: func() platform.Platform { return platform.OpenWrt }}
	plan := routedTestPlan(t)
	batches := 0
	oldIP, oldUp := routedIP, routedDevUp
	t.Cleanup(func() { routedIP, routedDevUp = oldIP, oldUp })
	routedDevUp = func(string) bool { return true }
	routedIP = func(_ context.Context, stdin string, args ...string) (string, error) {
		if strings.Join(args, " ") == "-4 -force -batch -" {
			batches++
		}
		return "", nil
	}
	s.preloadRoutedTables(context.Background(), plan, nil)
	if batches != 1 {
		t.Errorf("a new table was not preloaded (%d batches)", batches)
	}
	batches = 0
	s.preloadRoutedTables(context.Background(), plan, plan)
	if batches != 0 {
		t.Error("a table the installed plane uses was written before the install")
	}
}

// TestParseRoutedTableDefault: ip prints 0.0.0.0/0 and ::/0 as "default"; read back as
// those prefixes, an unchanged table is not rewritten and a removed one is deleted.
func TestParseRoutedTableDefault(t *testing.T) {
	v4 := parseRoutedTable("default dev awg1 scope link\nblackhole 198.18.0.0/24\n", false)
	v6 := parseRoutedTable("blackhole default dev lo metric 1024 pref medium\n", true)
	if v4["0.0.0.0/0"] != "dev awg1" || v4["198.18.0.0/24"] != "blackhole" || v6["::/0"] != "blackhole" {
		t.Errorf("v4 %v v6 %v", v4, v6)
	}
}

// TestSyncRoutedTablesDeviceDown: a list moved to a device that is down leaves nothing in
// its table through the device it used before.
func TestSyncRoutedTablesDeviceDown(t *testing.T) {
	s := &Server{cfg: &config.Config{RoutingMode: "fast"}, platformOf: func() platform.Platform { return platform.OpenWrt }}
	plan := routedTestPlan(t)
	table := plan.RoutedZones(pbr.Options{})[0].Table
	var batch string
	oldIP, oldUp := routedIP, routedDevUp
	t.Cleanup(func() { routedIP, routedDevUp = oldIP, oldUp })
	routedDevUp = func(string) bool { return false }
	routedIP = func(_ context.Context, stdin string, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case fmt.Sprintf("-4 route show table %d", table):
			return "198.18.0.0/24 dev awg0 scope link\n198.18.1.0/24 dev awg0 scope link\n", nil
		case "-4 -force -batch -":
			batch = stdin
			return "", nil
		}
		return "", nil
	}
	if err := s.syncRoutedTables(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if strings.Count(batch, "route del ") != 2 || strings.Contains(batch, "replace") {
		t.Errorf("routes through the old device stayed:\n%s", batch)
	}
}
