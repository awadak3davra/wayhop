package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wayhop/internal/ctflush"
	"wayhop/internal/failover"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// fastestProfile is awg31Profile with the Telegram list in fastest mode over three NDM tunnels; the
// Instagram list keeps the group.
func fastestProfile() model.Profile {
	p := awg31Profile()
	p.RoutingLists[0].Candidates = []string{"nl1", "nl4", "nl5"}
	p.RoutingLists[0].Outbound = "nl1"
	p.RoutingLists[0].Fastest = &model.FastestPolicy{Enabled: true}
	return p
}

// fastestServer is appliedFailoverServer with the KeeneticOS compile (list egresses on), which the
// dev box's platform detection would not choose by itself.
func fastestServer(t *testing.T, profile model.Profile, tables *fakeTables) (*Server, *pbr.Plan) {
	t.Helper()
	s, _ := appliedFailoverServer(t, profile, profile, tables)
	keeneticPlane(s)
	plan, _, err := pbr.Compile(&profile, pbr.Options{CollectDomainZones: true, ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	s.applyState.rec.Committed.Materialization.Kernel.Plan = plan
	return s, plan
}

var tgTargets = []string{"149.154.167.51:443", "91.108.56.130:443"}

func listHandshakes(ms map[string]int) map[failover.ProbeKey]failover.ProbeResult {
	out := handshakes("cp.cloudflare.com:80", ms)
	for _, t := range tgTargets {
		for k, v := range handshakes(t, ms) {
			out[k] = v
		}
	}
	return out
}

// The list's own table follows the fastest of ITS candidates by ITS targets, beside the group's
// table, and the restore loop never re-seeds it.
func TestFastestListTickElectsIntoItsOwnTable(t *testing.T) {
	profile := fastestProfile()
	tables := &fakeTables{}
	s, plan := fastestServer(t, profile, tables)
	group := egressTable(t, plan, "grp-awg31")
	list := egressTable(t, plan, model.ListEgressTag("tg"))
	if list == group {
		t.Fatal("the list shares the group's table")
	}
	tables.show = map[bool]string{false: "default dev nwg1 table " + itoa(list) + " scope link \n" + keeneticTableDump(itoa(group))}
	tables.probes = listHandshakes(map[string]int{"awg1": -1, "nwg1": 120, "nwg4": 69, "nwg5": 90})
	s.monitor = healthWith(t, []string{"ca", "nl1", "nl4", "nl5"}, "spare")

	s.listFailoverTick(context.Background())
	want := "v4 nwg4 " + itoa(list)
	found := false
	for _, w := range tables.writes {
		if w == want {
			found = true
		}
		if strings.HasSuffix(w, " "+itoa(list)) && w != want {
			t.Fatalf("unexpected write into the list table: %s", w)
		}
	}
	if !found {
		t.Fatalf("writes %v, want %q", tables.writes, want)
	}
	st := s.fastestStates()["tg"]
	if st.Current != "nl4" || st.List == nil || st.List.Mode != "auto" || len(st.List.Matrix["nl4"]) != 2 {
		t.Fatalf("state %+v / %+v", st, st.List)
	}
	if strings.Join(st.Targets, ",") != strings.Join(tgTargets, ",") {
		t.Fatalf("targets %v (telegram's built-in ones expected)", st.Targets)
	}
	// The next tick is not the list's cycle: nothing is measured or decided for it.
	tables.writes = nil
	tables.show = map[bool]string{false: "default dev nwg4 table " + itoa(list) + " scope link \n" + keeneticTableDump(itoa(group))}
	tables.probes = listHandshakes(map[string]int{"awg1": -1, "nwg1": 10, "nwg4": -1, "nwg5": 90})
	s.listFailoverTick(context.Background())
	for _, w := range tables.writes {
		if strings.HasSuffix(w, " "+itoa(list)) {
			t.Fatalf("decided between cycles: %v", tables.writes)
		}
	}
}

// Verification accepts any candidate: an emptied or re-pointed list table is never "restored" to the
// compile-time tunnel, and a list unit accepts every candidate's link.
func TestFastestListTableIsNotRestoredAndAcceptsAnyCandidate(t *testing.T) {
	profile := fastestProfile()
	s, plan := fastestServer(t, profile, &fakeTables{})
	list := egressTable(t, plan, model.ListEgressTag("tg"))
	up := func(string) bool { return true }
	for _, lost := range lostTableRoutes(plan, &profile, map[int]string{}, up) {
		if lost.Table == list {
			t.Fatalf("restore would re-seed the list table: %+v", lost)
		}
	}
	units := fastestUnitsFrom(plan, &profile, kernelIfaceByEndpoint(&profile, s.appliedKernelDevices()),
		autoFastestTargets, nil, time.Now().UnixMilli())
	if len(units) != 1 {
		t.Fatalf("units %+v", units)
	}
	for _, iface := range []string{"nwg1", "nwg4", "nwg5"} {
		if !units[0].Accepts(iface) {
			t.Fatalf("%s rejected", iface)
		}
	}
	if units[0].Accepts("awg1") || units[0].Accepts("eth3") {
		t.Fatal("accepts a non-candidate")
	}
}

func TestAutoFastestTargets(t *testing.T) {
	cases := []struct {
		rl   model.RoutingList
		want string
	}{
		{model.RoutingList{ID: "tg", Name: "Telegram"}, "149.154.167.51:443,91.108.56.130:443"},
		{model.RoutingList{ID: "x", Name: "Instagram"}, "instagram.com:443,facebook.com:443"},
		{model.RoutingList{ID: "x", Manual: []string{"10.0.0.0/8", "203.0.113.0/24", "198.51.100.0/22", "1.1.1.1"}}, "198.51.100.1:443,203.0.113.1:443"},
		{model.RoutingList{ID: "x", Manual: []string{"*.example.org", "example.net"}}, "example.org:443,example.net:443"},
	}
	for _, c := range cases {
		if got := strings.Join(autoFastestTargets(c.rl), ","); got != c.want {
			t.Errorf("%+v: %s, want %s", c.rl.Manual, got, c.want)
		}
	}
}

func doJSON(t *testing.T, h http.HandlerFunc, method, path, id string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	if id != "" {
		r.SetPathValue("id", id)
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestFastestAPI(t *testing.T) {
	s, _ := fastestServer(t, fastestProfile(), &fakeTables{})
	w := doJSON(t, s.handleFastestLists, "GET", "/api/lists/fastest", "", nil)
	var sum struct {
		Supported bool             `json:"supported"`
		Lists     []fastestSummary `json:"lists"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &sum); err != nil || len(sum.Lists) != 1 || !sum.Lists[0].Active || len(sum.Lists[0].Candidates) != 3 {
		t.Fatalf("summary %s", w.Body.String())
	}
	if w := doJSON(t, s.handleFastestList, "GET", "/api/lists/tg/fastest", "tg", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"auto_targets":true`) {
		t.Fatalf("detail %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s.handleFastestList, "GET", "/api/lists/zz/fastest", "zz", nil); w.Code != 404 {
		t.Fatalf("unknown list %d", w.Code)
	}
	if w := doJSON(t, s.handleFastestProbe, "POST", "/x", "tg", nil); w.Code != http.StatusAccepted || !s.fastest.want["tg"] {
		t.Fatalf("probe %d", w.Code)
	}
	if w := doJSON(t, s.handleFastestPin, "POST", "/x", "tg", map[string]any{"candidate": "ca", "minutes": 15}); w.Code != 400 {
		t.Fatalf("pin to a non-candidate: %d", w.Code)
	}
	before := time.Now().Unix()
	if w := doJSON(t, s.handleFastestPin, "POST", "/x", "tg", map[string]any{"candidate": "nl5", "minutes": 15}); w.Code != 200 {
		t.Fatalf("pin %d %s", w.Code, w.Body.String())
	}
	p := s.store.Profile()
	f := findList(&p, "tg").Fastest
	if f.Pinned != "nl5" || f.PinnedUntil < before+900 || f.PinnedUntil > before+905 {
		t.Fatalf("pin stored %+v", f)
	}
	if w := doJSON(t, s.handleFastestExclude, "POST", "/x", "tg", map[string]any{"candidate": "nl5", "excluded": true}); w.Code != 200 {
		t.Fatalf("exclude %d", w.Code)
	}
	p = s.store.Profile()
	f = findList(&p, "tg").Fastest
	if f.Pinned != "" || len(f.Excluded) != 1 {
		t.Fatalf("excluding the pinned tunnel must unpin: %+v", f)
	}
	if w := doJSON(t, s.handleFastestPin, "POST", "/x", "tg", map[string]any{"candidate": "nl4", "minutes": 0}); w.Code != 200 {
		t.Fatal("pin until cancelled")
	}
	if w := doJSON(t, s.handleFastestUnpin, "POST", "/x", "tg", nil); w.Code != 200 {
		t.Fatal("unpin")
	}
	p = s.store.Profile()
	if f := findList(&p, "tg").Fastest; f.Pinned != "" || f.PinnedUntil != 0 {
		t.Fatalf("unpin stored %+v", f)
	}
	// ig is not in fastest mode.
	if w := doJSON(t, s.handleFastestUnpin, "POST", "/x", "ig", nil); w.Code != http.StatusConflict {
		t.Fatalf("unpin a plain list: %d", w.Code)
	}
}

func TestUpsertNormalizesOneCandidate(t *testing.T) {
	s, _ := fastestServer(t, fastestProfile(), &fakeTables{})
	rl := model.RoutingList{ID: "new", Name: "New", Enabled: true, Manual: []string{"203.0.113.0/24"},
		Candidates: []string{"nl4"}, Outbound: "nl1", Fastest: &model.FastestPolicy{Enabled: true}}
	w := doJSON(t, s.handleUpsertRoutingList, "POST", "/api/routing", "", rl)
	if w.Code != 200 {
		t.Fatalf("upsert %d %s", w.Code, w.Body.String())
	}
	p := s.store.Profile()
	got := findList(&p, "new")
	if got.Outbound != "nl4" || got.Fastest.Enabled {
		t.Fatalf("stored %+v / %+v", got, got.Fastest)
	}
}

func TestFastestFindingsLimitAndNotes(t *testing.T) {
	s, _ := fastestServer(t, fastestProfile(), &fakeTables{})
	p := fastestProfile()
	for i := 0; i < model.MaxFastestLists; i++ {
		p.RoutingLists = append(p.RoutingLists, model.RoutingList{ID: fmt.Sprintf("l%d", i), Enabled: true,
			Manual: []string{"203.0.113.0/24"}, Candidates: []string{"nl1", "nl4"}, Outbound: "nl1",
			Fastest: &model.FastestPolicy{Enabled: true}})
	}
	p.RoutingLists[0].Fastest.Pinned = "nl5"
	p.RoutingLists = append(p.RoutingLists, model.RoutingList{ID: "one", Enabled: true, Manual: []string{"203.0.113.0/24"},
		Candidates: []string{"nl1"}, Outbound: "nl1", Fastest: &model.FastestPolicy{Enabled: true}})
	ids := map[string]bool{}
	for _, f := range s.fastestFindings(&p) {
		ids[f.ID] = true
		if f.ID == "routing_list.fastest_limit" && f.Blocks != "apply" {
			t.Fatal("the limit must block Apply")
		}
	}
	for _, want := range []string{"routing_list.fastest_limit", "routing_list.fastest_one", "routing_list.fastest_pinned"} {
		if !ids[want] {
			t.Errorf("missing finding %s (got %v)", want, ids)
		}
	}
	// The kernel plane runs the choice in fast (and hybrid) mode on any router; in a mode with no
	// kernel plane a router that is not KeeneticOS says so.
	if ids["routing_list.fastest_platform"] {
		t.Error("fast mode has a kernel plane: the option runs, no platform finding")
	}
	s.cfg.RoutingMode = "mixed"
	s.platformOf = func() platform.Platform { return platform.OpenWrt }
	found := false
	for _, f := range s.fastestFindings(&p) {
		found = found || f.ID == "routing_list.fastest_platform"
	}
	if !found {
		t.Error("mixed mode on OpenWrt has no kernel plane: the review must say the list uses its first tunnel")
	}
	s.cfg.RoutingMode = "fast"
	// At the limit exactly: no blocker.
	p.RoutingLists = p.RoutingLists[:len(p.RoutingLists)-2]
	for _, f := range s.fastestFindings(&p) {
		if f.ID == "routing_list.fastest_limit" {
			t.Fatal("32 lists must pass")
		}
	}
}

// The journal is restored at start, marked only when it changed, and written by the rate-limited
// writer (the rate limit itself is writebehind's, tested there).
func TestFastestJournalPersistence(t *testing.T) {
	dir := t.TempDir()
	doc := fastestJournalDoc{V: 1, Lists: map[string][]failover.UnitEvent{"list:tg": {{At: 1, To: "nl4", Reason: "faster"}}}}
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(filepath.Join(dir, fastestJournalFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	profile := fastestProfile()
	tables := &fakeTables{}
	s, plan := fastestServer(t, profile, tables)
	s.applyStateDir = dir
	e := s.kernelElector()
	if s.fastest.journal == nil {
		t.Fatal("no journal writer")
	}
	list := egressTable(t, plan, model.ListEgressTag("tg"))
	group := egressTable(t, plan, "grp-awg31")
	tables.show = map[bool]string{false: "default dev nwg1 table " + itoa(list) + " scope link \n" + keeneticTableDump(itoa(group))}
	tables.probes = listHandshakes(map[string]int{"awg1": -1, "nwg1": 120, "nwg4": 69, "nwg5": 90})
	s.monitor = healthWith(t, []string{"ca", "nl1", "nl4", "nl5"}, "spare")
	s.listFailoverTick(context.Background())
	st := s.fastestStates()["tg"]
	if len(st.Events) < 2 || st.Events[0].At != 1 {
		t.Fatalf("restored journal lost: %+v", st.Events)
	}
	if !s.fastest.journal.Pending() {
		t.Fatal("a new event must mark the journal")
	}
	if err := s.fastest.journal.Flush(); err != nil {
		t.Fatal(err)
	}
	s.persistFastestJournal(e)
	if s.fastest.journal.Pending() {
		t.Fatal("no change, no mark")
	}
	b, _ = os.ReadFile(filepath.Join(dir, fastestJournalFile))
	var got fastestJournalDoc
	if json.Unmarshal(b, &got) != nil || len(got.Lists["list:tg"]) != len(st.Events) {
		t.Fatalf("journal on disk %s", b)
	}
	_ = s.fastest.journal.Close()
}

// A switch resets the list's flows by its own mark when asked, and reaches the bot at most once per
// 10 minutes per list, only when the list asked for alerts.
func TestFastestEventsResetAndNotify(t *testing.T) {
	profile := fastestProfile()
	profile.RoutingLists[0].Fastest.ResetOnSwitch = true
	profile.RoutingLists[0].Fastest.Notify = true
	s, plan := fastestServer(t, profile, &fakeTables{})
	var mark uint32
	for _, eg := range plan.Egresses {
		if eg.Tag == model.ListEgressTag("tg") {
			mark = eg.Mark
		}
	}
	flushed := make(chan uint32, 4)
	old := fastestFlush
	fastestFlush = func(m, _ uint32) (ctflush.Result, error) { flushed <- m; return ctflush.Result{}, nil }
	defer func() { fastestFlush = old }()
	key := failover.UnitKey{Owner: model.ListEgressTag("tg"), Table: 160}
	units := []failover.TableUnit{{Key: key, Name: "Telegram"}}
	ev := failover.UnitEvent{Key: key, From: "nl1", To: "nl4", ToIface: "nwg4", Reason: "faster", Wrote: true}
	s.onFastestEvents(units, []failover.UnitEvent{ev, ev}, plan, &profile)
	for i := 0; i < 2; i++ {
		select {
		case m := <-flushed:
			if m != mark {
				t.Fatalf("flushed mark %#x, want %#x", m, mark)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no flush")
		}
	}
	evs := s.monitor.Events(10)
	if len(evs) != 2 || evs[0].Quiet == evs[1].Quiet {
		t.Fatalf("one alert, one quiet repeat expected: %+v", evs)
	}
	for _, e := range evs {
		if e.ID != "list:tg" || e.From != "nl1" || e.To != "nl4" {
			t.Fatalf("event %+v", e)
		}
	}
}
