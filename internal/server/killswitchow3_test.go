package server

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"wayhop/internal/clash"
	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// ow3Profile is the reviewer's scratch profile: a list whose first candidate is
// a plain tunnel and whose kill switch comes from a group among its candidates, a list that blocks
// when all its tunnels are down, and a list with no kill switch that uses the same plain tunnel.
func ow3ReviewProfile() model.Profile {
	ext := func(id, iface, peer string) model.Endpoint {
		return model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineExternal,
			Params: map[string]any{"interface": iface, "endpoint_ip": peer}}
	}
	return model.Profile{
		Endpoints: []model.Endpoint{ext("nl", "awg0", "198.51.100.48"), ext("fi", "awg2", "198.51.100.144"), ext("se", "awg3", "198.51.100.160")},
		Groups: []model.Group{
			{ID: "grp-office", Name: "Office", Type: model.GroupFallback, Members: []string{"nl"}, KillSwitch: true},
			{ID: "grp-open", Name: "Open", Type: model.GroupFallback, Members: []string{"fi", "se"}},
		},
		RoutingLists: []model.RoutingList{
			{ID: "office", Name: "Office", Outbound: "grp-office", Enabled: true, Manual: []string{"intra.example.org"}},
			{ID: "mix", Name: "Mix", Outbound: "fi", Candidates: []string{"fi", "grp-office"}, Enabled: true, Manual: []string{"a.example.net", "192.0.2.0/24"},
				Fastest: &model.FastestPolicy{Enabled: true}},
			{ID: "blk", Name: "Blk", Outbound: "se", Candidates: []string{"se", "nl"}, Enabled: true, Manual: []string{"b.example.net", "198.51.100.0/25"},
				Fastest: &model.FastestPolicy{Enabled: true, OnAllDown: model.OnAllDownBlock}},
			{ID: "plain", Name: "Plain", Outbound: "fi", Enabled: true, Manual: []string{"c.example.net"}},
		},
		Rules: []model.Rule{{ID: "rest", Outbound: "grp-open"}},
	}
}

func ow3Server(t *testing.T, mode string) *Server {
	t.Helper()
	namesPaths(t)
	cfg := config.Default()
	cfg.RoutingMode = mode
	s := &Server{cfg: cfg}
	s.platformOf = func() platform.Platform { return platform.OpenWrt }
	return s
}

func nameSet(t *testing.T, plan *pbr.Plan, set string) pbr.GuardNameSet {
	t.Helper()
	for _, ns := range plan.GuardNameSets {
		if ns.Set == set {
			return ns
		}
	}
	t.Fatalf("no name set %s in %+v", set, plan.GuardNameSets)
	return pbr.GuardNameSet{}
}

// A list's candidates were all taken for outbounds of the core, and any tag of a
// connection's chain counted: the list `mix` (first candidate the plain tunnel fi) took every
// connection that left through fi for any other list, rule or the default route, and with the core
// down those addresses were dropped on the provider although their routes had no kill switch.
// A list that blocks when all its tunnels are down had no name set at all.
func TestNamesAreLearnedOnlyFromTheListsOwnRoute(t *testing.T) {
	p := ow3ReviewProfile()
	plan, _, err := pbr.Compile(&p, pbr.Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	office, mix, blk := nameSet(t, plan, "kn_office"), nameSet(t, plan, "kn_mix"), nameSet(t, plan, "kn_blk")
	if !slices.Equal(office.Outbounds, []string{"grp-office"}) || office.Direct || office.Shared {
		t.Errorf("office: %+v", office)
	}
	if !slices.Equal(mix.Outbounds, []string{"fi"}) || !mix.Direct || !mix.Shared || !slices.Equal(mix.RuleSets, []string{"rs-mix", "rsm-mix"}) {
		t.Errorf("mix (fi is also the plain list's tunnel): %+v", mix)
	}
	if !slices.Equal(blk.Outbounds, []string{"se"}) || !blk.Direct || blk.Shared {
		t.Errorf("blk (block when all are down is a kill switch for its names too): %+v", blk)
	}
	if len(plan.GuardNameSets) != 3 || !plan.GuardNames {
		t.Errorf("name sets %+v, GuardNames %v", plan.GuardNameSets, plan.GuardNames)
	}
	guard := plan.RenderNftGuardWith(pbr.NamesHold{Seconds: 600, Pass: []string{"whtun0"}})
	for _, want := range []string{"set kn_blk_4 {", "ip daddr @kn_blk_4 jump ks_names", "set wh_hold {"} {
		if !strings.Contains(guard, want) {
			t.Errorf("no %q in the guard:\n%s", want, guard)
		}
	}

	s := ow3Server(t, "hybrid")
	var ran []string
	run := func(_ context.Context, program string) error { ran = append(ran, program); return nil }
	ruled := func(ip, rule string, chains ...string) clash.Conn {
		c := connTo(ip, chains...)
		c.Rule = rule
		return c
	}
	s.learnNames(context.Background(), plan, []clash.Conn{
		// Other routes' traffic through the tunnel fi: the default rule's group, the plain list.
		connTo("203.0.113.10", "fi", "grp-open"),
		connTo("203.0.113.11", "grp-open", "fi"), // the same, should the core list the chain the other way round
		ruled("203.0.113.12", "rule_set=rsm-plain => route(fi)", "fi"),
		connTo("203.0.113.13", "fi"), // routed to fi by a rule the core does not name: not provably the list's
		// The list's own.
		ruled("203.0.113.20", "rule_set=[rs-mix rsm-mix] => route(fi)", "fi"),
		ruled("203.0.113.21", "rule_set=rsm-mix => route(fi)", "fi"),
		// A group's traffic is the group's whichever member carries it, in either order.
		connTo("203.0.113.30", "nl", "grp-office"),
		connTo("203.0.113.31", "grp-office", "nl"),
		// The block-when-down list's tunnel is used by no open route: the outbound alone tells.
		connTo("203.0.113.40", "se"),
		connTo("203.0.113.41", "se", "grp-open"), // se as the open group's member
	}, run)
	want := pbr.RenderGuardLearn("kn_blk", map[string]int{"203.0.113.40": ksNameTTL}) +
		pbr.RenderGuardLearn("kn_mix", map[string]int{"203.0.113.20": ksNameTTL, "203.0.113.21": ksNameTTL}) +
		pbr.RenderGuardLearn("kn_office", map[string]int{"203.0.113.30": ksNameTTL, "203.0.113.31": ksNameTTL})
	if len(ran) != 1 || ran[0] != want {
		t.Errorf("learned:\n%s\nwant:\n%s", strings.Join(ran, "---\n"), want)
	}
}

// Review says what the reviews found it did not: a tunnel shared with an open route, what a
// name not seen in use means, what a shared address costs, and a plan from an
// older build (for which the sentence must not read "the core carries IPv6").
func TestReviewAfterTheSecondRoundOfTheStage2Review(t *testing.T) {
	p := ow3ReviewProfile()
	plan, _, err := pbr.Compile(&p, pbr.Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	s := ow3Server(t, "hybrid")
	detail := func() string {
		t.Helper()
		fs := s.namesHoldFindings(s.config(), plan)
		if len(fs) != 1 {
			t.Fatalf("findings: %+v", fs)
		}
		return fs[0].Detail
	}
	stored := detail()
	for _, want := range []string{"The tunnel of mix (by fi) is also where", "has not seen in use", "An address several sites share",
		"applied by an earlier build of WayHop", "Apply once."} {
		if !strings.Contains(stored, want) {
			t.Errorf("no %q in:\n%s", want, stored)
		}
	}
	if strings.Contains(stored, "covers both alike") || strings.Contains(stored, "nobody has reached") {
		t.Errorf("a stored plan's Review:\n%s", stored)
	}
	plan.CoreTun, plan.CoreTunV6 = "whtun0", true
	if now := detail(); !strings.Contains(now, "covers both alike") || strings.Contains(now, "earlier build") {
		t.Errorf("this build's plan:\n%s", now)
	}
	s = ow3Server(t, "fast")
	if fast := detail(); strings.Contains(fast, "no new ones are noted") || !strings.Contains(fast, "The tunnel of mix (by fi)") {
		t.Errorf("fast mode:\n%s", fast)
	}
}

// The core's connections were read on the reconcile tick, every 30 s, so a connection
// shorter than that was mostly missed. They are read by a loop of their own: every pass learns, the
// pace follows what a pass costs, and a failing load is not logged at every pass.
func TestNamesAreLearnedOnTheirOwnTimer(t *testing.T) {
	if got := []time.Duration{learnPace(0), learnPace(100 * time.Millisecond), learnPace(600 * time.Millisecond), learnPace(5 * time.Second)}; !slices.Equal(got,
		[]time.Duration{5 * time.Second, 5 * time.Second, 12 * time.Second, 30 * time.Second}) {
		t.Errorf("pace: %v", got)
	}
	p := ow3ReviewProfile()
	plan, _, err := pbr.Compile(&p, pbr.Options{ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	s := ow3Server(t, "hybrid")
	reads := 0
	body := `{"connections":[{"id":"1","chains":["nl","grp-office"],"metadata":{"destinationIP":"203.0.113.30"}}]}`
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/connections" {
			reads++
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(core.Close)
	if s.clash, err = clash.New(strings.TrimPrefix(core.URL, "http://"), ""); err != nil {
		t.Fatal(err)
	}
	var ran []string
	var fail error
	old := ksLearnRun
	ksLearnRun = func(*ksLearnTarget) func(context.Context, string) error {
		return func(_ context.Context, program string) error {
			ran = append(ran, program)
			return fail
		}
	}
	t.Cleanup(func() { ksLearnRun = old })
	ctx := context.Background()

	// No plan installed, or the core is down: nothing is read.
	if wait := s.learnNamesOnce(ctx, true); wait != ksLearnEvery || reads != 0 {
		t.Fatalf("without a plan: wait %v, %d reads", wait, reads)
	}
	s.setLearnTarget(plan, ExecutionToolIdentityV1{}, ExecutionToolIdentityV1{})
	if s.learnNamesOnce(ctx, false); reads != 0 {
		t.Fatalf("the core is down and its table was read")
	}

	if wait := s.learnNamesOnce(ctx, true); wait < ksLearnEvery || wait > ksLearnSlowest {
		t.Errorf("wait %v", wait)
	}
	want := pbr.RenderGuardLearn("kn_office", map[string]int{"203.0.113.30": ksNameTTL})
	if reads != 1 || len(ran) != 1 || ran[0] != want {
		t.Fatalf("%d reads, learned %q, want %q", reads, ran, want)
	}
	// The same connection at the next pass: read, nothing to load.
	if s.learnNamesOnce(ctx, true); reads != 2 || len(ran) != 1 {
		t.Errorf("%d reads, %d loads", reads, len(ran))
	}
	// A connection that lived for a few seconds is there at one pass and learned.
	body = `{"connections":[{"id":"2","chains":["nl","grp-office"],"metadata":{"destinationIP":"203.0.113.31"}}]}`
	if s.learnNamesOnce(ctx, true); len(ran) != 2 || !strings.Contains(ran[1], "203.0.113.31") {
		t.Errorf("the short connection was not learned: %q", ran)
	}

	// A load the kernel refuses is tried again at every pass and logged once in five minutes.
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	fail = errors.New("Error: Could not process rule: No space left on device")
	body = `{"connections":[{"id":"3","chains":["nl","grp-office"],"metadata":{"destinationIP":"203.0.113.32"}}]}`
	for i := 0; i < 4; i++ {
		s.learnNamesOnce(ctx, true)
	}
	if n := strings.Count(logged.String(), "were not added to the guard"); n != 1 || len(ran) != 6 {
		t.Errorf("%d log lines for 4 failed passes (%d loads):\n%s", n, len(ran), logged.String())
	}

	// A plan without kill-switched names stops the loop's work.
	s.setLearnTarget(&pbr.Plan{}, ExecutionToolIdentityV1{}, ExecutionToolIdentityV1{})
	before := reads
	if s.learnNamesOnce(ctx, true); reads != before {
		t.Errorf("a plan without name sets was read for")
	}
}
