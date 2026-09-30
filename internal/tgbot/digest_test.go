package tgbot

import (
	"context"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
)

func TestDigestDayWindow(t *testing.T) {
	at := func(hh, mm int) time.Time { return time.Date(2026, 9, 24, hh, mm, 20, 0, time.UTC) }
	cfg := config.Telegram{Digest: "08:30"}
	for _, c := range []struct {
		now  time.Time
		due  bool
		want string
	}{
		{at(8, 29), false, ""},
		{at(8, 30), true, "2026-09-24"},
		{at(8, 59), true, "2026-09-24"}, // a router back at 08:40 still sends it
		{at(9, 0), false, ""},           // one back at noon does not
		{at(20, 30), false, ""},
	} {
		day, due := digestDay(cfg, c.now)
		if due != c.due || day != c.want {
			t.Errorf("%s: %q %v, want %q %v", c.now.Format("15:04"), day, due, c.want, c.due)
		}
	}
	// A window across midnight belongs to the day it opened on.
	day, due := digestDay(config.Telegram{Digest: "23:50"}, at(0, 10))
	if !due || day != "2026-09-23" {
		t.Fatalf("00:10 after a 23:50 digest: %q %v", day, due)
	}
	if _, due := digestDay(config.Telegram{}, at(8, 30)); due {
		t.Fatal("no time set, and still due")
	}
}

func ev(at time.Time, kind, id, name, to string) Event {
	return Event{At: at, Kind: kind, ID: id, Name: name, To: to}
}

// newestFirst is the order Events returns.
func newestFirst(evs ...Event) []Event {
	out := make([]Event, len(evs))
	for i, e := range evs {
		out[len(evs)-1-i] = e
	}
	return out
}

func TestOutagesOverTheWindow(t *testing.T) {
	now := testNow
	from := now.Add(-24 * time.Hour)
	h := func(n float64) time.Time { return now.Add(time.Duration(-n * float64(time.Hour))) }
	log := EventLog{Known: true, Since: h(30), Events: newestFirst(
		ev(h(29), "down", "old", "old", ""), ev(h(26), "up", "old", "old", ""), // over before the window
		ev(h(25), "down", "nl", "nl-main", ""), ev(h(23.5), "up", "nl", "nl-main", ""), // straddles its start
		ev(h(5), "down", "nl", "nl-main", ""), ev(h(4.75), "up", "nl", "nl-main", ""),
		ev(h(23), "up", "se", "se-fast", ""),    // down since before the log began
		ev(h(2), "down", "de", "de-backup", ""), // still down
		ev(h(3), "down", "fast", "fast-eu", ""), ev(h(3).Add(6*time.Minute), "up", "fast", "fast-eu", ""),
		ev(h(1), "switch", "fast", "fast-eu", "nl-main"),
	)}
	got := outages(log, from, now, map[string]bool{"fast": true})
	want := []outage{
		{ID: "de", Name: "de-backup", Count: 1, Down: 2 * time.Hour, Open: true},
		{ID: "se", Name: "se-fast", Count: 1, Down: time.Hour},
		{ID: "nl", Name: "nl-main", Count: 2, Down: 45 * time.Minute},
		{ID: "fast", Name: "fast-eu", Group: true, Count: 1, Down: 6 * time.Minute},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("#%d: %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSwitchesCountAndEndOnTheLastMember(t *testing.T) {
	now := testNow
	log := EventLog{Known: true, Events: newestFirst(
		ev(now.Add(-30*time.Hour), "switch", "fast", "fast-eu", "de-backup"), // outside
		ev(now.Add(-3*time.Hour), "switch", "fast", "fast-eu", "de-backup"),
		ev(now.Add(-2*time.Hour), "switch", "fast", "fast-eu", "nl-main"),
		ev(now.Add(-time.Hour), "switch", "media", "media", "se-fast"),
	)}
	got := switches(log, now.Add(-24*time.Hour), now)
	if len(got) != 2 || got[0] != (switched{Name: "fast-eu", Now: "nl-main", Count: 2}) || got[1].Count != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestTrafficIsTheDifferenceSinceTheBase(t *testing.T) {
	base := counters{bytes: map[string][2]int64{"nl": {1000, 100}, "de": {5000, 500}}}
	s := Status{Exits: []Exit{
		{ID: "nl", Name: "nl-main", BytesDown: 3000, BytesUp: 400},
		{ID: "de", Name: "de-backup", BytesDown: 700, BytesUp: 70}, // reset by an Apply: what it has now
		{ID: "se", Name: "se-fast", BytesDown: 10_000, BytesUp: 1}, // new since the base
		{ID: "idle", Name: "idle"},
		{ID: "fast", Name: "fast-eu", Group: true, BytesDown: 1 << 40},
	}}
	got := trafficSince(s, base)
	want := []traffic{{"se-fast", 10_000, 1}, {"nl-main", 2000, 300}, {"de-backup", 700, 70}}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("#%d: %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestCountTakesTheNounsForm(t *testing.T) {
	for _, c := range []struct {
		lang string
		n    int
		want string
	}{
		{"en", 0, "0 outages"}, {"en", 1, "1 outage"}, {"en", 2, "2 outages"},
		{"ru", 1, "1 сбой"}, {"ru", 2, "2 сбоя"}, {"ru", 5, "5 сбоев"}, {"ru", 11, "11 сбоев"},
		{"ru", 12, "12 сбоев"}, {"ru", 21, "21 сбой"}, {"ru", 22, "22 сбоя"}, {"ru", 111, "111 сбоев"},
	} {
		if got := Count(c.lang, c.n, "n.outage"); got != c.want {
			t.Errorf("%s %d: %q, want %q", c.lang, c.n, got, c.want)
		}
	}
	if got := Count("ru", 3, "n.time"); got != "3 раза" {
		t.Errorf("ru 3 times: %q", got)
	}
}

func TestBytesLikeThePanel(t *testing.T) {
	for _, c := range []struct {
		lang string
		n    int64
		want string
	}{
		{"en", 0, "0 B"}, {"en", 900, "900 B"}, {"en", 1536, "1.5 KB"}, {"en", 5 << 20, "5 MB"},
		{"en", 3_435_973_837, "3.2 GB"}, {"ru", 3_435_973_837, "3,2 ГБ"}, {"en", 3 << 40, "3 TB"},
	} {
		if got := Bytes(c.lang, c.n); got != c.want {
			t.Errorf("%s %d: %q, want %q", c.lang, c.n, got, c.want)
		}
	}
}

func sampleDigest() digest {
	s := sampleStatus()
	s.Changes = Changes{Known: true, Pending: true, Count: 3}
	s.Update = SelfUpdate{Available: true, Latest: "0.5.7"}
	return digest{
		At: testNow, Status: s, LogKnown: true, From: testNow.Add(-24 * time.Hour), FullDay: true,
		Outages: []outage{
			{Name: "de-backup", Count: 2, Down: 47 * time.Minute, Open: true},
			{Name: "fast-eu", Group: true, Count: 1, Down: 6 * time.Minute},
		},
		Switches:    []switched{{Name: "fast-eu", Now: "nl-main", Count: 3}},
		Restarts:    1,
		Traffic:     []traffic{{"nl-main", 3_435_973_837, 429_916_160}, {"de-backup", 125_829_120, 8 << 20}},
		TrafficFrom: testNow.Add(-24 * time.Hour),
	}
}

func TestDigestView(t *testing.T) {
	text, kb := view{lang: "en", now: testNow, role: roleOwner}.Digest(sampleDigest())
	for _, want := range []string{
		"☀️ <b>Daily summary</b> · Wed, 23 Sep",
		"🟡 Degraded · exits up: 1 of 2",
		"<b>Last 24 hours</b>",
		"🔴 <b>de-backup</b>: 2 outages, 47 min in total · still down",
		"🔴 <b>fast-eu</b> (group): 1 outage, 6 min in total",
		"🔁 <b>fast-eu</b> switched 3 times · now nl-main",
		"♻️ sing-box restarted 1 time",
		"<b>Traffic by exit</b> · 24 h\nnl-main · ↓ 3.2 GB ↑ 410 MB\nde-backup · ↓ 120 MB ↑ 8 MB",
		"⏱ Router up 6d 4h",
		"📝 Changes: <b>3 not applied</b>",
		"⬆️ WayHop 0.5.7 is available",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("lacks %q:\n%s", want, text)
		}
	}
	if kb == nil || len(kb.Rows) != 1 || kb.Rows[0][0].CallbackData != cbStatus || kb.Rows[0][1].CallbackData != cbEvents+"0" {
		t.Fatalf("keyboard %+v", kb)
	}
	if strings.HasSuffix(text, "\n") {
		t.Fatal("trailing newline")
	}

	ru, _ := view{lang: "ru", now: testNow, role: roleViewer}.Digest(sampleDigest())
	for _, want := range []string{
		"☀️ <b>Сводка за сутки</b> · ср, 23 сентября",
		"🔴 <b>de-backup</b>: 2 сбоя, всего 47 мин · недоступен до сих пор",
		"🔁 <b>fast-eu</b> переключалась 3 раза · сейчас nl-main",
		"nl-main · ↓ 3,2 ГБ ↑ 410 МБ",
	} {
		if !strings.Contains(ru, want) {
			t.Errorf("ru lacks %q:\n%s", want, ru)
		}
	}
	if _, kb := (view{lang: "en", now: testNow, role: roleAlerts}).Digest(sampleDigest()); kb != nil {
		t.Fatal("an alerts-only chat got buttons")
	}
}

func TestDigestViewOfACalmPartialDay(t *testing.T) {
	d := digest{At: testNow, Status: Status{Exits: []Exit{{ID: "nl", State: StateAlive}}}, LogKnown: true,
		From: testNow.Add(-5 * time.Hour), TrafficFrom: testNow.Add(-5 * time.Hour),
		Traffic: []traffic{{"nl-main", 2048, 0}}}
	text, _ := view{lang: "en", now: testNow}.Digest(d)
	for _, want := range []string{"🟢 All good · exits up: 1 of 1", "<b>Since 09:32</b> (the log starts there)",
		"✅ No outages, no switches", "<b>Traffic by exit</b> · since 09:32", "nl-main · ↓ 2 KB ↑ 0 B"} {
		if !strings.Contains(text, want) {
			t.Errorf("lacks %q:\n%s", want, text)
		}
	}
	for _, not := range []string{"Router up", "Changes", "available"} {
		if strings.Contains(text, not) {
			t.Errorf("mentions %q with nothing to say:\n%s", not, text)
		}
	}
}

func TestDigestSurvivesAPanickingBackend(t *testing.T) {
	h := newHarness(t, owner)
	h.be.panics = true
	h.bot.digestStep(context.Background(), testNow) // a panic here would end the test binary
	if !h.bot.counters.at.IsZero() {
		t.Fatal("counters read from a backend that panicked")
	}
}

// End to end: the first tick reads the counters, the digest goes out once at its time, silently and
// through quiet hours, and a second process on the same day does not send it again.
func TestDigestIsSentOnceAtItsTime(t *testing.T) {
	h := newHarness(t, owner, viewerChat)
	_ = h.st.UpdateTelegram(func(tg *config.Telegram) error {
		tg.Digest, tg.QuietFrom, tg.QuietTo = "14:35", "14:00", "15:00"
		return nil
	})
	s := sampleStatus()
	s.Exits[0].BytesDown, s.Exits[0].BytesUp = 1<<30, 1<<20
	h.be.status = s
	at := testNow.Add(3 * time.Minute) // 14:35
	h.be.events = EventLog{Known: true, Since: testNow.Add(-48 * time.Hour), Events: newestFirst(
		ev(at.Add(-2*time.Hour), "down", "de-backup", "de-backup", ""))}
	ctx := context.Background()

	h.bot.digestStep(ctx, testNow) // 14:32: reads the counters only
	s.Exits[0].BytesDown += 3 << 30
	h.be.status = s
	h.bot.digestStep(ctx, testNow.Add(2*time.Minute)) // 14:34: not yet
	if len(h.bot.out.q) != 0 {
		t.Fatal("sent before its time")
	}
	h.bot.now = func() time.Time { return at }
	h.bot.digestStep(ctx, at)
	h.bot.digestStep(ctx, at.Add(time.Minute))
	if len(h.bot.out.q) != 1 {
		t.Fatalf("%d digests queued", len(h.bot.out.q))
	}
	h.deliver(h.bot.out.q[0].a)
	calls := h.api.callsTo("sendMessage")
	if len(calls) != 2 {
		t.Fatalf("%d sends; quiet hours must not hold the digest", len(calls))
	}
	for _, c := range calls {
		if c.Params["disable_notification"] != true {
			t.Fatalf("not silent: %v", c.Params)
		}
	}
	en, ru := h.sendsTo(500)[0].Params["text"].(string), h.sendsTo(600)[0].Params["text"].(string)
	if !strings.Contains(en, "Daily summary") || !strings.Contains(en, "nl-main · ↓ 3 GB ↑ 0 B") ||
		!strings.Contains(en, "🔴 <b>de-backup</b>: 1 outage, 2h in total · still down") {
		t.Fatalf("en:\n%s", en)
	}
	if !strings.Contains(ru, "Сводка за сутки") {
		t.Fatalf("ru:\n%s", ru)
	}
	if len(h.be.claimed) != 1 || h.be.claimed[0] != "2026-09-23" {
		t.Fatalf("claimed %v", h.be.claimed)
	}

	// A restarted daemon, in the same half hour: the claim on disk stops a second digest.
	h2 := newHarness(t, owner)
	h2.be = h.be
	h2.bot.be = h.be
	h2.st = h.st
	h2.bot.st = h.st
	h2.bot.digestStep(ctx, at.Add(2*time.Minute))
	h2.bot.digestStep(ctx, at.Add(3*time.Minute))
	if len(h2.bot.out.q) != 0 {
		t.Fatal("sent twice after a restart")
	}
}

// /summary is the digest on demand: it reads the same things and moves nothing, so the next daily
// digest still measures traffic from its own last time.
func TestSummaryOnDemandLeavesTheDigestAlone(t *testing.T) {
	h := newHarness(t, owner)
	s := sampleStatus()
	s.Exits[0].BytesDown = 1 << 30
	h.be.status = s
	h.be.events = EventLog{Known: true, Since: testNow.Add(-2 * time.Hour)}
	ctx := context.Background()
	h.bot.digestStep(ctx, testNow) // the baseline the daily digest measures from
	base := h.bot.baseCounters()

	s.Exits[0].BytesDown += 2 << 30
	h.be.status = s
	h.text(500, "private", "/summary", "en")
	sent := h.sent()
	if len(sent) != 1 {
		t.Fatalf("sent %q", sent)
	}
	for _, want := range []string{"📋 <b>Summary</b> · Wed, 23 Sep, 14:32", "<b>Since 12:32</b>",
		"<b>Traffic by exit</b> · since 14:32\nnl-main · ↓ 2 GB ↑ 0 B"} {
		if !strings.Contains(sent[0], want) {
			t.Fatalf("lacks %q:\n%s", want, sent[0])
		}
	}
	kb := h.api.lastKeyboard(t, "sendMessage")
	if len(kb) != 1 || kb[0][0].CallbackData != cbSummary || kb[0][1].CallbackData != cbStatus {
		t.Fatalf("keyboard %+v", kb)
	}
	if after := h.bot.baseCounters(); !after.at.Equal(base.at) || after.bytes["nl-main"] != base.bytes["nl-main"] {
		t.Fatalf("the summary moved the digest's counters: %+v -> %+v", base, after)
	}
	if len(h.be.claimed) != 0 || len(h.bot.out.q) != 0 {
		t.Fatal("the summary claimed or queued a digest")
	}

	// From the More menu it replaces the menu, and its Refresh redraws it in place.
	h.press(500, cbMore)
	if kb := h.api.lastKeyboard(t, "editMessageText"); kb[1][1].CallbackData != cbSummary {
		t.Fatalf("the More menu lacks the summary: %+v", kb)
	}
	h.press(500, cbSummary)
	if e := h.edited(); len(e) != 2 || !strings.Contains(e[1], "📋 <b>Summary</b>") {
		t.Fatalf("edits %q", e)
	}

	// An alerts-only chat gets no state, the summary included.
	a := newHarness(t, alertsChat)
	a.text(-700, "group", "/summary", "en")
	if sent := a.sent(); len(sent) != 1 || strings.Contains(sent[0], "Summary") {
		t.Fatalf("alerts-only chat: %q", sent)
	}
}

// Before the first reading there is no baseline, and a summary then says nothing about traffic
// rather than calling every total since the daemon started "today's".
func TestSummaryBeforeTheFirstReading(t *testing.T) {
	h := newHarness(t, owner)
	s := sampleStatus()
	s.Exits[0].BytesDown = 5 << 30
	h.be.status = s
	h.text(500, "private", "/digest", "en")
	if sent := h.sent(); len(sent) != 1 || strings.Contains(sent[0], "Traffic by exit") {
		t.Fatalf("sent %q", sent)
	}
}

// The digest loop writes the counters while a chat reads them; run under -race.
func TestSummaryAndTheDigestLoopDoNotRace(t *testing.T) {
	h := newHarness(t, owner)
	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			h.bot.digestStep(ctx, testNow.Add(time.Duration(i)*time.Minute))
			h.bot.setCounters(counters{}) // make the next step read them again
		}
	}()
	v := view{lang: "en", now: testNow}
	for i := 0; i < 50; i++ {
		h.bot.summary(ctx, v, 500, nil)
	}
	<-done
}
