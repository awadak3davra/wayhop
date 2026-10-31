package tgbot

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wayhop/internal/config"
)

type fakeBackend struct {
	mu         sync.Mutex
	status     Status
	events     EventLog
	tested     []string
	testErr    error
	panics     bool
	pulse      Pulse
	boot       BootInfo
	decideErr  error
	kept       int
	rolledBack int
	trace      Trace
	traced     []string
	devices    []Device
	measured   bool
	checks     []Check
	diagRuns   int
	diagGate   chan struct{} // when set, Diagnose waits on it
	pinged     []string
	restarts   int
	restartErr error
	lists      ListsRefresh
	listsGate  chan struct{} // when set, RefreshLists waits on it
	subAdded   int
	subErr     error
	preview    ApplyPreview
	applied    []string
	applyErr   error
	backups    int
	update     UpdateInfo
	checks2    int
	installed  []string
	installErr error
	claimed    []string // days ClaimDigest granted
	speed      SpeedReport
	speedErr   error
	speedRuns  int
	speedExits []string // the exit each run measured, "" for the default route
	// routed records every SetRouting call (true = on); routeErr fails them.
	routed   []bool
	routeErr error
}

// SetRouting flips the fake's routing switch the way the daemon does, unless routeErr is set.
func (f *fakeBackend) SetRouting(_ context.Context, on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routed = append(f.routed, on)
	if f.routeErr != nil {
		return f.routeErr
	}
	f.status.Routing = Routing{}
	if !on {
		f.status.Routing = Routing{Off: true, By: "telegram"}
	}
	return nil
}

func (f *fakeBackend) ClaimDigest(day string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range f.claimed {
		if d == day {
			return false
		}
	}
	f.claimed = append(f.claimed, day)
	return true
}

func (f *fakeBackend) UpdateCheck(context.Context) UpdateInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks2++
	return f.update
}

func (f *fakeBackend) setUpdate(u UpdateInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.update = u
}

func (f *fakeBackend) UpdateInstall(_ context.Context, version string) (UpdateResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installed = append(f.installed, version)
	if f.installErr != nil {
		return UpdateResult{}, f.installErr
	}
	return UpdateResult{Installed: version, Restarting: true}, nil
}

func (f *fakeBackend) RestartDaemon(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restarts++
	return f.restartErr
}

func (f *fakeBackend) RefreshLists(context.Context) (ListsRefresh, error) {
	f.mu.Lock()
	gate := f.listsGate
	f.mu.Unlock()
	if gate != nil {
		<-gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lists, nil
}

func (f *fakeBackend) RefreshSubscription(context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.subAdded, f.subErr
}

func (f *fakeBackend) ApplyPreview(context.Context) (ApplyPreview, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.preview, nil
}

func (f *fakeBackend) ApplyTest(_ context.Context, rev string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, rev)
	return f.applyErr
}

func (f *fakeBackend) Backup(context.Context) (string, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.backups++
	return "wayhop-backup.json", []byte(`{"wayhop_backup":1}`), nil
}

func (f *fakeBackend) Trace(_ context.Context, target string) (Trace, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.traced = append(f.traced, target)
	if strings.ContainsAny(target, "!$ ") || target == "" {
		return Trace{}, ErrBadTarget
	}
	tr := f.trace
	tr.Target = target
	return tr, nil
}

func (f *fakeBackend) Devices(context.Context) DeviceList {
	f.mu.Lock()
	defer f.mu.Unlock()
	return DeviceList{Devices: f.devices, Measured: f.measured}
}

func (f *fakeBackend) Diagnose(context.Context) []Check {
	f.mu.Lock()
	gate := f.diagGate
	f.diagRuns++
	checks := f.checks
	f.mu.Unlock()
	if gate != nil {
		<-gate
	}
	return checks
}

func (f *fakeBackend) SpeedTest(_ context.Context, exit string, step func(string)) (SpeedReport, error) {
	f.mu.Lock()
	f.speedRuns++
	f.speedExits = append(f.speedExits, exit)
	rep, err := f.speed, f.speedErr
	f.mu.Unlock()
	if err != nil {
		return SpeedReport{}, err
	}
	step(LegLine)
	if !rep.Route.Skipped {
		step(LegRoute)
	}
	return rep, nil
}

func (f *fakeBackend) Ping(_ context.Context, host string) (PingResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pinged = append(f.pinged, host)
	if strings.HasPrefix(host, "-") {
		return PingResult{}, ErrBadTarget
	}
	return PingResult{Target: host, Ran: true, OK: true, LossPct: 0, AvgMs: 23.4}, nil
}

func (f *fakeBackend) Lookup(_ context.Context, host string) (LookupResult, error) {
	return LookupResult{Target: host, IPs: []string{"192.0.2.14"}, CNAME: "edge.cdn.example.net."}, nil
}

func (f *fakeBackend) Pulse(context.Context) Pulse {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pulse
}

func (f *fakeBackend) Boot() BootInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.boot
}

func (f *fakeBackend) ConfirmApply(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kept++
	return f.decideErr
}

func (f *fakeBackend) RollbackApply(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rolledBack++
	return f.decideErr
}

func (f *fakeBackend) Status(context.Context) Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.panics {
		panic("backend exploded")
	}
	return f.status
}

func (f *fakeBackend) TestExit(_ context.Context, id string) (Exit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tested = append(f.tested, id)
	if f.testErr != nil {
		return Exit{}, f.testErr
	}
	e, ok := f.status.ExitByID(id)
	if !ok {
		return Exit{}, errors.New("no such exit")
	}
	e.LatencyMs = 33
	return e, nil
}

func (f *fakeBackend) Events(int) EventLog {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.events
}

type fakeStore struct {
	mu sync.Mutex
	t  config.Telegram
}

func (s *fakeStore) Telegram() config.Telegram {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.t.Clone()
	return c
}

func (s *fakeStore) UpdateTelegram(fn func(*config.Telegram) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.t.Clone()
	if err := fn(&c); err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}
	s.t = c
	return nil
}

var testNow = time.Date(2026, 9, 23, 14, 32, 0, 0, time.UTC)

func sampleStatus() Status {
	return Status{
		At: testNow, Version: "0.5.6",
		Core:   Core{Available: true, Running: true},
		ExitIP: ExitIP{Known: true, IP: "198.51.100.3", Country: "Netherlands", Code: "NL", City: "Amsterdam"},
		Exits: []Exit{
			{ID: "nl-main", Name: "nl-main", Kind: "wireguard", State: StateAlive, LatencyMs: 42, AvgLatency: 45, SuccessRate: 100, UptimeS: 3600},
			{ID: "de-backup", Name: "de-backup", Kind: "vless", State: StateDown, SuccessRate: 62, Cause: "handshake did not complete", Fix: "check the server key"},
		},
		Groups:  []Group{{ID: "fast", Name: "fast-eu", Members: []string{"nl-main", "de-backup"}, Elected: "nl-main"}},
		System:  System{Known: true, MemUsedPct: 41.2, Load1: 0.32, UptimeS: 6*86400 + 4*3600, TempC: 52},
		Traffic: Rates{Known: true, Down: 1_550_000, Up: 137_500},
	}
}

type harness struct {
	t   *testing.T
	api *fakeAPI
	be  *fakeBackend
	st  *fakeStore
	bot *Bot
}

func newHarness(t *testing.T, chats ...config.TelegramChat) *harness {
	t.Helper()
	h := &harness{t: t, api: newFakeAPI(t), be: &fakeBackend{status: sampleStatus()},
		st: &fakeStore{t: config.Telegram{Enabled: true, Token: testToken, Chats: chats}}}
	h.bot = New(h.api.client(), h.be, h.st, Options{Now: func() time.Time { return testNow }, Logf: t.Logf})
	h.bot.me = User{ID: 1, IsBot: true, Username: "home_wayhop_bot"}
	return h
}

func (h *harness) text(chat int64, typ, text, lang string) {
	h.bot.handle(context.Background(), Update{Message: &Message{
		MessageID: 10, Chat: Chat{ID: chat, Type: typ, Title: "Group"}, Date: testNow.Unix(), Text: text,
		From: &User{ID: chat, FirstName: "Sam", LanguageCode: lang},
	}})
}

// press handles a button press and waits for the work it detached from the handler (an Apply, a
// refresh, a speed test), so a test reads the outcome.
func (h *harness) press(chat int64, data string) {
	h.bot.handle(context.Background(), Update{CallbackQuery: &CallbackQuery{
		ID: "q1", From: User{ID: chat, FirstName: "Sam"}, Data: data,
		Message: &Message{MessageID: 99, Chat: Chat{ID: chat, Type: "private"}},
	}})
	h.bot.wg.Wait()
}

func (h *harness) sent() []string {
	var out []string
	for _, c := range h.api.callsTo("sendMessage") {
		out = append(out, c.Params["text"].(string))
	}
	return out
}

func (h *harness) edited() []string {
	var out []string
	for _, c := range h.api.callsTo("editMessageText") {
		out = append(out, c.Params["text"].(string))
	}
	return out
}

var owner = config.TelegramChat{ID: 500, Name: "Sam", Role: roleOwner, Lang: "en"}

func TestStrangerGetsOneRefusalAndIsListed(t *testing.T) {
	h := newHarness(t)
	h.text(777, "private", "/status", "en")
	h.text(777, "private", "/exits", "en")
	if got := h.sent(); len(got) != 1 || !strings.Contains(got[0], "private bot") {
		t.Fatalf("want exactly one refusal, got %q", got)
	}
	s := h.bot.gate.Strangers()
	if len(s) != 1 || s[0].ChatID != 777 || s[0].Attempts != 2 || s[0].Name != "Sam" {
		t.Fatalf("strangers %+v", s)
	}
}

func TestStrangerNeverSeesState(t *testing.T) {
	h := newHarness(t)
	h.text(777, "private", "/status", "ru")
	h.press(777, cbStatus)
	for _, s := range append(h.sent(), h.edited()...) {
		if strings.Contains(s, "198.51.100.3") || strings.Contains(s, "nl-main") {
			t.Fatalf("state leaked to an unpaired chat: %q", s)
		}
	}
	a := h.api.callsTo("answerCallbackQuery")
	if len(a) != 1 || a[0].Params["show_alert"] != true {
		t.Fatalf("an unpaired button press must get a visible refusal: %v", a)
	}
}

func TestGreetingIsNotSpentAsAWrongCode(t *testing.T) {
	h := newHarness(t)
	h.text(777, "private", "hello", "en")
	if got := h.sent(); len(got) != 1 || strings.Contains(got[0], "not valid") {
		t.Fatalf("a greeting should get the explanation, got %q", got)
	}
	if len(h.bot.gate.bad[777]) != 0 {
		t.Fatal("a greeting was counted as a wrong code")
	}
}

func TestPairingWithDeepLinkCode(t *testing.T) {
	h := newHarness(t)
	code, _ := h.bot.gate.NewCode(roleOwner)
	h.text(500, "private", "/start "+code, "ru")
	chats := h.st.Telegram().Chats
	if len(chats) != 1 || chats[0].ID != 500 || chats[0].Role != roleOwner || chats[0].Lang != "ru" || chats[0].Name != "Sam" {
		t.Fatalf("chats %+v", chats)
	}
	got := h.sent()
	if len(got) != 2 || !strings.Contains(got[0], "владелец") || !strings.Contains(got[1], "Всё в порядке") && !strings.Contains(got[1], "Частичный сбой") {
		t.Fatalf("replies %q", got)
	}
	// Single use.
	h.text(600, "private", "/start "+code, "en")
	if len(h.st.Telegram().Chats) != 1 {
		t.Fatal("a pairing code worked twice")
	}
}

func TestCodePastedByHandInAnyCase(t *testing.T) {
	h := newHarness(t)
	code, _ := h.bot.gate.NewCode(roleViewer)
	typed := strings.ToLower(code[:4]) + "-" + strings.ToLower(code[4:])
	h.text(501, "private", typed, "en")
	if c := h.st.Telegram().Chats; len(c) != 1 || c[0].Role != roleViewer {
		t.Fatalf("chats %+v", c)
	}
}

func TestOwnerCodeInAGroupGivesViewer(t *testing.T) {
	h := newHarness(t)
	code, _ := h.bot.gate.NewCode(roleOwner)
	h.text(-100, "supergroup", "/pair@home_wayhop_bot "+code, "en")
	c := h.st.Telegram().Chats
	if len(c) != 1 || c[0].Role != roleViewer || c[0].Name != "Group" {
		t.Fatalf("a group must never hold owner rights: %+v", c)
	}
}

func TestWrongCodesAreLimited(t *testing.T) {
	h := newHarness(t)
	code, _ := h.bot.gate.NewCode(roleOwner)
	for i := 0; i < maxBadCodes; i++ {
		h.text(502, "private", "/start ZZZZZZZZ", "en")
	}
	h.text(502, "private", "/start "+code, "en")
	if len(h.st.Telegram().Chats) != 0 {
		t.Fatal("the right code worked after the attempt limit")
	}
	got := h.sent()
	if !strings.Contains(got[len(got)-1], "Too many") {
		t.Fatalf("last reply %q", got[len(got)-1])
	}
}

func TestCodeExpires(t *testing.T) {
	h := newHarness(t)
	now := testNow
	h.bot.gate.now = func() time.Time { return now }
	code, _ := h.bot.gate.NewCode(roleOwner)
	now = now.Add(CodeTTL + time.Second)
	h.text(503, "private", "/start "+code, "en")
	if len(h.st.Telegram().Chats) != 0 {
		t.Fatal("an expired code paired a chat")
	}
}

func TestStatusCommandAndRefreshInPlace(t *testing.T) {
	h := newHarness(t, owner)
	h.text(500, "private", "/status", "en")
	got := h.sent()
	if len(got) != 1 {
		t.Fatalf("sent %q", got)
	}
	for _, want := range []string{"🟡 <b>Degraded</b> · 14:32", "🇳🇱 Netherlands, Amsterdam · <code>198.51.100.3</code>",
		"fast-eu → 🟢 nl-main · 42 ms", "Exits: 1 up · 1 down", "Core: sing-box running",
		"Traffic: ↓ 12.4 Mbit/s · ↑ 1.1 Mbit/s", "Router: RAM 41% · load 0.32 · up 6d 4h · 52°C"} {
		if !strings.Contains(got[0], want) {
			t.Fatalf("status lacks %q:\n%s", want, got[0])
		}
	}
	h.press(500, cbStatus)
	if e := h.edited(); len(e) != 1 || !strings.Contains(e[0], "Degraded") {
		t.Fatalf("refresh must edit in place, edited %q", e)
	}
	if len(h.sent()) != 1 {
		t.Fatal("refresh sent a new message")
	}
}

func TestExitListCardAndTest(t *testing.T) {
	h := newHarness(t, owner)
	h.press(500, cbExits)
	list := h.edited()[0]
	if strings.Index(list, "🔴 <b>de-backup") > strings.Index(list, "🟢 <b>nl-main") {
		t.Fatalf("down exits come first:\n%s", list)
	}
	h.press(500, cbExit+"de-backup")
	card := h.edited()[1]
	for _, want := range []string{"🔴 <b>de-backup</b> <i>(vless)</i>", "Cause: handshake did not complete", "Fix: check the server key"} {
		if !strings.Contains(card, want) {
			t.Fatalf("card lacks %q:\n%s", want, card)
		}
	}
	h.press(500, cbTest+"nl-main")
	if len(h.be.tested) != 1 || h.be.tested[0] != "nl-main" {
		t.Fatalf("tested %v", h.be.tested)
	}
	if res := h.edited()[2]; !strings.Contains(res, "Tested just now · 14:32") || !strings.Contains(res, "Latency 33 ms") {
		t.Fatalf("test result:\n%s", res)
	}
}

func TestTestFailureIsShownOnTheCard(t *testing.T) {
	h := newHarness(t, owner)
	h.be.testErr = errors.New("monitor not running")
	h.press(500, cbTest+"nl-main")
	if res := h.edited()[0]; !strings.Contains(res, "Test failed: monitor not running") {
		t.Fatalf("got:\n%s", res)
	}
}

func TestVanishedExitFallsBackToTheList(t *testing.T) {
	h := newHarness(t, owner)
	h.press(500, cbExit+"deleted-one")
	if res := h.edited()[0]; !strings.Contains(res, "no longer exists") || !strings.Contains(res, "<b>Exits</b>") {
		t.Fatalf("got:\n%s", res)
	}
}

func TestLongIDsGoThroughTheRefTable(t *testing.T) {
	h := newHarness(t, owner)
	long := "endpoint with spaces and a very long name that does not fit a callback"
	h.be.status.Exits = append(h.be.status.Exits, Exit{ID: long, Name: "long", State: StateAlive})
	text, kb := h.bot.view("en").Exits(h.be.status, 0)
	_ = text
	var data string
	for _, row := range kb.Rows {
		for _, b := range row {
			if b.Text == "🟢 long" {
				data = b.CallbackData
			}
			if len(b.CallbackData) > 64 {
				t.Fatalf("callback data over Telegram's 64 bytes: %q", b.CallbackData)
			}
		}
	}
	if !strings.HasPrefix(data, cbExit+"~") {
		t.Fatalf("long id not referenced: %q", data)
	}
	h.press(500, data)
	if !strings.Contains(h.edited()[0], "<b>long</b>") {
		t.Fatalf("ref did not resolve:\n%s", h.edited()[0])
	}
}

func TestEventsPaging(t *testing.T) {
	h := newHarness(t, owner)
	var evs []Event
	for i := 0; i < 23; i++ {
		evs = append(evs, Event{At: testNow.Add(-time.Duration(i) * time.Minute), Kind: "down", ID: fmt.Sprintf("e%d", i), Name: fmt.Sprintf("exit-%d", i)})
	}
	h.be.events = EventLog{Known: true, Events: evs, Since: testNow.Add(-3 * time.Hour), Total: 30}
	h.press(500, cbEvents+"0")
	p0 := h.edited()[0]
	if !strings.Contains(p0, "exit-0 went down") || strings.Contains(p0, "exit-10 ") {
		t.Fatalf("page 0:\n%s", p0)
	}
	if kb := string(h.api.callsTo("editMessageText")[0].Raw); !strings.Contains(kb, "Page 1 of 3") || !strings.Contains(kb, `"ev:1"`) {
		t.Fatalf("page 0 keyboard: %s", kb)
	}
	if !strings.Contains(p0, "since 11:32 (3h ago)") {
		t.Fatalf("the RAM-only window must be stated:\n%s", p0)
	}
	h.press(500, cbEvents+"2")
	p2 := h.edited()[1]
	if !strings.Contains(p2, "exit-22") || !strings.Contains(p2, "dropped from memory") {
		t.Fatalf("last page:\n%s", p2)
	}
}

func TestAlertsOnlyChatGetsNoState(t *testing.T) {
	h := newHarness(t, config.TelegramChat{ID: -200, Name: "Group", Role: roleAlerts, Lang: "en"})
	h.text(-200, "group", "/status", "en")
	if got := h.sent(); len(got) != 1 || !strings.Contains(got[0], "only receives alerts") {
		t.Fatalf("got %q", got)
	}
}

// A command queued at Telegram while the router was out of touch is not run when it finally
// arrives, and its sender is told so, once. Its age is measured when it arrives, on Telegram's own
// clock: against the bot's start, every command queued during an outage after the start was run,
// and against the router's clock a router that is ahead dropped fresh commands.
func TestLateCommandsAreNotRunAndTheSenderIsTold(t *testing.T) {
	viewerGroup := config.TelegramChat{ID: -300, Name: "Group", Role: roleViewer, Lang: "en"}
	for _, tc := range []struct {
		name    string
		chat    int64
		typ     string
		text    string
		sent    time.Time // the message's date
		recv    time.Time // when it arrived, by Telegram's clock (zero: unknown)
		routerT time.Time // the router's clock
		run     bool      // answered with the status
		told    bool      // got the late notice
	}{
		{"fresh", 500, "private", "/status", testNow, testNow.Add(2 * time.Second), testNow, true, false},
		{"fresh, router clock three hours ahead", 500, "private", "/status", testNow, testNow.Add(time.Second), testNow.Add(3 * time.Hour), true, false},
		{"after an outage the bot rode out", 500, "private", "/status", testNow, testNow.Add(40 * time.Minute), testNow.Add(40 * time.Minute), false, true},
		{"after an outage, router clock behind", 500, "private", "/status", testNow, testNow.Add(40 * time.Minute), testNow.Add(-time.Hour), false, true},
		{"no server time: the router's clock", 500, "private", "/status", testNow.Add(-3 * time.Hour), time.Time{}, testNow, false, true},
		{"a late site name in private", 500, "private", "youtube.com", testNow, testNow.Add(time.Hour), testNow, false, true},
		{"late group chatter", -300, "group", "hello all", testNow, testNow.Add(time.Hour), testNow, false, false},
		{"late command in a group", -300, "group", "/status@home_wayhop_bot", testNow, testNow.Add(time.Hour), testNow, false, true},
		{"late stranger", 777, "private", "/status", testNow, testNow.Add(time.Hour), testNow, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, owner, viewerGroup)
			h.bot.now = func() time.Time { return tc.routerT }
			h.bot.handle(context.Background(), Update{Message: &Message{Chat: Chat{ID: tc.chat, Type: tc.typ},
				Date: tc.sent.Unix(), Text: tc.text, From: &User{ID: 500, FirstName: "Sam"}, recv: tc.recv}})
			sent := h.sent()
			ran := len(sent) == 1 && strings.Contains(sent[0], "Degraded")
			told := len(sent) == 1 && strings.Contains(sent[0], "arrived only now")
			if ran != tc.run || told != tc.told || len(sent) > 1 {
				t.Fatalf("sent %q", sent)
			}
			if told && !strings.Contains(sent[0], "<code>"+esc(tc.text)+"</code> from "+(view{lang: "en", now: tc.routerT}).clock(tc.sent)) {
				t.Fatalf("the notice does not say which message, sent when: %q", sent[0])
			}
		})
	}
	// A backlog is told once, not once per message.
	h := newHarness(t, owner)
	for i := 0; i < 5; i++ {
		h.bot.handle(context.Background(), Update{Message: &Message{Chat: Chat{ID: 500, Type: "private"},
			Date: testNow.Add(-3 * time.Hour).Unix(), Text: "/restart", From: &User{ID: 500}}})
	}
	if sent := h.sent(); len(sent) != 1 || !strings.Contains(sent[0], "arrived only now") {
		t.Fatalf("backlog: %q", sent)
	}
	if h.be.restarts != 0 {
		t.Fatal("a late command was run")
	}
}

// The age of a command is read on the clock of the server that delivered it.
func TestPollUpdatesReportsTheServersTime(t *testing.T) {
	f := newFakeAPI(t)
	_, at, err := f.client().pollUpdates(context.Background(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(at); at.IsZero() || d < -5*time.Second || d > 5*time.Second {
		t.Fatalf("server time %v (%v off)", at, d)
	}
}

func TestCommandForAnotherBotIsIgnored(t *testing.T) {
	h := newHarness(t, config.TelegramChat{ID: -300, Name: "Group", Role: roleViewer, Lang: "en"})
	h.text(-300, "group", "/status@other_bot", "en")
	h.text(-300, "group", "good morning everyone", "en")
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("got %q", got)
	}
	h.text(-300, "group", "/status@Home_WayHop_Bot", "en")
	if len(h.sent()) != 1 {
		t.Fatal("a command addressed to this bot was ignored")
	}
}

func TestLanguageSwitchPersists(t *testing.T) {
	h := newHarness(t, owner)
	h.press(500, cbLang+"ru")
	if c := h.st.Telegram().Chats[0]; c.Lang != "ru" {
		t.Fatalf("lang %q", c.Lang)
	}
	if e := h.edited(); !strings.Contains(e[0], "Частичный сбой") {
		t.Fatalf("not re-rendered in Russian:\n%s", e[0])
	}
	h.press(500, cbLang+"xx")
	if c := h.st.Telegram().Chats[0]; c.Lang != "ru" {
		t.Fatal("an unknown language was stored")
	}
}

func TestUnknownButtonShowsThePresent(t *testing.T) {
	h := newHarness(t, owner)
	h.press(500, "v0:gone")
	if e := h.edited(); len(e) != 1 || !strings.Contains(e[0], "Degraded") {
		t.Fatalf("got %q", e)
	}
}

func TestHandlerPanicIsContained(t *testing.T) {
	h := newHarness(t, owner)
	h.be.panics = true
	h.bot.dispatch(context.Background(), Update{Message: &Message{Chat: Chat{ID: 500, Type: "private"},
		Date: testNow.Unix(), Text: "/status", From: &User{ID: 500}}})
	h.bot.wg.Wait() // would never return, or the test binary would crash, without the recover
}

func TestRunConnectsPublishesMenuAndServes(t *testing.T) {
	h := newHarness(t, owner)
	h.api.on("getMe", func(map[string]any) (int, string) {
		return 200, `{"ok":true,"result":{"id":1,"is_bot":true,"first_name":"Home","username":"home_wayhop_bot"}}`
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var polls int
	var pmu sync.Mutex
	h.api.on("getUpdates", func(p map[string]any) (int, string) {
		pmu.Lock()
		defer pmu.Unlock()
		polls++
		if polls == 1 {
			return 200, fmt.Sprintf(`{"ok":true,"result":[{"update_id":7,"message":{"message_id":1,"date":%d,"text":"/status","chat":{"id":500,"type":"private"},"from":{"id":500,"first_name":"Sam"}}}]}`, time.Now().Unix()) // dated on the clock the fake's Date header is on
		}
		if p["offset"] != float64(8) {
			t.Errorf("offset not advanced: %v", p["offset"])
		}
		// Let the worker finish its reply before the loop is stopped.
		for i := 0; i < 500 && len(h.api.callsTo("sendMessage")) == 0; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		return 200, `{"ok":true,"result":[]}`
	})
	done := make(chan struct{})
	go func() { h.bot.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
	// One default menu and one per client language answered in something other than English, in
	// that language: a Belarusian client gets the Russian menu it gets its replies in.
	menus := map[string]string{}
	for _, c := range h.api.callsTo("setMyCommands") {
		code, _ := c.Params["language_code"].(string)
		menus[code] = c.Params["commands"].([]any)[0].(map[string]any)["description"].(string)
	}
	if len(menus) != 1+len(clientLangs) || menus[""] != T("en", "cmd.status") ||
		menus["be"] != T("ru", "cmd.status") || menus["uk"] != T("uk", "cmd.status") {
		t.Fatalf("menus %q", menus)
	}
	if len(h.api.callsTo("deleteWebhook")) != 1 {
		t.Fatal("a leftover webhook would 409 every poll")
	}
	if got := h.sent(); len(got) != 1 || !strings.Contains(got[0], "Degraded") {
		t.Fatalf("sent %q", got)
	}
	if i := h.bot.Info(); i.State != StateOnline || i.Username != "home_wayhop_bot" {
		t.Fatalf("info %+v", i)
	}
}

func TestRunReportsARejectedToken(t *testing.T) {
	h := newHarness(t)
	h.api.on("getMe", func(map[string]any) (int, string) {
		return 401, `{"ok":false,"error_code":401,"description":"Unauthorized"}`
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.bot.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for h.bot.Info().State != StateUnauthorized {
		if time.Now().After(deadline) {
			t.Fatalf("state %+v", h.bot.Info())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

// A proxy's own 404 in front of the Bot API is a path that does not work yet, not a revoked token:
// the bot keeps retrying with its backoff instead of sleeping ten minutes as "unauthorized", and
// the state it shows names the page, never the token.
func TestRunTreatsAProxyErrorPageAsTheNetwork(t *testing.T) {
	h := newHarness(t)
	var calls int32
	var mu sync.Mutex
	h.api.on("getMe", func(map[string]any) (int, string) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return 404, "<html>404 Not Found: /bot" + testToken + "/getMe</html>"
		}
		return 200, `{"ok":true,"result":{"id":1,"is_bot":true,"first_name":"Home","username":"home_wayhop_bot"}}`
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.bot.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	sawError := false
	for h.bot.Info().State != StateOnline {
		i := h.bot.Info()
		if i.State == StateUnauthorized {
			t.Fatalf("a proxy page read as a rejected token: %+v", i)
		}
		if i.State == StateError {
			sawError = true
			if strings.Contains(i.Error, strings.SplitN(testToken, ":", 2)[1]) {
				t.Fatalf("token in the state: %q", i.Error)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("did not come online after the page went away: %+v", i)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if !sawError {
		t.Log("the error state was not sampled; the retry still came within the 1s backoff")
	}
}

// Every status the bot shows is drawn for the chat's own role and mute. After pairing, a language
// switch and the panel's welcome it was drawn as if for nobody: an owner lost Keep / Roll back in
// the middle of a test Apply, and a muted chat the line saying so.
func TestStatusAlwaysCarriesTheChatsRole(t *testing.T) {
	for _, tc := range []struct {
		name  string
		role  string
		muted bool
		show  func(h *harness)
	}{
		{"paired with an owner code", roleOwner, false, func(h *harness) {
			code, _ := h.bot.gate.NewCode(roleOwner)
			h.text(500, "private", "/start "+code, "en")
		}},
		{"language switched", roleOwner, true, func(h *harness) {
			_ = h.st.UpdateTelegram(func(tg *config.Telegram) error { tg.Chats = []config.TelegramChat{owner}; return nil })
			h.bot.out.mute(500, testNow.Add(time.Hour))
			h.press(500, cbLang+"en")
		}},
		{"welcomed from the panel", roleOwner, true, func(h *harness) {
			_ = h.st.UpdateTelegram(func(tg *config.Telegram) error { tg.Chats = []config.TelegramChat{owner}; return nil })
			h.bot.out.mute(500, testNow.Add(time.Hour))
			m := NewManager(h.be, h.st, nil)
			m.cur, m.api = h.bot, h.bot.api
			if err := m.Welcome(context.Background(), owner); err != nil {
				h.t.Fatal(err)
			}
		}},
		{"a viewer still gets no Keep", roleViewer, false, func(h *harness) {
			code, _ := h.bot.gate.NewCode(roleViewer)
			h.text(500, "private", "/start "+code, "en")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.be.status.FailSafe = FailSafe{Armed: true, Remaining: 3 * time.Minute, Window: "w1"}
			tc.show(h)
			calls := append(h.api.callsTo("sendMessage"), h.api.callsTo("editMessageText")...)
			var status apiCall
			for _, c := range calls {
				if strings.Contains(c.Params["text"].(string), "Test Apply awaiting confirmation") {
					status = c
				}
			}
			if status.Method == "" {
				t.Fatalf("no status shown: %q", h.sent())
			}
			kb, text := toJSON(status.Params["reply_markup"]), status.Params["text"].(string)
			if keep := strings.Contains(kb, `"ak:w1"`); keep != (tc.role == roleOwner) {
				t.Fatalf("Keep offered=%v to a %s: %s", keep, tc.role, kb)
			}
			if muted := strings.Contains(text, "Alerts muted until"); muted != tc.muted {
				t.Fatalf("mute line shown=%v: %s", muted, text)
			}
		})
	}
}

// A view is edited in place. Only a message Telegram refuses for good (a Bad Request: too old,
// deleted) gets the view as a new message; flood control is waited out and the edit tried again,
// and a server error or a page that is not Telegram's leaves no second copy behind.
func TestShowSendsANewMessageOnlyWhenTheOldOneIsGone(t *testing.T) {
	for _, tc := range []struct {
		name   string
		first  [2]any // the first edit's answer: status, body
		edits  int
		sends  int
		minDur time.Duration
	}{
		{"edited", [2]any{200, `{"ok":true,"result":true}`}, 1, 0, 0},
		{"message gone", [2]any{400, `{"ok":false,"error_code":400,"description":"Bad Request: message to edit not found"}`}, 1, 1, 0},
		{"too old to edit", [2]any{400, `{"ok":false,"error_code":400,"description":"Bad Request: message can't be edited"}`}, 1, 1, 0},
		{"flood control, short", [2]any{429, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 1","parameters":{"retry_after":1}}`}, 2, 0, time.Second},
		{"flood control, too long to wait", [2]any{429, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 300","parameters":{"retry_after":300}}`}, 1, 0, 0},
		{"server error", [2]any{500, `{"ok":false,"error_code":500,"description":"Internal Server Error"}`}, 1, 0, 0},
		{"proxy page", [2]any{502, "<html>Bad Gateway</html>"}, 1, 0, 0},
		{"chat blocked the bot", [2]any{403, `{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`}, 1, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, owner)
			var n atomic.Int32
			h.api.on("editMessageText", func(map[string]any) (int, string) {
				if n.Add(1) == 1 {
					return tc.first[0].(int), tc.first[1].(string)
				}
				return 200, `{"ok":true,"result":true}`
			})
			start := time.Now()
			h.press(500, cbStatus)
			if e, s := len(h.api.callsTo("editMessageText")), len(h.api.callsTo("sendMessage")); e != tc.edits || s != tc.sends {
				t.Fatalf("edits %d (want %d), sends %d (want %d)", e, tc.edits, s, tc.sends)
			}
			if time.Since(start) < tc.minDur {
				t.Fatal("the flood-control wait was not honoured")
			}
		})
	}
}

// A reply refused by flood control is sent again after the wait Telegram names.
func TestReplyWaitsOutFloodControl(t *testing.T) {
	h := newHarness(t, owner)
	var n atomic.Int32
	h.api.on("sendMessage", func(map[string]any) (int, string) {
		if n.Add(1) == 1 {
			return 429, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 1","parameters":{"retry_after":1}}`
		}
		return 200, `{"ok":true,"result":{"message_id":3,"chat":{"id":500,"type":"private"},"date":1}}`
	})
	h.text(500, "private", "/status", "en")
	if got := n.Load(); got != 2 {
		t.Fatalf("%d sends, want the refused one and its retry", got)
	}
}

// A pairing code issued without a role, or with one the bot does not know, pairs a viewer: never an
// owner, who can apply, restart and download every secret.
func TestPairingCodeRoleDefaultsToViewer(t *testing.T) {
	for _, tc := range []struct{ asked, got string }{
		{"", roleViewer}, {"admin", roleViewer}, {"OWNER", roleViewer},
		{roleOwner, roleOwner}, {roleViewer, roleViewer}, {roleAlerts, roleAlerts},
	} {
		g := NewGate()
		code, _ := g.NewCode(tc.asked)
		if role, res := g.Redeem(Chat{ID: 1, Type: "private"}, code); res != RedeemOK || role != tc.got {
			t.Errorf("code for %q paired a %q (%v), want %q", tc.asked, role, res, tc.got)
		}
	}
}

// Wrong codes are remembered for their hour, per chat, and no longer: a stream of wrong codes from
// ever new chats grew the map for the life of the daemon. The limit itself still holds.
func TestWrongCodesAreForgottenAndBounded(t *testing.T) {
	g := NewGate()
	now := testNow
	g.now = func() time.Time { return now }
	for id := int64(1); id <= maxBadChats+50; id++ {
		g.Redeem(Chat{ID: id, Type: "private"}, "ZZZZZZZZ")
	}
	if n := len(g.bad); n > maxBadChats {
		t.Fatalf("%d chats remembered, cap %d", n, maxBadChats)
	}
	for i := 0; i < maxBadCodes; i++ {
		g.Redeem(Chat{ID: 9999, Type: "private"}, "ZZZZZZZZ")
	}
	if _, res := g.Redeem(Chat{ID: 9999, Type: "private"}, "ZZZZZZZZ"); res != RedeemLimited {
		t.Fatalf("the limit no longer holds: %v", res)
	}
	now = now.Add(badCodeWindow)
	g.Strangers() // any visit to the gate prunes
	if n := len(g.bad); n != 0 {
		t.Fatalf("%d chats still remembered after their hour", n)
	}
}
