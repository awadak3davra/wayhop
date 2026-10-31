package tgbot

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wayhop/internal/config"
)

var (
	viewerChat = config.TelegramChat{ID: 600, Name: "Mom", Role: roleViewer, Lang: "ru"}
	alertsChat = config.TelegramChat{ID: -700, Name: "Family", Role: roleAlerts, Lang: "en"}
)

func (h *harness) deliver(a Alert) {
	h.t.Helper()
	q := &queued{a: a, done: map[int64]bool{}}
	if err := h.bot.deliver(context.Background(), q); err != nil {
		h.t.Fatalf("deliver: %v", err)
	}
}

func (h *harness) sendsTo(chat int64) []apiCall {
	var out []apiCall
	for _, c := range h.api.callsTo("sendMessage") {
		if int64(c.Params["chat_id"].(float64)) == chat {
			out = append(out, c)
		}
	}
	return out
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func downUp() (Alert, Alert) {
	s := sampleStatus()
	return exitDown(evAt(10, "down", "de-backup", "de-backup"), s), exitUp(evAt(130, "up", "de-backup", "de-backup"), 2*time.Minute)
}

func TestAlertReachesEveryChatInItsLanguageAndRole(t *testing.T) {
	h := newHarness(t, owner, viewerChat, alertsChat)
	down, _ := downUp()
	h.deliver(down)
	o, v, a := h.sendsTo(500), h.sendsTo(600), h.sendsTo(-700)
	if len(o) != 1 || len(v) != 1 || len(a) != 1 {
		t.Fatalf("owner %d viewer %d alerts %d", len(o), len(v), len(a))
	}
	if !strings.Contains(o[0].Params["text"].(string), "is down") || !strings.Contains(v[0].Params["text"].(string), "недоступен") {
		t.Fatalf("languages: %q / %q", o[0].Params["text"], v[0].Params["text"])
	}
	if _, has := a[0].Params["reply_markup"]; has {
		t.Fatal("an alerts-only chat got buttons")
	}
	if o[0].Params["disable_notification"] == true {
		t.Fatal("a warning must ring")
	}
}

func TestSwitchedOffKindIsNotSent(t *testing.T) {
	h := newHarness(t, owner)
	_ = h.st.UpdateTelegram(func(tg *config.Telegram) error { tg.AlertsOff = []string{KindExits}; return nil })
	down, _ := downUp()
	h.deliver(down)
	if len(h.sent()) != 0 {
		t.Fatal("a switched-off kind was sent")
	}
}

func TestRecoveryRepliesToTheOutage(t *testing.T) {
	h := newHarness(t, owner)
	down, up := downUp()
	h.deliver(down)
	h.deliver(up)
	calls := h.sendsTo(500)
	if len(calls) != 2 {
		t.Fatalf("sent %d", len(calls))
	}
	downID := int64(0)
	for i, c := range h.api.calls {
		if c.Method == "sendMessage" {
			downID = int64(i + 1) // the fake numbers messages by call order
			break
		}
	}
	rp, _ := calls[1].Params["reply_parameters"].(map[string]any)
	if rp == nil || int64(rp["message_id"].(float64)) != downID {
		t.Fatalf("the recovery is not a reply to the outage: %v (want %d)", calls[1].Params["reply_parameters"], downID)
	}
	if calls[1].Params["disable_notification"] != true {
		t.Fatal("a recovery is good news and should arrive silently")
	}
	if _, open := h.bot.out.openMsg(500, "exit:de-backup"); open {
		t.Fatal("the incident stays open after its recovery")
	}
}

func TestApplyCountdownEditsAndTheOutcomeCloses(t *testing.T) {
	h := newHarness(t, owner, viewerChat)
	armed := applyArmed(testNow, FailSafePulse{Pending: true, SecondsLeft: 300})
	h.deliver(armed)
	if kb := h.sendsTo(500)[0].Params["reply_markup"]; !strings.Contains(toJSON(kb), cbKeep) {
		t.Fatalf("owner keyboard %v", kb)
	}
	if kb := h.sendsTo(600)[0].Params["reply_markup"]; strings.Contains(toJSON(kb), cbKeep) {
		t.Fatalf("viewer keyboard %v", kb)
	}
	h.deliver(applyCountdown(testNow, FailSafePulse{Pending: true, SecondsLeft: 250}))
	edits := h.edited()
	if len(edits) != 2 || !strings.Contains(edits[0], "4:10") {
		t.Fatalf("countdown edits %q", edits)
	}
	if len(h.sent()) != 2 {
		t.Fatal("a countdown sent new messages")
	}
	// Rolled back: loud, as a reply, and the armed message loses its buttons.
	h.deliver(applyClosed(testNow, "al.apply.rolledback", SevCritical, false))
	if len(h.sent()) != 4 {
		t.Fatalf("rollback notices %d", len(h.sent()))
	}
	last := h.api.callsTo("editMessageText")
	closing := last[len(last)-1]
	if !strings.Contains(closing.Params["text"].(string), "Rolled back") && !strings.Contains(closing.Params["text"].(string), "Откат") {
		t.Fatalf("closing edit %q", closing.Params["text"])
	}
	if _, has := closing.Params["reply_markup"]; has {
		t.Fatal("the closed message kept its Keep/Roll back buttons")
	}
	// A countdown after the end has nothing to edit.
	before := len(h.edited())
	h.deliver(applyCountdown(testNow, FailSafePulse{Pending: true, SecondsLeft: 10}))
	if len(h.edited()) != before {
		t.Fatal("edited a closed incident")
	}
}

func TestQuietHoursHoldAndSummarise(t *testing.T) {
	h := newHarness(t, owner)
	_ = h.st.UpdateTelegram(func(tg *config.Telegram) error { tg.QuietFrom, tg.QuietTo = "14:00", "15:00"; return nil })
	down, up := downUp()
	h.deliver(down)
	h.deliver(up)
	h.deliver(uplinkLost(testNow))
	sent := h.sent()
	if len(sent) != 1 || !strings.Contains(sent[0], "No internet") {
		t.Fatalf("during quiet hours only the critical alert goes out: %q", sent)
	}
	h.bot.flushHeld(context.Background())
	if len(h.sent()) != 1 {
		t.Fatal("summary sent while still quiet")
	}
	later := testNow.Add(40 * time.Minute) // 15:12
	h.bot.now = func() time.Time { return later }
	h.bot.flushHeld(context.Background())
	sent = h.sent()
	if len(sent) != 2 {
		t.Fatalf("after quiet hours: %q", sent)
	}
	sum := sent[1]
	for _, want := range []string{"While alerts were held</b> (2)", "<code>14:32</code> 🔴 <b>de-backup</b> is down", "is back"} {
		if !strings.Contains(sum, want) {
			t.Fatalf("summary lacks %q:\n%s", want, sum)
		}
	}
	if len(h.bot.out.heldChats()) != 0 {
		t.Fatal("held alerts not cleared")
	}
}

func TestMuteFromTheButtonAndUnmute(t *testing.T) {
	h := newHarness(t, owner)
	h.press(500, cbMute+"60")
	a := h.api.callsTo("answerCallbackQuery")
	if len(a) != 1 || !strings.Contains(a[0].Params["text"].(string), "muted until 15:32") {
		t.Fatalf("answer %v", a)
	}
	down, _ := downUp()
	h.deliver(down)
	if len(h.sent()) != 0 {
		t.Fatal("a muted chat got a warning")
	}
	h.deliver(applyArmed(testNow, FailSafePulse{Pending: true, SecondsLeft: 300}))
	if len(h.sent()) != 1 {
		t.Fatal("a mute held a Keep/Roll back request")
	}
	h.text(500, "private", "/status", "en")
	if s := h.sent(); !strings.Contains(s[len(s)-1], "Alerts muted until 15:32") {
		t.Fatalf("status does not show the mute:\n%s", s[len(s)-1])
	}
	h.press(500, cbMute+"0")
	h.bot.flushHeld(context.Background())
	if s := h.sent(); !strings.Contains(s[len(s)-1], "While alerts were held</b> (1)") {
		t.Fatalf("after unmute:\n%s", s[len(s)-1])
	}
}

func TestMuteCommand(t *testing.T) {
	h := newHarness(t, owner)
	h.text(500, "private", "/mute 30", "en")
	if s := h.sent(); len(s) != 1 || !strings.Contains(s[0], "until 15:02") {
		t.Fatalf("got %q", s)
	}
	h.text(500, "private", "/unmute", "en")
	if s := h.sent(); !strings.Contains(s[1], "Alerts are on") {
		t.Fatalf("got %q", s)
	}
}

// Telegram unreachable mid-delivery: the alert stays queued and later reaches only the chats that
// did not get it yet.
func TestDeliveryRetriesWithoutDuplicates(t *testing.T) {
	h := newHarness(t, owner, viewerChat)
	var fail atomic.Bool
	fail.Store(false)
	var n atomic.Int32
	h.api.on("sendMessage", func(p map[string]any) (int, string) {
		if p["chat_id"] == float64(600) && fail.Load() {
			return 502, "<html>Bad Gateway</html>"
		}
		n.Add(1)
		return 200, `{"ok":true,"result":{"message_id":` + strconv.Itoa(int(n.Load())) + `,"chat":{"id":1,"type":"private"},"date":1}}`
	})
	fail.Store(true)
	down, _ := downUp()
	q := &queued{a: down, done: map[int64]bool{}}
	if err := h.bot.deliver(context.Background(), q); err == nil || !retryable(err) {
		t.Fatalf("want a retryable error, got %v", err)
	}
	fail.Store(false)
	if err := h.bot.deliver(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if o, v := len(h.sendsTo(500)), len(h.sendsTo(600)); o != 1 || v != 2 {
		t.Fatalf("owner got %d (want 1), viewer calls %d (want 2: failed + retried)", o, v)
	}
}

func TestBlockedChatDoesNotStopTheOthers(t *testing.T) {
	h := newHarness(t, viewerChat, owner)
	h.api.on("sendMessage", func(p map[string]any) (int, string) {
		if p["chat_id"] == float64(600) {
			return 403, `{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`
		}
		return 200, `{"ok":true,"result":{"message_id":5,"chat":{"id":500,"type":"private"},"date":1}}`
	})
	down, _ := downUp()
	h.deliver(down)
	if len(h.sendsTo(500)) != 1 {
		t.Fatal("the owner did not get the alert after another chat blocked the bot")
	}
}

// A provider's block page answers 403 too. It is not the chat refusing the bot: the alert stays
// queued for the next try, and nobody is told the chat stopped accepting messages.
func TestBlockPageIsNotABlockedChat(t *testing.T) {
	for _, status := range []int{403, 404, 401} {
		h := newHarness(t, viewerChat, owner)
		h.api.on("sendMessage", func(map[string]any) (int, string) {
			return status, "<html><body>Access to this resource is restricted</body></html>"
		})
		down, _ := downUp()
		q := &queued{a: down, done: map[int64]bool{}}
		err := h.bot.deliver(context.Background(), q)
		if err == nil || !retryable(err) || len(q.done) != 0 {
			t.Fatalf("%d: err %v, done %v: the alert must stay queued for every chat", status, err, q.done)
		}
		if h.bot.out.markReachable(600) || len(h.bot.out.q) != 0 {
			t.Fatalf("%d: the chat was marked as refusing the bot", status)
		}
	}
}

func TestKeepAndRollBackFromTheChat(t *testing.T) {
	h := newHarness(t, owner, viewerChat)
	window := FailSafePulse{Pending: true, SecondsLeft: 300, Window: "w1"}
	h.be.pulse.FailSafe = window
	h.deliver(applyArmed(testNow, window))
	if kb := toJSON(h.sendsTo(500)[0].Params["reply_markup"]); !strings.Contains(kb, `"ak:w1"`) || !strings.Contains(kb, `"ar:w1"`) {
		t.Fatalf("the buttons do not name their test Apply: %s", kb)
	}
	h.press(600, cbKeep+"w1")
	if h.be.kept != 0 {
		t.Fatal("a viewer kept a test Apply")
	}
	if a := h.api.callsTo("answerCallbackQuery"); a[0].Params["show_alert"] != true {
		t.Fatalf("viewer refusal %v", a[0].Params)
	}
	h.press(500, cbKeep+"w1")
	if h.be.kept != 1 {
		t.Fatal("keep did not reach the router")
	}
	if e := h.edited(); len(e) != 1 || !strings.Contains(e[0], "Kept by Sam · 14:32") {
		t.Fatalf("edit %q", e)
	}
	// Found on the demo: the watcher's closing edit then overwrote "Kept by Sam" with the generic
	// outcome. The chat that decided keeps its attribution.
	ownerEdits := func() int {
		n := 0
		for _, c := range h.api.callsTo("editMessageText") {
			if c.Params["chat_id"] == float64(500) {
				n++
			}
		}
		return n
	}
	before := ownerEdits()
	h.deliver(applyClosed(testNow, "al.apply.kept", SevInfo, true))
	if ownerEdits() != before {
		t.Fatal("the closing edit overwrote the owner's attribution")
	}
	if last := h.api.callsTo("editMessageText"); last[len(last)-1].Params["chat_id"] != float64(600) {
		t.Fatal("the viewer's copy was not closed")
	}
	// A failure is a message in the chat: the press was acknowledged at once, before the slow work,
	// and a toast would hold 200 characters for a moment.
	h.be.decideErr = errContains("there is no unsaved configuration to keep")
	h.press(500, cbRollback+"w1")
	a := h.api.callsTo("answerCallbackQuery")
	if last := a[len(a)-1]; last.Params["text"] != "⏳" {
		t.Fatalf("the press was not acknowledged first: %v", last.Params)
	}
	sent := h.sendsTo(500)
	if text := sent[len(sent)-1].Params["text"].(string); text != "⚠️ Did not work: there is no unsaved configuration to keep" {
		t.Fatalf("failure message %q", text)
	}
}

// Telegram refuses an answer to a button press longer than 200 characters, and the press then
// shows nothing at all.
func TestButtonAnswersFitTelegramsLimit(t *testing.T) {
	f := newFakeAPI(t)
	if err := f.client().AnswerCallback(context.Background(), "q", strings.Repeat("é", 500), true); err != nil {
		t.Fatal(err)
	}
	if n := len([]rune(f.callsTo("answerCallbackQuery")[0].Params["text"].(string))); n != maxAnswer {
		t.Fatalf("%d characters", n)
	}
}

type errContains string

func (e errContains) Error() string { return string(e) }

func TestStatusOffersKeepToOwnersOnly(t *testing.T) {
	h := newHarness(t, owner, viewerChat)
	h.be.status.FailSafe = FailSafe{Armed: true, Remaining: 3 * time.Minute}
	h.text(500, "private", "/status", "en")
	h.text(600, "private", "/status", "ru")
	o, v := h.sendsTo(500), h.sendsTo(600)
	if !strings.Contains(string(o[0].Raw), cbKeep) {
		t.Fatal("an owner's status lacks Keep while a test Apply runs")
	}
	if strings.Contains(string(v[0].Raw), `"ak"`) {
		t.Fatal("a viewer's status offers Keep")
	}
}

func TestManagerSendsTheBootAlertOnce(t *testing.T) {
	api := newFakeAPI(t)
	api.on("getMe", func(map[string]any) (int, string) {
		return 200, `{"ok":true,"result":{"id":1,"is_bot":true,"first_name":"Home","username":"home_wayhop_bot"}}`
	})
	api.on("getUpdates", func(map[string]any) (int, string) {
		time.Sleep(20 * time.Millisecond)
		return 200, `{"ok":true,"result":[]}`
	})
	st := &fakeStore{t: config.Telegram{Enabled: true, Token: testToken, APIBase: api.srv.URL, Chats: []config.TelegramChat{owner}}}
	be := &fakeBackend{status: sampleStatus(), boot: BootInfo{DaemonStart: time.Now().Add(-time.Minute), RouterUp: 90 * 24 * time.Hour, Version: "0.5.7"}}
	m := NewManager(be, st, func(config.Telegram) *http.Client { return api.srv.Client() })
	m.logf = t.Logf
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	waitFor(t, "boot alert", func() bool { return len(api.callsTo("sendMessage")) == 1 })
	if txt := api.callsTo("sendMessage")[0].Params["text"].(string); txt != "🔄 WayHop restarted (0.5.7)." {
		t.Fatalf("boot alert %q", txt)
	}
	_ = st.UpdateTelegram(func(tg *config.Telegram) error { tg.Via = "nl"; return nil })
	m.Reload()
	time.Sleep(200 * time.Millisecond)
	if n := len(api.callsTo("sendMessage")); n != 1 {
		t.Fatalf("a bot restart repeated the boot alert (%d)", n)
	}
}

// drain delivers the queue the way deliverLoop does, without its pauses.
func (h *harness) drain() {
	h.t.Helper()
	for q := h.bot.out.peek(); q != nil; q = h.bot.out.peek() {
		if err := h.bot.deliver(context.Background(), q); err != nil {
			h.t.Fatalf("deliver: %v", err)
		}
		h.bot.out.pop(q)
	}
}

func silent(c apiCall) bool { return c.Params["disable_notification"] == true }

// An outage that came through at night is followed by its all-clear, not by silence until the
// morning: the end of an incident goes the way its beginning went. One whose beginning was held is
// held with it.
func TestRecoveryFollowsItsOutageThroughQuietHours(t *testing.T) {
	down, up := downUp()
	for _, tc := range []struct {
		name        string
		open, end   Alert
		quietBefore bool // quiet hours already on when the outage is delivered
		mute        bool // the chat is muted instead
		wantSends   int  // messages sent at once
		wantHeld    int  // alerts held for the summary
	}{
		{"uplink at night", uplinkLost(testNow), uplinkBack(testNow.Add(time.Minute), time.Minute), true, false, 2, 0},
		{"core at night", coreDown(testNow, time.Minute, ""), coreUp(testNow.Add(time.Minute), 2*time.Minute), true, false, 2, 0},
		{"uplink while muted", uplinkLost(testNow), uplinkBack(testNow.Add(time.Minute), time.Minute), false, true, 2, 0},
		{"exit told before quiet hours began", down, up, false, false, 2, 0},
		{"exit held at night, end held too", down, up, true, false, 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, owner)
			quiet := func() {
				_ = h.st.UpdateTelegram(func(tg *config.Telegram) error { tg.QuietFrom, tg.QuietTo = "14:00", "15:00"; return nil })
			}
			if tc.quietBefore {
				quiet()
			}
			if tc.mute {
				h.bot.out.mute(500, testNow.Add(time.Hour))
			}
			h.deliver(tc.open)
			if !tc.quietBefore && !tc.mute {
				quiet() // the night begins between the outage and its end
			}
			h.deliver(tc.end)
			sent := h.sendsTo(500)
			if len(sent) != tc.wantSends || len(h.bot.out.held[500]) != tc.wantHeld {
				t.Fatalf("sent %d (want %d), held %d (want %d)", len(sent), tc.wantSends, len(h.bot.out.held[500]), tc.wantHeld)
			}
			if tc.wantSends == 2 {
				if rp, _ := sent[1].Params["reply_parameters"].(map[string]any); rp == nil {
					t.Fatal("the all-clear does not reply to its outage")
				}
				if !silent(sent[1]) {
					t.Fatal("the all-clear must not ring at night")
				}
			}
		})
	}
}

// An outage that cut Telegram off and its end, both still queued when the link returns, are one
// silent message with how long it lasted: a loud "no internet" arriving after the internet came
// back was a false alarm with the all-clear right behind it.
func TestOutageAndItsEndQueuedTogetherAreOneQuietMessage(t *testing.T) {
	at := func(min int) time.Time { return testNow.Add(time.Duration(min) * time.Minute) }
	evs := func(min int, kind string, ids ...string) []Event {
		var out []Event
		for _, id := range ids {
			out = append(out, Event{At: at(min), Kind: kind, ID: id, Name: id})
		}
		return out
	}
	ups := func(min int, ids ...string) []upEvent {
		var out []upEvent
		for _, e := range evs(min, "up", ids...) {
			out = append(out, upEvent{e, 5 * time.Minute})
		}
		return out
	}
	for _, tc := range []struct {
		name   string
		alerts []Alert
		quiet  bool
		sends  int    // messages sent
		want   string // in the first one
		loud   bool   // the first one rings
		held   int
	}{
		{"uplink", []Alert{uplinkLost(at(-20)), uplinkBack(at(-5), 15*time.Minute)}, false, 1, "out 14:12–14:27", false, 0},
		{"uplink at night comes through, quietly", []Alert{uplinkLost(at(-20)), uplinkBack(at(-5), 15*time.Minute)}, true, 1, "Internet is back", false, 0},
		{"core", []Alert{coreDown(at(-20), time.Minute, ""), coreUp(at(-5), 15*time.Minute)}, false, 1, "out 14:12–14:27", false, 0},
		{"a burst and its whole end", []Alert{manyDown(evs(-20, "down", "a", "b", "c"), Status{}), manyUp(ups(-5, "a", "b", "c"))}, false, 1, "3 exits are back", false, 0},
		{"an exit at night waits for the summary", []Alert{exitDown(evs(-20, "down", "a")[0], Status{}), exitUp(evs(-5, "up", "a")[0], 15*time.Minute)}, true, 0, "", false, 1},
		{"a partial end is its own news", []Alert{manyDown(evs(-20, "down", "a", "b", "c"), Status{}), exitUp(evs(-5, "up", "a")[0], 15*time.Minute)}, false, 2, "3 exits are down", true, 0},
		{"a loud end is not merged", []Alert{applyArmed(at(-20), FailSafePulse{Pending: true}), applyClosed(at(-5), "al.apply.rolledback", SevCritical, false)}, false, 2, "", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, owner)
			if tc.quiet {
				_ = h.st.UpdateTelegram(func(tg *config.Telegram) error { tg.QuietFrom, tg.QuietTo = "14:00", "15:00"; return nil })
			}
			for _, a := range tc.alerts {
				h.bot.out.push(a)
			}
			h.drain()
			sent := h.sendsTo(500)
			if len(sent) != tc.sends || len(h.bot.out.held[500]) != tc.held {
				t.Fatalf("sent %d (want %d), held %d (want %d): %v", len(sent), tc.sends, len(h.bot.out.held[500]), tc.held, h.sent())
			}
			if tc.sends == 0 {
				return
			}
			if text := sent[0].Params["text"].(string); !strings.Contains(text, tc.want) {
				t.Fatalf("first message lacks %q:\n%s", tc.want, text)
			}
			if silent(sent[0]) == tc.loud {
				t.Fatalf("first message silent=%v", silent(sent[0]))
			}
			if tc.sends == 1 {
				if _, open := h.bot.out.openMsg(500, tc.alerts[0].incidents()[0]); open {
					t.Fatal("the merged message left its incident open")
				}
				if strings.Contains(sent[0].Params["text"].(string), "delivered late") {
					t.Fatal("the merged message already says when; it needs no late stamp")
				}
			}
		})
	}
}

// An alert delivered more than a minute after it happened says when that was, on the router's
// clock: a queue that waited out an outage must not read as news of now.
func TestLateAlertSaysWhenItHappened(t *testing.T) {
	msk := time.FixedZone("MSK", 3*3600)
	for _, tc := range []struct {
		name string
		at   time.Time
		want string // "" = no stamp
	}{
		{"on time", testNow.Add(-30 * time.Second), ""},
		{"a minute is not late", testNow.Add(-time.Minute), ""},
		{"five minutes late", testNow.Add(-5 * time.Minute), "🕒 at 17:27, delivered late"},
		{"yesterday", testNow.Add(-20 * time.Hour), "🕒 at 22 Sep 21:32, delivered late"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, owner)
			h.bot.now = func() time.Time { return testNow.In(msk) }
			h.deliver(coreDown(tc.at, time.Minute, ""))
			text := h.sendsTo(500)[0].Params["text"].(string)
			if tc.want == "" && strings.Contains(text, "delivered late") || tc.want != "" && !strings.Contains(text, tc.want) {
				t.Fatalf("want %q in:\n%s", tc.want, text)
			}
		})
	}
	h := newHarness(t, config.TelegramChat{ID: 600, Name: "Mom", Role: roleViewer, Lang: "ru"})
	h.deliver(uplinkLost(testNow.Add(-5 * time.Minute)))
	if text := h.sendsTo(600)[0].Params["text"].(string); !strings.Contains(text, "в 14:27, доставлено с опозданием") {
		t.Fatalf("ru stamp:\n%s", text)
	}
}

// A Keep or Roll back button decides only the test Apply it was offered for. One left from an
// earlier window (an old message, a press queued during an outage, a build before the buttons named
// their window) is refused with the present state, and the router is not touched.
func TestKeepAndRollBackAreBoundToTheirTestApply(t *testing.T) {
	testing2 := FailSafePulse{Pending: true, SecondsLeft: 200, Window: "w2"}
	unsaved := FailSafePulse{Live: true, Window: "w2"}
	for _, tc := range []struct {
		name     string
		now      FailSafePulse
		data     string
		kept     int
		rolled   int
		refused  bool
		freshBtn bool // the status shown after a refusal offers the running window's buttons
	}{
		{"keep the running window", testing2, cbKeep + "w2", 1, 0, false, false},
		{"roll back the running window", testing2, cbRollback + "w2", 0, 1, false, false},
		{"keep the unsaved state after the window", unsaved, cbKeep + "w2", 1, 0, false, false},
		{"a button of an earlier window", testing2, cbKeep + "w1", 0, 0, true, true},
		{"roll back of an earlier window", testing2, cbRollback + "w1", 0, 0, true, true},
		{"nothing is under test any more", FailSafePulse{}, cbKeep + "w2", 0, 0, true, false},
		{"a button from before windows were named", testing2, cbKeepOld, 0, 0, true, true},
		{"a roll back from before windows were named", testing2, cbRollbackOld, 0, 0, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, owner)
			h.be.pulse.FailSafe = tc.now
			if tc.now.Pending {
				h.be.status.FailSafe = FailSafe{Armed: true, Remaining: 200 * time.Second, Window: tc.now.Window}
			}
			h.press(500, tc.data)
			if h.be.kept != tc.kept || h.be.rolledBack != tc.rolled {
				t.Fatalf("kept %d, rolled back %d", h.be.kept, h.be.rolledBack)
			}
			a := h.api.callsTo("answerCallbackQuery")
			refused := len(a) > 0 && strings.Contains(a[0].Params["text"].(string), "test Apply that is over")
			if refused != tc.refused {
				t.Fatalf("answer %v", a)
			}
			if !tc.refused {
				return
			}
			if a[0].Params["show_alert"] != true {
				t.Fatal("the refusal of a decision must be seen, not a passing toast")
			}
			kb := toJSON(h.api.lastKeyboard(t, "editMessageText"))
			if fresh := strings.Contains(kb, `"ak:w2"`); fresh != tc.freshBtn {
				t.Fatalf("the present state's buttons: %s", kb)
			}
			if len(cbKeep+"w2") > 64 {
				t.Fatal("callback data over Telegram's 64 bytes")
			}
		})
	}
}

// A chat with many incidents open forgets the oldest first, and never the test Apply's: its message
// holds the Keep / Roll back buttons the countdown edits.
func TestOpenIncidentsForgetTheOldestButNeverTheApply(t *testing.T) {
	o := newOutbox()
	o.setOpen(1, "apply", 1)
	for i := 2; i <= incidentsCap; i++ {
		o.setOpen(1, "exit:"+strconv.Itoa(i), int64(i))
	}
	for i := 0; i < 3*incidentsCap; i++ {
		o.setOpen(1, "exit:new"+strconv.Itoa(i), int64(1000+i))
		if _, ok := o.openMsg(1, "apply"); !ok {
			t.Fatalf("the test Apply's message was forgotten after %d new incidents", i+1)
		}
	}
	if len(o.open[1]) != incidentsCap {
		t.Fatalf("%d open, cap %d", len(o.open[1]), incidentsCap)
	}
	if _, ok := o.openMsg(1, "exit:2"); ok {
		t.Fatal("the oldest incident outlived newer ones")
	}
	// Reopening a known incident forgets nothing.
	o.setOpen(1, "apply", 5000)
	if len(o.open[1]) != incidentsCap {
		t.Fatalf("%d open after a reopen", len(o.open[1]))
	}
}
