package tgbot

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
)

// pressIn handles a button pressed by user from on a message in chat, which may be a group or a
// channel (the harness's press is a private chat's own owner).
func (h *harness) pressIn(chat Chat, from int64, data string) {
	h.bot.handle(context.Background(), Update{CallbackQuery: &CallbackQuery{
		ID: "q1", From: User{ID: from, FirstName: "Lee"}, Data: data,
		Message: &Message{MessageID: 99, Chat: chat},
	}})
	h.bot.wg.Wait()
}

// A channel is alerts-only whatever its record says. Pairing forces it to alerts, but the panel could
// later make it a viewer, and then every alert in it carried Status and Mute: anyone who can see the
// channel (a public one: anyone at all) could press them, since a callback is authorised by the chat,
// not by who pressed. A subscriber muted the channel for a week, switched its uplink alerts off in
// config.json and posted the LAN's device list into it (QA-102).
func TestAChannelIsAlertsOnlyWhateverItsRecordSays(t *testing.T) {
	channel := config.TelegramChat{ID: -100700, Name: "Family news", Role: roleViewer, Lang: "en"}
	h := newHarness(t, owner, channel)
	ch := Chat{ID: channel.ID, Type: "channel", Title: "Family news"}
	for _, data := range []string{cbMute + "10080", cbAlertKind + KindUplink, cbDevices, cbStatus, cbKeep + "w1"} {
		h.pressIn(ch, 777, data)
	}
	if u := h.bot.out.mutedUntil(channel.ID, testNow); !u.IsZero() {
		t.Fatalf("a subscriber muted the channel until %v", u)
	}
	for _, c := range h.st.Telegram().Chats {
		if len(c.AlertsOff) != 0 {
			t.Fatalf("a subscriber switched alerts off for %d: %v", c.ID, c.AlertsOff)
		}
	}
	if len(h.edited()) != 0 || len(h.sent()) != 0 {
		t.Fatalf("a subscriber's press changed the channel: edits %q, sends %q", h.edited(), h.sent())
	}
	for _, a := range h.api.callsTo("answerCallbackQuery") {
		if a.Params["text"] != T("en", "alerts.only") {
			t.Fatalf("answer %v", a.Params)
		}
	}
	// A command posted in the channel reads no state either.
	h.bot.handle(context.Background(), Update{ChannelPost: &Message{MessageID: 11, Chat: ch, Date: testNow.Unix(), Text: "/status"}})
	for _, s := range h.sent() {
		if strings.Contains(s, "nl-main") || strings.Contains(s, "198.51.100.3") {
			t.Fatalf("a channel post read the state: %q", s)
		}
	}
}

// Pairing records the chat's type, so the panel and the API can tell a channel from a group: both
// have negative ids, and only the type says which one may hold a viewer.
func TestPairingRecordsTheChatType(t *testing.T) {
	h := newHarness(t)
	code, _ := h.bot.gate.NewCode(roleViewer)
	h.bot.handle(context.Background(), Update{ChannelPost: &Message{MessageID: 12,
		Chat: Chat{ID: -100701, Type: "channel", Title: "Family news"}, Date: testNow.Unix(), Text: "/start " + code}})
	c := h.st.Telegram().Chats
	if len(c) != 1 || c[0].Type != "channel" || c[0].Role != roleAlerts {
		t.Fatalf("chats %+v", c)
	}
}

// countingStore counts the saves of the Telegram block.
type countingStore struct {
	*fakeStore
	saves int
}

func (c *countingStore) UpdateTelegram(fn func(*config.Telegram) error) error {
	c.saves++
	return c.fakeStore.UpdateTelegram(fn)
}

// A channel paired before the chat type was recorded and later made a viewer: the role was overridden
// per update, so its presses were refused, but the outbox renders alerts by the stored role, and every
// alert in it still carried Status and Mute for any subscriber to press. The first update that shows
// Telegram's word on the type saves it, with the alerts role, once.
func TestAChannelPairedBeforeTheTypeWasRecordedIsSavedAsAlertsOnly(t *testing.T) {
	channel := config.TelegramChat{ID: -100702, Name: "Family news", Role: roleViewer, Lang: "en"}
	h := newHarness(t, owner, channel)
	cs := &countingStore{fakeStore: h.st}
	h.bot = New(h.api.client(), h.be, cs, Options{Now: func() time.Time { return testNow }, Logf: t.Logf})
	h.bot.me = User{ID: 1, IsBot: true, Username: "home_wayhop_bot"}
	ch := Chat{ID: channel.ID, Type: "channel", Title: "Family news"}
	h.bot.handle(context.Background(), Update{ChannelPost: &Message{MessageID: 11, Chat: ch, Date: testNow.Unix(), Text: "/status"}})

	t2 := h.st.Telegram()
	var rec config.TelegramChat
	for _, c := range t2.Chats {
		if c.ID == channel.ID {
			rec = c
		}
	}
	if rec.Type != "channel" || rec.Role != roleAlerts {
		t.Fatalf("the channel's record: %+v", rec)
	}
	if !slices.Contains(t2.StaleMenus, channel.ID) {
		t.Fatalf("the viewer's menu is not taken back: %v", t2.StaleMenus)
	}

	h.deliver(coreRestarted(testNow, CorePulse{Restarts: 1}, CorePulse{}))
	sends := h.sendsTo(channel.ID)
	if len(sends) == 0 {
		t.Fatal("the alert did not reach the channel")
	}
	if kb, has := sends[len(sends)-1].Params["reply_markup"]; has {
		t.Fatalf("an alert in the channel carries buttons: %v", kb)
	}

	h.pressIn(ch, 777, cbStatus)
	h.bot.handle(context.Background(), Update{ChannelPost: &Message{MessageID: 12, Chat: ch, Date: testNow.Unix(), Text: "/exits"}})
	if cs.saves != 1 {
		t.Fatalf("%d saves, want one", cs.saves)
	}
}
