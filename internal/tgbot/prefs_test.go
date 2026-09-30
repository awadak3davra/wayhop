package tgbot

import (
	"slices"
	"strings"
	"testing"

	"wayhop/internal/config"
)

func (h *harness) chat(id int64) config.TelegramChat {
	for _, c := range h.st.Telegram().Chats {
		if c.ID == id {
			return c
		}
	}
	h.t.Fatalf("chat %d is not paired", id)
	return config.TelegramChat{}
}

func buttonTexts(kb [][]InlineButton) []string {
	var out []string
	for _, row := range kb {
		for _, b := range row {
			out = append(out, b.Text)
		}
	}
	return out
}

// A chat switches a kind off for itself from the bot, and back on; the board redraws in place.
func TestChatSwitchesItsOwnAlerts(t *testing.T) {
	h := newHarness(t, owner, viewerChat)
	h.press(600, cbMore)
	if !slices.Contains(buttonTexts(h.api.lastKeyboard(t, "editMessageText")), "🔔 Оповещения") {
		t.Fatal("the More menu has no alerts button")
	}
	h.press(600, cbAlertsMenu)
	e := h.edited()
	if !strings.Contains(e[len(e)-1], "Оповещения в этом чате") {
		t.Fatalf("board %q", e[len(e)-1])
	}
	texts := buttonTexts(h.api.lastKeyboard(t, "editMessageText"))
	if !slices.Contains(texts, "✅ Переключения") || slices.Contains(texts, "✅ Сводка за сутки") {
		t.Fatalf("buttons %v", texts)
	}
	h.press(600, cbAlertKind+KindSwitches)
	if got := h.chat(600).AlertsOff; !slices.Equal(got, []string{KindSwitches}) {
		t.Fatalf("alerts_off %v", got)
	}
	if !slices.Contains(buttonTexts(h.api.lastKeyboard(t, "editMessageText")), "⬜ Переключения") {
		t.Fatal("the board was not redrawn")
	}
	if toast := h.api.callsTo("answerCallbackQuery"); !strings.Contains(toast[len(toast)-1].Params["text"].(string), "Переключения: выключено в этом чате") {
		t.Fatalf("toast %v", toast[len(toast)-1].Params)
	}
	h.press(600, cbAlertKind+KindSwitches)
	if got := h.chat(600).AlertsOff; len(got) != 0 {
		t.Fatalf("switched back on, alerts_off %v", got)
	}
	if got := h.chat(500).AlertsOff; len(got) != 0 {
		t.Fatalf("another chat's switches moved: %v", got)
	}
}

// Delivery honours both the panel's switches and the chat's own.
func TestDeliveryHonoursAChatsOwnSwitches(t *testing.T) {
	mom := viewerChat
	mom.AlertsOff = []string{KindExits}
	h := newHarness(t, owner, mom)
	down, _ := downUp()
	h.deliver(down)
	if len(h.sendsTo(500)) != 1 || len(h.sendsTo(600)) != 0 {
		t.Fatalf("exit alert: owner %d, mom %d", len(h.sendsTo(500)), len(h.sendsTo(600)))
	}
	h.deliver(uplinkLost(testNow))
	if len(h.sendsTo(600)) != 1 {
		t.Fatal("mom lost the alert she kept")
	}
}

// A kind the panel switched off is off for every chat: the board names it and offers no button,
// and a stale button cannot switch it for one chat.
func TestThePanelSwitchHoldsForEveryChat(t *testing.T) {
	h := newHarness(t, owner)
	_ = h.st.UpdateTelegram(func(tg *config.Telegram) error { tg.AlertsOff = []string{KindSwitches}; return nil })
	h.text(500, "private", "/alerts", "en")
	sent := h.sent()
	if len(sent) != 1 || !strings.Contains(sent[0], "Off in the panel for every chat: Switches.") {
		t.Fatalf("board %q", sent)
	}
	for _, b := range buttonTexts(h.api.lastKeyboard(t, "sendMessage")) {
		if strings.Contains(b, "Switches") {
			t.Fatalf("a button for a kind the panel switched off: %q", b)
		}
	}
	h.press(500, cbAlertKind+KindSwitches)
	if got := h.chat(500).AlertsOff; len(got) != 0 {
		t.Fatalf("a stale button switched it: %v", got)
	}
	h.press(500, cbAlertKind+"no-such-kind")
	if got := h.chat(500).AlertsOff; len(got) != 0 {
		t.Fatalf("an unknown kind was stored: %v", got)
	}
}

// While the daily digest is on, a chat can decline it for itself.
func TestAChatCanDeclineTheDigest(t *testing.T) {
	h := newHarness(t, owner, viewerChat)
	_ = h.st.UpdateTelegram(func(tg *config.Telegram) error { tg.Digest = "09:00"; return nil })
	h.press(600, cbAlertsMenu)
	if !slices.Contains(buttonTexts(h.api.lastKeyboard(t, "editMessageText")), "✅ Сводка за сутки") {
		t.Fatal("no digest switch while the digest is on")
	}
	h.press(600, cbAlertKind+KindDigest)
	h.deliver(digestAlert(sampleDigest()))
	if len(h.sendsTo(500)) != 1 || len(h.sendsTo(600)) != 0 {
		t.Fatalf("digest: owner %d, mom %d", len(h.sendsTo(500)), len(h.sendsTo(600)))
	}
}
