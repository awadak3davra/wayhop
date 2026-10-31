package server

import (
	"net/http"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/tgbot"
)

// A channel's subscribers can press the buttons on its posts, and Telegram does not say who may: a
// channel made a viewer in the panel carried Status and Mute on every alert, for anyone who can see it
// to press (QA-102). Pairing forces a channel to alerts and records its type; the panel's role change
// refuses viewer and owner for a chat recorded as a channel, as it refuses owner for any group.
func TestTelegramChannelStaysAlertsOnly(t *testing.T) {
	s := tgServer(t)
	g := s.telegram().Gate()
	g.Seen(tgbot.Chat{ID: -100700, Type: "channel", Title: "Family news"}, nil)
	if w := tgDo(t, s, http.MethodPost, "/api/telegram/strangers/-100700/allow", `{"role":"viewer"}`); w.Code != http.StatusOK {
		t.Fatalf("allow = %d %s", w.Code, w.Body)
	}
	chats := s.Telegram().Chats
	if len(chats) != 1 || chats[0].Type != "channel" || chats[0].Role != config.TelegramAlerts {
		t.Fatalf("chats %+v", chats)
	}
	for _, role := range []string{config.TelegramViewer, config.TelegramOwner} {
		if w := tgDo(t, s, http.MethodPut, "/api/telegram/chats/-100700", `{"role":"`+role+`"}`); w.Code != http.StatusBadRequest {
			t.Fatalf("a channel was made %s: %d", role, w.Code)
		}
	}
	if c := s.Telegram().Chats; c[0].Role != config.TelegramAlerts {
		t.Fatalf("the refused change was stored: %+v", c)
	}
	// Its language still changes, and a group (not a channel) may still be a viewer.
	if w := tgDo(t, s, http.MethodPut, "/api/telegram/chats/-100700", `{"lang":"uk"}`); w.Code != http.StatusOK {
		t.Fatalf("language of a channel = %d %s", w.Code, w.Body)
	}
	_ = s.UpdateTelegram(func(tg *config.Telegram) error {
		tg.Chats = append(tg.Chats, config.TelegramChat{ID: -300, Type: "supergroup", Role: config.TelegramAlerts})
		return nil
	})
	if w := tgDo(t, s, http.MethodPut, "/api/telegram/chats/-300", `{"role":"viewer"}`); w.Code != http.StatusOK {
		t.Fatalf("a group as viewer = %d %s", w.Code, w.Body)
	}
}
