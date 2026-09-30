package tgbot

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
)

const supergroup = -1001234567890

// upgraded makes the fake Bot API refuse sends to the old group the way Telegram does once the group
// has become a supergroup, and accept everything else.
func upgraded(h *harness, old int64) {
	var n int64
	h.api.on("sendMessage", func(p map[string]any) (int, string) {
		chat, _ := p["chat_id"].(float64)
		if int64(chat) == old {
			return http.StatusBadRequest, `{"ok":false,"error_code":400,"description":"Bad Request: group chat was upgraded to a supergroup chat","parameters":{"migrate_to_chat_id":` + jsonInt(supergroup) + `}}`
		}
		n++
		b, _ := json.Marshal(map[string]any{"ok": true, "result": map[string]any{
			"message_id": 1000 + n, "chat": map[string]any{"id": int64(chat), "type": "supergroup"}, "date": 1}})
		return http.StatusOK, string(b)
	})
}

func jsonInt(v int64) string { b, _ := json.Marshal(v); return string(b) }

func (h *harness) chats() []config.TelegramChat { return h.st.Telegram().Chats }

// The announcement was missed (the bot was down), so the first alert learns of the move from
// Telegram's refusal: the pairing moves and the alert still arrives.
func TestAnUpgradedGroupKeepsGettingAlerts(t *testing.T) {
	h := newHarness(t, owner, alertsChat)
	upgraded(h, alertsChat.ID)
	down, _ := downUp()
	h.deliver(down)
	if got := h.sendsTo(supergroup); len(got) != 1 || !strings.Contains(got[0].Params["text"].(string), "de-backup") {
		t.Fatalf("the supergroup got %d alerts", len(got))
	}
	var moved config.TelegramChat
	for _, c := range h.chats() {
		if c.ID == alertsChat.ID {
			t.Fatal("the old group id is still paired")
		}
		if c.ID == supergroup {
			moved = c
		}
	}
	if moved.Role != roleAlerts || moved.Name != "Family" || moved.Lang != "en" {
		t.Fatalf("the pairing did not move whole: %+v", moved)
	}
	if len(h.sendsTo(500)) != 1 {
		t.Fatal("the owner's chat lost its alert")
	}
	// The next alert goes straight to the new id.
	before := len(h.api.callsTo("sendMessage"))
	_, up := downUp()
	h.deliver(up)
	if calls := h.api.callsTo("sendMessage")[before:]; len(calls) != 2 {
		t.Fatalf("%d sends for one alert to two chats", len(calls))
	}
}

// Telegram announces the move in both chats. The first announcement moves the pairing, the second
// finds nothing left to move, and neither needs text or a recent date.
func TestUpgradeAnnouncementsMoveThePairing(t *testing.T) {
	h := newHarness(t, owner, alertsChat)
	h.bot.out.mute(alertsChat.ID, testNow.Add(time.Hour))
	h.bot.out.setOpen(alertsChat.ID, "exit:de-backup", 77)
	h.bot.out.hold(alertsChat.ID, Alert{Kind: KindExits, At: testNow})
	h.bot.handle(context.Background(), Update{Message: &Message{
		MessageID: 5, Chat: Chat{ID: alertsChat.ID, Type: "group"}, Date: 1, MigrateToChatID: supergroup}})
	h.bot.handle(context.Background(), Update{Message: &Message{
		MessageID: 1, Chat: Chat{ID: supergroup, Type: "supergroup"}, Date: 1, MigrateFromChatID: alertsChat.ID}})
	ids := []int64{}
	for _, c := range h.chats() {
		ids = append(ids, c.ID)
	}
	if len(ids) != 2 || ids[1] != supergroup {
		t.Fatalf("chats %v", ids)
	}
	if h.bot.out.mutedUntil(supergroup, testNow).IsZero() {
		t.Fatal("the mute stayed behind")
	}
	if id, ok := h.bot.out.openMsg(supergroup, "exit:de-backup"); !ok || id != 77 {
		t.Fatal("the open incident stayed behind")
	}
	if h.bot.out.heldChats()[0] != supergroup {
		t.Fatal("the held alerts stayed behind")
	}
	if len(h.sent()) != 0 {
		t.Fatal("an announcement was answered")
	}
}

func TestUpgradeOfAnUnpairedGroupChangesNothing(t *testing.T) {
	h := newHarness(t, owner)
	h.bot.handle(context.Background(), Update{Message: &Message{
		Chat: Chat{ID: -555, Type: "group"}, MigrateToChatID: supergroup}})
	if c := h.chats(); len(c) != 1 || c[0].ID != 500 {
		t.Fatalf("chats %+v", c)
	}
}

// When the supergroup was paired on its own as well, its own record stands.
func TestUpgradeIntoAnAlreadyPairedSupergroup(t *testing.T) {
	both := config.TelegramChat{ID: supergroup, Name: "Family", Role: roleViewer, Lang: "ru"}
	h := newHarness(t, owner, alertsChat, both)
	if !h.bot.migrate(alertsChat.ID, supergroup) {
		t.Fatal("not moved")
	}
	c := h.chats()
	if len(c) != 2 || !reflect.DeepEqual(c[1], both) {
		t.Fatalf("chats %+v", c)
	}
}
