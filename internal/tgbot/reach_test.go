package tgbot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// refusing makes the fake Bot API answer sends to chat the way Telegram does once the person
// blocked the bot, while *blocked is true; everything else is accepted.
func refusing(h *harness, chat int64, blocked *bool) {
	var mu sync.Mutex
	var n int64
	h.api.on("sendMessage", func(p map[string]any) (int, string) {
		mu.Lock()
		defer mu.Unlock()
		id, _ := p["chat_id"].(float64)
		if int64(id) == chat && *blocked {
			return http.StatusForbidden, `{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`
		}
		n++
		b, _ := json.Marshal(map[string]any{"ok": true, "result": map[string]any{
			"message_id": 2000 + n, "chat": map[string]any{"id": int64(id), "type": "private"}, "date": 1}})
		return http.StatusOK, string(b)
	})
}

// logLines captures the bot's log.
func logLines(h *harness) *[]string {
	var mu sync.Mutex
	lines := &[]string{}
	h.bot.logf = func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		*lines = append(*lines, fmt.Sprintf(f, a...))
	}
	return lines
}

func count(lines []string, sub string) int {
	n := 0
	for _, l := range lines {
		if strings.Contains(l, sub) {
			n++
		}
	}
	return n
}

// A chat that blocked the bot is told to the owners once, quietly skipped after that, and news
// again only after a message got through in between.
func TestAChatThatBlockedTheBotIsToldOnce(t *testing.T) {
	h := newHarness(t, owner, viewerChat)
	blocked := true
	refusing(h, viewerChat.ID, &blocked)
	logs := logLines(h)
	down, up := downUp()
	h.deliver(down)
	h.deliver(up)
	if n := len(h.bot.out.q); n != 1 {
		t.Fatalf("%d notices queued for one blocked chat", n)
	}
	if n := count(*logs, "no longer accepts"); n != 1 {
		t.Fatalf("%d log lines for one blocked chat: %q", n, *logs)
	}
	notice := h.bot.out.q[0].a
	h.deliver(notice)
	got := h.sendsTo(500)
	text := got[len(got)-1].Params["text"].(string)
	if !strings.Contains(text, "<b>Mom</b> no longer accepts the bot's messages (Telegram says: bot was blocked by the user)") {
		t.Fatalf("notice %q", text)
	}
	// Two alerts were tried there and refused; the owners-only notice was not tried at all.
	if n := len(h.sendsTo(600)); n != 2 {
		t.Fatalf("%d sends tried to the blocked viewer", n)
	}

	// Unblocked: the next alert gets through and clears the record; a new block is news again.
	blocked = false
	h.deliver(uplinkLost(testNow))
	if len(h.sendsTo(600)) != 3 || count(*logs, "accepts messages again") != 1 {
		t.Fatalf("recovery: %d sends, logs %q", len(h.sendsTo(600)), *logs)
	}
	blocked = true
	h.deliver(uplinkBack(testNow.Add(time.Minute), time.Minute))
	if n := len(h.bot.out.q); n != 2 {
		t.Fatalf("a second block is not news: %d queued", n)
	}
}

// The notice is for owners: a viewer does not get it even when it can be reached.
func TestTheNoticeIsForOwnersOnly(t *testing.T) {
	h := newHarness(t, owner, viewerChat, alertsChat)
	h.deliver(unreachableAlert(alertsChat, &APIError{Code: 403, Description: "Forbidden: bot was kicked from the group chat"}, testNow))
	if len(h.sendsTo(500)) != 1 || len(h.sendsTo(600)) != 0 {
		t.Fatalf("owner %d, viewer %d", len(h.sendsTo(500)), len(h.sendsTo(600)))
	}
	if text := h.sendsTo(500)[0].Params["text"].(string); !strings.Contains(text, "Family") || !strings.Contains(text, "bot was kicked from the group chat") {
		t.Fatalf("notice %q", text)
	}
}

// The summary after quiet hours to a chat that refuses it is dropped: held again, it was sent again
// on every tick, for good.
func TestHeldAlertsForARefusingChatAreDropped(t *testing.T) {
	h := newHarness(t, owner, viewerChat)
	blocked := true
	refusing(h, viewerChat.ID, &blocked)
	h.st.t.QuietFrom, h.st.t.QuietTo = "14:00", "15:00"
	down, up := downUp()
	h.deliver(down)
	h.deliver(up)
	h.bot.now = func() time.Time { return testNow.Add(time.Hour) }
	for i := 0; i < 3; i++ {
		h.bot.flushHeld(context.Background())
	}
	if n := len(h.api.callsTo("sendMessage")); n != 2 {
		t.Fatalf("%d summary sends for two chats over three ticks", n)
	}
	if len(h.bot.out.heldChats()) != 0 {
		t.Fatal("the refused alerts are still held")
	}
	if len(h.sendsTo(500)) != 1 {
		t.Fatal("the owner lost the summary")
	}
}
