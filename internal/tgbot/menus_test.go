package tgbot

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
)

// chatMenuCalls is what the bot asked Telegram about chats' own menus: for each chat, the commands it
// was given (nil for a menu taken back) and the description of /status, which shows the language.
func chatMenuCalls(h *harness) map[int64][]string {
	out := map[int64][]string{}
	for _, method := range []string{"setMyCommands", "deleteMyCommands"} {
		for _, c := range h.api.callsTo(method) {
			scope, ok := c.Params["scope"].(map[string]any)
			if !ok || scope["type"] != "chat" {
				continue
			}
			chat := int64(scope["chat_id"].(float64))
			var names []string
			if method == "setMyCommands" {
				for _, cmd := range c.Params["commands"].([]any) {
					m := cmd.(map[string]any)
					names = append(names, m["command"].(string))
					if m["command"] == "status" {
						names = append(names, m["description"].(string))
					}
				}
			}
			out[chat] = names
		}
	}
	return out
}

// Each owner and viewer chat gets a menu of its own, in its language, with its role's commands; an
// alerts-only chat keeps the default one. A chat that changes language gets a new menu, a
// disconnected chat's is taken back, nothing is sent while nothing changes or while the bot is
// offline, and a refusal waits before it is tried again.
func TestChatMenus(t *testing.T) {
	alerts := config.TelegramChat{ID: -100, Name: "Family", Role: roleAlerts, Lang: "en"}
	h := newHarness(t, owner, viewerChat, alerts)
	ctx := context.Background()
	count := func() int { return len(h.api.callsTo("setMyCommands")) + len(h.api.callsTo("deleteMyCommands")) }

	h.bot.menuOnce(ctx)
	if count() != 0 {
		t.Fatal("menus sent while the bot was offline")
	}
	h.bot.setState(StateOnline, "")
	h.bot.menuOnce(ctx)
	got := chatMenuCalls(h)
	own, view := strings.Join(got[owner.ID], " "), strings.Join(got[viewerChat.ID], " ")
	if len(got) != 2 || !strings.Contains(own, "speed") || !strings.Contains(own, "maint") ||
		!strings.Contains(own, T("en", "cmd.status")) || strings.Contains(view, "speed") || strings.Contains(view, "maint") ||
		!strings.Contains(view, T("ru", "cmd.status")) {
		t.Fatalf("menus %q", got)
	}
	sent := count()
	h.bot.menuOnce(ctx)
	if count() != sent {
		t.Fatal("menus sent again with nothing changed")
	}

	_ = h.st.UpdateTelegram(func(tg *config.Telegram) error { tg.Chats[1].Lang = "uk"; return nil })
	h.bot.menuOnce(ctx)
	if got := chatMenuCalls(h)[viewerChat.ID]; count() != sent+1 || !strings.Contains(strings.Join(got, " "), T("uk", "cmd.status")) {
		t.Fatalf("after /lang: %q", got)
	}

	_ = h.st.UpdateTelegram(func(tg *config.Telegram) error { tg.Chats = tg.Chats[:1]; return nil })
	h.bot.menuOnce(ctx)
	if dels := h.api.callsTo("deleteMyCommands"); len(dels) != 1 || chatMenuCalls(h)[viewerChat.ID] != nil {
		t.Fatalf("a disconnected chat kept its menu: %d", len(dels))
	}

	h.api.on("setMyCommands", func(map[string]any) (int, string) {
		return 400, `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`
	})
	_ = h.st.UpdateTelegram(func(tg *config.Telegram) error { tg.Chats[0].Role = roleViewer; return nil })
	h.bot.menuOnce(ctx)
	sent = count()
	h.bot.menuOnce(ctx)
	if count() != sent {
		t.Fatal("a refused menu was tried again on the next tick")
	}
	h.bot.now = func() time.Time { return testNow.Add(menuRetry + time.Minute) }
	h.bot.menuOnce(ctx)
	if count() != sent+1 {
		t.Fatal("a refused menu was not tried again after the wait")
	}
}

// The bot describes itself where Telegram shows it: in an empty chat before /start, and on its
// profile. English by default and every client language the bot answers in another, each in its
// reply language, within Telegram's limits of 512 and 120 characters.
func TestDescribe(t *testing.T) {
	h := newHarness(t)
	h.bot.describe(context.Background())
	byCode := func(method, field string) map[string]string {
		out := map[string]string{}
		for _, c := range h.api.callsTo(method) {
			code, _ := c.Params["language_code"].(string)
			out[code] = c.Params[field].(string)
		}
		return out
	}
	desc, short := byCode("setMyDescription", "description"), byCode("setMyShortDescription", "short_description")
	if len(desc) != 1+len(clientLangs) || len(short) != 1+len(clientLangs) {
		t.Fatalf("%d descriptions, %d short ones", len(desc), len(short))
	}
	if desc[""] != T("en", "about") || desc["be"] != T("ru", "about") || desc["uk"] != T("uk", "about") || short["ru"] != T("ru", "about.short") {
		t.Fatalf("descriptions %q", desc)
	}
	for _, lang := range Languages {
		if n := textLen(T(lang, "about")); n > 512 {
			t.Errorf("%s description: %d characters", lang, n)
		}
		if n := textLen(T(lang, "about.short")); n > 120 {
			t.Errorf("%s short description: %d characters", lang, n)
		}
	}
}

// A menu that cannot be taken back because the chat itself is out of reach (the bot was blocked or
// removed, the group moved to a new id, the chat is gone) counts as taken back: asking again every
// ten minutes for as long as the bot runs changes nothing.
func TestChatMenuOfAGoneChatIsNotAskedAboutAgain(t *testing.T) {
	for _, refusal := range []string{
		`{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`,
		`{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`,
		`{"ok":false,"error_code":400,"description":"Bad Request: group chat was upgraded to a supergroup chat","parameters":{"migrate_to_chat_id":-1001}}`,
	} {
		h := newHarness(t, owner, viewerChat)
		ctx := context.Background()
		h.bot.setState(StateOnline, "")
		h.bot.menuOnce(ctx)
		h.api.on("deleteMyCommands", func(map[string]any) (int, string) { return 400, refusal })
		_ = h.st.UpdateTelegram(func(tg *config.Telegram) error { tg.Chats = tg.Chats[:1]; return nil })
		h.bot.menuOnce(ctx)
		now := testNow.Add(menuRetry + time.Minute)
		h.bot.now = func() time.Time { return now }
		h.bot.menuOnce(ctx)
		if n := len(h.api.callsTo("deleteMyCommands")); n != 1 {
			t.Fatalf("%s: asked %d times", refusal, n)
		}
	}
}

// StaleMenus is how the panel hands over a chat that left the owners and viewers, even while the bot
// was off: its menu is taken back and the chat leaves the list. A chat paired again keeps the menu
// it has by right, and a refusal that may pass keeps the chat listed until it is tried again.
func TestStaleMenusAreTakenBack(t *testing.T) {
	h := newHarness(t, owner)
	ctx := context.Background()
	_ = h.st.UpdateTelegram(func(tg *config.Telegram) error { tg.StaleMenus = []int64{700, owner.ID, 800}; return nil })
	h.api.on("deleteMyCommands", func(p map[string]any) (int, string) {
		if p["scope"].(map[string]any)["chat_id"] == float64(800) {
			return 502, `{"ok":false,"error_code":502,"description":"Bad Gateway"}`
		}
		return 200, `{"ok":true,"result":true}`
	})
	h.bot.setState(StateOnline, "")
	h.bot.menuOnce(ctx)
	calls := chatMenuCalls(h)
	if _, ok := calls[700]; !ok || calls[owner.ID] == nil || len(h.api.callsTo("deleteMyCommands")) != 2 {
		t.Fatalf("menus %q", calls)
	}
	if stale := h.st.Telegram().StaleMenus; !slices.Equal(stale, []int64{800}) {
		t.Fatalf("still listed: %v", stale)
	}
	h.api.on("deleteMyCommands", nil)
	h.bot.now = func() time.Time { return testNow.Add(menuRetry + time.Minute) }
	h.bot.menuOnce(ctx)
	if stale := h.st.Telegram().StaleMenus; len(stale) != 0 || len(h.api.callsTo("deleteMyCommands")) != 3 {
		t.Fatalf("after the wait: %v", stale)
	}
}

// A group that became a supergroup is refused under its old id, with the new one named: the pairing
// moves, and the next pass gives the new id the menu.
func TestChatMenuFollowsAGroupThatBecameASupergroup(t *testing.T) {
	group := config.TelegramChat{ID: -100, Name: "Family", Role: roleViewer, Lang: "en"}
	h := newHarness(t, owner, group)
	ctx := context.Background()
	h.api.on("setMyCommands", func(p map[string]any) (int, string) {
		if scope, ok := p["scope"].(map[string]any); ok && scope["chat_id"] == float64(-100) {
			return 400, `{"ok":false,"error_code":400,"description":"Bad Request: group chat was upgraded to a supergroup chat","parameters":{"migrate_to_chat_id":-1001}}`
		}
		return 200, `{"ok":true,"result":true}`
	})
	h.bot.setState(StateOnline, "")
	h.bot.menuOnce(ctx)
	h.bot.menuOnce(ctx)
	if chats := h.st.Telegram().Chats; chats[1].ID != -1001 || chatMenuCalls(h)[-1001] == nil {
		t.Fatalf("chats %+v, menus %q", chats, chatMenuCalls(h))
	}
}

// When StaleMenus cannot be saved (a full or read-only overlay), a menu that was taken back is not
// taken back again on every pass: it waits like a refusal, and the failure is logged once.
func TestStaleMenuWaitsWhileTheListCannotBeSaved(t *testing.T) {
	h := newHarness(t, owner)
	ctx := context.Background()
	if err := h.st.UpdateTelegram(func(tg *config.Telegram) error { tg.StaleMenus = []int64{700}; return nil }); err != nil {
		t.Fatal(err)
	}
	h.st.mu.Lock()
	h.st.t.QuietFrom = "23:00" // without QuietTo: every later save is refused
	h.st.mu.Unlock()
	var logged []string
	h.bot.logf = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	h.bot.setState(StateOnline, "")
	deletes := func() (n int) {
		for _, c := range h.api.callsTo("deleteMyCommands") {
			if scope, ok := c.Params["scope"].(map[string]any); ok && scope["chat_id"] == float64(700) {
				n++
			}
		}
		return n
	}
	for i := 0; i < 4; i++ {
		h.bot.menuOnce(ctx)
	}
	saves := 0
	for _, l := range logged {
		if strings.Contains(l, "telegram: menus:") {
			saves++
		}
	}
	if deletes() != 1 || saves != 1 {
		t.Fatalf("%d deletes and %d logged failures over 4 passes", deletes(), saves)
	}
	h.bot.now = func() time.Time { return testNow.Add(menuRetry + time.Minute) }
	h.bot.menuOnce(ctx)
	if deletes() != 2 {
		t.Fatal("not tried again after the wait")
	}
}
