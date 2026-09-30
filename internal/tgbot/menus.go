package tgbot

import (
	"context"
	"errors"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"wayhop/internal/config"
)

// A paired chat's own command menu: the commands its role can use, in its language. Telegram shows a
// chat's own menu above the ones kept per client language, so a chat that picked another language
// with /lang sees its menu in that language, and an owner sees the commands a viewer has not.

// menuRetry is how long a chat whose menu Telegram refused waits before it is tried again, so a
// chat that is gone is not asked about on every pass.
const menuRetry = 10 * time.Minute

type menus struct {
	sent  map[int64]string    // chat -> the menu it was given: role and language
	retry map[int64]time.Time // chat -> when a failed update may be tried again
	// failed is a chat's last refusal. It is logged when it is new, not on every retry.
	failed map[int64]string
	// pruneErr is why StaleMenus could not be saved last time, logged when it is new.
	pruneErr string
}

// chatMenu is a role's menu in a language. The default menu, for every chat without its own, is a
// viewer's; an alerts-only chat keeps it, since every command there gets the same answer.
func chatMenu(lang, role string) []Command {
	names := []string{"status", "exits", "events", "summary", "route", "devices"}
	if role == roleOwner {
		names = append(names, "speed")
	}
	names = append(names, "diag")
	if role == roleOwner {
		names = append(names, "maint")
	}
	names = append(names, "alerts", "mute", "lang", "help")
	out := make([]Command, 0, len(names))
	for _, c := range names {
		out = append(out, Command{Command: c, Description: T(lang, "cmd."+c)})
	}
	return out
}

// menuLoop keeps the chats' menus in line. It is a loop of its own because a slow Telegram holds
// each menu call for up to sendWait, and the watcher must not wait on them to notice an exit going
// down.
func (b *Bot) menuLoop(ctx context.Context) {
	t := time.NewTicker(watchEvery)
	defer t.Stop()
	for {
		b.menuOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// menuOnce brings every owner and viewer chat's menu in line with its role and language, and takes
// the menu back from a chat that should no longer have one: one this bot gave a menu to, or one
// the panel listed in StaleMenus when it unpaired the chat or made it alerts-only, which covers a
// change made while the bot was off. It calls Telegram only for what changed, and only while the
// bot is online.
func (b *Bot) menuOnce(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			b.logf("telegram: menu panic: %v\n%s", r, debug.Stack())
		}
	}()
	if b.Info().State != StateOnline {
		return
	}
	now := b.now()
	t := b.st.Telegram()
	want := map[int64]string{}
	for _, c := range t.Chats {
		if (c.Role == roleOwner || c.Role == roleViewer) && c.Lang != "" {
			want[c.ID] = c.Role + "/" + c.Lang
		}
	}
	m := &b.menus
	if m.sent == nil {
		m.sent, m.retry, m.failed = map[int64]string{}, map[int64]time.Time{}, map[int64]string{}
	}
	call := func(chat int64, fn func(context.Context) error) error {
		cctx, cancel := context.WithTimeout(ctx, sendWait)
		defer cancel()
		return fn(cctx)
	}
	done := func(chat int64) { delete(m.retry, chat); delete(m.failed, chat) }
	for chat, key := range want {
		if m.sent[chat] == key || now.Before(m.retry[chat]) {
			continue
		}
		role, lang, _ := strings.Cut(key, "/")
		err := call(chat, func(c context.Context) error { return b.api.SetChatCommands(c, chat, chatMenu(lang, role)) })
		switch to := migratedTo(err); {
		case err == nil:
			m.sent[chat] = key
			done(chat)
		case to != 0 && b.migrate(chat, to):
			// The group became a supergroup, and its pairing moved: the next pass serves the new id.
			done(chat)
		default:
			m.refused(chat, err, now, b.logf)
		}
	}
	back := map[int64]bool{}
	for chat := range m.sent {
		if _, ok := want[chat]; !ok {
			back[chat] = true
		}
	}
	var settled []int64 // StaleMenus entries that need nothing more
	for _, chat := range t.StaleMenus {
		if _, ok := want[chat]; ok {
			settled = append(settled, chat) // paired again: its menu is its by right
			continue
		}
		back[chat] = true
	}
	for chat := range back {
		if now.Before(m.retry[chat]) {
			continue
		}
		err := call(chat, func(c context.Context) error { return b.api.DeleteChatCommands(c, chat) })
		if err != nil && !chatGone(err) {
			m.refused(chat, err, now, b.logf)
			continue
		}
		// Taken back, or nothing is left to take: the chat is gone, or the bot is out of it.
		delete(m.sent, chat)
		done(chat)
		if slices.Contains(t.StaleMenus, chat) {
			settled = append(settled, chat)
		}
	}
	if len(settled) > 0 {
		err := b.st.UpdateTelegram(func(t *config.Telegram) error {
			t.StaleMenus = slices.DeleteFunc(t.StaleMenus, func(id int64) bool { return slices.Contains(settled, id) })
			return nil
		})
		if err != nil {
			// The list could not be saved (a full or read-only overlay): taking these menus back
			// again on every pass would only repeat the calls, so they wait like a refusal does. A
			// chat paired again keeps its own menu's pace.
			for _, chat := range settled {
				if _, ok := want[chat]; !ok {
					m.retry[chat] = now.Add(menuRetry)
				}
			}
			if m.pruneErr != err.Error() {
				m.pruneErr = err.Error()
				b.logf("telegram: menus: %v", err)
			}
		} else {
			m.pruneErr = ""
		}
	}
}

// refused holds a chat whose menu call failed until menuRetry has passed, logging the refusal when
// it is new.
func (m *menus) refused(chat int64, err error, now time.Time, logf func(string, ...any)) {
	if m.failed[chat] != err.Error() {
		m.failed[chat] = err.Error()
		logf("telegram: menu of %d: %v", chat, err)
	}
	m.retry[chat] = now.Add(menuRetry)
}

// chatGone reports a refusal that no retry changes, since the chat itself is out of reach: the
// person blocked the bot or removed it (403), the group became a supergroup under a new id, or the
// chat no longer exists.
func chatGone(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && (ae.Code == http.StatusForbidden || ae.MigrateTo != 0 ||
		strings.Contains(ae.Description, "chat not found"))
}
