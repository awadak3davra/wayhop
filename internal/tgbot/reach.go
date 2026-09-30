package tgbot

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"wayhop/internal/config"
)

// A chat that refuses the bot's messages: the person blocked the bot, deleted the chat, or removed
// the bot from the group. Telegram answers every send there with 403, and nothing the bot does will
// change that. Left alone, each alert to it was one more log line and nobody learnt that it was not
// arriving; an alert that silently never arrives is worse than none. So the first refusal is told to
// the owners once, later ones stay quiet, and the first message that gets through again clears it.

// markUnreachable records chat as refusing messages; it reports whether that is news.
func (o *outbox) markUnreachable(chat int64) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.unreach[chat] {
		return false
	}
	o.unreach[chat] = true
	return true
}

// markReachable clears the record once a message got through; it reports whether there was one.
func (o *outbox) markReachable(chat int64) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	was := o.unreach[chat]
	delete(o.unreach, chat)
	return was
}

// refused handles a send to rec that failed for good. A refusal of the chat itself (403) is told to
// the owners once; anything else is one log line, as before.
func (b *Bot) refused(rec config.TelegramChat, err error) {
	if !IsBlocked(err) {
		b.logf("telegram: alert to %d: %v", rec.ID, err)
		return
	}
	if !b.out.markUnreachable(rec.ID) {
		return
	}
	b.logf("telegram: chat %d no longer accepts messages (%v); alerts to it fail until it does", rec.ID, err)
	b.Notify(unreachableAlert(rec, err, b.now()))
}

// delivered notes that a message reached chat, which ends a refusal recorded for it.
func (b *Bot) delivered(chat int64) {
	if b.out.markReachable(chat) {
		b.logf("telegram: chat %d accepts messages again", chat)
	}
}

// unreachableAlert tells the owners which chat stopped getting alerts, and what Telegram said.
func unreachableAlert(rec config.TelegramChat, err error, now time.Time) Alert {
	name := rec.Name
	if name == "" {
		name = strconv.FormatInt(rec.ID, 10)
	}
	reason := ""
	var ae *APIError
	if errors.As(err, &ae) {
		reason = strings.TrimPrefix(ae.Description, "Forbidden: ")
	}
	a := simpleAlert(KindBot, SevWarning, now, func(lang string) string {
		return T(lang, "al.unreachable", esc(name), esc(reason))
	})
	a.Owners = true
	return a
}
