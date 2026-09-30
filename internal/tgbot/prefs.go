package tgbot

import (
	"context"
	"slices"
	"strings"

	"wayhop/internal/config"
)

// Per-chat alert switches: /alerts, and "🔔 Alerts" in the More menu. The panel's switches hold for
// the whole router; a chat can also switch kinds off for itself, so a parent's phone gets the outage
// and the lost internet without every group switch and test Apply.

const (
	cbAlertsMenu = "an"  // this chat's alert switches
	cbAlertKind  = "an:" // + kind: switch it for this chat
)

// chatKinds is what a chat can switch for itself: every alert kind, and the daily digest while the
// digest is on.
func chatKinds(t config.Telegram) []string {
	kinds := append([]string(nil), AlertKinds...)
	if t.Digest != "" {
		kinds = append(kinds, KindDigest)
	}
	return kinds
}

// wants reports whether rec gets alerts of kind: neither the panel nor the chat switched it off.
func wants(t config.Telegram, rec config.TelegramChat, kind string) bool {
	return !alertOff(t, kind) && !slices.Contains(rec.AlertsOff, kind)
}

// Alerts is a chat's switch board: a button per kind, marked on or off for this chat. Kinds the
// panel switched off are named but have no button, since the chat cannot switch them back on.
func (v view) Alerts(t config.Telegram, rec config.TelegramChat) (string, *Keyboard) {
	var b strings.Builder
	b.WriteString(v.t("an.title") + "\n" + v.t("an.hint") + "\n")
	var panelOff []string
	var rows [][]InlineButton
	var row []InlineButton
	for _, k := range chatKinds(t) {
		name := v.t("kind." + k)
		if alertOff(t, k) {
			panelOff = append(panelOff, name)
			continue
		}
		mark := "✅ "
		if slices.Contains(rec.AlertsOff, k) {
			mark = "⬜ "
		}
		row = append(row, btn(mark+name, cbAlertKind+k))
		if len(row) == 2 {
			rows = append(rows, row)
			row = nil
		}
	}
	if len(row) > 0 {
		rows = append(rows, row)
	}
	if len(panelOff) > 0 {
		b.WriteString("\n<i>" + v.t("an.panel", strings.Join(panelOff, ", ")) + "</i>\n")
	}
	rows = append(rows, []InlineButton{btn(v.t("b.back"), cbMore), btn(v.t("b.status"), cbStatus)})
	return strings.TrimRight(b.String(), "\n"), &Keyboard{Rows: rows}
}

// toggleAlert switches kind on or off for the chat that pressed it, and redraws the board in place.
func (b *Bot) toggleAlert(ctx context.Context, v view, q *CallbackQuery, rec config.TelegramChat, kind string) {
	t := b.st.Telegram()
	if !slices.Contains(chatKinds(t), kind) || alertOff(t, kind) {
		// A button from before the panel switched the kind off, or the digest was turned off.
		b.answer(ctx, q, v.t("stale"), false)
		text, kb := v.Alerts(t, rec)
		b.show(ctx, q.Message, text, kb)
		return
	}
	off := false
	err := b.st.UpdateTelegram(func(t *config.Telegram) error {
		for i := range t.Chats {
			if t.Chats[i].ID != rec.ID {
				continue
			}
			// A new slice either way: the list may share its array with the copy it came from.
			if cur := t.Chats[i].AlertsOff; slices.Contains(cur, kind) {
				t.Chats[i].AlertsOff = slices.DeleteFunc(slices.Clone(cur), func(k string) bool { return k == kind })
			} else {
				t.Chats[i].AlertsOff = append(slices.Clone(cur), kind)
				off = true
			}
			return nil
		}
		return errNotPaired
	})
	if err != nil {
		b.logf("telegram: alert switch for %d: %v", rec.ID, err)
		b.answer(ctx, q, v.t("err.save"), true)
		return
	}
	key := "an.on"
	if off {
		key = "an.off"
	}
	b.answer(ctx, q, v.t(key, v.t("kind."+kind)), false)
	if now, ok := b.chatRecord(rec.ID); ok {
		rec = now
	}
	text, kb := v.Alerts(b.st.Telegram(), rec)
	b.show(ctx, q.Message, text, kb)
}
