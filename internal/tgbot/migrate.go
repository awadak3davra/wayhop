package tgbot

import (
	"errors"

	"wayhop/internal/config"
)

// errNotPaired keeps UpdateTelegram from saving when the chat that moved is not one of ours.
var errNotPaired = errors.New("not a paired chat")

// migrate follows a group that Telegram turned into a supergroup. That happens to ordinary groups
// when an admin changes certain settings, and the supergroup is a new chat with a new id: sends to
// the old id are refused from then on, so a paired family group would stop getting alerts without
// a word. The chat keeps its role, language and name under the new id, and what the bot holds for it
// moves along: open incidents, a mute, alerts held back for it.
//
// It reports whether the chat now lives at to. A chat that is not paired, or a second announcement
// of the same move, changes nothing. A new id that is already paired keeps its own record, and the
// old one is dropped.
func (b *Bot) migrate(from, to int64) bool {
	if from == 0 || to == 0 || from == to {
		return false
	}
	err := b.st.UpdateTelegram(func(t *config.Telegram) error {
		at := -1
		for i, c := range t.Chats {
			if c.ID == from {
				at = i
			}
		}
		if at < 0 {
			return errNotPaired
		}
		for _, c := range t.Chats {
			if c.ID == to {
				t.Chats = append(t.Chats[:at], t.Chats[at+1:]...)
				return nil
			}
		}
		t.Chats[at].ID = to
		return nil
	})
	if err != nil {
		if !errors.Is(err, errNotPaired) {
			b.logf("telegram: chat %d became supergroup %d, and the move could not be saved: %v", from, to, err)
		}
		return false
	}
	b.out.migrate(from, to)
	b.gate.Forget(to) // it may have spoken before the announcement and been listed as a stranger
	b.logf("telegram: chat %d became supergroup %d; its pairing moved with it", from, to)
	return true
}

// migrate moves what the outbox holds for a chat to the chat's new id.
func (o *outbox) migrate(from, to int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if m, ok := o.open[from]; ok {
		if o.open[to] == nil {
			o.open[to] = map[string]int64{}
		}
		for k, v := range m {
			o.open[to][k] = v
		}
		delete(o.open, from)
	}
	if u, ok := o.muted[from]; ok {
		if u.After(o.muted[to]) {
			o.muted[to] = u
		}
		delete(o.muted, from)
	}
	if o.unreach[from] {
		o.unreach[to] = true
		delete(o.unreach, from)
	}
	if h, ok := o.held[from]; ok {
		o.held[to] = append(o.held[to], h...)
		delete(o.held, from)
	}
}
