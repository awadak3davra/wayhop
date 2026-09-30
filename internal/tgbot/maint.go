package tgbot

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"wayhop/internal/config"
)

// Callback data of the maintenance menu.
const (
	cbMaint   = "mt"  // the menu
	cbDo      = "do:" // + action that changes nothing live (refreshes stage their results)
	cbAsk     = "cq:" // + action that needs a confirmation
	cbConfirm = "cf:" // + nonce
	cbCancel  = "cx:" // + nonce

	confirmTTL = 2 * time.Minute
	listsWait  = 70 * time.Second
	applyWait  = 3 * time.Minute
)

// Maintenance actions.
const (
	actLists   = "lists"
	actSub     = "sub"
	actApply   = "apply"
	actRestart = "restart"
	actBackup  = "backup"
)

// confirmation is an action waiting for its "yes". The nonce in the button is single-use, expires,
// and only counts in the chat it was issued to: a forwarded or stale button does nothing.
type confirmation struct {
	chat   int64
	action string
	arg    string
	until  time.Time
	// end, once the question is answered, is how it ended, as the key of the text a later tap on
	// either of its buttons gets: confirmed, cancelled or expired.
	end string
}

type confirms struct {
	mu sync.Mutex
	m  map[string]confirmation
	// spent keeps used nonces for a while, with how their question ended, so a second tap on its
	// buttons is told what became of it instead of being taken for an expired question.
	spent map[string]confirmation
}

// spentKeep is how long a used nonce is remembered: longer than any confirmed action runs.
const spentKeep = 10 * time.Minute

func (c *confirms) issue(chat int64, action, arg string, now time.Time) string {
	buf := make([]byte, 5)
	if _, err := rand.Read(buf); err != nil {
		panic("tgbot: crypto/rand failed: " + err.Error())
	}
	nonce := strings.ToLower(base32.StdEncoding.EncodeToString(buf))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]confirmation{}
	}
	for k, v := range c.m {
		if now.After(v.until) {
			delete(c.m, k)
		}
	}
	c.m[nonce] = confirmation{chat: chat, action: action, arg: arg, until: now.Add(confirmTTL)}
	return nonce
}

// redeem spends a nonce on a tap of its question's Confirm button, or of its Cancel button when
// cancel is set. ok is true for a live nonce of this chat confirmed in time. ended is set for a
// nonce this chat has already spent: a second tap on the question's buttons, queued or late, which
// must neither run the action twice nor disturb the message that is reporting it. It is the key of
// the text that tap gets: how the question ended.
func (c *confirms) redeem(nonce string, chat int64, now time.Time, cancel bool) (cf confirmation, ok bool, ended string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, s := range c.spent {
		if now.After(s.until) {
			delete(c.spent, k)
		}
	}
	if s, found := c.spent[nonce]; found && s.chat == chat {
		return s, false, s.end
	}
	cf, found := c.m[nonce]
	if !found || cf.chat != chat {
		return confirmation{}, false, ""
	}
	delete(c.m, nonce)
	if c.spent == nil {
		c.spent = map[string]confirmation{}
	}
	ok = !cancel && !now.After(cf.until)
	s := cf
	switch {
	case cancel:
		s.end = "mt.cancelled"
	case ok:
		s.end = "mt.again"
	default:
		s.end = "mt.expired"
	}
	s.until = now.Add(spentKeep)
	c.spent[nonce] = s
	return cf, ok, ""
}

// Maintenance renders the owner's menu.
func (v view) Maintenance(s Status) (string, *Keyboard) {
	var b strings.Builder
	b.WriteString(v.t("mt.title") + "\n")
	switch {
	case !s.Changes.Known:
	case s.Changes.Pending && s.Changes.Count > 0:
		b.WriteString(v.t("mt.pending.n", s.Changes.Count) + "\n")
	case s.Changes.Pending:
		b.WriteString(v.t("mt.pending.some") + "\n")
	default:
		b.WriteString(v.t("mt.pending.none") + "\n")
	}
	b.WriteString("\n<i>" + v.t("mt.hint") + "</i>")
	var rows [][]InlineButton
	if s.Changes.Pending {
		rows = append(rows, []InlineButton{btn(v.t("b.apply"), cbAsk+actApply)})
	}
	rows = append(rows,
		[]InlineButton{btn(v.t("b.lists"), cbDo+actLists), btn(v.t("b.sub"), cbDo+actSub)},
		[]InlineButton{btn(v.t("b.backup"), cbAsk+actBackup), btn(v.t("b.updates"), cbDo+actUpdate)},
		[]InlineButton{btn(v.t("b.restart"), cbAsk+actRestart)},
		[]InlineButton{btn(v.t("b.back"), cbMore), btn(v.t("b.status"), cbStatus)},
	)
	return b.String(), &Keyboard{Rows: rows}
}

// maintBack is the one-button way back to the menu under a result.
func (v view) maintBack(extra ...InlineButton) *Keyboard {
	row := append(extra, btn(v.t("b.maint.back"), cbMaint))
	return &Keyboard{Rows: [][]InlineButton{row}}
}

// maintCommand opens the menu from /maint and asks about a speed test from /speed. It reports
// whether cmd was one of them.
func (b *Bot) maintCommand(ctx context.Context, v view, rec config.TelegramChat, cmd string) bool {
	var render func() (string, *Keyboard)
	switch cmd {
	case "maint", "maintenance", "admin":
		render = func() (string, *Keyboard) { return v.Maintenance(b.status(ctx)) }
	case "speed", "speedtest":
		render = func() (string, *Keyboard) { return b.speedAsk(ctx, v, rec.ID, "") }
	default:
		return false
	}
	if rec.Role != roleOwner {
		b.reply(ctx, rec.ID, v.t("err.denied"), nil)
		return true
	}
	b.reply(ctx, rec.ID, "", render)
	return true
}

// backFrom is where a cancelled or expired question returns: a speed test to where it was offered
// (the exit's card, or the tools), everything else to the maintenance menu.
func (b *Bot) backFrom(ctx context.Context, v view, cf confirmation) (string, *Keyboard) {
	switch {
	case cf.action == actSpeed && cf.arg != "":
		if e, ok := b.status(ctx).ExitByID(cf.arg); ok {
			return v.Exit(e, "")
		}
		return v.More()
	case cf.action == actSpeed:
		return v.More()
	}
	return v.Maintenance(b.status(ctx))
}

// maintCallback runs the maintenance buttons. It reports whether data was one of them.
func (b *Bot) maintCallback(ctx context.Context, v view, q *CallbackQuery, rec config.TelegramChat) bool {
	data := q.Data
	if data != cbMaint && !strings.HasPrefix(data, cbDo) && !strings.HasPrefix(data, cbAsk) &&
		!strings.HasPrefix(data, cbConfirm) && !strings.HasPrefix(data, cbCancel) {
		return false
	}
	if rec.Role != roleOwner {
		b.answer(ctx, q, v.t("err.denied"), true)
		return true
	}
	m := q.Message
	switch {
	case data == cbMaint:
		b.answer(ctx, q, "", false)
		text, kb := v.Maintenance(b.status(ctx))
		b.show(ctx, m, text, kb)
	case strings.HasPrefix(data, cbDo):
		b.answer(ctx, q, "", false)
		switch strings.TrimPrefix(data, cbDo) {
		case actLists:
			b.refreshLists(ctx, v, m)
		case actSub:
			b.refreshSub(ctx, v, m)
		case actUpdate:
			b.updateCheck(ctx, v, m)
		}
	case strings.HasPrefix(data, cbAsk):
		b.answer(ctx, q, "", false)
		action, ref, _ := strings.Cut(strings.TrimPrefix(data, cbAsk), ":")
		b.ask(ctx, v, m, action, ref)
	case strings.HasPrefix(data, cbCancel):
		cf, _, ended := b.confirms.redeem(strings.TrimPrefix(data, cbCancel), m.Chat.ID, b.now(), true)
		if ended != "" {
			b.answer(ctx, q, v.t(ended), false)
			return true
		}
		b.answer(ctx, q, v.t("mt.cancelled"), false)
		text, kb := b.backFrom(ctx, v, cf)
		b.show(ctx, m, text, kb)
	case strings.HasPrefix(data, cbConfirm):
		cf, ok, ended := b.confirms.redeem(strings.TrimPrefix(data, cbConfirm), m.Chat.ID, b.now(), false)
		if ended != "" {
			b.answer(ctx, q, v.t(ended), false)
			return true
		}
		if !ok {
			b.answer(ctx, q, v.t("mt.expired"), true)
			text, kb := b.backFrom(ctx, v, cf)
			b.show(ctx, m, text, kb)
			return true
		}
		b.answer(ctx, q, "", false)
		who := q.From.DisplayName()
		b.logf("telegram: %s (chat %d) confirmed %s", who, m.Chat.ID, cf.action)
		b.run(ctx, v, m, cf, who)
	}
	return true
}

// ask turns the message into the question for an action that changes the router, or explains why
// there is nothing to ask.
func (b *Bot) ask(ctx context.Context, v view, m *Message, action, ref string) {
	var q strings.Builder
	var ok, arg string
	switch action {
	case actApply:
		cctx, cancel := context.WithTimeout(ctx, backendWait)
		p, err := b.be.ApplyPreview(cctx)
		cancel()
		switch {
		case err != nil:
			b.show(ctx, m, v.t("mt.apply.fail", esc(err.Error())), v.maintBack())
			return
		case !p.Pending:
			b.show(ctx, m, v.t("mt.apply.nothing"), v.maintBack())
			return
		case len(p.Blockers) > 0:
			q.WriteString(v.t("mt.apply.blocked", len(p.Blockers)) + "\n")
			q.WriteString(v.bullets(p.Blockers, 5))
			q.WriteString("\n" + v.t("mt.apply.blocked.fix"))
			b.show(ctx, m, q.String(), v.maintBack())
			return
		}
		q.WriteString(v.t("mt.apply.ask") + "\n")
		if p.Count > 0 {
			q.WriteString(v.t("mt.apply.count", p.Count) + " ")
		}
		if p.MayInterrupt {
			q.WriteString(v.t("mt.apply.interrupt"))
		}
		q.WriteString("\n" + v.t("mt.apply.window"))
		if len(p.Confirms) > 0 {
			q.WriteString("\n\n" + v.t("mt.apply.confirms") + "\n")
			q.WriteString(v.bullets(p.Confirms, 5))
		}
		ok, arg = v.t("mt.apply.ok"), p.Rev
	case actRestart:
		q.WriteString(v.t("mt.restart.ask"))
		ok = v.t("mt.restart.ok")
	case actBackup:
		q.WriteString(v.t("mt.backup.ask"))
		ok = v.t("mt.backup.ok")
	case actInstall:
		b.askInstall(ctx, v, m)
		return
	case actSpeed:
		text, kb := b.speedAsk(ctx, v, m.Chat.ID, ref)
		b.show(ctx, m, text, kb)
		return
	default:
		return
	}
	nonce := b.confirms.issue(m.Chat.ID, action, arg, b.now())
	kb := &Keyboard{Rows: [][]InlineButton{{btn(ok, cbConfirm+nonce), btn(v.t("b.cancel"), cbCancel+nonce)}}}
	b.show(ctx, m, strings.TrimRight(q.String(), "\n"), kb)
}

// bullets lists up to n items and counts the rest. The Apply question acknowledges every finding
// it names, so a list cut at five without a word hid findings the owner was agreeing to.
func (v view) bullets(items []string, n int) string {
	var b strings.Builder
	for _, t := range firstN(items, n) {
		b.WriteString("• " + esc(t) + "\n")
	}
	if len(items) > n {
		b.WriteString(v.t("digest.more", len(items)-n) + "\n")
	}
	return b.String()
}

func firstN(ss []string, n int) []string {
	if len(ss) > n {
		return ss[:n]
	}
	return ss
}

// run performs a confirmed action and leaves its outcome in the message.
func (b *Bot) run(ctx context.Context, v view, m *Message, cf confirmation, who string) {
	switch cf.action {
	case actApply:
		b.show(ctx, m, v.t("mt.apply.run"), nil)
		cctx, cancel := context.WithTimeout(ctx, applyWait)
		err := b.be.ApplyTest(cctx, cf.arg)
		cancel()
		if err != nil {
			b.show(ctx, m, v.t("mt.apply.fail", esc(err.Error())), v.maintBack())
			return
		}
		// The watcher sees the window open and sends Keep / Roll back to every owner.
		b.show(ctx, m, v.t("mt.apply.done", esc(who)), v.maintBack())
	case actRestart:
		// Said first: the restart takes this process down with it.
		b.show(ctx, m, v.t("mt.restart.run"), nil)
		cctx, cancel := context.WithTimeout(ctx, backendWait)
		err := b.be.RestartDaemon(cctx)
		cancel()
		if err != nil {
			b.show(ctx, m, v.t("mt.restart.fail", esc(errorText(v, err))), v.maintBack())
		}
	case actBackup:
		cctx, cancel := context.WithTimeout(ctx, backendWait)
		name, data, err := b.be.Backup(cctx)
		cancel()
		if err == nil {
			sctx, scancel := context.WithTimeout(ctx, time.Minute)
			_, err = b.api.SendDocument(sctx, m.Chat.ID, name, data, v.t("mt.backup.caption", v.clock(b.now())))
			scancel()
		}
		if err != nil {
			b.show(ctx, m, v.t("mt.backup.fail", esc(err.Error())), v.maintBack())
			return
		}
		b.show(ctx, m, v.t("mt.backup.sent"), v.maintBack())
	case actInstall:
		b.install(ctx, v, m, cf.arg)
	case actSpeed:
		// Up to a minute of measuring must not hold one of the handler slots other chats' presses
		// wait for; the speed-test lock already keeps tests one at a time.
		b.detach(func() { b.speed(ctx, v, m, cf.arg) })
	}
}

func (b *Bot) refreshLists(ctx context.Context, v view, m *Message) {
	b.show(ctx, m, v.t("mt.lists.run"), nil)
	cctx, cancel := context.WithTimeout(ctx, listsWait)
	r, err := b.be.RefreshLists(cctx)
	cancel()
	if err != nil {
		b.show(ctx, m, v.t("mt.lists.fail", esc(err.Error())), v.maintBack())
		return
	}
	var text strings.Builder
	if r.Lists == 0 {
		text.WriteString(v.t("mt.lists.none"))
	} else {
		text.WriteString(v.t("mt.lists.done", r.Changed, r.Lists))
	}
	for _, f := range r.Failed[:min(len(r.Failed), 3)] {
		key := "mt.lists.err"
		if f.Empty {
			key = "mt.lists.err.empty"
		}
		text.WriteString("\n⚠️ " + v.t(key, "«"+esc(f.List)+"»", esc(truncate(f.Err, 160))))
	}
	if len(r.Failed) > 3 {
		text.WriteString("\n" + v.t("digest.more", len(r.Failed)-3))
	}
	if r.Unreached > 0 {
		text.WriteString("\n" + v.t("mt.lists.unreached", r.Unreached))
	}
	var extra []InlineButton
	if r.Changed > 0 {
		extra = append(extra, btn(v.t("b.apply"), cbAsk+actApply))
	}
	b.show(ctx, m, text.String(), v.maintBack(extra...))
}

func (b *Bot) refreshSub(ctx context.Context, v view, m *Message) {
	b.show(ctx, m, v.t("mt.sub.run"), nil)
	cctx, cancel := context.WithTimeout(ctx, listsWait)
	added, err := b.be.RefreshSubscription(cctx)
	cancel()
	if err != nil {
		b.show(ctx, m, v.t("mt.sub.fail", esc(err.Error())), v.maintBack())
		return
	}
	var extra []InlineButton
	if added > 0 {
		extra = append(extra, btn(v.t("b.apply"), cbAsk+actApply))
	}
	b.show(ctx, m, v.t("mt.sub.done", added), v.maintBack(extra...))
}

// errorText is an error for the chat; ErrUnavailable reads as what it is.
func errorText(v view, err error) string {
	if errors.Is(err, ErrUnavailable) {
		return v.t("mt.unavailable")
	}
	return fmt.Sprint(err)
}
