package tgbot

import (
	"context"
	"crypto/rand"
	"encoding/base32"
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
	// The routing switch: off takes WayHop's routing off the router, on restores the last applied
	// configuration. Both ask first.
	actRoutingOff = "routeoff"
	actRoutingOn  = "routeon"
)

// routingWait bounds a switch: switching on re-executes the committed configuration.
const routingWait = 2 * time.Minute

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
	if s.Routing.Off {
		b.WriteString(v.t("st.routingoff") + "\n")
	}
	b.WriteString("\n<i>" + v.t("mt.hint") + "</i>")
	var rows [][]InlineButton
	if s.Changes.Pending && !s.Routing.Off {
		rows = append(rows, []InlineButton{btn(v.t("b.apply"), cbAsk+actApply)})
	}
	rows = append(rows, []InlineButton{v.routingButton(s)})
	rows = append(rows,
		[]InlineButton{btn(v.t("b.lists"), cbDo+actLists), btn(v.t("b.sub"), cbDo+actSub)},
		[]InlineButton{btn(v.t("b.backup"), cbAsk+actBackup), btn(v.t("b.updates"), cbDo+actUpdate)},
		[]InlineButton{btn(v.t("b.restart"), cbAsk+actRestart)},
		[]InlineButton{btn(v.t("b.back"), cbMore), btn(v.t("b.status"), cbStatus)},
	)
	return b.String(), &Keyboard{Rows: rows}
}

// routingButton is the routing switch's button: the way to the other state.
func (v view) routingButton(s Status) InlineButton {
	if s.Routing.Off {
		return btn(v.t("b.routing.on"), cbAsk+actRoutingOn)
	}
	return btn(v.t("b.routing.off"), cbAsk+actRoutingOff)
}

// Routing renders the routing switch on its own: what it is now, and the button to change it.
func (v view) Routing(s Status) (string, *Keyboard) {
	var b strings.Builder
	if s.Routing.Off {
		b.WriteString(v.t("rt.off") + "\n")
		if !s.Routing.Since.IsZero() {
			b.WriteString(v.t("rt.since", v.clock(s.Routing.Since)) + "\n")
		}
		if s.Routing.Err != "" {
			b.WriteString("\n⚠️ " + esc(truncate(s.Routing.Err, 400)) + "\n")
		}
	} else {
		b.WriteString(v.t("rt.on") + "\n")
	}
	b.WriteString("\n<i>" + v.t("rt.hint") + "</i>")
	return b.String(), &Keyboard{Rows: [][]InlineButton{{v.routingButton(s)}, {btn(v.t("b.maint.back"), cbMaint)}}}
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
	case "routing":
		render = func() (string, *Keyboard) { return v.Routing(b.status(ctx)) }
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
		// A refresh runs for up to a minute and an update check reaches GitHub: off the handler
		// slots, like the confirmed actions below, so that four of them cannot hold every slot while
		// an owner's Keep waits behind them.
		switch strings.TrimPrefix(data, cbDo) {
		case actLists:
			b.detach(func() { b.refreshLists(ctx, v, m) })
		case actSub:
			b.detach(func() { b.refreshSub(ctx, v, m) })
		case actUpdate:
			b.detach(func() { b.updateCheck(ctx, v, m) })
		}
	case strings.HasPrefix(data, cbAsk):
		b.answer(ctx, q, "", false)
		action, ref, _ := strings.Cut(strings.TrimPrefix(data, cbAsk), ":")
		if action == actInstall {
			// The question follows a fresh update check, which may take its 45 seconds.
			b.detach(func() { b.ask(ctx, v, m, action, ref) })
			return true
		}
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
			b.show(ctx, m, v.t("mt.apply.fail", esc(errorText(v, err))), v.maintBack())
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
	case actRoutingOff, actRoutingOn:
		// Asked against the state as it is now: a stale button for the state the router already has
		// shows that state instead of a question with only one answer.
		st := b.status(ctx)
		if st.Routing.Off == (action == actRoutingOff) {
			text, kb := v.Routing(st)
			b.show(ctx, m, text, kb)
			return
		}
		if action == actRoutingOff {
			q.WriteString(v.t("rt.off.ask"))
			ok = v.t("rt.off.ok")
		} else {
			q.WriteString(v.t("rt.on.ask"))
			ok = v.t("rt.on.ok")
		}
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

// run performs a confirmed action and leaves its outcome in the message. What takes long (an Apply,
// a backup upload, a routing switch, an install, a speed test) runs outside the handler slots: an
// Apply that holds a slot for its minutes is exactly when an owner's Keep must not queue behind it.
func (b *Bot) run(ctx context.Context, v view, m *Message, cf confirmation, who string) {
	switch cf.action {
	case actApply:
		b.detach(func() { b.applyTest(ctx, v, m, cf.arg, who) })
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
		b.detach(func() { b.backup(ctx, v, m) })
	case actRoutingOff, actRoutingOn:
		// Up to two minutes of tearing routes down or putting them back, so like an Apply it runs
		// outside the handler slots.
		b.detach(func() { b.switchRouting(ctx, v, m, cf.action == actRoutingOn, who) })
	case actInstall:
		b.detach(func() { b.install(ctx, v, m, cf.arg) })
	case actSpeed:
		// Up to a minute of measuring must not hold one of the handler slots other chats' presses
		// wait for; the speed-test lock already keeps tests one at a time.
		b.detach(func() { b.speed(ctx, v, m, cf.arg) })
	}
}

// applyTest is the confirmed Apply, as a test: the watcher sees the window open and sends Keep /
// Roll back to every owner.
func (b *Bot) applyTest(ctx context.Context, v view, m *Message, rev, who string) {
	b.show(ctx, m, v.t("mt.apply.run"), nil)
	cctx, cancel := context.WithTimeout(ctx, applyWait)
	err := b.be.ApplyTest(cctx, rev)
	cancel()
	if err != nil {
		b.show(ctx, m, v.t("mt.apply.fail", esc(errorText(v, err))), v.maintBack())
		return
	}
	b.show(ctx, m, v.t("mt.apply.done", esc(who)), v.maintBack())
}

// switchRouting is the confirmed routing switch: off, or back on, without touching the configuration.
func (b *Bot) switchRouting(ctx context.Context, v view, m *Message, on bool, who string) {
	running, done := "rt.off.run", "rt.off.done"
	if on {
		running, done = "rt.on.run", "rt.on.done"
	}
	b.show(ctx, m, v.t(running), nil)
	cctx, cancel := context.WithTimeout(ctx, routingWait)
	err := b.be.SetRouting(cctx, on)
	cancel()
	back := &Keyboard{Rows: [][]InlineButton{{btn(v.t("b.maint.back"), cbMaint), btn(v.t("b.status"), cbStatus)}}}
	if err != nil {
		b.show(ctx, m, v.t("rt.fail", esc(truncate(errorText(v, err), 600))), back)
		return
	}
	b.show(ctx, m, v.t(done, esc(who)), back)
}

// backup sends the full backup to the chat as a file.
func (b *Bot) backup(ctx context.Context, v view, m *Message) {
	cctx, cancel := context.WithTimeout(ctx, backendWait)
	name, data, err := b.be.Backup(cctx)
	cancel()
	if err == nil {
		sctx, scancel := context.WithTimeout(ctx, time.Minute)
		_, err = b.api.SendDocument(sctx, m.Chat.ID, name, data, v.t("mt.backup.caption", v.clock(b.now())))
		scancel()
	}
	if err != nil {
		b.show(ctx, m, v.t("mt.backup.fail", esc(errorText(v, err))), v.maintBack())
		return
	}
	b.show(ctx, m, v.t("mt.backup.sent"), v.maintBack())
}

func (b *Bot) refreshLists(ctx context.Context, v view, m *Message) {
	b.show(ctx, m, v.t("mt.lists.run"), nil)
	cctx, cancel := context.WithTimeout(ctx, listsWait)
	r, err := b.be.RefreshLists(cctx)
	cancel()
	if err != nil {
		b.show(ctx, m, v.t("mt.lists.fail", esc(errorText(v, err))), v.maintBack())
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
		b.show(ctx, m, v.t("mt.sub.fail", esc(errorText(v, err))), v.maintBack())
		return
	}
	var extra []InlineButton
	if added > 0 {
		extra = append(extra, btn(v.t("b.apply"), cbAsk+actApply))
	}
	b.show(ctx, m, v.t("mt.sub.done", added), v.maintBack(extra...))
}
