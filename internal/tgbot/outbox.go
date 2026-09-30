package tgbot

import (
	"context"
	"errors"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"wayhop/internal/config"
)

const (
	outboxCap      = 200 // alerts waiting for delivery; the oldest non-critical ones go first
	heldCap        = 50  // alerts held per chat during quiet hours or a mute
	summaryLines   = 15  // lines in the summary that follows quiet hours
	incidentsCap   = 64  // open incidents remembered per chat
	sendGap        = 60 * time.Millisecond
	deliverTick    = 15 * time.Second
	maxDeliverWait = time.Minute
)

// queued is an alert on its way, with the chats that already have it: a retry after an outage
// must not deliver it twice.
type queued struct {
	a    Alert
	done map[int64]bool
}

// outbox holds alerts until they are delivered, what each chat has open, and who is muted.
type outbox struct {
	mu    sync.Mutex
	q     []*queued
	wake  chan struct{}
	open  map[int64]map[string]int64 // chat -> incident -> message id of its opening alert
	muted map[int64]time.Time
	held  map[int64][]Alert
	// unreach holds the chats that refuse the bot's messages (see reach.go).
	unreach map[int64]bool
}

func newOutbox() *outbox {
	return &outbox{wake: make(chan struct{}, 1), open: map[int64]map[string]int64{},
		muted: map[int64]time.Time{}, held: map[int64][]Alert{}, unreach: map[int64]bool{}}
}

func (o *outbox) push(a Alert) {
	o.mu.Lock()
	if len(o.q) >= outboxCap {
		drop := 0
		for i, q := range o.q {
			if q.a.Sev < SevCritical {
				drop = i
				break
			}
		}
		o.q = append(o.q[:drop], o.q[drop+1:]...)
	}
	o.q = append(o.q, &queued{a: a, done: map[int64]bool{}})
	o.mu.Unlock()
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

func (o *outbox) peek() *queued {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.q) == 0 {
		return nil
	}
	return o.q[0]
}

func (o *outbox) pop(q *queued) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.q) > 0 && o.q[0] == q {
		o.q = o.q[1:]
	}
}

func (o *outbox) openMsg(chat int64, incident string) (int64, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	id, ok := o.open[chat][incident]
	return id, ok
}

func (o *outbox) setOpen(chat int64, incident string, msg int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	m := o.open[chat]
	if m == nil {
		m = map[string]int64{}
		o.open[chat] = m
	}
	if len(m) >= incidentsCap {
		for k := range m {
			delete(m, k)
			break
		}
	}
	m[incident] = msg
}

func (o *outbox) closeOpen(chat int64, incident string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.open[chat], incident)
}

func (o *outbox) mute(chat int64, until time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if until.IsZero() {
		delete(o.muted, chat)
	} else {
		o.muted[chat] = until
	}
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

func (o *outbox) mutedUntil(chat int64, now time.Time) time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	if u, ok := o.muted[chat]; ok && now.Before(u) {
		return u
	}
	return time.Time{}
}

func (o *outbox) hold(chat int64, a Alert) {
	o.mu.Lock()
	defer o.mu.Unlock()
	h := append(o.held[chat], a)
	if len(h) > heldCap {
		h = h[len(h)-heldCap:]
	}
	o.held[chat] = h
}

func (o *outbox) takeHeld(chat int64) []Alert {
	o.mu.Lock()
	defer o.mu.Unlock()
	h := o.held[chat]
	delete(o.held, chat)
	return h
}

func (o *outbox) heldChats() []int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []int64
	for c, h := range o.held {
		if len(h) > 0 {
			out = append(out, c)
		}
	}
	return out
}

// clockMinutes parses "HH:MM" into minutes after midnight.
func clockMinutes(s string) (int, bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, false
	}
	h, err1 := strconv.Atoi(s[:2])
	m, err2 := strconv.Atoi(s[3:])
	if err1 != nil || err2 != nil || h > 23 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// inQuietHours reports whether now falls in [from, to), a window that may wrap midnight.
func inQuietHours(t config.Telegram, now time.Time) bool {
	from, ok1 := clockMinutes(t.QuietFrom)
	to, ok2 := clockMinutes(t.QuietTo)
	if !ok1 || !ok2 || from == to {
		return false
	}
	m := now.Hour()*60 + now.Minute()
	if from < to {
		return m >= from && m < to
	}
	return m >= from || m < to
}

func alertOff(t config.Telegram, kind string) bool {
	for _, k := range t.AlertsOff {
		if k == kind {
			return true
		}
	}
	return false
}

// Notify queues an alert for every paired chat that wants its kind.
func (b *Bot) Notify(a Alert) {
	if a.At.IsZero() {
		a.At = b.now()
	}
	b.out.push(a)
}

// deliverLoop sends queued alerts, holds back what can wait, and summarises what was held. A send
// that fails for a network reason keeps the alert queued: the outage that cut Telegram off is
// usually the news, and it must arrive when the link returns.
func (b *Bot) deliverLoop(ctx context.Context) {
	tick := time.NewTicker(deliverTick)
	defer tick.Stop()
	wait := time.Duration(0)
	for {
		if wait > 0 {
			if !sleep(ctx, wait) {
				return
			}
		}
		b.guard("held-alert summary", func() { b.flushHeld(ctx) })
		wait = 0
		for q := b.out.peek(); q != nil; q = b.out.peek() {
			var err error
			b.guard("alert delivery", func() { err = b.deliver(ctx, q) })
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				wait = retryAfter(err)
				if wait == 0 {
					wait = 5 * time.Second
				}
				if wait > maxDeliverWait {
					wait = maxDeliverWait
				}
				break
			}
			b.out.pop(q)
		}
		if wait > 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-b.out.wake:
		case <-tick.C:
		}
	}
}

// guard runs one step of the delivery loop with a panic contained, as the command handlers, the
// watcher and the digest are: a bug that makes one alert fail to render must cost that alert (the
// error stays nil, so the loop drops it and goes on), never the router's daemon.
func (b *Bot) guard(what string, f func()) {
	defer func() {
		if r := recover(); r != nil {
			b.logf("telegram: %s panic: %v\n%s", what, r, debug.Stack())
		}
	}()
	f()
}

// retryable is an error worth queueing for: the network, or Telegram asking to slow down. A
// refusal (bad request, blocked by the user) is not going to change on retry.
func retryable(err error) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.RetryAfter > 0 || ae.Code >= 500
	}
	return err != nil
}

// deliver sends one alert to every chat that should have it and does not yet.
func (b *Bot) deliver(ctx context.Context, q *queued) error {
	t := b.st.Telegram()
	now := b.now()
	a := q.a
	for _, rec := range t.Chats {
		if q.done[rec.ID] || !wants(t, rec, a.Kind) || (a.Owners && rec.Role != roleOwner) {
			continue
		}
		lang := b.langOf(rec, nil)
		err := b.deliverTo(ctx, t, rec, lang, a, now)
		if to := migratedTo(err); to != 0 && b.migrate(rec.ID, to) {
			rec.ID = to // the announcement was missed; Telegram's refusal named the new id
			err = b.deliverTo(ctx, t, rec, lang, a, now)
		}
		if err != nil {
			if retryable(err) {
				return err
			}
			b.refused(rec, err)
		}
		q.done[rec.ID] = true
		if !sleep(ctx, sendGap) {
			return ctx.Err()
		}
	}
	return nil
}

func (b *Bot) deliverTo(ctx context.Context, t config.Telegram, rec config.TelegramChat, lang string, a Alert, now time.Time) error {
	cctx, cancel := context.WithTimeout(ctx, sendWait)
	defer cancel()
	openID, hasOpen := int64(0), false
	for _, inc := range a.incidents() {
		if id, ok := b.out.openMsg(rec.ID, inc); ok {
			openID, hasOpen = id, true
			break
		}
	}
	closeAll := func() {
		for _, inc := range a.incidents() {
			b.out.closeOpen(rec.ID, inc)
		}
	}
	if a.Edit {
		if !hasOpen {
			return nil // this chat never got the opening message (held, or paired later)
		}
		text, kb := a.Render(lang, rec.Role)
		if rec.Role == roleAlerts {
			kb = nil
		}
		err := b.api.EditMessage(cctx, rec.ID, openID, text, kb)
		if a.Resolves {
			closeAll()
		}
		return err
	}
	if !a.Scheduled && (a.Sev == SevInfo || a.Sev == SevWarning) && (inQuietHours(t, now) || !b.out.mutedUntil(rec.ID, now).IsZero()) {
		b.out.hold(rec.ID, a)
		if a.Resolves {
			closeAll()
		}
		return nil
	}
	text, kb := a.Render(lang, rec.Role)
	if rec.Role == roleAlerts {
		kb = nil // an alerts-only chat has no buttons to press
	}
	opts := SendOptions{Keyboard: kb, Silent: a.Sev == SevInfo || a.Scheduled, NoPreview: true}
	// News about one incident replies to its opening message. A burst of new failures is its own
	// news, even when one of the exits had an older message; a burst of recoveries replies.
	if hasOpen && (a.Resolves || len(a.Incidents) == 0) {
		opts.ReplyTo = openID
	}
	m, err := b.api.SendMessage(cctx, rec.ID, text, opts)
	if d := retryAfter(err); d > 0 && d <= maxDeliverWait {
		if !sleep(ctx, d) {
			return ctx.Err()
		}
		m, err = b.api.SendMessage(cctx, rec.ID, text, opts)
	}
	if err != nil {
		return err
	}
	b.delivered(rec.ID)
	if a.Resolves {
		closeAll()
		if hasOpen && a.Closed != nil {
			// Best effort: the outcome has arrived; a failed edit only leaves old buttons, which
			// answer with the present state when pressed.
			_ = b.api.EditMessage(cctx, rec.ID, openID, a.Closed(lang), nil)
		}
		return nil
	}
	// This message opens every incident it tells of that has no opening message yet; one already
	// open keeps its own.
	for _, inc := range a.incidents() {
		if _, ok := b.out.openMsg(rec.ID, inc); !ok {
			b.out.setOpen(rec.ID, inc, m.MessageID)
		}
	}
	return nil
}

// flushHeld sends each chat one summary of what was held once its quiet hours or mute end.
func (b *Bot) flushHeld(ctx context.Context) {
	t := b.st.Telegram()
	now := b.now()
	if inQuietHours(t, now) {
		return
	}
	for _, chat := range b.out.heldChats() {
		if !b.out.mutedUntil(chat, now).IsZero() {
			continue
		}
		rec, ok := b.chatRecord(chat)
		held := b.out.takeHeld(chat)
		if !ok || len(held) == 0 {
			continue
		}
		lang := b.langOf(rec, nil)
		v := b.view(lang)
		var s strings.Builder
		s.WriteString(T(lang, "al.held", len(held)))
		loud := false
		for i, a := range held {
			if i == summaryLines {
				s.WriteString("\n" + T(lang, "al.held.more", len(held)-summaryLines))
				break
			}
			s.WriteString("\n<code>" + v.clock(a.At) + "</code> " + a.Line(lang))
			loud = loud || a.Sev >= SevWarning
		}
		opts := SendOptions{Silent: !loud, NoPreview: true,
			Keyboard: &Keyboard{Rows: [][]InlineButton{{btn(T(lang, "b.status"), cbStatus)}}}}
		cctx, cancel := context.WithTimeout(ctx, sendWait)
		_, err := b.api.SendMessage(cctx, chat, s.String(), opts)
		if to := migratedTo(err); to != 0 && b.migrate(chat, to) {
			chat = to
			_, err = b.api.SendMessage(cctx, chat, s.String(), opts)
		}
		cancel()
		if err != nil && !retryable(err) {
			// A chat that refuses the summary will not take it on the next tick either: held again,
			// it was sent again every 15 seconds, for good.
			b.refused(rec, err)
			continue
		}
		if err != nil {
			b.logf("telegram: held-alert summary to %d: %v", chat, err)
			for _, a := range held {
				b.out.hold(chat, a)
			}
			return
		}
		b.delivered(chat)
	}
}
