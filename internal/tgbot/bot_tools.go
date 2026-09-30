package tgbot

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	"wayhop/internal/config"
)

const (
	askFor    = 3 * time.Minute // how long a question ("which site?") waits for its answer
	traceWait = 15 * time.Second
	diagWait  = 25 * time.Second
	probeWait = 15 * time.Second
)

// asks remembers which chats were asked a question and are expected to answer it with their next
// plain message.
type asks struct {
	mu sync.Mutex
	m  map[int64]pendingAsk
}

type pendingAsk struct {
	kind  string
	until time.Time
}

func (a *asks) set(chat int64, kind string, until time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.m == nil {
		a.m = map[int64]pendingAsk{}
	}
	a.m[chat] = pendingAsk{kind: kind, until: until}
}

// take returns the question a chat still owes an answer to, and forgets it.
func (a *asks) take(chat int64, now time.Time) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.m[chat]
	delete(a.m, chat)
	if !ok || now.After(p.until) {
		return ""
	}
	return p.kind
}

// cleanTarget turns what people paste into what the tools take: "https://www.youtube.com/watch?v=x"
// becomes "www.youtube.com", a trailing dot goes, and a mistyped scheme-less path loses its path.
func cleanTarget(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	if i := strings.IndexAny(s, "/?#"); i > 0 {
		s = s[:i]
	}
	if strings.Count(s, ":") == 1 { // host:port, not an IPv6 address
		s = s[:strings.IndexByte(s, ':')]
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(s, "[]"), "."))
}

// looksLikeHost reports whether a plain message is plausibly a site or an address: one word, a dot
// or a colon in it, and only the characters a hostname or an IP literal can have.
func looksLikeHost(s string) bool {
	s = cleanTarget(s)
	if s == "" || len(s) > 253 || !strings.ContainsAny(s, ".:") || strings.ContainsAny(s, " \t") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == ':' || r == '_') {
			return false
		}
	}
	return !strings.HasPrefix(s, ".") && !strings.HasPrefix(s, "-")
}

// askRoute asks which destination to trace; the next plain message from the chat answers it.
func (b *Bot) askRoute(ctx context.Context, chat int64, lang string) {
	b.asks.set(chat, "route", b.now().Add(askFor))
	cctx, cancel := context.WithTimeout(ctx, sendWait)
	defer cancel()
	if _, err := b.api.SendMessage(cctx, chat, b.view(lang).RoutePrompt(), SendOptions{Ask: "youtube.com"}); err != nil {
		b.logf("telegram: send to %d: %v", chat, err)
	}
}

// route traces target and either sends the answer or, when m is a message the bot sent, replaces it.
func (b *Bot) route(ctx context.Context, v view, chat int64, target string, m *Message) {
	target = cleanTarget(target)
	cctx, cancel := context.WithTimeout(ctx, traceWait)
	tr, err := b.be.Trace(cctx, target)
	cancel()
	var text string
	var kb *Keyboard
	switch {
	case errors.Is(err, ErrBadTarget) || target == "":
		text = v.t("rt.bad")
	case err != nil:
		text = v.t("err.backend", esc(err.Error()))
	default:
		text, kb = v.Trace(tr, b.status(ctx))
	}
	if m != nil {
		b.show(ctx, m, text, kb)
		return
	}
	b.reply(ctx, chat, "", func() (string, *Keyboard) { return text, kb })
}

func (b *Bot) devices(ctx context.Context, v view, chat int64, m *Message) {
	cctx, cancel := context.WithTimeout(ctx, backendWait)
	devs := b.be.Devices(cctx)
	cancel()
	text, kb := v.Devices(devs)
	if m != nil {
		b.show(ctx, m, text, kb)
		return
	}
	b.reply(ctx, chat, "", func() (string, *Keyboard) { return text, kb })
}

// diag runs the Diagnostics battery once at a time for the whole bot: it fans out to a dozen
// remote probes, and two chats pressing it together must not double that on a small router. The
// "running" message is replaced by the result.
func (b *Bot) diag(ctx context.Context, v view, chat int64, m *Message, q *CallbackQuery) {
	if !b.diagMu.TryLock() {
		if q != nil {
			b.answer(ctx, q, v.t("dg.busy"), false)
		} else {
			b.reply(ctx, chat, v.t("dg.busy"), nil)
		}
		return
	}
	defer b.diagMu.Unlock()
	if q != nil {
		b.answer(ctx, q, "", false)
	}
	if m != nil {
		b.show(ctx, m, v.t("dg.running"), nil)
	} else {
		cctx, cancel := context.WithTimeout(ctx, sendWait)
		sent, err := b.api.SendMessage(cctx, chat, v.t("dg.running"), SendOptions{})
		cancel()
		if err != nil {
			b.logf("telegram: send to %d: %v", chat, err)
			return
		}
		m = &sent
		m.Chat.ID = chat
	}
	cctx, cancel := context.WithTimeout(ctx, diagWait)
	checks := b.be.Diagnose(cctx)
	cancel()
	text, kb := v.Diag(checks, b.now())
	b.show(ctx, m, text, kb)
}

func (b *Bot) ping(ctx context.Context, v view, chat int64, target string) {
	target = cleanTarget(target)
	if target == "" {
		b.reply(ctx, chat, v.t("pg.usage"), nil)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, probeWait)
	p, err := b.be.Ping(cctx, target)
	cancel()
	switch {
	case errors.Is(err, ErrBadTarget):
		b.reply(ctx, chat, v.t("rt.bad"), nil)
	case err != nil:
		b.reply(ctx, chat, v.t("err.backend", esc(err.Error())), nil)
	default:
		b.reply(ctx, chat, v.Ping(p), nil)
	}
}

func (b *Bot) lookup(ctx context.Context, v view, chat int64, target string) {
	target = cleanTarget(target)
	if target == "" {
		b.reply(ctx, chat, v.t("dn.usage"), nil)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, probeWait)
	l, err := b.be.Lookup(cctx, target)
	cancel()
	switch {
	case errors.Is(err, ErrBadTarget):
		b.reply(ctx, chat, v.t("rt.bad"), nil)
	case err != nil:
		b.reply(ctx, chat, v.t("err.backend", esc(err.Error())), nil)
	default:
		b.reply(ctx, chat, v.Lookup(l), nil)
	}
}

// toolCommand runs the tool commands. It reports whether cmd was one of them.
func (b *Bot) toolCommand(ctx context.Context, v view, rec config.TelegramChat, cmd, arg string) bool {
	chat := rec.ID
	switch cmd {
	case "route", "trace", "where":
		if strings.TrimSpace(arg) == "" {
			b.askRoute(ctx, chat, v.lang)
		} else {
			b.route(ctx, v, chat, arg, nil)
		}
	case "devices", "clients":
		b.devices(ctx, v, chat, nil)
	case "diag", "check", "diagnostics":
		b.diag(ctx, v, chat, nil, nil)
	case "ping":
		b.ping(ctx, v, chat, arg)
	case "dns", "resolve", "nslookup":
		b.lookup(ctx, v, chat, arg)
	case "summary", "digest":
		b.summary(ctx, v, chat, nil)
	case "more", "tools":
		b.reply(ctx, chat, "", v.More)
	default:
		return false
	}
	return true
}

// toolCallback runs the tool buttons. It reports whether data was one of them.
func (b *Bot) toolCallback(ctx context.Context, v view, q *CallbackQuery) bool {
	m := q.Message
	switch {
	case q.Data == cbMore:
		b.answer(ctx, q, "", false)
		text, kb := v.More()
		b.show(ctx, m, text, kb)
	case q.Data == cbRoute:
		b.answer(ctx, q, "", false)
		b.askRoute(ctx, m.Chat.ID, v.lang)
	case strings.HasPrefix(q.Data, cbRouteAg):
		target, ok := b.refs.resolve(strings.TrimPrefix(q.Data, cbRouteAg))
		if !ok {
			b.answer(ctx, q, v.t("stale"), false)
			b.askRoute(ctx, m.Chat.ID, v.lang)
			return true
		}
		b.answer(ctx, q, "🔎", false)
		b.route(ctx, v, m.Chat.ID, target, m)
	case q.Data == cbDevices:
		b.answer(ctx, q, "", false)
		b.devices(ctx, v, m.Chat.ID, m)
	case q.Data == cbSummary:
		b.answer(ctx, q, "", false)
		b.summary(ctx, v, m.Chat.ID, m)
	case q.Data == cbDiag:
		b.diag(ctx, v, m.Chat.ID, m, q)
	default:
		return false
	}
	return true
}
