package tgbot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/localtz"
)

const (
	pollTimeout = 50 // seconds Telegram holds a getUpdates open
	watchEvery  = 5 * time.Second
	// staleCommand: a text command older than this when it arrives is dropped. Telegram keeps
	// unconfirmed updates for a day, so a router coming back from a power cut would otherwise answer
	// hours-old commands.
	staleCommand = 2 * time.Minute
	maxInflight  = 4 // updates handled at once
	backendWait  = 10 * time.Second
	sendWait     = 15 * time.Second
	testWait     = 12 * time.Second
)

// Bot states, as the panel shows them.
const (
	StateOff          = "off"
	StateConnecting   = "connecting"
	StateOnline       = "online"
	StateError        = "error"
	StateUnauthorized = "unauthorized"
	StateConflict     = "conflict"
)

// Info is the bot's connection state for the panel.
type Info struct {
	State    string    `json:"state"`
	Username string    `json:"username,omitempty"`
	Name     string    `json:"name,omitempty"`
	Error    string    `json:"error,omitempty"`
	Since    time.Time `json:"since"`
	LastPoll time.Time `json:"last_poll,omitempty"`
}

// Options are the optional parts of a Bot.
type Options struct {
	Gate *Gate
	Now  func() time.Time
	Logf func(format string, args ...any)
	// out carries the alerts, mutes and open incidents over from the bot this one replaces.
	out *outbox
}

// Bot is one running bot: one token, one poll loop.
type Bot struct {
	api      *Client
	be       Backend
	st       Store
	gate     *Gate
	now      func() time.Time
	logf     func(string, ...any)
	started  time.Time
	refs     *refTable
	sem      chan struct{}
	wg       sync.WaitGroup
	out      *outbox
	watch    *watcher
	asks     asks
	confirms confirms
	menus    menus      // touched only by menuLoop
	diagMu   sync.Mutex // one Diagnostics run at a time
	upd      updates
	// updateFirst and updateEvery pace the daily update check (tests shorten them).
	updateFirst, updateEvery time.Duration
	// counters are the totals the next digest measures from: the digest loop moves them, /summary
	// reads them, hence the lock. digestSent, the day it last sent, is the loop's alone.
	digestMu   sync.Mutex
	counters   counters
	digestSent string

	mu   sync.Mutex
	me   User
	info Info
}

// routerNow is the router's wall clock, in the zone its own `date` uses. Every time the bot shows
// and every local-time setting (quiet hours, the digest) is read in it; Go alone would say UTC on
// KeeneticOS and on OpenWrt without zoneinfo.
func routerNow() time.Time { return time.Now().In(localtz.Location()) }

// New builds a bot. Run starts it.
func New(api *Client, be Backend, st Store, o Options) *Bot {
	if o.Gate == nil {
		o.Gate = NewGate()
	}
	if o.Now == nil {
		o.Now = routerNow
	}
	if o.Logf == nil {
		o.Logf = log.Printf
	}
	if o.out == nil {
		o.out = newOutbox()
	}
	b := &Bot{api: api, be: be, st: st, gate: o.Gate, now: o.Now, logf: o.Logf, refs: newRefTable(),
		sem: make(chan struct{}, maxInflight), out: o.out, watch: newWatcher(),
		updateFirst: updateFirst, updateEvery: updateEvery}
	b.started = b.now()
	b.info = Info{State: StateConnecting, Since: b.started}
	return b
}

// Info returns the connection state.
func (b *Bot) Info() Info {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.info
}

// Me returns the bot's identity once it is known.
func (b *Bot) Me() User {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.me
}

func (b *Bot) setState(state, errText string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.info.State != state || b.info.Error != errText {
		if state != b.info.State {
			b.info.Since = b.now()
		}
		if state == StateError || state == StateConflict || state == StateUnauthorized {
			b.logf("telegram: %s: %s", state, errText)
		}
	}
	b.info.State, b.info.Error = state, errText
	if state == StateOnline {
		b.info.LastPoll = b.now()
	}
}

// backoff grows 1s, 2s, 4s ... up to max, and resets on success.
type backoff struct {
	n   int
	max time.Duration
}

func (bo *backoff) next() time.Duration {
	d := time.Second << bo.n
	if d > bo.max || d <= 0 {
		d = bo.max
	} else {
		bo.n++
	}
	return d
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Run connects and serves until ctx ends. It never returns early on a network or API error: a
// router loses its uplink all the time, and the bot must come back by itself when it returns.
func (b *Bot) Run(ctx context.Context) {
	defer b.wg.Wait()
	// The watcher and the outbox run from the start, connected or not: alerts raised while Telegram
	// is unreachable are delivered when it comes back.
	b.wg.Add(5)
	go func() { defer b.wg.Done(); b.watchLoop(ctx) }()
	go func() { defer b.wg.Done(); b.menuLoop(ctx) }()
	go func() { defer b.wg.Done(); b.deliverLoop(ctx) }()
	go func() { defer b.wg.Done(); b.updateLoop(ctx) }()
	go func() { defer b.wg.Done(); b.digestLoop(ctx) }()
	bo := backoff{max: time.Minute}
	for {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		me, err := b.api.GetMe(cctx)
		cancel()
		if err == nil {
			b.mu.Lock()
			b.me = me
			b.info.Username, b.info.Name = me.Username, me.FirstName
			b.mu.Unlock()
			break
		}
		if ctx.Err() != nil {
			return
		}
		wait := bo.next()
		if IsUnauthorized(err) {
			// A revoked or mistyped token does not heal itself; the panel restarts the bot when the
			// token changes. Check rarely, in case it was a transient 401 from a proxy.
			b.setState(StateUnauthorized, "Telegram rejected the bot token")
			wait = 10 * time.Minute
		} else {
			b.setState(StateError, err.Error())
		}
		if !sleep(ctx, wait) {
			return
		}
	}
	b.setup(ctx)
	b.detach(func() { b.describe(ctx) })
	// Telegram answered getMe: the bot is reachable now, not after the first long poll returns.
	b.setState(StateOnline, "")

	var offset int64
	bo = backoff{max: time.Minute}
	for ctx.Err() == nil {
		cctx, cancel := context.WithTimeout(ctx, (pollTimeout+20)*time.Second)
		ups, err := b.api.GetUpdates(cctx, offset, pollTimeout)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			wait := bo.next()
			switch {
			case IsConflict(err):
				b.setState(StateConflict, "another program is reading this bot's updates (the same token is used elsewhere)")
				wait = 30 * time.Second
			case IsUnauthorized(err):
				b.setState(StateUnauthorized, "Telegram rejected the bot token")
				wait = 10 * time.Minute
			default:
				b.setState(StateError, err.Error())
			}
			if d := retryAfter(err); d > wait {
				wait = d
			}
			if !sleep(ctx, wait) {
				return
			}
			continue
		}
		bo = backoff{max: time.Minute}
		b.setState(StateOnline, "")
		for _, u := range ups {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			b.dispatch(ctx, u)
		}
	}
}

// clientCodes are the Telegram client languages the bot answers in something other than English,
// in a stable order: each gets its own menu and description.
func clientCodes() []string {
	codes := make([]string, 0, len(clientLangs))
	for code := range clientLangs {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	return codes
}

// describe sets what Telegram shows in an empty chat with the bot before /start, what this bot is
// and how a chat is paired, and the line on its profile, in English by default and for every client
// language the bot answers in another. Twenty calls, so it runs once per start, off the poll loop;
// a failure only leaves the previous text in place.
func (b *Bot) describe(ctx context.Context) {
	for _, code := range append([]string{""}, clientCodes()...) {
		lang := Languages[0]
		if code != "" {
			lang = clientLangs[code]
		}
		for _, set := range []func(context.Context) error{
			func(c context.Context) error { return b.api.SetDescription(c, T(lang, "about"), code) },
			func(c context.Context) error { return b.api.SetShortDescription(c, T(lang, "about.short"), code) },
		} {
			cctx, cancel := context.WithTimeout(ctx, sendWait)
			err := set(cctx)
			cancel()
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				b.logf("telegram: description (%s): %v", code, err)
			}
		}
	}
}

// setup clears a leftover webhook (it would make every getUpdates a 409) and publishes the
// command menu. Failures are logged, not fatal: the bot works without a menu.
func (b *Bot) setup(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, sendWait)
	defer cancel()
	if err := b.api.DeleteWebhook(cctx); err != nil {
		b.logf("telegram: deleteWebhook: %v", err)
	}
	// The default menu, for every client language without its own, then one per client language the
	// bot answers in another language, so the menu reads like the replies.
	if err := b.api.SetCommands(cctx, commandMenu(Languages[0]), ""); err != nil {
		b.logf("telegram: setMyCommands: %v", err)
	}
	for _, code := range clientCodes() {
		if err := b.api.SetCommands(cctx, commandMenu(clientLangs[code]), code); err != nil {
			b.logf("telegram: setMyCommands(%s): %v", code, err)
		}
	}
}

// watchLoop turns router state changes into alerts.
func (b *Bot) watchLoop(ctx context.Context) {
	t := time.NewTicker(watchEvery)
	defer t.Stop()
	for {
		b.watchOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (b *Bot) watchOnce(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			b.logf("telegram: watcher panic: %v\n%s", r, debug.Stack())
		}
	}()
	cctx, cancel := context.WithTimeout(ctx, backendWait)
	p := b.be.Pulse(cctx)
	cancel()
	log := b.be.Events(256)
	for _, a := range b.watch.step(b.now(), p, log, func() Status { return b.status(ctx) }) {
		b.Notify(a)
	}
}

func commandMenu(lang string) []Command { return chatMenu(lang, roleViewer) }

// dispatch hands one update to a worker. A handler panic is contained: the bot is a convenience,
// and a bug in a view must never take the router's daemon down with it.
func (b *Bot) dispatch(ctx context.Context, u Update) {
	select {
	case b.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		defer func() { <-b.sem }()
		defer func() {
			if r := recover(); r != nil {
				b.logf("telegram: handler panic: %v\n%s", r, debug.Stack())
			}
		}()
		b.handle(ctx, u)
	}()
}

// detach runs a long confirmed action outside the handler slots, which it would otherwise hold for
// its whole length while other chats' presses queue behind it. Run waits for it like for a handler,
// and a panic in it is contained the same way.
func (b *Bot) detach(f func()) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				b.logf("telegram: handler panic: %v\n%s", r, debug.Stack())
			}
		}()
		f()
	}()
}

func (b *Bot) handle(ctx context.Context, u Update) {
	switch {
	case u.CallbackQuery != nil:
		b.onCallback(ctx, u.CallbackQuery)
	case u.Message != nil:
		b.onMessage(ctx, u.Message)
	case u.ChannelPost != nil:
		b.onMessage(ctx, u.ChannelPost)
	}
}

// chatRecord finds a paired chat.
func (b *Bot) chatRecord(id int64) (config.TelegramChat, bool) {
	for _, c := range b.st.Telegram().Chats {
		if c.ID == id {
			return c, true
		}
	}
	return config.TelegramChat{}, false
}

func (b *Bot) langOf(rec config.TelegramChat, from *User) string {
	if rec.Lang != "" {
		return rec.Lang
	}
	if from != nil {
		return LangFor(from.LanguageCode)
	}
	return Languages[0]
}

func (b *Bot) view(lang string) view {
	return view{lang: lang, now: b.now(), ref: b.refs.ref}
}

// chatView is a view for one paired chat: its role decides the buttons, its mute is shown.
func (b *Bot) chatView(lang string, rec config.TelegramChat) view {
	v := b.view(lang)
	v.role, v.muted = rec.Role, b.out.mutedUntil(rec.ID, v.now)
	return v
}

var commandRE = regexp.MustCompile(`^/([A-Za-z0-9_]{1,32})(?:@([A-Za-z0-9_]{3,64}))?(?:\s+(.*))?$`)

// parseCommand splits "/cmd@bot args". addressed is false for a command meant for another bot in
// the same group.
func parseCommand(text, botUser string) (cmd, arg string, addressed bool) {
	m := commandRE.FindStringSubmatch(strings.TrimSpace(text))
	if m == nil {
		return "", strings.TrimSpace(text), true
	}
	if m[2] != "" && botUser != "" && !strings.EqualFold(m[2], botUser) {
		return "", "", false
	}
	return strings.ToLower(m[1]), strings.TrimSpace(m[3]), true
}

func (b *Bot) onMessage(ctx context.Context, m *Message) {
	// A group's move to a supergroup is announced in both chats, as messages with no text. They are
	// followed however late they arrive: they are not commands, and a missed one costs the alerts.
	switch {
	case m.MigrateToChatID != 0:
		b.migrate(m.Chat.ID, m.MigrateToChatID)
		return
	case m.MigrateFromChatID != 0:
		b.migrate(m.MigrateFromChatID, m.Chat.ID)
		return
	}
	if m.Text == "" {
		return
	}
	if m.Date > 0 && b.started.Sub(time.Unix(m.Date, 0)) > staleCommand {
		return
	}
	cmd, arg, addressed := parseCommand(m.Text, b.Me().Username)
	if !addressed {
		return
	}
	private := m.Chat.Type == "private"
	rec, paired := b.chatRecord(m.Chat.ID)
	if !paired {
		code := ""
		switch {
		case cmd == "start" || cmd == "pair":
			code = arg
		case cmd == "" && private && looksLikeCode(arg):
			code = arg // a code pasted on its own
		}
		if code != "" {
			b.pair(ctx, m, code)
			return
		}
		// Group chatter is not addressed to the bot; everything else gets one polite refusal
		// per interval and lands in the panel's list of chats that asked.
		if (private || cmd != "") && b.gate.Seen(m.Chat, m.From) {
			b.reply(ctx, m.Chat.ID, T(LangFor(fromLang(m.From)), "stranger"), nil)
		}
		return
	}
	lang := b.langOf(rec, m.From)
	v := b.chatView(lang, rec)
	if cmd == "" && rec.Role != roleAlerts {
		// A plain message answers the question the bot asked, and in a private chat a bare site
		// name is a question in itself: "youtube.com" means "where does youtube.com go?".
		if b.asks.take(m.Chat.ID, b.now()) == "route" || (private && looksLikeHost(arg)) {
			b.route(ctx, v, m.Chat.ID, arg, nil)
			return
		}
	}
	if cmd == "" && !private {
		return // group chatter is not for the bot
	}
	if cmd == "start" && arg != "" {
		b.reply(ctx, m.Chat.ID, T(lang, "pair.already", T(lang, "role."+rec.Role)), nil)
		return
	}
	if rec.Role == roleAlerts {
		if cmd != "" {
			b.reply(ctx, m.Chat.ID, T(lang, "alerts.only"), nil)
		}
		return
	}
	switch cmd {
	case "start", "menu", "status":
		b.reply(ctx, m.Chat.ID, "", func() (string, *Keyboard) { return v.Status(b.status(ctx)) })
	case "exits":
		b.reply(ctx, m.Chat.ID, "", func() (string, *Keyboard) { return v.Exits(b.status(ctx), 0) })
	case "events":
		b.reply(ctx, m.Chat.ID, "", func() (string, *Keyboard) { return v.Events(b.be.Events(256), 0) })
	case "help":
		b.reply(ctx, m.Chat.ID, "", func() (string, *Keyboard) { return v.Help(rec.Role) })
	case "alerts", "notifications":
		b.reply(ctx, m.Chat.ID, "", func() (string, *Keyboard) { return v.Alerts(b.st.Telegram(), rec) })
	case "lang", "language":
		b.reply(ctx, m.Chat.ID, "", v.Lang)
	case "mute":
		b.setMute(ctx, rec, lang, arg, nil)
	case "unmute":
		b.setMute(ctx, rec, lang, "0", nil)
	default:
		if !b.toolCommand(ctx, v, rec, cmd, arg) && !b.maintCommand(ctx, v, rec, cmd) {
			b.reply(ctx, m.Chat.ID, T(lang, "unknown.cmd"), nil)
		}
	}
}

func fromLang(u *User) string {
	if u == nil {
		return ""
	}
	return u.LanguageCode
}

// pair redeems a code for the chat that sent it and records the chat.
func (b *Bot) pair(ctx context.Context, m *Message, code string) {
	lang := LangFor(fromLang(m.From))
	role, res := b.gate.Redeem(m.Chat, code)
	switch res {
	case RedeemLimited:
		b.reply(ctx, m.Chat.ID, T(lang, "pair.limited"), nil)
		return
	case RedeemBad:
		b.reply(ctx, m.Chat.ID, T(lang, "pair.bad"), nil)
		return
	}
	name := m.Chat.DisplayName()
	if m.Chat.Type == "private" && m.From != nil {
		name = m.From.DisplayName()
	}
	rec := config.TelegramChat{ID: m.Chat.ID, Name: name, Role: role, Lang: lang, PairedAt: b.now().Unix()}
	err := b.st.UpdateTelegram(func(t *config.Telegram) error {
		for i := range t.Chats {
			if t.Chats[i].ID == rec.ID {
				t.Chats[i] = rec
				return nil
			}
		}
		t.Chats = append(t.Chats, rec)
		return nil
	})
	if err != nil {
		b.logf("telegram: saving paired chat %d: %v", rec.ID, err)
		b.reply(ctx, m.Chat.ID, T(lang, "err.backend", esc(err.Error())), nil)
		return
	}
	b.logf("telegram: paired chat %d (%s) as %s", rec.ID, rec.Name, rec.Role)
	b.reply(ctx, m.Chat.ID, T(lang, "pair.ok", T(lang, "role."+role)), nil)
	if role != roleAlerts {
		v := b.view(lang)
		b.reply(ctx, m.Chat.ID, "", func() (string, *Keyboard) { return v.Status(b.status(ctx)) })
	}
}

// status reads the backend under its own deadline.
func (b *Bot) status(ctx context.Context) Status {
	cctx, cancel := context.WithTimeout(ctx, backendWait)
	defer cancel()
	s := b.be.Status(cctx)
	if s.At.IsZero() {
		s.At = b.now()
	}
	// The update line comes from the last check, which is the bot's own: a status must not reach
	// GitHub every time somebody presses Refresh.
	if info, _ := b.upd.get(); info.Available && info.Managed == "" {
		s.Update = SelfUpdate{Available: true, Latest: info.Latest}
	}
	return s
}

// reply sends text, or the output of render when text is empty.
func (b *Bot) reply(ctx context.Context, chat int64, text string, render func() (string, *Keyboard)) {
	var kb *Keyboard
	if render != nil {
		text, kb = render()
	}
	cctx, cancel := context.WithTimeout(ctx, sendWait)
	defer cancel()
	if _, err := b.api.SendMessage(cctx, chat, text, SendOptions{Keyboard: kb, NoPreview: true}); err != nil {
		b.logf("telegram: send to %d: %v", chat, err)
		return
	}
	b.delivered(chat) // an answer got through: a chat that had blocked the bot has let it back
}

// show replaces the message a button belongs to; if Telegram refuses the edit (too old, deleted),
// the view is sent as a new message instead.
func (b *Bot) show(ctx context.Context, m *Message, text string, kb *Keyboard) {
	cctx, cancel := context.WithTimeout(ctx, sendWait)
	defer cancel()
	err := b.api.EditMessage(cctx, m.Chat.ID, m.MessageID, text, kb)
	if err == nil {
		return
	}
	b.logf("telegram: edit in %d: %v", m.Chat.ID, err)
	if _, err := b.api.SendMessage(cctx, m.Chat.ID, text, SendOptions{Keyboard: kb, NoPreview: true}); err != nil {
		b.logf("telegram: send to %d: %v", m.Chat.ID, err)
	}
}

func (b *Bot) answer(ctx context.Context, q *CallbackQuery, text string, alert bool) {
	cctx, cancel := context.WithTimeout(ctx, sendWait)
	defer cancel()
	if err := b.api.AnswerCallback(cctx, q.ID, text, alert); err != nil {
		b.logf("telegram: answerCallbackQuery: %v", err)
	}
}

func (b *Bot) onCallback(ctx context.Context, q *CallbackQuery) {
	if q.Message == nil {
		b.answer(ctx, q, "", false)
		return
	}
	rec, paired := b.chatRecord(q.Message.Chat.ID)
	if !paired {
		b.answer(ctx, q, T(LangFor(q.From.LanguageCode), "err.denied"), true)
		return
	}
	lang := b.langOf(rec, &q.From)
	if rec.Role == roleAlerts {
		b.answer(ctx, q, T(lang, "alerts.only"), false)
		return
	}
	v := b.chatView(lang, rec)
	data := q.Data
	switch {
	case data == cbNoop:
		b.answer(ctx, q, "", false)
	case data == cbAlertsMenu:
		b.answer(ctx, q, "", false)
		text, kb := v.Alerts(b.st.Telegram(), rec)
		b.show(ctx, q.Message, text, kb)
	case strings.HasPrefix(data, cbAlertKind):
		b.toggleAlert(ctx, v, q, rec, strings.TrimPrefix(data, cbAlertKind))
	case data == cbStatus:
		b.answer(ctx, q, "", false)
		text, kb := v.Status(b.status(ctx))
		b.show(ctx, q.Message, text, kb)
	case data == cbExits:
		b.answer(ctx, q, "", false)
		text, kb := v.Exits(b.status(ctx), 0)
		b.show(ctx, q.Message, text, kb)
	case strings.HasPrefix(data, cbExitsPage):
		b.answer(ctx, q, "", false)
		page, _ := strconv.Atoi(strings.TrimPrefix(data, cbExitsPage))
		text, kb := v.Exits(b.status(ctx), page)
		b.show(ctx, q.Message, text, kb)
	case data == cbHelp:
		b.answer(ctx, q, "", false)
		text, kb := v.Help(rec.Role)
		b.show(ctx, q.Message, text, kb)
	case strings.HasPrefix(data, cbExit):
		b.answer(ctx, q, "", false)
		b.exitCard(ctx, v, q.Message, strings.TrimPrefix(data, cbExit), "")
	case strings.HasPrefix(data, cbTest):
		b.answer(ctx, q, "⚡", false)
		b.testExit(ctx, v, q.Message, strings.TrimPrefix(data, cbTest))
	case strings.HasPrefix(data, cbEvents):
		b.answer(ctx, q, "", false)
		page, _ := strconv.Atoi(strings.TrimPrefix(data, cbEvents))
		text, kb := v.Events(b.be.Events(256), page)
		b.show(ctx, q.Message, text, kb)
	case strings.HasPrefix(data, cbLang):
		b.setLang(ctx, q, rec, strings.TrimPrefix(data, cbLang))
	case strings.HasPrefix(data, cbMute):
		b.setMute(ctx, rec, lang, strings.TrimPrefix(data, cbMute), q)
	case data == cbKeep || data == cbRollback:
		b.decideApply(ctx, q, rec, lang, data == cbKeep)
	case b.maintCallback(ctx, v, q, rec):
	case b.toolCallback(ctx, v, q):
	default:
		// A button from an older build or a restarted daemon. Show the present instead of an error.
		b.answer(ctx, q, T(lang, "stale"), false)
		text, kb := v.Status(b.status(ctx))
		b.show(ctx, q.Message, text, kb)
	}
}

func (b *Bot) exitCard(ctx context.Context, v view, m *Message, ref, note string) {
	id, ok := b.refs.resolve(ref)
	var e Exit
	if ok {
		e, ok = b.status(ctx).ExitByID(id)
	}
	if !ok {
		text, kb := v.Exits(b.status(ctx), 0)
		b.show(ctx, m, "<i>"+v.t("ex.gone")+"</i>\n\n"+text, kb)
		return
	}
	text, kb := v.Exit(e, note)
	b.show(ctx, m, text, kb)
}

func (b *Bot) testExit(ctx context.Context, v view, m *Message, ref string) {
	id, ok := b.refs.resolve(ref)
	if !ok {
		b.exitCard(ctx, v, m, ref, "")
		return
	}
	cctx, cancel := context.WithTimeout(ctx, testWait)
	e, err := b.be.TestExit(cctx, id)
	cancel()
	if err != nil {
		b.exitCard(ctx, v, m, ref, v.t("ex.testfail", esc(err.Error())))
		return
	}
	text, kb := v.Exit(e, v.t("ex.tested")+" · "+v.clock(b.now()))
	b.show(ctx, m, text, kb)
}

func (b *Bot) setLang(ctx context.Context, q *CallbackQuery, rec config.TelegramChat, lang string) {
	ok := false
	for _, l := range Languages {
		ok = ok || l == lang
	}
	if !ok {
		b.answer(ctx, q, "", false)
		return
	}
	err := b.st.UpdateTelegram(func(t *config.Telegram) error {
		for i := range t.Chats {
			if t.Chats[i].ID == rec.ID {
				t.Chats[i].Lang = lang
			}
		}
		return nil
	})
	if err != nil {
		b.answer(ctx, q, err.Error(), true)
		return
	}
	b.answer(ctx, q, T(lang, "lang.set"), false)
	v := b.view(lang)
	text, kb := v.Status(b.status(ctx))
	b.show(ctx, q.Message, text, kb)
}

// refTable maps object ids to short callback tokens. Most ids are short and safe and are used as
// they are; a long or odd one gets a hash token, remembered for the life of the bot.
type refTable struct {
	mu    sync.Mutex
	byRef map[string]string
}

func newRefTable() *refTable { return &refTable{byRef: map[string]string{}} }

var plainRef = regexp.MustCompile(`^[A-Za-z0-9._-]{1,40}$`)

func (r *refTable) ref(id string) string {
	if plainRef.MatchString(id) {
		return id
	}
	sum := sha256.Sum256([]byte(id))
	ref := "~" + hex.EncodeToString(sum[:6])
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.byRef) > 4096 {
		r.byRef = map[string]string{}
	}
	r.byRef[ref] = id
	return ref
}

func (r *refTable) resolve(ref string) (string, bool) {
	if !strings.HasPrefix(ref, "~") {
		return ref, plainRef.MatchString(ref)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.byRef[ref]
	return id, ok
}

// String is for logs.
func (i Info) String() string {
	if i.Error != "" {
		return fmt.Sprintf("%s (%s)", i.State, i.Error)
	}
	return i.State
}

// setMute mutes a chat's alerts for arg minutes ("" = 60, "0" = unmute). Critical alerts and
// Keep/Roll back requests still arrive; what was held is summarised when the mute ends.
func (b *Bot) setMute(ctx context.Context, rec config.TelegramChat, lang, arg string, q *CallbackQuery) {
	mins := 60
	if arg != "" {
		n, err := strconv.Atoi(strings.TrimSpace(arg))
		if err != nil || n < 0 || n > 7*24*60 {
			n = 60
		}
		mins = n
	}
	var msg string
	if mins == 0 {
		b.out.mute(rec.ID, time.Time{})
		msg = T(lang, "mute.off")
	} else {
		until := b.now().Add(time.Duration(mins) * time.Minute)
		b.out.mute(rec.ID, until)
		msg = T(lang, "mute.on", b.view(lang).clock(until))
	}
	if q != nil {
		b.answer(ctx, q, msg, false)
		return
	}
	b.reply(ctx, rec.ID, msg, nil)
}

// decideApply is Keep or Roll back pressed on a test-Apply message. Owners only: it changes what
// the router runs.
func (b *Bot) decideApply(ctx context.Context, q *CallbackQuery, rec config.TelegramChat, lang string, keep bool) {
	if rec.Role != roleOwner {
		b.answer(ctx, q, T(lang, "err.denied"), true)
		return
	}
	// The press is acknowledged at once: a rollback can take longer than Telegram waits for the
	// answer, and a late answer is refused, which left the owner with a spinner and no news.
	b.answer(ctx, q, "⏳", false)
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	var err error
	if keep {
		err = b.be.ConfirmApply(cctx)
	} else {
		err = b.be.RollbackApply(cctx)
	}
	cancel()
	who := q.From.DisplayName()
	if err != nil {
		b.logf("telegram: %s pressed %s: %v", who, map[bool]string{true: "keep", false: "roll back"}[keep], err)
		// In the chat, not in a toast: a toast holds 200 characters and is gone in a moment, and the
		// countdown message keeps its buttons for another try.
		b.reply(ctx, rec.ID, "⚠️ "+T(lang, "apply.failed", esc(err.Error())), nil)
		return
	}
	b.logf("telegram: %s (chat %d) pressed %s", who, rec.ID, map[bool]string{true: "keep", false: "roll back"}[keep])
	// This chat's message now says who decided; the watcher's closing edit is for the other chats.
	b.out.closeOpen(rec.ID, "apply")
	key := "apply.rolledback_by"
	if keep {
		key = "apply.kept_by"
	}
	b.show(ctx, q.Message, T(lang, key, esc(who), b.view(lang).clock(b.now())), &Keyboard{Rows: [][]InlineButton{{btn(T(lang, "b.status"), cbStatus)}}})
}
