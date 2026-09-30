package tgbot

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"wayhop/internal/config"
)

// ClientFunc builds the HTTP client the bot talks to Telegram through, for the given settings (the
// daemon binds it to a tunnel, or points it at the local proxy).
type ClientFunc func(config.Telegram) *http.Client

// Manager owns the running bot: it starts one when the bot is enabled, restarts it when the token
// or the path to Telegram changes, and stops it when disabled. Chat and alert settings are read live
// and need no restart.
type Manager struct {
	be     Backend
	st     Store
	client ClientFunc
	gate   *Gate
	// out outlives each bot: a new token, server or path restarts the bot, and the alerts waiting
	// for Telegram, the mutes and the open incidents must not go with the old one.
	out  *outbox
	logf func(string, ...any)
	now  func() time.Time

	mu     sync.Mutex
	parent context.Context
	cur    *Bot
	api    *Client
	cancel context.CancelFunc
	done   chan struct{}
	key    string
	// bootSent: the "back online" alert goes out once per daemon start, not on every bot restart.
	bootSent bool
}

// bootAlertWindow: a bot enabled long after the daemon started has no news about the start.
const bootAlertWindow = 30 * time.Minute

// NewManager returns a stopped manager. Start runs it.
func NewManager(be Backend, st Store, client ClientFunc) *Manager {
	if client == nil {
		client = func(config.Telegram) *http.Client { return &http.Client{} }
	}
	return &Manager{be: be, st: st, client: client, gate: NewGate(), out: newOutbox(), logf: log.Printf, now: routerNow}
}

// Gate is the pairing gate shared by every bot this manager runs.
func (m *Manager) Gate() *Gate { return m.gate }

// Start runs the bot per the stored settings until ctx ends.
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	m.parent = ctx
	m.mu.Unlock()
	m.Reload()
	go func() {
		<-ctx.Done()
		m.mu.Lock()
		defer m.mu.Unlock()
		m.stopLocked()
	}()
}

func botKey(t config.Telegram) string {
	if !t.Enabled || t.Token == "" {
		return ""
	}
	return t.Token + "\x00" + t.APIBase + "\x00" + t.Via
}

// Reload brings the running bot in line with the stored settings.
func (m *Manager) Reload() {
	t := m.st.Telegram()
	key := botKey(t)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.parent == nil || m.parent.Err() != nil {
		return
	}
	if key == m.key && (key == "") == (m.cur == nil) {
		return
	}
	m.stopLocked()
	m.key = key
	if key == "" {
		return
	}
	m.api = NewClient(t.APIBase, t.Token, m.client(t))
	m.cur = New(m.api, m.be, m.st, Options{Gate: m.gate, Logf: m.logf, Now: m.now, out: m.out})
	ctx, cancel := context.WithCancel(m.parent)
	m.cancel, m.done = cancel, make(chan struct{})
	bot, done := m.cur, m.done
	if !m.bootSent {
		m.bootSent = true
		if bi := m.be.Boot(); !bi.DaemonStart.IsZero() && m.now().Sub(bi.DaemonStart) < bootAlertWindow {
			bot.Notify(bootAlert(bi, m.now()))
		}
	}
	go func() {
		defer close(done)
		bot.Run(ctx)
	}()
	m.logf("telegram: bot started")
}

func (m *Manager) stopLocked() {
	if m.cur == nil {
		return
	}
	m.cancel()
	select {
	case <-m.done:
	case <-time.After(10 * time.Second):
		m.logf("telegram: the previous bot did not stop within 10s; continuing")
	}
	m.cur, m.api, m.cancel, m.done, m.key = nil, nil, nil, nil, ""
	m.logf("telegram: bot stopped")
}

// Info is the running bot's state, or "off".
func (m *Manager) Info() Info {
	m.mu.Lock()
	b := m.cur
	m.mu.Unlock()
	if b == nil {
		return Info{State: StateOff}
	}
	return b.Info()
}

// ErrNotRunning is returned by operations that need a connected bot.
var ErrNotRunning = errors.New("the Telegram bot is not running")

func (m *Manager) running() (*Bot, *Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur == nil {
		return nil, nil, ErrNotRunning
	}
	return m.cur, m.api, nil
}

// Check validates settings against Telegram without saving them: it calls getMe with the given
// token through the path those settings describe.
func (m *Manager) Check(ctx context.Context, t config.Telegram) (User, error) {
	return NewClient(t.APIBase, t.Token, m.client(t)).GetMe(ctx)
}

// Send delivers one HTML message to a chat through the running bot, following the chat if Telegram
// says it has become a supergroup.
func (m *Manager) Send(ctx context.Context, chat int64, html string) error {
	b, api, err := m.running()
	if err != nil {
		return err
	}
	_, err = api.SendMessage(ctx, chat, html, SendOptions{NoPreview: true})
	if to := migratedTo(err); to != 0 && b.migrate(chat, to) {
		_, err = api.SendMessage(ctx, to, html, SendOptions{NoPreview: true})
	}
	return err
}

// Welcome greets a chat the panel just paired, in its language, with the status view.
func (m *Manager) Welcome(ctx context.Context, rec config.TelegramChat) error {
	b, api, err := m.running()
	if err != nil {
		return err
	}
	lang := rec.Lang
	if lang == "" {
		lang = Languages[0]
	}
	if _, err := api.SendMessage(ctx, rec.ID, T(lang, "pair.ok", T(lang, "role."+rec.Role)), SendOptions{}); err != nil {
		return err
	}
	if rec.Role == roleAlerts {
		return nil
	}
	text, kb := b.view(lang).Status(b.status(ctx))
	_, err = api.SendMessage(ctx, rec.ID, text, SendOptions{Keyboard: kb, NoPreview: true})
	return err
}

// DeepLink is the t.me link that pairs a chat with code, "" while the bot's name is unknown.
func (m *Manager) DeepLink(code string) string {
	b, _, err := m.running()
	if err != nil {
		return ""
	}
	if u := b.Me().Username; u != "" {
		return "https://t.me/" + u + "?start=" + code
	}
	return ""
}
