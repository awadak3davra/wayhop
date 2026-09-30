package tgbot

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"wayhop/internal/config"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestManagerFollowsTheSettings(t *testing.T) {
	api := newFakeAPI(t)
	api.on("getMe", func(map[string]any) (int, string) {
		return 200, `{"ok":true,"result":{"id":1,"is_bot":true,"first_name":"Home","username":"home_wayhop_bot"}}`
	})
	api.on("getUpdates", func(map[string]any) (int, string) {
		time.Sleep(20 * time.Millisecond)
		return 200, `{"ok":true,"result":[]}`
	})
	st := &fakeStore{}
	var clients atomic.Int32
	m := NewManager(&fakeBackend{status: sampleStatus()}, st, func(config.Telegram) *http.Client {
		clients.Add(1)
		return api.srv.Client()
	})
	m.logf = t.Logf
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	if m.Info().State != StateOff {
		t.Fatalf("disabled bot is %q", m.Info().State)
	}

	_ = st.UpdateTelegram(func(tg *config.Telegram) error {
		tg.Enabled, tg.Token, tg.APIBase = true, testToken, api.srv.URL
		return nil
	})
	m.Reload()
	waitFor(t, "online", func() bool { return m.Info().State == StateOnline })
	if link := m.DeepLink("ABCD2345"); link != "https://t.me/home_wayhop_bot?start=ABCD2345" {
		t.Fatalf("deep link %q", link)
	}

	// A change that does not touch the connection must not restart the bot.
	_ = st.UpdateTelegram(func(tg *config.Telegram) error { tg.QuietFrom, tg.QuietTo = "23:00", "07:00"; return nil })
	m.Reload()
	if clients.Load() != 1 {
		t.Fatalf("a quiet-hours change rebuilt the client (%d)", clients.Load())
	}
	// A new path to Telegram does.
	_ = st.UpdateTelegram(func(tg *config.Telegram) error { tg.Via = viaForTest; return nil })
	m.Reload()
	if clients.Load() != 2 {
		t.Fatalf("a via change did not restart the bot (%d)", clients.Load())
	}
	waitFor(t, "online again", func() bool { return m.Info().State == StateOnline })

	_ = st.UpdateTelegram(func(tg *config.Telegram) error { tg.Enabled = false; return nil })
	m.Reload()
	if m.Info().State != StateOff {
		t.Fatalf("disabled bot still %q", m.Info().State)
	}
	if err := m.Send(ctx, 1, "x"); err != ErrNotRunning {
		t.Fatalf("send on a stopped bot: %v", err)
	}
}

const viaForTest = "nl"

func TestManagerCheckDoesNotStartAnything(t *testing.T) {
	api := newFakeAPI(t)
	api.on("getMe", func(map[string]any) (int, string) {
		return 200, `{"ok":true,"result":{"id":1,"is_bot":true,"first_name":"Home","username":"home_wayhop_bot"}}`
	})
	m := NewManager(&fakeBackend{}, &fakeStore{}, func(config.Telegram) *http.Client { return api.srv.Client() })
	u, err := m.Check(context.Background(), config.Telegram{Token: testToken, APIBase: api.srv.URL})
	if err != nil || u.Username != "home_wayhop_bot" {
		t.Fatalf("check %v %+v", err, u)
	}
	if len(api.callsTo("getUpdates")) != 0 || m.Info().State != StateOff {
		t.Fatal("a token check started polling")
	}
}
