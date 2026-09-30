package tgbot

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Update actions of the maintenance menu.
const (
	actUpdate  = "update"  // check (cbDo)
	actInstall = "install" // install the latest (cbAsk, then cbConfirm)

	updateFirst = 10 * time.Minute // the first daily check waits for the router to settle after a boot
	updateEvery = 24 * time.Hour
	updateWait  = 45 * time.Second
	installWait = 4 * time.Minute
)

// updates remembers the last check, for /status, and which release was already announced, so a
// daily check does not announce the same version every day.
type updates struct {
	mu        sync.Mutex
	last      UpdateInfo
	at        time.Time
	announced string
}

func (u *updates) record(info UpdateInfo, at time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.last, u.at = info, at
}

func (u *updates) get() (UpdateInfo, time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.last, u.at
}

// announce reports whether version is news, and remembers it.
func (u *updates) announce(version string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if version == "" || version == u.announced {
		return false
	}
	u.announced = version
	return true
}

// Update renders the result of a check. Owners get Install when there is something to install.
func (v view) Update(info UpdateInfo) (string, *Keyboard) {
	var b strings.Builder
	var extra []InlineButton
	switch {
	case info.Managed != "":
		b.WriteString(v.t("up.managed", esc(info.Managed)))
	case info.NoChannel:
		b.WriteString(v.t("up.nochannel"))
	case info.Err != "":
		b.WriteString(v.t("up.fail", esc(info.Err)))
	case info.Available:
		b.WriteString(v.t("up.available", esc(info.Latest), esc(info.Current)))
		if info.Auto {
			b.WriteString("\n" + v.t("up.auto"))
		}
		if v.role == roleOwner {
			extra = append(extra, btn(v.t("b.install", info.Latest), cbAsk+actInstall))
		}
	case info.Decided:
		b.WriteString(v.t("up.latest", esc(info.Current)))
	default:
		b.WriteString(v.t("up.unknown", esc(info.Current)))
	}
	return b.String(), v.maintBack(extra...)
}

// checkUpdate runs a check and remembers it.
func (b *Bot) checkUpdate(ctx context.Context) UpdateInfo {
	cctx, cancel := context.WithTimeout(ctx, updateWait)
	info := b.be.UpdateCheck(cctx)
	cancel()
	b.upd.record(info, b.now())
	return info
}

// updateCheck is the maintenance button: check now and say what was found.
func (b *Bot) updateCheck(ctx context.Context, v view, m *Message) {
	b.show(ctx, m, v.t("up.run"), nil)
	text, kb := v.Update(b.checkUpdate(ctx))
	b.show(ctx, m, text, kb)
}

// askInstall asks to install the release a fresh check finds; the confirmation carries that exact
// version, so what is installed is what was asked about.
func (b *Bot) askInstall(ctx context.Context, v view, m *Message) {
	info := b.checkUpdate(ctx)
	if !info.Available || info.Managed != "" {
		text, kb := v.Update(info)
		if !info.Available && info.Managed == "" && info.Err == "" && !info.NoChannel {
			text = v.t("up.none") + "\n" + text
		}
		b.show(ctx, m, text, kb)
		return
	}
	nonce := b.confirms.issue(m.Chat.ID, actInstall, info.Latest, b.now())
	kb := &Keyboard{Rows: [][]InlineButton{{btn(v.t("up.ok"), cbConfirm+nonce), btn(v.t("b.cancel"), cbCancel+nonce)}}}
	b.show(ctx, m, v.t("up.ask", esc(info.Latest)), kb)
}

// install is the confirmed update. The process is replaced at the end of it, so the outcome is
// written before the restart can take the bot down; the boot alert names the new version.
func (b *Bot) install(ctx context.Context, v view, m *Message, version string) {
	b.show(ctx, m, v.t("up.installing", esc(version)), nil)
	cctx, cancel := context.WithTimeout(ctx, installWait)
	res, err := b.be.UpdateInstall(cctx, version)
	cancel()
	switch {
	case err != nil:
		b.show(ctx, m, v.t("up.installfail", esc(err.Error())), v.maintBack())
	case res.Restarting:
		b.show(ctx, m, v.t("up.done", esc(res.Installed)), nil)
	default:
		b.show(ctx, m, v.t("up.done.norestart", esc(res.Installed), esc(res.Note)), v.maintBack())
	}
}

// updateLoop checks for a new WayHop once a day and announces each new release once.
func (b *Bot) updateLoop(ctx context.Context) {
	wait := b.updateFirst
	for {
		if !sleep(ctx, wait) {
			return
		}
		wait = b.updateEvery
		info := b.checkUpdate(ctx)
		if info.Available && info.Managed == "" && b.upd.announce(info.Latest) {
			b.Notify(updateAlert(info, b.now()))
		}
	}
}

func updateAlert(info UpdateInfo, now time.Time) Alert {
	text := func(lang string) string {
		s := T(lang, "up.available", esc(info.Latest), esc(info.Current))
		if info.Auto {
			s += "\n" + T(lang, "up.auto")
		}
		return s
	}
	return Alert{Kind: KindUpdates, Sev: SevInfo, At: now,
		Render: func(lang, role string) (string, *Keyboard) {
			row := []InlineButton{btn(T(lang, "b.status"), cbStatus)}
			if role == roleOwner && !info.Auto {
				row = append([]InlineButton{btn(T(lang, "b.install", info.Latest), cbAsk+actInstall)}, row...)
			}
			return text(lang), &Keyboard{Rows: [][]InlineButton{row}}
		},
		Line: func(lang string) string { return firstLine(text(lang)) },
	}
}
