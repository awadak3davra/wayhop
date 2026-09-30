package tgbot

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestUpdateViews(t *testing.T) {
	owner := view{lang: "en", now: testNow, role: roleOwner}
	viewer := view{lang: "en", now: testNow, role: roleViewer}
	cases := []struct {
		info UpdateInfo
		want string
	}{
		{UpdateInfo{Current: "0.5.6", Managed: "apk"}, "installed by apk here"},
		{UpdateInfo{Current: "0.5.6", NoChannel: true}, "no update channel"},
		{UpdateInfo{Current: "0.5.6", Err: "github unreachable"}, "The check failed: github unreachable"},
		{UpdateInfo{Current: "0.5.6", Latest: "0.5.6", Decided: true}, "WayHop 0.5.6 is the latest release"},
		{UpdateInfo{Current: "0.5.6"}, "could not be told"},
		{UpdateInfo{Current: "0.5.6", Latest: "0.5.7", Available: true, Decided: true, Auto: true}, "WayHop 0.5.7 is available</b> (this router runs 0.5.6).\nAuto-update is on"},
	}
	for _, c := range cases {
		if text, _ := owner.Update(c.info); !strings.Contains(text, c.want) {
			t.Errorf("%+v:\n%s", c.info, text)
		}
	}
	avail := UpdateInfo{Current: "0.5.6", Latest: "0.5.7", Available: true, Decided: true}
	if _, kb := owner.Update(avail); kb.Rows[0][0].CallbackData != cbAsk+actInstall {
		t.Fatalf("owner keyboard %+v", kb)
	}
	if _, kb := viewer.Update(avail); strings.Contains(toJSON(kb), cbAsk+actInstall) {
		t.Fatal("a viewer got Install")
	}
}

func TestUpdateFromMaintenance(t *testing.T) {
	h := newHarness(t, owner)
	h.be.update = UpdateInfo{Current: "0.5.6", Latest: "0.5.7", Available: true, Decided: true}
	h.press(500, cbDo+actUpdate)
	if e := lastEdit(h); !strings.Contains(e, "WayHop 0.5.7 is available") {
		t.Fatalf("check: %q", e)
	}
	h.press(500, h.buttonData("editMessageText", "Install 0.5.7"))
	if q := lastEdit(h); !strings.Contains(q, "Install WayHop 0.5.7?") || !strings.Contains(q, "keeps the running binary as a backup") {
		t.Fatalf("question: %q", q)
	}
	// A newer release appearing between the question and the answer does not change what is installed.
	h.be.setUpdate(UpdateInfo{Current: "0.5.6", Latest: "0.5.8", Available: true, Decided: true})
	h.press(500, h.buttonData("editMessageText", "Install"))
	if len(h.be.installed) != 1 || h.be.installed[0] != "0.5.7" {
		t.Fatalf("installed %v: the version asked about must be the one installed", h.be.installed)
	}
	if e := lastEdit(h); !strings.Contains(e, "WayHop 0.5.7 is installed.</b> Restarting now") {
		t.Fatalf("done: %q", e)
	}
}

func TestInstallWithNothingNewer(t *testing.T) {
	h := newHarness(t, owner)
	h.be.update = UpdateInfo{Current: "0.5.6", Latest: "0.5.6", Decided: true}
	h.press(500, cbAsk+actInstall)
	if e := lastEdit(h); !strings.Contains(e, "nothing newer to install") || strings.Contains(string(h.api.callsTo("editMessageText")[0].Raw), cbConfirm) {
		t.Fatalf("got %q", e)
	}
}

func TestInstallFailureIsShown(t *testing.T) {
	h := newHarness(t, owner)
	h.be.update = UpdateInfo{Current: "0.5.6", Latest: "0.5.7", Available: true, Decided: true}
	h.be.installErr = errors.New("sha256 mismatch")
	h.press(500, cbAsk+actInstall)
	h.press(500, h.buttonData("editMessageText", "Install"))
	if e := lastEdit(h); !strings.Contains(e, "The update failed: sha256 mismatch") {
		t.Fatalf("got %q", e)
	}
}

func queuedKinds(b *Bot, kind string) int {
	b.out.mu.Lock()
	defer b.out.mu.Unlock()
	n := 0
	for _, q := range b.out.q {
		if q.a.Kind == kind {
			n++
		}
	}
	return n
}

// Each new release is announced once, however many daily checks see it.
func TestDailyCheckAnnouncesEachReleaseOnce(t *testing.T) {
	h := newHarness(t, owner)
	h.be.setUpdate(UpdateInfo{Current: "0.5.6", Latest: "0.5.7", Available: true, Decided: true})
	h.bot.updateFirst, h.bot.updateEvery = time.Millisecond, 3*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.bot.updateLoop(ctx); close(done) }()
	waitFor(t, "several checks", func() bool {
		h.be.mu.Lock()
		defer h.be.mu.Unlock()
		return h.be.checks2 >= 3
	})
	if n := queuedKinds(h.bot, KindUpdates); n != 1 {
		t.Fatalf("announced %d times", n)
	}
	h.be.setUpdate(UpdateInfo{Current: "0.5.6", Latest: "0.5.8", Available: true, Decided: true})
	waitFor(t, "the next release", func() bool { return queuedKinds(h.bot, KindUpdates) == 2 })
	cancel()
	<-done
	// The status shows what the last check found, without checking again.
	before := h.be.checks2
	if s := h.bot.status(context.Background()); !s.Update.Available || s.Update.Latest != "0.5.8" {
		t.Fatalf("status update %+v", s.Update)
	}
	if h.be.checks2 != before {
		t.Fatal("a status reached for the update check")
	}
}

func TestUpdateAlertButtons(t *testing.T) {
	a := updateAlert(UpdateInfo{Current: "0.5.6", Latest: "0.5.7", Available: true}, testNow)
	if a.Kind != KindUpdates || a.Sev != SevInfo {
		t.Fatalf("%+v", a)
	}
	if _, kb := a.Render("en", roleOwner); kb.Rows[0][0].CallbackData != cbAsk+actInstall {
		t.Fatalf("owner %+v", kb)
	}
	if _, kb := a.Render("en", roleViewer); strings.Contains(toJSON(kb), cbAsk) {
		t.Fatal("a viewer got Install")
	}
	auto := updateAlert(UpdateInfo{Current: "0.5.6", Latest: "0.5.7", Available: true, Auto: true}, testNow)
	if _, kb := auto.Render("en", roleOwner); strings.Contains(toJSON(kb), cbAsk) {
		t.Fatal("with auto-update on, Install is not offered")
	}
}
