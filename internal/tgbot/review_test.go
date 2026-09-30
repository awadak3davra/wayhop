package tgbot

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Regressions for the findings of the review of 2026-09-24 (docs/TELEGRAM_BOT.md in the
// development repository, iteration 15).

// The monitor holds exits' failures back for the whole uplink outage, so a tunnel that stays dead
// is marked down a probe round or two after the internet returns. That is news, and it was
// swallowed by a quiet window after the outage.
func TestAnExitStillDeadAfterTheOutageIsTold(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{LocalFault: true}, EventLog{Known: true}, sampleStatus)
	if back := w.step(testNow.Add(5*time.Second), Pulse{}, EventLog{Known: true}, sampleStatus); len(back) != 1 || back[0].Kind != KindUplink {
		t.Fatalf("uplink back: %q", texts(back))
	}
	down := evAt(15, "down", "de-backup", "de-backup")
	if got := w.step(testNow.Add(20*time.Second), Pulse{}, logOf(down), sampleStatus); len(got) != 1 || got[0].Incident != "exit:de-backup" {
		t.Fatalf("the dead tunnel after the outage: %q", texts(got))
	}
}

// An exit whose failure was told before the outage has its recovery told too, however close to the
// outage it comes; only a recovery whose failure went untold stays untold.
func TestARecoveryIsToldWhenItsFailureWas(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	d := evAt(10, "down", "de-backup", "de-backup")
	if got := w.step(testNow.Add(10*time.Second), Pulse{}, logOf(d), sampleStatus); len(got) != 1 {
		t.Fatalf("down before the outage: %q", texts(got))
	}
	w.step(testNow.Add(time.Minute), Pulse{LocalFault: true}, logOf(d), sampleStatus)
	w.step(testNow.Add(2*time.Minute), Pulse{}, logOf(d), sampleStatus)
	up := evAt(125, "up", "de-backup", "de-backup")
	got := w.step(testNow.Add(2*time.Minute+10*time.Second), Pulse{}, logOf(d, up), sampleStatus)
	if len(got) != 1 || !got[0].Resolves || got[0].Incident != "exit:de-backup" {
		t.Fatalf("recovery right after the outage: %q", texts(got))
	}
}

// The monitor stamps a probe round's changes with the round's start and appends them after the
// probes; "Test now" and the list failover append theirs stamped on the spot in between. A round's
// change appended after a later-stamped event was lost.
func TestAnEventAppendedLateIsStillNews(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	sw := evAt(12, "switch", "fast", "fast-eu")
	sw.From, sw.To = "de-backup", "nl-main"
	if got := w.step(testNow.Add(13*time.Second), Pulse{}, logOf(sw), sampleStatus); len(got) != 1 {
		t.Fatalf("switch: %q", texts(got))
	}
	down := evAt(10, "down", "de-backup", "de-backup") // appended after the switch
	got := w.step(testNow.Add(18*time.Second), Pulse{}, logOf(sw, down), sampleStatus)
	if len(got) != 1 || got[0].Incident != "exit:de-backup" {
		t.Fatalf("the late-appended failure: %q", texts(got))
	}
	if again := w.step(testNow.Add(23*time.Second), Pulse{}, logOf(sw, down), sampleStatus); len(again) != 0 {
		t.Fatalf("told twice: %q", texts(again))
	}
}

// A share link's name can hold a newline ("NL%0AAmsterdam" imports as two lines). Every message
// shows it on one line, so no line of a message opens a tag it does not close, and the summary after
// quiet hours, built from first lines, stays valid HTML.
func TestNamesStayOnOneLine(t *testing.T) {
	if got := esc("NL\nAmsterdam\r\t<b>\x00"); got != "NL Amsterdam  &lt;b&gt;" {
		t.Fatalf("esc %q", got)
	}
	a := exitDown(evAt(10, "down", "nl", "NL\nAmsterdam"), sampleStatus())
	if line := a.Line("en"); line != "🔴 <b>NL Amsterdam</b> is down" {
		t.Fatalf("summary line %q", line)
	}
}

// The Apply question acknowledges every finding it names; one cut at five says how many more.
func TestTheApplyQuestionCountsWhatItDoesNotList(t *testing.T) {
	v := view{lang: "en", now: testNow}
	got := v.bullets([]string{"a", "b", "c", "d", "e", "f", "g"}, 5)
	if !strings.HasSuffix(got, "• e\n…and 2 more\n") || strings.Contains(got, "• f") {
		t.Fatalf("bullets %q", got)
	}
	if got := v.bullets([]string{"a"}, 5); got != "• a\n" {
		t.Fatalf("one %q", got)
	}
}

// A bug that makes one alert panic while rendering costs that alert, not the delivery loop (and
// with it every alert after it, and the daemon).
func TestAPanickingAlertDoesNotStopDelivery(t *testing.T) {
	h := newHarness(t, owner)
	h.bot.logf = func(string, ...any) {}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.bot.deliverLoop(ctx); close(done) }()
	h.bot.Notify(Alert{Kind: KindExits, Sev: SevInfo, Render: func(string, string) (string, *Keyboard) { panic("render bug") }})
	h.bot.Notify(uplinkLost(testNow))
	deadline := time.Now().Add(5 * time.Second)
	for len(h.sendsTo(500)) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if got := h.sendsTo(500); len(got) != 1 || !strings.Contains(got[0].Params["text"].(string), "No internet") {
		t.Fatalf("the alert after the panicking one: %d sends", len(got))
	}
}
