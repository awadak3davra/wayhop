package tgbot

import (
	"strings"
	"testing"
	"time"
)

// rendered is an alert as one chat would see it.
func rendered(a Alert, lang, role string) (string, *Keyboard) { return a.Render(lang, role) }

func texts(as []Alert) []string {
	var out []string
	for _, a := range as {
		t, _ := a.Render("en", roleOwner)
		out = append(out, t)
	}
	return out
}

func evAt(sec int, kind, id, name string) Event {
	return Event{At: testNow.Add(time.Duration(sec) * time.Second), Kind: kind, ID: id, Name: name}
}

// logOf returns events newest first, as the monitor does.
func logOf(evs ...Event) EventLog {
	out := make([]Event, len(evs))
	for i, e := range evs {
		out[len(evs)-1-i] = e
	}
	return EventLog{Known: true, Events: out}
}

func TestWatcherBaselineIsNotNews(t *testing.T) {
	w := newWatcher()
	old := logOf(evAt(-600, "down", "de-backup", "de-backup"))
	p := Pulse{LocalFault: true, Core: CorePulse{Supervised: true, Alive: true, Restarts: 4}, FailSafe: FailSafePulse{Pending: true, Phase: "armed"}}
	if got := w.step(testNow, p, old, sampleStatus); len(got) != 0 {
		t.Fatalf("the first step announced the past: %q", texts(got))
	}
	if got := w.step(testNow.Add(5*time.Second), p, old, sampleStatus); len(got) != 0 {
		t.Fatalf("an unchanged second step announced %q", texts(got))
	}
}

func TestWatcherExitDownThenUp(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	down := evAt(10, "down", "de-backup", "de-backup")
	got := w.step(testNow.Add(10*time.Second), Pulse{}, logOf(down), sampleStatus)
	if len(got) != 1 || got[0].Kind != KindExits || got[0].Sev != SevWarning || got[0].Incident != "exit:de-backup" || got[0].Resolves {
		t.Fatalf("down: %+v", got)
	}
	text, kb := rendered(got[0], "en", roleOwner)
	for _, want := range []string{"🔴 <b>de-backup</b> is down", "Cause: handshake did not complete", "Fix: check the server key",
		"Group fast-eu now goes through <b>nl-main</b>"} {
		if !strings.Contains(text, want) {
			t.Fatalf("down text lacks %q:\n%s", want, text)
		}
	}
	if len(kb.Rows[0]) != 2 || kb.Rows[0][1].CallbackData != cbMute+"60" {
		t.Fatalf("a warning offers a mute: %+v", kb)
	}
	// The same log again is not news.
	if again := w.step(testNow.Add(15*time.Second), Pulse{}, logOf(down), sampleStatus); len(again) != 0 {
		t.Fatalf("repeated: %q", texts(again))
	}
	up := evAt(12*60+10, "up", "de-backup", "de-backup")
	up.LatencyMs = 51
	got = w.step(testNow.Add(13*time.Minute), Pulse{}, logOf(down, up), sampleStatus)
	if len(got) != 1 || !got[0].Resolves || got[0].Sev != SevInfo || got[0].Incident != "exit:de-backup" {
		t.Fatalf("up: %+v", got)
	}
	if text, _ := rendered(got[0], "ru", roleOwner); text != "🟢 <b>de-backup</b> снова в строю · не работал 12 мин · 51 мс" {
		t.Fatalf("up text %q", text)
	}
}

func TestWatcherTwoEventsInOneMillisecond(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	a, b := evAt(10, "down", "a", "a"), evAt(10, "down", "b", "b")
	got := w.step(testNow.Add(10*time.Second), Pulse{}, logOf(a, b), sampleStatus)
	if len(got) != 2 {
		t.Fatalf("got %q", texts(got))
	}
	c := evAt(10, "switch", "g", "g")
	got = w.step(testNow.Add(15*time.Second), Pulse{}, logOf(a, b, c), sampleStatus)
	if len(got) != 1 || got[0].Kind != KindSwitches {
		t.Fatalf("a late event at the same millisecond: %q", texts(got))
	}
}

func TestWatcherLastMemberDownSaysSo(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	st := func() Status {
		s := sampleStatus()
		s.Groups[0].Elected = "nl-main"
		return s
	}
	got := w.step(testNow.Add(10*time.Second), Pulse{}, logOf(evAt(10, "down", "nl-main", "nl-main")), st)
	if text, _ := rendered(got[0], "en", roleOwner); !strings.Contains(text, "Group fast-eu has no working member left") {
		t.Fatalf("got:\n%s", text)
	}
}

// Found on the demo: with the election unknown, the alert claimed the group had nothing left while
// other members were up. An unknown election says nothing.
func TestWatcherUnknownElectionClaimsNothing(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	st := func() Status {
		s := sampleStatus()
		s.Groups[0].Elected = ""
		return s
	}
	got := w.step(testNow.Add(10*time.Second), Pulse{}, logOf(evAt(10, "down", "de-backup", "de-backup")), st)
	if text, _ := rendered(got[0], "en", roleOwner); strings.Contains(text, "Group") {
		t.Fatalf("claimed something about a group whose election is unknown:\n%s", text)
	}
}

func TestWatcherUplinkSwallowsTheExits(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	d1, d2 := evAt(10, "down", "a", "a"), evAt(10, "down", "b", "b")
	got := w.step(testNow.Add(10*time.Second), Pulse{LocalFault: true}, logOf(d1, d2), sampleStatus)
	if len(got) != 1 || got[0].Kind != KindUplink || got[0].Sev != SevCritical || got[0].Incident != "uplink" {
		t.Fatalf("uplink lost: %q", texts(got))
	}
	u1, u2 := evAt(7*60, "up", "a", "a"), evAt(7*60+5, "up", "b", "b")
	got = w.step(testNow.Add(7*time.Minute+10*time.Second), Pulse{}, logOf(d1, d2, u1), sampleStatus)
	if len(got) != 1 || !got[0].Resolves || got[0].Kind != KindUplink {
		t.Fatalf("uplink back: %q", texts(got))
	}
	if text, _ := rendered(got[0], "en", roleOwner); text != "🟢 <b>Internet is back</b> · was out 7 min" {
		t.Fatalf("text %q", text)
	}
	// The straggler recovery a few seconds later belongs to the same incident.
	if got = w.step(testNow.Add(7*time.Minute+15*time.Second), Pulse{}, logOf(d1, d2, u1, u2), sampleStatus); len(got) != 0 {
		t.Fatalf("straggler announced: %q", texts(got))
	}
	// Much later, an exit going down is news again.
	d3 := evAt(20*60, "down", "a", "a")
	if got = w.step(testNow.Add(20*time.Minute), Pulse{}, logOf(d1, d2, u1, u2, d3), sampleStatus); len(got) != 1 || got[0].Kind != KindExits {
		t.Fatalf("later exit down: %q", texts(got))
	}
}

func TestWatcherCore(t *testing.T) {
	w := newWatcher()
	ok := CorePulse{Supervised: true, Alive: true, Restarts: 2}
	w.step(testNow, Pulse{Core: ok}, EventLog{}, sampleStatus)
	crashed := CorePulse{Supervised: true, Alive: true, Restarts: 3}
	got := w.step(testNow.Add(5*time.Second), Pulse{Core: crashed}, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Kind != KindCore || got[0].Sev != SevWarning {
		t.Fatalf("restart: %q", texts(got))
	}
	if text, _ := rendered(got[0], "en", roleOwner); text != "⚠️ sing-box crashed and was restarted (3 since WayHop started)" {
		t.Fatalf("text %q", text)
	}
	down := CorePulse{Supervised: true, Alive: false, Restarts: 3, Failed: 1, LastError: "exec format error"}
	if got = w.step(testNow.Add(10*time.Second), Pulse{Core: down}, EventLog{}, sampleStatus); len(got) != 0 {
		t.Fatalf("a core down for seconds is not an incident yet: %q", texts(got))
	}
	got = w.step(testNow.Add(75*time.Second), Pulse{Core: down}, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Sev != SevCritical || got[0].Incident != "core" {
		t.Fatalf("down: %q", texts(got))
	}
	if text, _ := rendered(got[0], "en", roleOwner); !strings.Contains(text, "for 1 min already") || !strings.Contains(text, "<code>exec format error</code>") {
		t.Fatalf("text %q", text)
	}
	if got = w.step(testNow.Add(80*time.Second), Pulse{Core: down}, EventLog{}, sampleStatus); len(got) != 0 {
		t.Fatalf("repeated: %q", texts(got))
	}
	got = w.step(testNow.Add(3*time.Minute), Pulse{Core: CorePulse{Supervised: true, Alive: true, Restarts: 3}}, EventLog{}, sampleStatus)
	if len(got) != 1 || !got[0].Resolves || got[0].Incident != "core" {
		t.Fatalf("up: %q", texts(got))
	}
}

func TestWatcherApplyWindow(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{}, sampleStatus)

	armed := Pulse{FailSafe: FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 300, Window: "w9"}}
	got := w.step(testNow.Add(5*time.Second), armed, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Sev != SevAction || got[0].Incident != "apply" {
		t.Fatalf("armed: %q", texts(got))
	}
	text, kb := rendered(got[0], "en", roleOwner)
	if !strings.Contains(text, "rolls back by itself in 5:00") || kb.Rows[0][0].CallbackData != cbKeep+"w9" || kb.Rows[0][1].CallbackData != cbRollback+"w9" {
		t.Fatalf("owner view %q %+v", text, kb)
	}
	if _, kb := rendered(got[0], "en", roleViewer); len(kb.Rows) != 1 || kb.Rows[0][0].CallbackData != cbStatus {
		t.Fatalf("a viewer must not get Keep/Roll back: %+v", kb)
	}

	armed.FailSafe.SecondsLeft = 270
	if got = w.step(testNow.Add(20*time.Second), armed, EventLog{}, sampleStatus); len(got) != 0 {
		t.Fatalf("countdown too early: %q", texts(got))
	}
	armed.FailSafe.SecondsLeft, armed.FailSafe.Phase = 262, "degraded"
	got = w.step(testNow.Add(38*time.Second), armed, EventLog{}, sampleStatus)
	if len(got) != 2 || got[0].Sev != SevWarning || !got[1].Edit {
		t.Fatalf("degraded + countdown: %+v", got)
	}
	if text, _ := rendered(got[1], "en", roleOwner); !strings.Contains(text, "4:22") || !strings.Contains(text, "check is failing") {
		t.Fatalf("countdown text %q", text)
	}

	rolled := Pulse{FailSafe: FailSafePulse{Phase: "rolled_back", Checked: true}}
	got = w.step(testNow.Add(2*time.Minute), rolled, EventLog{}, sampleStatus)
	if len(got) != 1 || !got[0].Resolves || got[0].Edit || got[0].Sev != SevCritical || got[0].Closed == nil {
		t.Fatalf("rolled back: %+v", got)
	}
}

// Found on the demo: a rollback somebody pressed was announced as "connectivity was lost". Only
// the fail-safe's own rollback, after a failed check, is that news.
func TestWatcherManualRollbackIsNotAnOutage(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{}, sampleStatus)
	w.step(testNow.Add(5*time.Second), Pulse{FailSafe: FailSafePulse{Pending: true, Live: true, Phase: "armed", Checked: true, CheckOK: true}}, EventLog{}, sampleStatus)
	got := w.step(testNow.Add(20*time.Second), Pulse{FailSafe: FailSafePulse{Phase: "rolled_back", Checked: true, CheckOK: true}}, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Sev != SevInfo || !got[0].Edit || !got[0].Resolves {
		t.Fatalf("manual rollback: %+v", got)
	}
	if text, _ := rendered(got[0], "en", roleOwner); strings.Contains(text, "Connectivity was lost") {
		t.Fatalf("manual rollback read as an outage: %q", text)
	}
}

func TestWatcherApplyKeptAndUnsaved(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{}, sampleStatus)
	armed := Pulse{FailSafe: FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 300}}
	w.step(testNow.Add(5*time.Second), armed, EventLog{}, sampleStatus)

	unsaved := Pulse{FailSafe: FailSafePulse{Live: true, Phase: "live_unsaved"}}
	got := w.step(testNow.Add(6*time.Minute), unsaved, EventLog{}, sampleStatus)
	if len(got) != 2 || !got[0].Resolves || !got[0].Edit || got[1].Sev != SevAction || got[1].Incident != "apply" {
		t.Fatalf("window passed: %+v", got)
	}
	if text, kb := rendered(got[0], "en", roleOwner); !strings.Contains(text, "window passed") || kb != nil {
		t.Fatalf("closed armed message %q %+v", text, kb)
	}

	kept := Pulse{FailSafe: FailSafePulse{Phase: "committed"}}
	got = w.step(testNow.Add(7*time.Minute), kept, EventLog{}, sampleStatus)
	if len(got) != 1 || !got[0].Resolves || !got[0].Edit {
		t.Fatalf("kept later: %+v", got)
	}
	if text, _ := rendered(got[0], "ru", roleOwner); !strings.Contains(text, "подтверждено") {
		t.Fatalf("text %q", text)
	}
}

// A failed rollback keeps the tested revision on record (it is what a retry undoes), so when its window
// closes at the reboot threshold with auto-reboot off the pulse reads pending=false, live=true. That
// was told as "the test window passed with the internet up" plus "runs unsaved, a reboot brings the
// previous one back" with a Keep button: all false, and the Keep is refused.
func TestWatcherRollbackFailedWindowClosesLoud(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{}, sampleStatus)
	w.step(testNow.Add(5*time.Second), Pulse{FailSafe: FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 300, Window: "w9"}}, EventLog{}, sampleStatus)
	failed := FailSafePulse{Pending: true, Live: true, Phase: "rollback_failed", LastError: "core: sing-box did not stop",
		Window: "w9", Checked: true}
	w.step(testNow.Add(2*time.Minute), Pulse{FailSafe: failed}, EventLog{}, sampleStatus)

	failed.Pending = false
	got := w.step(testNow.Add(6*time.Minute), Pulse{FailSafe: failed}, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Sev != SevCritical || !got[0].Resolves || got[0].Edit || got[0].Closed == nil {
		t.Fatalf("closed on a failed rollback: %q %+v", texts(got), got)
	}
	for _, lang := range Languages {
		text, kb := rendered(got[0], lang, roleOwner)
		if !strings.Contains(text, "sing-box did not stop") || strings.Contains(text, T(lang, "al.apply.passed")) {
			t.Errorf("%s: %q", lang, text)
		}
		if len(kb.Rows) != 2 || len(kb.Rows[0]) != 1 || kb.Rows[0][0].CallbackData != cbRollback+"w9" {
			t.Errorf("%s: the owner gets Roll back alone to retry: %+v", lang, kb)
		}
	}
	if text, _ := rendered(got[0], "en", roleOwner); !strings.Contains(text, "the rollback failed") {
		t.Errorf("text %q", text)
	}
	if got = w.step(testNow.Add(6*time.Minute+5*time.Second), Pulse{FailSafe: failed}, EventLog{}, sampleStatus); len(got) != 0 {
		t.Fatalf("the tested revision still on record is not news: %q", texts(got))
	}

	// The retry works: the record lets go of the Test.
	got = w.step(testNow.Add(7*time.Minute), Pulse{FailSafe: FailSafePulse{Phase: "rollback_failed", Checked: true}}, EventLog{}, sampleStatus)
	if len(got) != 1 || !got[0].Resolves {
		t.Fatalf("rolled back later: %+v", got)
	}
	if text, _ := rendered(got[0], "en", roleOwner); !strings.Contains(text, "Rolled back") {
		t.Errorf("text %q", text)
	}
}

// While the window still holds after a failed rollback (for its reboot fallback), its message kept
// counting down "rolls back by itself unless you keep it" with a Keep button the daemon refuses.
func TestWatcherCountdownAfterAFailedRollbackOffersTheRetry(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{}, sampleStatus)
	w.step(testNow.Add(5*time.Second), Pulse{FailSafe: FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 300, Window: "w9"}}, EventLog{}, sampleStatus)

	failed := FailSafePulse{Pending: true, Live: true, Phase: "rollback_failed", LastError: "core: sing-box did not stop",
		Window: "w9", Checked: true}
	got := w.step(testNow.Add(2*time.Minute), Pulse{FailSafe: failed}, EventLog{}, sampleStatus)
	if len(got) != 2 || got[0].Sev != SevCritical || !got[1].Edit {
		t.Fatalf("rollback failed + countdown: %+v", got)
	}
	text, kb := rendered(got[1], "en", roleOwner)
	if !strings.Contains(text, "rollback failed") || !strings.Contains(text, "sing-box did not stop") {
		t.Errorf("the countdown still reads as a running test: %q", text)
	}
	if len(kb.Rows) != 2 || len(kb.Rows[0]) != 1 || kb.Rows[0][0].CallbackData != cbRollback+"w9" {
		t.Errorf("after a failed rollback the owner gets Roll back alone: %+v", kb)
	}
}

// rollbackRetryOnly reports whether kb offers the owner Roll back for window and no Keep.
func rollbackRetryOnly(kb *Keyboard, window string) bool {
	if kb == nil || len(kb.Rows) == 0 || len(kb.Rows[0]) != 1 || kb.Rows[0][0].CallbackData != cbRollback+window {
		return false
	}
	for _, row := range kb.Rows {
		for _, b := range row {
			if strings.HasPrefix(b.CallbackData, cbKeep) {
				return false
			}
		}
	}
	return true
}

// A Roll back pressed after the window closed, and boot's rollback of a Test a restart left, can fail
// too. Both mark the record, but the bot read only the window's phase: it said nothing, and the
// "unsaved" message kept its Keep, which the daemon now refuses.
func TestWatcherRollbackFailedAfterTheWindowIsTold(t *testing.T) {
	w := newWatcher()
	unsaved := FailSafePulse{Live: true, Phase: "live_unsaved", Window: "w9"}
	w.step(testNow, Pulse{FailSafe: unsaved}, EventLog{}, sampleStatus)
	failed := unsaved
	failed.RollbackOutstanding, failed.RollbackError = true, "core: sing-box did not restart"

	got := w.step(testNow.Add(time.Minute), Pulse{FailSafe: failed}, EventLog{}, sampleStatus)
	// Loud, and it closes the incident: the "unsaved" message it replies to loses its Keep.
	if len(got) != 1 || got[0].Sev != SevCritical || !got[0].Resolves || got[0].Edit || got[0].Closed == nil {
		t.Fatalf("a failed rollback after the window: %q %+v", texts(got), got)
	}
	for _, lang := range Languages {
		text, kb := rendered(got[0], lang, roleOwner)
		if !strings.Contains(text, "sing-box did not restart") || !rollbackRetryOnly(kb, "w9") {
			t.Errorf("%s: %q %+v", lang, text, kb)
		}
		if _, kb := rendered(got[0], lang, roleViewer); rollbackRetryOnly(kb, "w9") {
			t.Errorf("%s: a viewer got the Roll back button", lang)
		}
	}
	if got = w.step(testNow.Add(time.Minute+5*time.Second), Pulse{FailSafe: failed}, EventLog{}, sampleStatus); len(got) != 0 {
		t.Fatalf("told twice: %q", texts(got))
	}
	// The retry works: the Test leaves the record.
	got = w.step(testNow.Add(2*time.Minute), Pulse{FailSafe: FailSafePulse{Phase: "live_unsaved"}}, EventLog{}, sampleStatus)
	if len(got) != 1 || !got[0].Resolves {
		t.Fatalf("rolled back later: %q", texts(got))
	}
}

// Boot rolls the Test back as the daemon starts, so its failure can be on record before the bot first
// looks; that look only records a baseline, and the failure was never told.
func TestWatcherRollbackOutstandingAtStartIsTold(t *testing.T) {
	w := newWatcher()
	failed := FailSafePulse{Live: true, Window: "w9", RollbackOutstanding: true, RollbackError: "uci: preflight refused"}
	if got := w.step(testNow, Pulse{FailSafe: failed}, EventLog{}, sampleStatus); len(got) != 0 {
		t.Fatalf("the first step only records a baseline: %q", texts(got))
	}
	got := w.step(testNow.Add(5*time.Second), Pulse{FailSafe: failed}, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Sev != SevCritical || !strings.Contains(texts(got)[0], "preflight refused") {
		t.Fatalf("an outstanding rollback at start: %q", texts(got))
	}
	if got = w.step(testNow.Add(10*time.Second), Pulse{FailSafe: failed}, EventLog{}, sampleStatus); len(got) != 0 {
		t.Fatalf("told twice: %q", texts(got))
	}
}

// Inside the window the record is marked a moment before the phase turns rollback_failed, and after a
// failed Roll back the next connectivity tick relabels the phase (degraded, armed, even rolled_back for
// a rollback the window can no longer dispatch). The phase alone told the failure twice or not at all,
// went back to a countdown with Keep, and closed the window as rolled back.
func TestWatcherWindowRollbackFailureFollowsTheRecord(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{}, sampleStatus)
	armed := FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 300, Window: "w9"}
	w.step(testNow.Add(5*time.Second), Pulse{FailSafe: armed}, EventLog{}, sampleStatus)

	marked := armed
	marked.RollbackOutstanding, marked.RollbackError = true, "core: sing-box did not restart"
	got := w.step(testNow.Add(10*time.Second), Pulse{FailSafe: marked}, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Sev != SevCritical || !strings.Contains(texts(got)[0], "sing-box did not restart") {
		t.Fatalf("the failed rollback, seen in the record first: %q", texts(got))
	}
	phased := marked
	phased.Phase, phased.LastError = "rollback_failed", "core: sing-box did not restart"
	if got = w.step(testNow.Add(15*time.Second), Pulse{FailSafe: phased}, EventLog{}, sampleStatus); len(got) != 0 {
		t.Fatalf("told again when the phase caught up: %q", texts(got))
	}
	relabelled := marked
	relabelled.Phase = "degraded"
	if got = w.step(testNow.Add(20*time.Second), Pulse{FailSafe: relabelled}, EventLog{}, sampleStatus); len(got) != 0 {
		t.Fatalf("a relabelled phase is not news: %q", texts(got))
	}
	got = w.step(testNow.Add(40*time.Second), Pulse{FailSafe: relabelled}, EventLog{}, sampleStatus)
	if len(got) != 1 || !got[0].Edit {
		t.Fatalf("countdown: %q", texts(got))
	}
	if text, kb := rendered(got[0], "en", roleOwner); !strings.Contains(text, "rollback failed") || !rollbackRetryOnly(kb, "w9") {
		t.Fatalf("the countdown went back to a running test: %q %+v", text, kb)
	}

	closed := marked
	closed.Pending, closed.Phase = false, "rolled_back"
	got = w.step(testNow.Add(5*time.Minute), Pulse{FailSafe: closed}, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Sev != SevCritical || !strings.Contains(texts(got)[0], "the rollback failed") {
		t.Fatalf("a window whose rollback is outstanding closed as: %q", texts(got))
	}
}

// With auto-reboot on, a failed rollback's window ends in the reboot phase with the mark still set. The
// mark was read first, so the bot sent "closed, but the rollback failed, roll back again" and never the
// reboot: a retry asked of a router that is going down. Whether or not the bot saw the failure before.
func TestWatcherRebootAfterAFailedRollbackIsTheReboot(t *testing.T) {
	for _, seenFailure := range []bool{true, false} {
		w := newWatcher()
		w.step(testNow, Pulse{}, EventLog{}, sampleStatus)
		armed := FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 300, Window: "w9"}
		w.step(testNow.Add(5*time.Second), Pulse{FailSafe: armed}, EventLog{}, sampleStatus)
		failed := armed
		failed.Phase, failed.LastError, failed.Checked = "rollback_failed", "core: sing-box did not restart", true
		failed.RollbackOutstanding, failed.RollbackError = true, "core: sing-box did not restart"
		if seenFailure {
			w.step(testNow.Add(2*time.Minute), Pulse{FailSafe: failed}, EventLog{}, sampleStatus)
		}

		rebooting := failed
		rebooting.Pending, rebooting.Phase = false, "reboot"
		got := w.step(testNow.Add(6*time.Minute), Pulse{FailSafe: rebooting}, EventLog{}, sampleStatus)
		if len(got) != 1 || got[0].Sev != SevCritical || !got[0].Resolves {
			t.Fatalf("seen=%v: the window closed on a reboot as %q", seenFailure, texts(got))
		}
		for _, lang := range Languages {
			text, kb := rendered(got[0], lang, roleOwner)
			if text != T(lang, "al.apply.reboot") {
				t.Errorf("seen=%v %s: %q, want the reboot", seenFailure, lang, text)
			}
			if kb != nil && rollbackRetryOnly(kb, "w9") {
				t.Errorf("seen=%v %s: Roll back offered on a router that is rebooting", seenFailure, lang)
			}
		}
	}
}

// The status view's buttons follow the same rule: Keep is refused while a rollback is outstanding,
// and Roll back retries it whether the window still holds or not.
func TestStatusOffersOnlyTheRetryWhileARollbackIsOutstanding(t *testing.T) {
	for _, armed := range []bool{true, false} {
		s := sampleStatus()
		s.FailSafe = FailSafe{Armed: armed, Remaining: time.Minute, Window: "w9", RollbackOutstanding: true}
		if _, kb := (view{lang: "en", now: testNow, role: roleOwner}).Status(s); !rollbackRetryOnly(kb, "w9") {
			t.Errorf("armed=%v: owner keyboard %+v", armed, kb)
		}
		if _, kb := (view{lang: "en", now: testNow, role: roleViewer}).Status(s); rollbackRetryOnly(kb, "w9") {
			t.Errorf("armed=%v: a viewer got Roll back", armed)
		}
	}
}

func TestWatcherMemory(t *testing.T) {
	w := newWatcher()
	hi := Pulse{Mem: MemPulse{Known: true, UsedPct: 95}}
	w.step(testNow, Pulse{Mem: MemPulse{Known: true, UsedPct: 50}}, EventLog{}, sampleStatus)
	var got []Alert
	for i := 1; i <= 4; i++ {
		got = append(got, w.step(testNow.Add(time.Duration(i)*5*time.Second), hi, EventLog{}, sampleStatus)...)
	}
	if len(got) != 1 || got[0].Kind != KindSystem || got[0].Incident != "mem" {
		t.Fatalf("high: %q", texts(got))
	}
	if got = w.step(testNow.Add(time.Minute), Pulse{Mem: MemPulse{Known: true, UsedPct: 88}}, EventLog{}, sampleStatus); len(got) != 0 {
		t.Fatalf("between the thresholds nothing changes: %q", texts(got))
	}
	got = w.step(testNow.Add(2*time.Minute), Pulse{Mem: MemPulse{Known: true, UsedPct: 60}}, EventLog{}, sampleStatus)
	if len(got) != 1 || !got[0].Resolves {
		t.Fatalf("back to normal: %q", texts(got))
	}
}

// The storage alert the documentation promises, in the memory's way: a few low pulses in a row open
// it, a level between the marks changes nothing, and it closes once there is clearly room again.
func TestWatcherStorage(t *testing.T) {
	const mib = 1 << 20
	for _, tc := range []struct {
		name  string
		free  []uint64 // MiB free, one pulse each, after a baseline with room
		want  []string // incident and whether it resolves, per alert
		texts []string // in the alerts, English
	}{
		{"low for a while", []uint64{2, 2, 2, 2}, []string{"disk open"}, []string{"almost full</b>: 2 MB free"}},
		{"a dip is not an incident", []uint64{2, 2, 9, 2, 2}, nil, nil},
		{"low, then room again", []uint64{1, 1, 1, 4, 4, 6}, []string{"disk open", "disk resolves"}, []string{"almost full", "has room again: 6 MB free"}},
		{"between the marks it stays open", []uint64{1, 1, 1, 4, 4}, []string{"disk open"}, nil},
		{"unknown free space says nothing", []uint64{0, 0, 0, 0}, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWatcher()
			w.step(testNow, Pulse{Disk: DiskPulse{Known: true, FreeBytes: 50 * mib}}, EventLog{}, sampleStatus)
			var got []Alert
			for i, f := range tc.free {
				p := Pulse{Disk: DiskPulse{Known: f != 0, FreeBytes: f * mib}}
				got = append(got, w.step(testNow.Add(time.Duration(i+1)*watchEvery), p, EventLog{}, sampleStatus)...)
			}
			var desc []string
			for _, a := range got {
				d := a.Incident + " open"
				if a.Resolves {
					d = a.Incident + " resolves"
				}
				desc = append(desc, d)
				if a.Kind != KindSystem {
					t.Errorf("kind %q", a.Kind)
				}
			}
			if strings.Join(desc, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("alerts %q, want %q: %q", desc, tc.want, texts(got))
			}
			for i, w := range tc.texts {
				if text, _ := rendered(got[i], "en", roleOwner); !strings.Contains(text, w) {
					t.Errorf("alert %d lacks %q: %s", i, w, text)
				}
			}
		})
	}
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{}, sampleStatus)
	var got []Alert
	for i := 1; i <= diskLowSamples; i++ {
		got = append(got, w.step(testNow.Add(time.Duration(i)*watchEvery), Pulse{Disk: DiskPulse{Known: true, FreeBytes: mib}}, EventLog{}, sampleStatus)...)
	}
	if text, _ := rendered(got[0], "uk", roleViewer); !strings.Contains(text, "Накопичувач роутера майже заповнений") {
		t.Fatalf("uk: %s", text)
	}
}

func TestBootAlert(t *testing.T) {
	start := testNow.Add(-time.Minute)
	cases := []struct {
		name string
		bi   BootInfo
		want string
		sev  Severity
	}{
		{"power cut", BootInfo{DaemonStart: start, RouterUp: 2 * time.Minute, LastSeen: testNow.Add(-2*time.Hour - 30*time.Minute), Version: "0.5.6"},
			"started at 14:29; last heard from at 12:02 (offline about 2h 27 min)", SevWarning},
		{"short reboot", BootInfo{DaemonStart: start, RouterUp: 2 * time.Minute, LastSeen: testNow.Add(-8 * time.Minute)},
			"(offline about 5 min)", SevInfo},
		{"reboot, no record", BootInfo{DaemonStart: start, RouterUp: time.Minute}, "The router restarted</b> at 14:30", SevInfo},
		{"daemon only", BootInfo{DaemonStart: start, RouterUp: 40 * 24 * time.Hour, Version: "0.5.7"}, "WayHop restarted (0.5.7)", SevInfo},
		{"stale record", BootInfo{DaemonStart: start, RouterUp: time.Minute, LastSeen: testNow.Add(-30 * 24 * time.Hour)}, "The router restarted", SevInfo},
		{"rolled back", BootInfo{DaemonStart: start, RouterUp: 40 * 24 * time.Hour, Version: "0.5.7", UpdateNote: "The update to v0.5.8 was rolled back at 2026-10-17 14:28: it crashes on start."},
			"WayHop restarted (0.5.7).\n⚠️ Last update: The update to v0.5.8 was rolled back", SevWarning},
	}
	for _, c := range cases {
		a := bootAlert(c.bi, testNow)
		text, _ := a.Render("en", roleOwner)
		if !strings.Contains(text, c.want) || a.Sev != c.sev || a.Kind != KindBoot {
			t.Errorf("%s: sev %d\n%s", c.name, a.Sev, text)
		}
	}
}
