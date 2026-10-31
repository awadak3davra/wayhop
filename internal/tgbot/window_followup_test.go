package tgbot

import (
	"context"
	"strings"
	"testing"
	"time"
)

// replacedMeanwhile is a daemon where a Test B from the panel is recorded while the press waits for
// the apply lock: the window the press passed (w1) is no longer the one running when the daemon
// decides. The daemon compares the window under that lock, as applyConfirm does.
type replacedMeanwhile struct{ *fakeBackend }

func (r replacedMeanwhile) decide(window string, keep bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pulse.FailSafe.Window = "w2"
	if window != r.pulse.FailSafe.Window {
		return ErrWindowChanged
	}
	if keep {
		r.kept++
	} else {
		r.rolledBack++
	}
	return nil
}

func (r replacedMeanwhile) ConfirmApply(_ context.Context, window string) error {
	return r.decide(window, true)
}

func (r replacedMeanwhile) RollbackApply(_ context.Context, window string) error {
	return r.decide(window, false)
}

// Keep on Test A's message while Test B ran from the panel: the bot's window check passed (B was not
// recorded yet) and the daemon then kept whatever it found, B, untested. The daemon now refuses a
// decision for a window that is not the one running; the press was already acknowledged, so the
// message itself says nothing was changed and shows the present.
func TestDecisionOnAReplacedWindowShowsThePresent(t *testing.T) {
	for _, data := range []string{cbKeep + "w1", cbRollback + "w1"} {
		h := newHarness(t, owner)
		h.be.pulse.FailSafe = FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 120, Window: "w1"}
		h.bot.be = replacedMeanwhile{h.be}
		h.press(500, data)
		if h.be.kept+h.be.rolledBack != 0 {
			t.Fatalf("%s decided the newer Test: kept %d, rolled back %d", data, h.be.kept, h.be.rolledBack)
		}
		for _, s := range h.sent() {
			if strings.Contains(s, "Did not work") {
				t.Fatalf("%s: a refusal read as a failure: %q", data, h.sent())
			}
		}
		e := h.edited()
		if len(e) == 0 || !strings.HasPrefix(e[len(e)-1], "⚠️ "+T("en", "apply.stale")) {
			t.Fatalf("%s: the message does not say nothing was changed: %q", data, e)
		}
		if n := len(h.api.callsTo("answerCallbackQuery")); n != 1 {
			t.Fatalf("%s: %d answers to one press", data, n)
		}
	}
}

// A Test B applied while A's window is pending on its own rollback is seen once with A's phase under
// B's name: the pulse reads the fail-safe before the record. B started out marked as rolled back by
// itself, so its later Roll back closed with the loud "Connectivity was lost", and its message showed
// A's time left, 0:00.
func TestWatcherNewTestSeenWithTheOldWindowsRollbackStartsClean(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{}, sampleStatus)
	at := func(sec int) time.Time { return testNow.Add(time.Duration(sec) * time.Second) }
	a := FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 180, Window: "wA", Checked: true, CheckOK: true}
	w.step(at(5), Pulse{FailSafe: a}, EventLog{}, sampleStatus)
	a.Phase, a.CheckOK, a.SecondsLeft = "degraded", false, 145
	w.step(at(40), Pulse{FailSafe: a}, EventLog{}, sampleStatus)

	mixed := FailSafePulse{Pending: true, Live: true, Phase: "rolled_back", Window: "wB", Checked: true}
	got := w.step(at(75), Pulse{FailSafe: mixed}, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Sev != SevCritical || !got[0].Resolves || got[0].Edit {
		t.Fatalf("A's rollback under B's name: %q %+v", texts(got), got)
	}
	if text, _ := rendered(got[0], "en", roleOwner); !strings.Contains(text, "Connectivity was lost") {
		t.Fatalf("A closed as %q", text)
	}

	// B's own read opens its message, with its own time left.
	b := FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 175, Window: "wB"}
	got = w.step(at(80), Pulse{FailSafe: b}, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Sev != SevAction || got[0].Edit {
		t.Fatalf("B's message: %q %+v", texts(got), got)
	}
	if text, kb := rendered(got[0], "en", roleOwner); !strings.Contains(text, "2:55") || !strings.Contains(toJSON(kb), `"ak:wB"`) {
		t.Fatalf("B's message: %q %s", text, toJSON(kb))
	}

	// B ends on a Roll back somebody pressed: quiet. A's rollback is not B's.
	got = w.step(at(90), Pulse{FailSafe: FailSafePulse{Phase: "rolled_back", Checked: true, CheckOK: true}}, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Sev != SevInfo || !got[0].Edit {
		t.Fatalf("B's manual Roll back: %q %+v", texts(got), got)
	}
}

// Once the fail-safe rolls back by itself the countdown stops, but its last edit kept Keep and Roll
// back on the message until the window closed; a Roll back pressed then read "Did not work: a rollback
// is already in progress" right before the critical alert. The message is redrawn once without them.
func TestWatcherTakesTheButtonsOffOnceTheFailSafeRollsBack(t *testing.T) {
	h := newHarness(t, owner)
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{}, sampleStatus)
	at := func(sec int) time.Time { return testNow.Add(time.Duration(sec) * time.Second) }
	fs := FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 180, Window: "wA", Checked: true, CheckOK: true}
	for _, a := range w.step(at(5), Pulse{FailSafe: fs}, EventLog{}, sampleStatus) {
		h.deliver(a)
	}
	open, ok := h.bot.out.openMsg(500, "apply")
	if !ok {
		t.Fatal("no apply message")
	}
	fs.Phase, fs.SecondsLeft, fs.CheckOK = "rolled_back", 0, false
	got := w.step(at(40), Pulse{FailSafe: fs}, EventLog{}, sampleStatus)
	if len(got) != 1 || !got[0].Edit || got[0].Resolves {
		t.Fatalf("the rollback did not redraw the message: %q %+v", texts(got), got)
	}
	h.deliver(got[0])
	edits := h.api.callsTo("editMessageText")
	if len(edits) == 0 || int64(edits[len(edits)-1].Params["message_id"].(float64)) != open {
		t.Fatalf("edits %v", edits)
	}
	last := edits[len(edits)-1].Params
	if _, has := last["reply_markup"]; has || !strings.Contains(last["text"].(string), "rolling back") {
		t.Fatalf("the message after the rollback: %v", last)
	}
	// Once: the window stays pending until the next healthy tick, and nothing more is drawn meanwhile.
	if got := w.step(at(45), Pulse{FailSafe: fs}, EventLog{}, sampleStatus); len(got) != 0 {
		t.Fatalf("redrawn again: %q", texts(got))
	}
}

// A Keep or Roll back that reaches the bot while the fail-safe rolls back by itself (before the
// redraw lands) is answered with that rollback, and decides nothing.
func TestDecisionDuringTheFailSafesRollbackIsAnsweredAsSuch(t *testing.T) {
	for _, data := range []string{cbKeep + "w1", cbRollback + "w1"} {
		h := newHarness(t, owner)
		h.be.pulse.FailSafe = FailSafePulse{Pending: true, Live: true, Phase: "rolled_back", Window: "w1"}
		h.be.decideErr = errContains("a rollback is already in progress — retry once it finishes")
		h.press(500, data)
		if h.be.kept+h.be.rolledBack != 0 {
			t.Fatalf("%s reached the daemon during the rollback", data)
		}
		for _, s := range h.sent() {
			if strings.Contains(s, "Did not work") {
				t.Fatalf("%s: %q", data, h.sent())
			}
		}
		a := h.api.callsTo("answerCallbackQuery")
		if len(a) != 1 || a[0].Params["text"] != T("en", "al.apply.rolling") {
			t.Fatalf("%s: answers %v", data, a)
		}
	}
}

// The panel's Keep of A and a new Test B inside one pulse looked like B replacing A, and A's message
// said "replaced". A kept Test is the committed revision, under its own window name.
func TestWatcherTellsAKeepFollowedByANewTestAsKept(t *testing.T) {
	at := func(sec int) time.Time { return testNow.Add(time.Duration(sec) * time.Second) }
	for _, tc := range []struct {
		committed, want string
	}{{"wA", "kept"}, {"w0", "replaced"}, {"", "replaced"}} {
		w := newWatcher()
		w.step(testNow, Pulse{}, EventLog{}, sampleStatus)
		w.step(at(5), Pulse{FailSafe: FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 180, Window: "wA", Checked: true, CheckOK: true}}, EventLog{}, sampleStatus)
		got := w.step(at(10), Pulse{FailSafe: FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 180, Window: "wB", Committed: tc.committed}}, EventLog{}, sampleStatus)
		if len(got) != 2 || !got[0].Edit || !got[0].Resolves || got[0].Sev != SevInfo || got[1].Sev != SevAction {
			t.Fatalf("committed %q: %q %+v", tc.committed, texts(got), got)
		}
		if text, _ := rendered(got[0], "en", roleOwner); !strings.Contains(text, tc.want) {
			t.Fatalf("committed %q: A closed as %q, want %q", tc.committed, text, tc.want)
		}
	}
}
