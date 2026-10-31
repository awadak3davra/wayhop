package tgbot

import (
	"strings"
	"testing"
	"time"
)

// The fail-safe's own rollback leaves its window pending until the next healthy tick (failsafe
// tickHealth sets rolled_back and dispatches the rollback; only a later tick clears pending), so the
// watcher, pulsing three times as often, sees testing/rolled_back for a while and then a close whose
// last check passed. That close was told as a manual Roll back: a silent edit, no critical alert,
// and meanwhile the countdown kept offering Keep / Roll back with "rolls back by itself" (QA-098).
func TestWatcherAutomaticRollbackPendingStepIsStillLoud(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{}, sampleStatus)
	at := func(sec int) time.Time { return testNow.Add(time.Duration(sec) * time.Second) }
	fs := FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 180, Window: "w9", Checked: true, CheckOK: true}
	if got := w.step(at(5), Pulse{FailSafe: fs}, EventLog{}, sampleStatus); len(got) != 1 || got[0].Sev != SevAction {
		t.Fatalf("armed: %q", texts(got))
	}
	fs.Phase, fs.CheckOK, fs.SecondsLeft = "degraded", false, 145
	w.step(at(40), Pulse{FailSafe: fs}, EventLog{}, sampleStatus)

	// The rollback tick: still pending, the rollback dispatched (SecondsLeft is 0 after it). Then the
	// rollback finished: the record let go of the Test, so nothing is live and the window has no name.
	fs.Phase, fs.SecondsLeft = "rolled_back", 0
	var during []Alert
	during = append(during, w.step(at(75), Pulse{FailSafe: fs}, EventLog{}, sampleStatus)...)
	fs.Live, fs.Window = false, ""
	during = append(during, w.step(at(110), Pulse{FailSafe: fs}, EventLog{}, sampleStatus)...)
	for _, a := range during {
		text, kb := rendered(a, "en", roleOwner)
		if strings.Contains(text, "rolls back by itself") || strings.Contains(toJSON(kb), cbKeep) {
			t.Fatalf("after the rollback the message still counts down with Keep: %q %s", text, toJSON(kb))
		}
	}

	// The next healthy tick closes the window: the last check passed, the rollback was the fail-safe's.
	closed := FailSafePulse{Phase: "rolled_back", Checked: true, CheckOK: true}
	got := w.step(at(115), Pulse{FailSafe: closed}, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Sev != SevCritical || got[0].Edit || !got[0].Resolves || got[0].Closed == nil {
		t.Fatalf("an automatic rollback closed quietly: %q %+v", texts(got), got)
	}
	if text, _ := rendered(got[0], "en", roleOwner); !strings.Contains(text, "Connectivity was lost") {
		t.Fatalf("closing text %q", text)
	}

	// The next window starts clean: a Roll back pressed in it is the quiet outcome again.
	w.step(at(200), Pulse{FailSafe: FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 180, Window: "w10", Checked: true, CheckOK: true}}, EventLog{}, sampleStatus)
	got = w.step(at(210), Pulse{FailSafe: FailSafePulse{Phase: "rolled_back", Checked: true, CheckOK: true}}, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Sev != SevInfo || !got[0].Edit {
		t.Fatalf("a manual Roll back in the next window: %+v", got)
	}
}

// A second Test applied inside the first one's window supersedes it (ArmHealth bumps the epoch and
// pending stays true), so the watcher saw testing -> testing and its countdown re-rendered the first
// message with the new window's buttons: an owner deciding about the first Test kept the second one,
// which nobody had asked about (QA-100). The old message closes without buttons; the new Test gets its
// own message.
func TestWatcherSecondTestInsideTheWindowGetsItsOwnMessage(t *testing.T) {
	h := newHarness(t, owner)
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{}, sampleStatus)
	at := func(sec int) time.Time { return testNow.Add(time.Duration(sec) * time.Second) }
	a := FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 180, Window: "wA", Checked: true, CheckOK: true}
	for _, al := range w.step(at(5), Pulse{FailSafe: a}, EventLog{}, sampleStatus) {
		h.deliver(al)
	}
	openA, ok := h.bot.out.openMsg(500, "apply")
	if !ok {
		t.Fatal("test A opened no message")
	}

	b := a
	b.Window = "wB"
	got := w.step(at(65), Pulse{FailSafe: b}, EventLog{}, sampleStatus)
	for _, al := range got {
		if _, kb := rendered(al, "en", roleOwner); al.Edit && strings.Contains(toJSON(kb), "wB") {
			t.Fatalf("test A's message was rebound to test B: %q", texts(got))
		}
	}
	for _, al := range got {
		h.deliver(al)
	}
	sends := h.sendsTo(500)
	if len(sends) != 2 || !strings.Contains(toJSON(sends[1].Params["reply_markup"]), `"ak:wB"`) {
		t.Fatalf("test B has no message of its own: %d sends", len(sends))
	}
	var lastA apiCall
	for _, c := range h.api.callsTo("editMessageText") {
		if int64(c.Params["message_id"].(float64)) == openA {
			lastA = c
		}
	}
	if lastA.Params == nil {
		t.Fatal("test A's message was left with its buttons")
	}
	if _, has := lastA.Params["reply_markup"]; has || strings.Contains(lastA.Params["text"].(string), "rolls back by itself") {
		t.Fatalf("test A's message after B: %v", lastA.Params)
	}
	if openB, _ := h.bot.out.openMsg(500, "apply"); openB == openA {
		t.Fatal("the countdown still edits test A's message")
	}

	// A's own buttons now decide nothing: they name a window that is over.
	h.be.pulse.FailSafe = b
	h.press(500, cbKeep+"wA")
	if h.be.kept != 0 {
		t.Fatal("test A's Keep kept test B")
	}
}

// A test whose rollback finished (nothing live, the window unnamed) and that a new Test then replaced
// while it was still pending: the rollback is told as the fail-safe's, and the new Test opens its own
// message rather than inheriting the old one.
func TestWatcherTestAfterAnAutomaticRollbackIsANewWindow(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{}, sampleStatus)
	at := func(sec int) time.Time { return testNow.Add(time.Duration(sec) * time.Second) }
	w.step(at(5), Pulse{FailSafe: FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 180, Window: "wA", Checked: true, CheckOK: true}}, EventLog{}, sampleStatus)
	w.step(at(70), Pulse{FailSafe: FailSafePulse{Pending: true, Phase: "rolled_back", Checked: true}}, EventLog{}, sampleStatus)
	got := w.step(at(75), Pulse{FailSafe: FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 180, Window: "wB", Checked: true, CheckOK: true}}, EventLog{}, sampleStatus)
	if len(got) != 2 || got[0].Sev != SevCritical || !got[0].Resolves || got[1].Sev != SevAction || got[1].Edit {
		t.Fatalf("rollback then a new Test: %q %+v", texts(got), got)
	}
	if _, kb := rendered(got[1], "en", roleOwner); !strings.Contains(toJSON(kb), `"ak:wB"`) {
		t.Fatalf("the new Test's buttons: %s", toJSON(kb))
	}
	// Test B ends on a Roll back somebody pressed: quiet, the fail-safe's rollback of A is not B's.
	got = w.step(at(90), Pulse{FailSafe: FailSafePulse{Phase: "rolled_back", Checked: true, CheckOK: true}}, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Sev != SevInfo || !got[0].Edit {
		t.Fatalf("B's manual Roll back: %+v", got)
	}
}
