package tgbot

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// raceBackend decides a test Apply the way the daemon does: one decision at a time under its apply
// lock, and once the first has recorded its outcome nothing is live, so a second one is refused. The
// first call may be held at the lock until release closes.
type raceBackend struct {
	*fakeBackend
	applyMu sync.Mutex
	hold    chan struct{} // closed when the first decision holds the lock
	release chan struct{}
	once    sync.Once
}

func newRaceBackend(f *fakeBackend) *raceBackend {
	return &raceBackend{fakeBackend: f, hold: make(chan struct{}), release: make(chan struct{})}
}

func (r *raceBackend) decide(keep bool) error {
	first := false
	r.once.Do(func() { first = true })
	if !first {
		r.mu.Lock()
		inFlight := !keep && r.pulse.FailSafe.Pending && r.pulse.FailSafe.Window != ""
		r.mu.Unlock()
		if inFlight {
			// failsafe.RollbackNow refuses a second press while the first one's rollback runs.
			return errContains("a rollback is already in progress — retry once it finishes")
		}
	}
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	if first {
		close(r.hold)
		<-r.release
	}
	f := r.fakeBackend
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pulse.FailSafe.Window == "" {
		if keep {
			return errContains("there is no unsaved configuration to keep")
		}
		return errContains("no unsaved configuration to roll back — the committed configuration is running")
	}
	// Recorded: nothing is live any more. The fail-safe's own verdict (pending false) lands a moment
	// later, outside the lock, so a pulse read now still says the window is pending.
	f.pulse.FailSafe.Live, f.pulse.FailSafe.Window = false, ""
	if keep {
		f.kept++
	} else {
		f.rolledBack++
	}
	return nil
}

func (r *raceBackend) ConfirmApply(context.Context, string) error  { return r.decide(true) }
func (r *raceBackend) RollbackApply(context.Context, string) error { return r.decide(false) }

func raceHarness(t *testing.T) (*harness, *raceBackend) {
	h := newHarness(t, owner)
	rb := newRaceBackend(h.be)
	h.bot = New(h.api.client(), rb, h.st, Options{Now: func() time.Time { return testNow }, Logf: t.Logf})
	h.bot.me = User{ID: 1, IsBot: true, Username: "home_wayhop_bot"}
	h.be.pulse.FailSafe = FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 120, Window: "w1"}
	return h, rb
}

// doubleTap presses data twice on the same message, the second press while the first one's decision
// holds the daemon's lock, and waits for both.
func doubleTap(t *testing.T, h *harness, rb *raceBackend, data string) {
	press := func() {
		h.bot.handle(context.Background(), Update{CallbackQuery: &CallbackQuery{
			ID: "q", From: User{ID: 500, FirstName: "Sam"}, Data: data,
			Message: &Message{MessageID: 99, Chat: Chat{ID: 500, Type: "private"}},
		}})
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); press() }()
	<-rb.hold
	go func() { defer wg.Done(); press() }()
	// Both presses are acknowledged before the slow work; the second has then made its decision.
	waitFor(t, "both presses acknowledged", func() bool { return len(h.api.callsTo("answerCallbackQuery")) == 2 })
	time.Sleep(50 * time.Millisecond) // the second press reaches the daemon's lock, where it waits
	close(rb.release)
	wg.Wait()
}

// A double tap on Keep: the second press passed the window check while the first was still saving
// under the apply lock, then got "there is no unsaved configuration to keep", and the chat read
// "Kept by Sam" followed by "Did not work": a false failure as the last word on the safety net,
// inviting a needless Roll back or a second Apply (QA-103).
func TestDoubleTapOnKeepIsNotReportedAsAFailure(t *testing.T) {
	h, rb := raceHarness(t)
	doubleTap(t, h, rb, cbKeep+"w1")
	for _, s := range h.sent() {
		if strings.Contains(s, "Did not work") {
			t.Fatalf("a kept Apply was reported as a failure: %q", h.sent())
		}
	}
	if h.be.kept != 1 {
		t.Fatalf("kept %d times", h.be.kept)
	}
	if e := h.edited(); len(e) == 0 || !strings.Contains(e[len(e)-1], "Kept by Sam") {
		t.Fatalf("the message does not say who kept it: %q", e)
	}
}

// The same for Roll back, whose second press while the first one's rollback runs is refused by the
// fail-safe with "a rollback is already in progress".
func TestDoubleTapOnRollBackIsNotReportedAsAFailure(t *testing.T) {
	h, rb := raceHarness(t)
	doubleTap(t, h, rb, cbRollback+"w1")
	for _, s := range h.sent() {
		if strings.Contains(s, "Did not work") {
			t.Fatalf("a rolled back Apply was reported as a failure: %q", h.sent())
		}
	}
	if h.be.rolledBack != 1 {
		t.Fatalf("rolled back %d times", h.be.rolledBack)
	}
	if e := h.edited(); len(e) == 0 || !strings.Contains(e[len(e)-1], "Rolled back by Sam") {
		t.Fatalf("the message does not say who rolled it back: %q", e)
	}
}

// The window was decided elsewhere (the panel's Keep, another owner's chat) between this press's
// check and its own decision: the daemon refuses it, and that is not a failure to report. The
// watcher's closing edit tells this chat the outcome.
func TestKeepRefusedBecauseTheWindowWasDecidedElsewhereIsQuiet(t *testing.T) {
	h, _ := raceHarness(t)
	h.bot.be = decidedElsewhere{h.be}
	h.press(500, cbKeep+"w1")
	for _, s := range h.sent() {
		if strings.Contains(s, "Did not work") {
			t.Fatalf("a Keep that lost to the panel's was reported as a failure: %q", h.sent())
		}
	}
}

// decidedElsewhere is a daemon where the panel's Keep lands just before the bot's.
type decidedElsewhere struct{ *fakeBackend }

func (d decidedElsewhere) ConfirmApply(context.Context, string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pulse.FailSafe = FailSafePulse{Phase: "committed", Checked: true, CheckOK: true}
	return errContains("there is no unsaved configuration to keep")
}
