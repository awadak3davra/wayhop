package tgbot

import (
	"errors"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
)

// buttonData finds the callback data of the button whose text contains label in the last
// message sent or edited.
func (h *harness) buttonData(method, label string) string {
	h.t.Helper()
	for _, row := range h.api.lastKeyboard(h.t, method) {
		for _, b := range row {
			if strings.Contains(b.Text, label) {
				return b.CallbackData
			}
		}
	}
	h.t.Fatalf("no %q button in the last %s", label, method)
	return ""
}

func lastEdit(h *harness) string {
	e := h.edited()
	if len(e) == 0 {
		h.t.Fatal("nothing was edited")
	}
	return e[len(e)-1]
}

func TestMaintenanceIsForOwners(t *testing.T) {
	h := newHarness(t, owner, viewerChat)
	h.text(600, "private", "/maint", "ru")
	if s := h.sent(); len(s) != 1 || !strings.Contains(s[0], "не разрешено") {
		t.Fatalf("viewer /maint: %q", s)
	}
	for _, data := range []string{cbMaint, cbAsk + actRestart, cbDo + actLists} {
		h.press(600, data)
	}
	a := h.api.callsTo("answerCallbackQuery")
	for _, c := range a {
		if c.Params["show_alert"] != true {
			t.Fatalf("a viewer's maintenance press was not refused: %v", c.Params)
		}
	}
	if h.be.restarts != 0 {
		t.Fatal("a viewer restarted the daemon")
	}
	// The More menu offers Maintenance to owners only.
	h.press(600, cbMore)
	if strings.Contains(string(h.api.callsTo("editMessageText")[0].Raw), `"mt"`) {
		t.Fatal("a viewer's More menu offers Maintenance")
	}
	h.press(500, cbMore)
	if !strings.Contains(string(h.api.callsTo("editMessageText")[1].Raw), `"mt"`) {
		t.Fatal("an owner's More menu lacks Maintenance")
	}
}

func TestRestartAsksThenSaysSoBeforeGoing(t *testing.T) {
	h := newHarness(t, owner)
	h.text(500, "private", "/maint", "en")
	h.press(500, cbAsk+actRestart)
	if q := lastEdit(h); !strings.Contains(q, "Restart WayHop?") {
		t.Fatalf("question %q", q)
	}
	if h.be.restarts != 0 {
		t.Fatal("restarted before the confirmation")
	}
	yes := h.buttonData("editMessageText", "Restart")
	h.press(500, yes)
	if h.be.restarts != 1 {
		t.Fatal("the confirmed restart did not run")
	}
	if e := lastEdit(h); !strings.Contains(e, "restarting") {
		t.Fatalf("the chat must hear about the restart before it happens: %q", e)
	}
	// The nonce is spent.
	h.press(500, yes)
	if h.be.restarts != 1 {
		t.Fatal("a confirmation worked twice")
	}
}

func TestRestartUnavailableInTheDemo(t *testing.T) {
	h := newHarness(t, owner)
	h.be.restartErr = ErrUnavailable
	h.press(500, cbAsk+actRestart)
	h.press(500, h.buttonData("editMessageText", "Restart"))
	if e := lastEdit(h); !strings.Contains(e, "Could not restart: not available on this router (the demo") {
		t.Fatalf("got %q", e)
	}
}

func TestConfirmationIsBoundToItsChatAndExpires(t *testing.T) {
	h := newHarness(t, owner, config2Owner)
	now := testNow
	h.bot.now = func() time.Time { return now }
	h.press(500, cbAsk+actBackup)
	yes := h.buttonData("editMessageText", "Send the backup")
	// Another owner's chat cannot spend it.
	h.press(501, yes)
	if h.be.backups != 0 {
		t.Fatal("a nonce from one chat worked in another")
	}
	// It expires.
	h.press(500, cbAsk+actBackup)
	yes = h.buttonData("editMessageText", "Send the backup")
	now = now.Add(confirmTTL + time.Second)
	h.press(500, yes)
	if h.be.backups != 0 {
		t.Fatal("an expired confirmation ran")
	}
	a := h.api.callsTo("answerCallbackQuery")
	if last := a[len(a)-1]; !strings.Contains(last.Params["text"].(string), "expired") {
		t.Fatalf("expiry answer %v", last.Params)
	}
	// A later tap on either button is told the same, and the message is left alone.
	edits := len(h.edited())
	h.press(500, yes)
	h.press(500, "cx:"+strings.TrimPrefix(yes, cbConfirm))
	a = h.api.callsTo("answerCallbackQuery")
	for _, c := range a[len(a)-2:] {
		if c.Params["text"] != "That confirmation expired. Nothing was done." {
			t.Fatalf("a later tap on an expired question: %v", c.Params)
		}
	}
	if h.be.backups != 0 || len(h.edited()) != edits {
		t.Fatalf("backups %d, edits %d -> %d", h.be.backups, edits, len(h.edited()))
	}
}

var config2Owner = config.TelegramChat{ID: 501, Name: "Bob", Role: roleOwner, Lang: "en"}

func TestBackupGoesToTheChatAsAFile(t *testing.T) {
	h := newHarness(t, owner)
	h.press(500, cbAsk+actBackup)
	if q := lastEdit(h); !strings.Contains(q, "keys and passwords") {
		t.Fatalf("the question must say what the file holds: %q", q)
	}
	h.press(500, h.buttonData("editMessageText", "Send the backup"))
	docs := h.api.callsTo("sendDocument")
	if len(docs) != 1 || !strings.Contains(string(docs[0].Raw), `filename="wayhop-backup.json"`) ||
		!strings.Contains(string(docs[0].Raw), "Delete this message once the file is saved elsewhere") {
		t.Fatalf("document %d", len(docs))
	}
	if e := lastEdit(h); !strings.Contains(e, "Backup sent") {
		t.Fatalf("got %q", e)
	}
}

// A tap on Confirm queued behind Cancel runs nothing and is told the question was cancelled, not
// that it was already confirmed.
func TestCancelLeavesNothingToRun(t *testing.T) {
	h := newHarness(t, owner)
	h.press(500, cbAsk+actRestart)
	yes := h.buttonData("editMessageText", "Restart")
	h.press(500, "cx:"+strings.TrimPrefix(yes, cbConfirm))
	edits := len(h.edited())
	h.press(500, yes)
	if h.be.restarts != 0 {
		t.Fatal("a cancelled confirmation still ran")
	}
	a := h.api.callsTo("answerCallbackQuery")
	if last := a[len(a)-1]; last.Params["text"] != "Cancelled." || len(h.edited()) != edits {
		t.Fatalf("answer %v, edits %d -> %d", last.Params, edits, len(h.edited()))
	}
}

func TestApplyFromTheChat(t *testing.T) {
	h := newHarness(t, owner)
	h.be.preview = ApplyPreview{Pending: true, Rev: "rev-7", Count: 3, MayInterrupt: true,
		Confirms: []string{"Connection cannot authenticate"}}
	h.press(500, cbAsk+actApply)
	q := lastEdit(h)
	for _, want := range []string{"Apply the saved changes as a test?", "3 change(s).", "may drop", "rolls back by itself",
		"Applying also confirms:\n• Connection cannot authenticate"} {
		if !strings.Contains(q, want) {
			t.Fatalf("question lacks %q:\n%s", want, q)
		}
	}
	h.press(500, h.buttonData("editMessageText", "Apply as a test"))
	if len(h.be.applied) != 1 || h.be.applied[0] != "rev-7" {
		t.Fatalf("applied %v: the reviewed revision, and only it, must be applied", h.be.applied)
	}
	if e := lastEdit(h); !strings.Contains(e, "Test Apply started</b> by Sam") {
		t.Fatalf("got %q", e)
	}
}

func TestApplyBlockedOrNothingToDo(t *testing.T) {
	h := newHarness(t, owner)
	h.be.preview = ApplyPreview{Pending: true, Rev: "r", Blockers: []string{"The configuration is invalid"}}
	h.press(500, cbAsk+actApply)
	if e := lastEdit(h); !strings.Contains(e, "Apply is blocked</b> by 1 issue(s):\n• The configuration is invalid") ||
		strings.Contains(string(h.api.callsTo("editMessageText")[0].Raw), cbConfirm) {
		t.Fatalf("blocked: %q", e)
	}
	h.be.preview = ApplyPreview{}
	h.press(500, cbAsk+actApply)
	if e := lastEdit(h); !strings.Contains(e, "Nothing to apply") {
		t.Fatalf("nothing: %q", e)
	}
	if len(h.be.applied) != 0 {
		t.Fatal("applied without a question")
	}
}

func TestApplyFailureIsReported(t *testing.T) {
	h := newHarness(t, owner)
	h.be.preview = ApplyPreview{Pending: true, Rev: "r1"}
	h.be.applyErr = errors.New("the configuration changed since you reviewed it")
	h.press(500, cbAsk+actApply)
	h.press(500, h.buttonData("editMessageText", "Apply as a test"))
	if e := lastEdit(h); !strings.Contains(e, "Apply failed: the configuration changed since you reviewed it") {
		t.Fatalf("got %q", e)
	}
}

func TestRefreshesOfferApplyWhenSomethingChanged(t *testing.T) {
	h := newHarness(t, owner)
	h.be.lists = ListsRefresh{Lists: 9, Changed: 2, Unreached: 2, Failed: []FeedIssue{
		{List: "RU <IPs>", Fails: 1, Err: "https://feeds.example/…: status 404 Not Found"},
		{List: "b", Fails: 1, Empty: true}, {List: "c", Fails: 1}, {List: "d", Fails: 1}, {List: "e", Fails: 1},
	}}
	h.press(500, cbDo+actLists)
	e := lastEdit(h)
	if !strings.Contains(e, "Changed: 2 of 9") ||
		!strings.Contains(e, "⚠️ «RU &lt;IPs&gt;» failed, the last good content is kept: https://feeds.example/…: status 404 Not Found") ||
		!strings.Contains(e, "⚠️ «b» failed, and the list has nothing from it yet") ||
		!strings.Contains(e, "«c»") || strings.Contains(e, "«d»") || !strings.Contains(e, "…and 2 more") ||
		!strings.Contains(e, "⏳ Not reached in time: 2 more. Refresh again to try them.") {
		t.Fatalf("lists: %q", e)
	}
	if h.buttonData("editMessageText", "Apply saved changes") != cbAsk+actApply {
		t.Fatal("no Apply offered after a change")
	}
	h.be.subAdded, h.be.subErr = 0, errors.New("no subscription is imported")
	h.press(500, cbDo+actSub)
	if e := lastEdit(h); !strings.Contains(e, "could not be refreshed: no subscription is imported") {
		t.Fatalf("sub: %q", e)
	}
}
