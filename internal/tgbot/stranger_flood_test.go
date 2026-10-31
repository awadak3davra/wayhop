package tgbot

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// An unpaired chat sending "/start x" over and over was answered every time: five "not valid", then
// "too many wrong codes" for every further message, with no throttle, although an unknown chat is
// promised one polite refusal (QA-099). Wrong codes are still answered (the attempt limit bounds them
// and a person who mistyped must hear it); the lockout is told once per refusal interval, and then
// nothing until that passes.
func TestPairingFloodFromAStrangerIsAnsweredBoundedly(t *testing.T) {
	h := newHarness(t)
	now := testNow
	h.bot.gate.now = func() time.Time { return now }
	for i := 0; i < 30; i++ {
		h.text(777, "private", "/start x", "en")
	}
	got := h.sent()
	if len(got) != maxBadCodes+1 {
		t.Fatalf("%d replies to 30 wrong codes, want %d: %q", len(got), maxBadCodes+1, got)
	}
	for i, s := range got[:maxBadCodes] {
		if !strings.Contains(s, "not valid") {
			t.Fatalf("reply %d: %q", i, s)
		}
	}
	if !strings.Contains(got[maxBadCodes], "Too many") {
		t.Fatalf("the lockout was not told: %q", got[maxBadCodes])
	}
	// Still locked a refusal interval later: told once more, then quiet again.
	now = now.Add(refuseEvery)
	h.text(777, "private", "/start x", "en")
	h.text(777, "private", "/start x", "en")
	if n := len(h.sent()); n != maxBadCodes+2 {
		t.Fatalf("%d replies after the interval, want %d", n, maxBadCodes+2)
	}
	// A pasted code and /pair go the same way.
	h.text(777, "private", "ZZZZZZZZ", "en")
	h.text(777, "private", "/pair ZZZZZZZZ", "en")
	if n := len(h.sent()); n != maxBadCodes+2 {
		t.Fatalf("a locked-out chat was answered again: %d", n)
	}
}

// Each of those answers went through the interactive path, which waits out Telegram's flood control
// (up to 30 s) inside one of the four handler slots that the poll loop blocks on. A stranger provoking
// 429s for its own chat thereby queued an owner's Keep behind minutes of sleeps, long enough for the
// test window to roll back (QA-099). An unpaired chat's answer is tried once and dropped on 429.
func TestStrangerRepliesNeverWaitOutFloodControl(t *testing.T) {
	h := newHarness(t, owner)
	var strangerCalls atomic.Int32
	h.api.on("sendMessage", func(p map[string]any) (int, string) {
		if p["chat_id"] == float64(777) || p["chat_id"] == float64(778) {
			strangerCalls.Add(1)
			return 429, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 2","parameters":{"retry_after":2}}`
		}
		return 200, `{"ok":true,"result":{"message_id":3,"chat":{"id":500,"type":"private"},"date":1}}`
	})
	start := time.Now()
	h.text(777, "private", "/start x", "en")        // a wrong code
	h.text(778, "private", "/status", "en")         // the polite refusal, to another stranger
	h.text(777, "private", "/start ZZZZZZZZ", "en") // another wrong code
	if d := time.Since(start); d >= 2*time.Second {
		t.Fatalf("answers to strangers waited out flood control for %v", d)
	}
	if n := strangerCalls.Load(); n != 3 {
		t.Fatalf("%d sends to strangers, want each of the three answers tried once", n)
	}
	// A paired chat's answer still waits the flood out (TestReplyWaitsOutFloodControl); the owner's own
	// replies are untouched here.
	h.text(500, "private", "/status", "en")
	if len(h.sendsTo(500)) != 1 {
		t.Fatal("the owner's answer did not go out")
	}
}

// A paired alerts-only group: any member may send commands, and each was answered "This chat only
// receives alerts" through the path that waits out flood control in a handler slot, the same queue an
// owner's Keep waits in. Its answers are tried once, as a stranger's are.
func TestAlertsOnlyGroupAnswersNeverWaitOutFloodControl(t *testing.T) {
	h := newHarness(t, owner, alertsChat)
	var groupCalls atomic.Int32
	h.api.on("sendMessage", func(p map[string]any) (int, string) {
		if p["chat_id"] == float64(alertsChat.ID) {
			groupCalls.Add(1)
			return 429, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 2","parameters":{"retry_after":2}}`
		}
		return 200, `{"ok":true,"result":{"message_id":3,"chat":{"id":500,"type":"private"},"date":1}}`
	})
	start := time.Now()
	h.text(alertsChat.ID, "group", "/status", "en")
	h.text(alertsChat.ID, "group", "/exits", "en")
	h.text(alertsChat.ID, "group", "/start ZZZZZZZZ", "en")
	if d := time.Since(start); d >= 2*time.Second {
		t.Fatalf("answers in an alerts-only group waited out flood control for %v", d)
	}
	if n := groupCalls.Load(); n != 3 {
		t.Fatalf("%d sends to the group, want each of the three answers tried once", n)
	}
}
