package tgbot

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
)

// A quiet outcome (kept, passed, a Roll back somebody pressed) rewrites the test Apply's message. When
// that edit failed for a network reason the alert stayed queued, but the incident had already been
// closed, so the retry found no message to edit and dropped the outcome: the phone kept "rolls back by
// itself in 1:40" with Keep / Roll back for good (QA-101). Right after a rollback restarts the core is
// exactly when the bot's path to Telegram is likely to fail once.
func TestQuietOutcomeEditIsRetriedAfterANetworkFailure(t *testing.T) {
	h := newHarness(t, owner)
	window := FailSafePulse{Pending: true, SecondsLeft: 100, Window: "w1"}
	h.deliver(applyArmed(testNow, window))
	armedID, ok := h.bot.out.openMsg(500, "apply")
	if !ok {
		t.Fatal("the armed message opened nothing")
	}

	var n atomic.Int32
	h.api.on("editMessageText", func(map[string]any) (int, string) {
		if n.Add(1) == 1 {
			return 502, `{"ok":false,"error_code":502,"description":"Bad Gateway"}`
		}
		return 200, `{"ok":true,"result":true}`
	})
	q := &queued{a: applyClosed(testNow, "al.apply.kept", SevInfo, true), done: map[int64]bool{}}
	err := h.bot.deliver(context.Background(), q)
	if err == nil || !retryable(err) {
		t.Fatalf("first try: %v, want a retryable error", err)
	}
	if _, open := h.bot.out.openMsg(500, "apply"); !open {
		t.Fatal("the incident was closed although its outcome never reached the chat")
	}
	if err := h.bot.deliver(context.Background(), q); err != nil {
		t.Fatalf("retry: %v", err)
	}
	edits := h.api.callsTo("editMessageText")
	if len(edits) != 2 {
		t.Fatalf("%d edits, want the failed one and its retry", len(edits))
	}
	last := edits[len(edits)-1]
	if int64(last.Params["message_id"].(float64)) != armedID || !strings.Contains(last.Params["text"].(string), "kept") {
		t.Fatalf("the retry edited %v", last.Params)
	}
	if _, open := h.bot.out.openMsg(500, "apply"); open {
		t.Fatal("the incident stays open after its outcome arrived")
	}

	// A refusal for good (the message is gone) still closes the incident: retrying cannot help.
	h.deliver(applyArmed(testNow, window))
	h.api.on("editMessageText", func(map[string]any) (int, string) {
		return 400, `{"ok":false,"error_code":400,"description":"Bad Request: message to edit not found"}`
	})
	q = &queued{a: applyClosed(testNow, "al.apply.kept", SevInfo, true), done: map[int64]bool{}}
	if err := h.bot.deliver(context.Background(), q); err != nil {
		t.Fatalf("a refused edit is not queued again: %v", err)
	}
	if _, open := h.bot.out.openMsg(500, "apply"); open {
		t.Fatal("an incident whose message is gone stays open")
	}
}
