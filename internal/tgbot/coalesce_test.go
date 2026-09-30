package tgbot

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// burst is n exits failing (or coming back) in the same moment, de-backup among them.
func burst(kind string, at int, n int) []Event {
	evs := []Event{evAt(at, kind, "de-backup", "de-backup")}
	for i := 1; i < n; i++ {
		evs = append(evs, evAt(at, kind, fmt.Sprintf("sub-%02d", i), fmt.Sprintf("Subscription %02d", i)))
	}
	return evs
}

// A provider's hiccup takes several exits down in one step: that is one message, with each exit's
// cause and what it left the groups with, and it opens every exit's incident.
func TestWatcherBurstIsOneMessage(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	downs := burst("down", 10, 5)
	got := w.step(testNow.Add(10*time.Second), Pulse{}, logOf(downs...), sampleStatus)
	if len(got) != 1 || got[0].Kind != KindExits || got[0].Sev != SevWarning || got[0].Resolves {
		t.Fatalf("burst: %q", texts(got))
	}
	if n := len(got[0].Incidents); n != 5 || got[0].Incidents[0] != "exit:de-backup" {
		t.Fatalf("incidents %v", got[0].Incidents)
	}
	text, _ := rendered(got[0], "en", roleOwner)
	for _, want := range []string{"🔴 <b>5 exits are down</b>", "• <b>de-backup</b> · <i>handshake did not complete</i>",
		"• <b>Subscription 04</b>", "Group fast-eu now goes through <b>nl-main</b>"} {
		if !strings.Contains(text, want) {
			t.Fatalf("lacks %q:\n%s", want, text)
		}
	}
	if ru, _ := rendered(got[0], "ru", roleOwner); !strings.HasPrefix(ru, "🔴 <b>Недоступно выходов: 5</b>") {
		t.Fatalf("ru %q", ru)
	}
	if line := got[0].Line("en"); line != "🔴 <b>5 exits are down</b>" {
		t.Fatalf("summary line %q", line)
	}

	ups := burst("up", 130, 4)
	got = w.step(testNow.Add(2*time.Minute+15*time.Second), Pulse{}, logOf(append(downs, ups...)...), sampleStatus)
	if len(got) != 1 || !got[0].Resolves || got[0].Sev != SevInfo || len(got[0].Incidents) != 4 {
		t.Fatalf("recoveries: %q", texts(got))
	}
	if text, _ := rendered(got[0], "en", roleOwner); !strings.Contains(text, "🟢 <b>4 exits are back</b>\n• <b>de-backup</b> · was down 2 min") {
		t.Fatalf("recoveries text:\n%s", text)
	}
}

// Two at once are still told apart: each message says more than a list line would.
func TestWatcherTwoFailuresStayApart(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	if got := w.step(testNow.Add(10*time.Second), Pulse{}, logOf(burst("down", 10, 2)...), sampleStatus); len(got) != 2 || got[0].Incident == "" {
		t.Fatalf("two failures: %q", texts(got))
	}
}

// In the chat the burst is one thread: every exit's incident points at the burst's message, a
// single recovery replies to it, and the burst of recoveries closes the rest.
func TestBurstIsOneThreadInTheChat(t *testing.T) {
	h := newHarness(t, owner)
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	downs := burst("down", 10, 5)
	h.deliver(w.step(testNow.Add(10*time.Second), Pulse{}, logOf(downs...), sampleStatus)[0])
	sends := h.sendsTo(500)
	if len(sends) != 1 {
		t.Fatalf("%d messages for one burst", len(sends))
	}
	first, ok := h.bot.out.openMsg(500, "exit:sub-03")
	if !ok {
		t.Fatal("the burst opened no incident for its exits")
	}
	for _, e := range downs {
		if id, _ := h.bot.out.openMsg(500, "exit:"+e.ID); id != first {
			t.Fatalf("%s points at %d, the burst is %d", e.ID, id, first)
		}
	}

	one := evAt(60, "up", "sub-03", "Subscription 03")
	h.deliver(w.step(testNow.Add(time.Minute), Pulse{}, logOf(append(downs, one)...), sampleStatus)[0])
	if reply := replyTo(h.sendsTo(500)[1]); reply != first {
		t.Fatalf("the single recovery replies to %d, not the burst %d", reply, first)
	}
	rest := []Event{evAt(130, "up", "de-backup", "de-backup"), evAt(130, "up", "sub-01", "Subscription 01"),
		evAt(130, "up", "sub-02", "Subscription 02"), evAt(130, "up", "sub-04", "Subscription 04")}
	all := append(append(downs, one), rest...)
	h.deliver(w.step(testNow.Add(2*time.Minute+15*time.Second), Pulse{}, logOf(all...), sampleStatus)[0])
	if reply := replyTo(h.sendsTo(500)[2]); reply != first {
		t.Fatalf("the burst of recoveries replies to %d, not %d", reply, first)
	}
	for _, e := range downs {
		if _, open := h.bot.out.openMsg(500, "exit:"+e.ID); open {
			t.Fatalf("%s is still open", e.ID)
		}
	}
}

func replyTo(c apiCall) int64 {
	rp, _ := c.Params["reply_parameters"].(map[string]any)
	id, _ := rp["message_id"].(float64)
	return int64(id)
}

// A burst waiting out quiet hours is one line of the summary, not five.
func TestBurstInQuietHoursIsOneLine(t *testing.T) {
	h := newHarness(t, owner)
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	h.st.t.QuietFrom, h.st.t.QuietTo = "14:00", "15:00"
	h.deliver(w.step(testNow.Add(10*time.Second), Pulse{}, logOf(burst("down", 10, 6)...), sampleStatus)[0])
	h.bot.now = func() time.Time { return testNow.Add(time.Hour) }
	h.bot.flushHeld(context.Background())
	sent := h.sent()
	if len(sent) != 1 || !strings.Contains(sent[0], "(1)") || !strings.Contains(sent[0], "6 exits are down") {
		t.Fatalf("summary %q", sent)
	}
}
