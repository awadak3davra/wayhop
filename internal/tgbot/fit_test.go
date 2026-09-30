package tgbot

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTextLenCountsWhatTelegramCounts(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int
	}{
		{"plain", 5},
		{"<b>bold</b> · <i>x</i>", 8},
		{"a &amp; b &lt;c&gt;", 9},
		{"🟢 up", 5}, // the emoji is two UTF-16 units
		{"<a href=\"https://t.me/x\">link</a>", 4},
	} {
		if got := textLen(c.in); got != c.want {
			t.Errorf("textLen(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// A message over the limit keeps the whole lines that fit, in order, with balanced tags, and says it
// was cut. One under the limit is untouched.
func TestFitCutsBetweenLines(t *testing.T) {
	short := "<b>Exits</b>\n🟢 <b>nl-main</b> · 42 ms"
	if fit(short) != short {
		t.Fatal("a short message was changed")
	}
	var lines []string
	for i := 0; i < 400; i++ {
		lines = append(lines, fmt.Sprintf("🔴 <b>exit-%03d</b> · <i>No response (timed out or blocked)</i>", i))
	}
	long := strings.Join(lines, "\n")
	got := fit(long)
	if textLen(got) > maxText+1 || !strings.HasSuffix(got, "\n…") {
		t.Fatalf("length %d, tail %q", textLen(got), got[len(got)-20:])
	}
	kept := strings.Split(strings.TrimSuffix(got, "\n…"), "\n")
	for i, l := range kept {
		if l != lines[i] {
			t.Fatalf("line %d changed: %q", i, l)
		}
	}
	if strings.Count(got, "<b>") != strings.Count(got, "</b>") || strings.Count(got, "<i>") != strings.Count(got, "</i>") {
		t.Fatal("unbalanced tags")
	}
	// A single line longer than a message loses its markup rather than being cut inside a tag.
	one := "<b>" + strings.Repeat("x&amp;", 3000) + "</b>"
	cut := fit(one)
	if textLen(cut) > maxText+1 || strings.Contains(cut, "<") || !strings.HasSuffix(cut, "…") {
		t.Fatalf("one long line: length %d, starts %q", textLen(cut), cut[:20])
	}
}

// The client applies it, so no view can lose a message to Telegram's limit.
func TestTheClientNeverSendsTooMuch(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client()
	long := strings.Repeat("🟢 <b>exit</b> · 42 ms\n", 500)
	if _, err := c.SendMessage(context.Background(), 1, long, SendOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.EditMessage(context.Background(), 1, 2, long, nil); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"sendMessage", "editMessageText"} {
		sent := f.callsTo(m)[0].Params["text"].(string)
		if n := textLen(sent); n > 4096 {
			t.Fatalf("%s sent %d characters", m, n)
		}
	}
}

func manyExits(n, down int) Status {
	s := sampleStatus()
	s.Exits = nil
	for i := 0; i < n; i++ {
		e := Exit{ID: fmt.Sprintf("sub-%03d", i), Name: fmt.Sprintf("Subscription node %03d", i), Kind: "vless",
			State: StateAlive, LatencyMs: 40 + i}
		if i < down {
			e.State, e.Cause = StateDown, "No response (timed out or blocked)"
		}
		s.Exits = append(s.Exits, e)
	}
	return s
}

// A subscription brings a hundred exits: the list pages, down exits first, groups on the first page.
func TestExitListPages(t *testing.T) {
	s := manyExits(53, 3)
	v := view{lang: "en", now: testNow, ref: func(id string) string { return id }}
	first, kb := v.Exits(s, 0)
	if strings.Count(first, "\n🔴") != 3 || strings.Count(first, "\n🟢") != exitsPage-3 || !strings.Contains(first, "<b>Groups</b>") {
		t.Fatalf("first page:\n%s", first)
	}
	nav := kb.Rows[len(kb.Rows)-2]
	if len(nav) != 2 || nav[0].Text != "Page 1 of 3" || nav[1].CallbackData != cbExitsPage+"1" {
		t.Fatalf("first page nav %+v", nav)
	}
	if exitButtons(kb) != exitsPage {
		t.Fatalf("%d exit buttons", exitButtons(kb))
	}
	last, kb := v.Exits(s, 2)
	if strings.Count(last, "Subscription node") != 53-2*exitsPage || strings.Contains(last, "<b>Groups</b>") {
		t.Fatalf("last page:\n%s", last)
	}
	nav = kb.Rows[len(kb.Rows)-2]
	if len(nav) != 2 || nav[0].CallbackData != cbExitsPage+"1" || nav[1].Text != "Page 3 of 3" {
		t.Fatalf("last page nav %+v", nav)
	}
	if refresh := kb.Rows[len(kb.Rows)-1][0]; refresh.CallbackData != cbExitsPage+"2" {
		t.Fatalf("refresh redraws %q", refresh.CallbackData)
	}
	if beyond, _ := v.Exits(s, 99); beyond != last {
		t.Fatal("a page past the end is not the last page")
	}
	// A short list has no page row at all.
	_, kb = v.Exits(sampleStatus(), 0)
	for _, row := range kb.Rows {
		for _, b := range row {
			if strings.HasPrefix(b.CallbackData, cbExitsPage) || b.CallbackData == cbNoop {
				t.Fatal("a one-page list got page buttons")
			}
		}
	}
}

func exitButtons(kb *Keyboard) int {
	n := 0
	for _, row := range kb.Rows {
		for _, b := range row {
			if strings.HasPrefix(b.CallbackData, cbExit) {
				n++
			}
		}
	}
	return n
}

// The page buttons work from the chat.
func TestExitListPageButton(t *testing.T) {
	h := newHarness(t, owner)
	h.be.status = manyExits(45, 0)
	h.press(500, cbExitsPage+"2")
	if e := h.edited(); len(e) != 1 || !strings.Contains(e[0], "Subscription node 044") || strings.Contains(e[0], "node 000") {
		t.Fatalf("page 3: %q", e)
	}
}

// One bad night on a hundred exits still fits one digest.
func TestDigestCapsItsLists(t *testing.T) {
	d := digest{At: testNow, Status: manyExits(60, 0), LogKnown: true, From: testNow.Add(-24 * time.Hour), FullDay: true}
	for i := 0; i < 60; i++ {
		d.Outages = append(d.Outages, outage{Name: fmt.Sprintf("node %02d", i), Count: 3, Down: time.Duration(60-i) * time.Minute})
		d.Switches = append(d.Switches, switched{Name: fmt.Sprintf("group %02d", i), Now: "x", Count: 60 - i})
	}
	text, _ := view{lang: "en", now: testNow}.Digest(d)
	if strings.Count(text, "🔴") != digestOutages || strings.Count(text, "🔁") != digestSwitches ||
		!strings.Contains(text, "…and 50 more") || !strings.Contains(text, "…and 55 more") {
		t.Fatalf("digest:\n%s", text)
	}
	if n := textLen(text); n > maxText {
		t.Fatalf("%d characters", n)
	}
}
