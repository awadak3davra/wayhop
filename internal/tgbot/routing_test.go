package tgbot

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The routing switch is an owner's: a viewer can neither open it nor press its buttons.
func TestRoutingSwitchIsForOwners(t *testing.T) {
	h := newHarness(t, owner, viewerChat)
	h.text(600, "private", "/routing", "ru")
	if s := h.sent(); len(s) != 1 || !strings.Contains(s[0], "не разрешено") {
		t.Fatalf("viewer /routing: %q", s)
	}
	for _, data := range []string{cbAsk + actRoutingOff, cbAsk + actRoutingOn} {
		h.press(600, data)
	}
	for _, c := range h.api.callsTo("answerCallbackQuery") {
		if c.Params["show_alert"] != true {
			t.Fatalf("a viewer's routing press was not refused: %v", c.Params)
		}
	}
	if len(h.be.routed) != 0 {
		t.Fatalf("a viewer switched routing: %v", h.be.routed)
	}
	if menu := strings.Join(commandNames(chatMenu("en", roleViewer)), " "); strings.Contains(menu, "routing") {
		t.Fatalf("a viewer's menu offers /routing: %s", menu)
	}
	if menu := strings.Join(commandNames(chatMenu("en", roleOwner)), " "); !strings.Contains(menu, "routing") {
		t.Fatalf("an owner's menu lacks /routing: %s", menu)
	}
}

func commandNames(cmds []Command) []string {
	out := make([]string, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, c.Command)
	}
	return out
}

// Off and back on, each asked first and run only on the confirmation.
func TestRoutingSwitchAsksThenSwitches(t *testing.T) {
	h := newHarness(t, owner)
	h.text(500, "private", "/routing", "en")
	if s := h.sent(); len(s) != 1 || !strings.Contains(s[0], "WayHop's routing is on") {
		t.Fatalf("/routing: %q", s)
	}
	h.press(500, h.buttonData("sendMessage", "Switch routing off"))
	if q := lastEdit(h); !strings.Contains(q, "Switch WayHop's routing off?") {
		t.Fatalf("question %q", q)
	}
	if len(h.be.routed) != 0 {
		t.Fatal("switched before the confirmation")
	}
	yes := h.buttonData("editMessageText", "Switch off")
	h.press(500, yes)
	if len(h.be.routed) != 1 || h.be.routed[0] {
		t.Fatalf("the confirmed switch-off did not run once: %v", h.be.routed)
	}
	if e := lastEdit(h); !strings.Contains(e, "Routing is off") || !strings.Contains(e, "Sam") {
		t.Fatalf("outcome %q", e)
	}
	h.press(500, yes)
	if len(h.be.routed) != 1 {
		t.Fatal("a confirmation worked twice")
	}

	// The maintenance menu now offers the way back, and no Apply while routing is off.
	h.be.status.Changes = Changes{Known: true, Pending: true, Count: 2}
	h.press(500, cbMaint)
	menu := lastEdit(h)
	if !strings.Contains(menu, "switched off") {
		t.Fatalf("the menu does not say routing is off: %q", menu)
	}
	raw := string(h.api.callsTo("editMessageText")[len(h.api.callsTo("editMessageText"))-1].Raw)
	if strings.Contains(raw, cbAsk+actApply) || !strings.Contains(raw, cbAsk+actRoutingOn) {
		t.Fatalf("menu buttons while routing is off: %s", raw)
	}
	h.press(500, cbAsk+actRoutingOn)
	if q := lastEdit(h); !strings.Contains(q, "Switch WayHop's routing back on?") {
		t.Fatalf("question %q", q)
	}
	h.press(500, h.buttonData("editMessageText", "Switch on"))
	if len(h.be.routed) != 2 || !h.be.routed[1] {
		t.Fatalf("the confirmed switch-on did not run: %v", h.be.routed)
	}
	if e := lastEdit(h); !strings.Contains(e, "Routing is back on") {
		t.Fatalf("outcome %q", e)
	}
}

// A stale button for the state the router already has shows that state rather than asking.
func TestRoutingSwitchStaleButtonShowsTheState(t *testing.T) {
	h := newHarness(t, owner)
	h.be.status.Routing = Routing{Off: true, Since: testNow.Add(-time.Hour), Err: "kernel routing plane: nft busy"}
	h.press(500, cbAsk+actRoutingOff)
	e := lastEdit(h)
	if !strings.Contains(e, "WayHop's routing is off") || !strings.Contains(e, "nft busy") || strings.Contains(e, "?") {
		t.Fatalf("stale off button: %q", e)
	}
	if len(h.be.routed) != 0 {
		t.Fatal("a stale button switched routing")
	}
}

func TestRoutingSwitchFailureIsReported(t *testing.T) {
	h := newHarness(t, owner)
	h.be.routeErr = errors.New("routing could not be switched back on; it stays off: sing-box binary not found")
	h.be.status.Routing = Routing{Off: true}
	h.press(500, cbAsk+actRoutingOn)
	h.press(500, h.buttonData("editMessageText", "Switch on"))
	if e := lastEdit(h); !strings.Contains(e, "The switch did not complete") || !strings.Contains(e, "binary not found") {
		t.Fatalf("failure %q", e)
	}
}

// The status says routing is off, and the stopped core is not reported as an outage.
func TestStatusSaysRoutingIsOff(t *testing.T) {
	s := sampleStatus()
	s.Core.Running = false
	s.Routing = Routing{Off: true}
	if got := s.Verdict(); got != HealthRoutingOff {
		t.Fatalf("Verdict = %v, want HealthRoutingOff", got)
	}
	text, _ := view{lang: "en", now: testNow}.Status(s)
	if !strings.Contains(text, "WayHop's routing is off") || !strings.Contains(text, "straight out through the provider") {
		t.Fatalf("status %q", text)
	}
}

// Switching routing off and on is told once each; the exits the stopped core carried, failing and
// coming back, are not news.
func TestWatcherRoutingSwitchHoldsTheExits(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	d1, d2 := evAt(10, "down", "a", "a"), evAt(12, "down", "b", "b")
	got := w.step(testNow.Add(10*time.Second), Pulse{RoutingOff: true}, logOf(d1), sampleStatus)
	if len(got) != 1 || got[0].Kind != KindApply || got[0].Incident != "routing" || got[0].Resolves {
		t.Fatalf("switched off: %q", texts(got))
	}
	if got = w.step(testNow.Add(20*time.Second), Pulse{RoutingOff: true}, logOf(d1, d2), sampleStatus); len(got) != 0 {
		t.Fatalf("exits failing with routing off were announced: %q", texts(got))
	}
	u1 := evAt(30, "up", "a", "a")
	got = w.step(testNow.Add(30*time.Second), Pulse{}, logOf(d1, d2, u1), sampleStatus)
	if len(got) != 1 || !got[0].Resolves || got[0].Incident != "routing" {
		t.Fatalf("switched on: %q", texts(got))
	}
	u2 := evAt(40, "up", "b", "b")
	if got = w.step(testNow.Add(40*time.Second), Pulse{}, logOf(d1, d2, u1, u2), sampleStatus); len(got) != 0 {
		t.Fatalf("an exit coming back with routing was announced: %q", texts(got))
	}
	d3 := evAt(5*60, "down", "a", "a")
	if got = w.step(testNow.Add(5*time.Minute), Pulse{}, logOf(d1, d2, u1, u2, d3), sampleStatus); len(got) != 1 || got[0].Kind != KindExits {
		t.Fatalf("a later failure with routing on is news again: %q", texts(got))
	}
}
