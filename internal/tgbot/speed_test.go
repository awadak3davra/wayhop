package tgbot

import (
	"strings"
	"testing"
)

func speedSample(lineDown, routeDown float64) SpeedReport {
	return SpeedReport{
		Line:  SpeedLeg{DownMbps: lineDown, UpMbps: 38.12, LatencyMs: 12},
		Route: SpeedLeg{DownMbps: routeDown, UpMbps: 19.4, LatencyMs: 58},
		Via:   "Auto (fastest) → nl-main",
	}
}

// The two legs side by side, the route named as the configured rules give it, and one sentence on
// what they say together.
func TestSpeedView(t *testing.T) {
	v := view{lang: "en", now: testNow}
	text := v.Speed(speedSample(94.23, 41.3))
	for _, want := range []string{
		"Provider's line: ↓ 94.2 Mbit/s ↑ 38.1 Mbit/s · 12 ms",
		"Through <b>Auto (fastest) → nl-main</b>: ↓ 41.3 Mbit/s ↑ 19.4 Mbit/s · 58 ms",
		"The route through <b>Auto (fastest) → nl-main</b> gives about 44% of the line's speed",
		"<i>Measured from the router itself",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("lacks %q:\n%s", want, text)
		}
	}
	for _, c := range []struct {
		route float64
		want  string
	}{{90, "keeps up with the line"}, {150, "faster than straight through"}, {20, "The tunnel is the bottleneck: about 21%"}} {
		if text := v.Speed(speedSample(94.23, c.route)); !strings.Contains(text, c.want) {
			t.Errorf("%v Mbit/s through WayHop: lacks %q:\n%s", c.route, c.want, text)
		}
	}
	ru := view{lang: "ru", now: testNow}.Speed(speedSample(94.23, 41.3))
	if !strings.Contains(ru, "Линия провайдера: ↓ 94,2 Мбит/с") || !strings.Contains(ru, "около 44% скорости линии") {
		t.Errorf("ru:\n%s", ru)
	}
	if n := textLen(text); n > maxText {
		t.Fatalf("%d characters", n)
	}
}

// Nothing is shown under a label it does not deserve, and no verdict is drawn from a leg that is not
// what it says: a failed leg says why; a site that goes straight out has no route through WayHop to
// measure; a line that left by a tunnel is that tunnel; a path that answered nothing says so in the
// reader's language; an upload or latency that did not complete is left out, not shown as 0.
func TestSpeedViewOfWhatWasNotMeasured(t *testing.T) {
	v := view{lang: "en", now: testNow}
	noVerdict := func(text string) bool {
		return !strings.Contains(text, "%") && !strings.Contains(text, "keeps up") && !strings.Contains(text, "faster than")
	}
	r := speedSample(94, 41)
	r.Route = SpeedLeg{Err: `download: proxyconnect tcp: dial tcp 127.0.0.1:7890: <refused>`, LatencyMs: -1}
	if text := v.Speed(r); !strings.Contains(text, "Through <b>Auto (fastest) → nl-main</b>: not measured (download: proxyconnect tcp: dial tcp 127.0.0.1:7890: &lt;refused&gt;)") ||
		!noVerdict(text) {
		t.Fatalf("failed leg:\n%s", text)
	}
	r.Route = SpeedLeg{Err: "latency: no answer in 8s", NoAnswer: true, LatencyMs: -1}
	if text := (view{lang: "ru", now: testNow}).Speed(r); !strings.Contains(text, "не измерено (нет ответа)") || strings.Contains(text, "8s") || !noVerdict(text) {
		t.Fatalf("no answer:\n%s", text)
	}
	r = speedSample(94, 0)
	r.Route, r.Via, r.Direct = SpeedLeg{Skipped: true}, "", true
	if text := v.Speed(r); !strings.Contains(text, "sites with no rule of their own go straight out here") || !noVerdict(text) {
		t.Fatalf("direct:\n%s", text)
	}
	r.Direct, r.Blocked = false, true
	if text := v.Speed(r); !strings.Contains(text, "a rule here blocks the test's site") || !noVerdict(text) {
		t.Fatalf("blocked:\n%s", text)
	}
	r.Blocked = false
	if text := v.Speed(r); !strings.Contains(text, "not measured, sing-box is not running") || !noVerdict(text) {
		t.Fatalf("no core:\n%s", text)
	}
	r.Native = true
	if text := v.Speed(r); !strings.Contains(text, "routes natively, without sing-box") {
		t.Fatalf("native:\n%s", text)
	}
	r = speedSample(94, 90)
	r.Line.Through = "awg0"
	if text := v.Speed(r); !strings.Contains(text, "the router's own traffic leaves through <b>awg0</b>, so this is that tunnel, not the line: ↓ 94 Mbit/s") ||
		!noVerdict(text) {
		t.Fatalf("line through a tunnel:\n%s", text)
	}
	r = speedSample(94, 0)
	r.Route, r.Via, r.Direct, r.ByRule = SpeedLeg{Skipped: true}, "", true, true
	if text := v.Speed(r); !strings.Contains(text, "a rule or list here sends the test's site straight out") ||
		strings.Contains(text, "sites with no rule") || !noVerdict(text) {
		t.Fatalf("straight out by a rule:\n%s", text)
	}
	r = SpeedReport{Line: SpeedLeg{DownMbps: 80, LatencyMs: -1}, Route: SpeedLeg{DownMbps: 70, LatencyMs: -1}}
	if text := v.Speed(r); !strings.Contains(text, "Provider's line: ↓ 80 Mbit/s\n") || !strings.Contains(text, "Through WayHop: ↓ 70 Mbit/s\n") {
		t.Fatalf("partial numbers:\n%s", text)
	}
	// An upload that was tried and not measured says so; one left out would read as never tried.
	r.Route.UpMissed = true
	if text := v.Speed(r); !strings.Contains(text, "Through WayHop: ↓ 70 Mbit/s ↑ not measured\n") {
		t.Fatalf("upload not measured:\n%s", text)
	}
}

// Only an owner measures: a test spends the family's line. The owner is asked first, the message
// says which leg is running, and the result replaces it.
func TestSpeedTestAsksOwnersThenRuns(t *testing.T) {
	h := newHarness(t, owner, viewerChat)
	h.be.speed = speedSample(94, 41)

	h.text(600, "private", "/speed", "ru")
	h.press(600, cbAsk+actSpeed)
	if s := h.sent(); len(s) != 1 || !strings.Contains(s[0], "не разрешено") {
		t.Fatalf("viewer /speed: %q", s)
	}
	if a := h.api.callsTo("answerCallbackQuery"); len(a) != 1 || a[0].Params["show_alert"] != true {
		t.Fatalf("a viewer's press was not refused: %v", a)
	}

	h.text(500, "private", "/speed", "en")
	if s := h.sent(); len(s) != 2 || !strings.Contains(s[1], "Measure the speed?") {
		t.Fatalf("question %q", s)
	}
	if h.be.speedRuns != 0 {
		t.Fatal("measured before the confirmation")
	}
	h.press(500, h.buttonData("sendMessage", "Measure"))
	h.bot.wg.Wait()
	if h.be.speedRuns != 1 {
		t.Fatal("the confirmed test did not run")
	}
	e := h.edited()
	if len(e) != 3 || !strings.Contains(e[0], "provider's line (1 of 2)") || !strings.Contains(e[1], "through WayHop (2 of 2)") ||
		!strings.Contains(e[2], "Through <b>Auto (fastest) → nl-main</b>: ↓ 41 Mbit/s") {
		t.Fatalf("edits %q", e)
	}
	// Again asks again: every run spends the line.
	h.press(500, h.buttonData("editMessageText", "Again"))
	if q := lastEdit(h); !strings.Contains(q, "Measure the speed?") || h.be.speedRuns != 1 {
		t.Fatalf("again: %q, runs %d", q, h.be.speedRuns)
	}
}

// A refused test never claims to be running: the busy answer replaces the question directly.
func TestSpeedTestWhileAnotherRuns(t *testing.T) {
	h := newHarness(t, owner)
	h.be.speedErr = ErrBusy
	h.press(500, cbAsk+actSpeed)
	h.press(500, h.buttonData("editMessageText", "Measure"))
	h.bot.wg.Wait()
	e := h.edited()
	if last := e[len(e)-1]; !strings.Contains(last, "Another speed test is running") || strings.Contains(strings.Join(e, "\n"), "1 of 2") {
		t.Fatalf("busy: %q", e)
	}
}

// A second tap on Measure (or on Cancel) while the test runs neither runs it twice nor replaces the
// message that is reporting it: the tap is told it was already confirmed.
func TestSpeedTestTappedTwice(t *testing.T) {
	h := newHarness(t, owner)
	h.be.speed = speedSample(94, 41)
	h.press(500, cbAsk+actSpeed)
	yes, no := h.buttonData("editMessageText", "Measure"), h.buttonData("editMessageText", "Cancel")
	h.press(500, yes)
	h.bot.wg.Wait()
	edits := len(h.edited())
	h.press(500, yes)
	h.press(500, no)
	h.bot.wg.Wait()
	if h.be.speedRuns != 1 || len(h.edited()) != edits {
		t.Fatalf("runs %d, edits %d -> %d", h.be.speedRuns, edits, len(h.edited()))
	}
	a := h.api.callsTo("answerCallbackQuery")
	for _, c := range a[len(a)-2:] {
		if c.Params["text"] != "Already confirmed." {
			t.Fatalf("answer %v", c.Params)
		}
	}
}

// Cancel leaves the question for the tools the test is offered among, not for Maintenance.
func TestSpeedTestCancelled(t *testing.T) {
	h := newHarness(t, owner)
	h.press(500, cbAsk+actSpeed)
	h.press(500, h.buttonData("editMessageText", "Cancel"))
	if e := lastEdit(h); !strings.Contains(e, "Tools") || h.be.speedRuns != 0 {
		t.Fatalf("cancel: %q, runs %d", e, h.be.speedRuns)
	}
}

// The test is offered where the question comes up: the tools, and next to who is using the line.
func TestSpeedButtonForOwners(t *testing.T) {
	has := func(kb *Keyboard) bool {
		for _, row := range kb.Rows {
			for _, b := range row {
				if b.CallbackData == cbAsk+actSpeed {
					return true
				}
			}
		}
		return false
	}
	own, viewer := view{lang: "en", now: testNow, role: roleOwner}, view{lang: "en", now: testNow, role: roleViewer}
	_, okb := own.More()
	_, vkb := viewer.More()
	_, odv := own.Devices(DeviceList{})
	_, vdv := viewer.Devices(DeviceList{})
	if !has(okb) || !has(odv) || has(vkb) || has(vdv) {
		t.Fatalf("owner more %v devices %v, viewer more %v devices %v", has(okb), has(odv), has(vkb), has(vdv))
	}
}

// A kernel tunnel is measured on its own from its card: bound to its interface, it moves nobody's
// traffic. The card offers it to an owner, for a tunnel that is not down.
func TestSpeedOfOneTunnel(t *testing.T) {
	h := newHarness(t, owner, viewerChat)
	h.be.status.Exits[0].Tunnel = true // nl-main, a WireGuard exit that is up
	h.be.status.Exits[1].Tunnel = true // de-backup, down
	h.be.speed = SpeedReport{Line: SpeedLeg{DownMbps: 94, LatencyMs: 12}, Route: SpeedLeg{DownMbps: 88, LatencyMs: 40}, Exit: "nl-main"}

	h.press(600, cbExit+"nl-main")
	h.press(500, cbExit+"de-backup")
	h.press(500, cbExit+"nl-main")
	cards := h.api.callsTo("editMessageText")
	for i, want := range []bool{false, false, true} {
		if got := strings.Contains(string(cards[i].Raw), `"cq:speed:`); got != want {
			t.Fatalf("card %d offers a speed test: %v", i, got)
		}
	}

	h.press(500, h.buttonData("editMessageText", "Speed"))
	if q := lastEdit(h); !strings.Contains(q, "Measure the speed of nl-main?") || !strings.Contains(q, "Nobody's traffic is moved") {
		t.Fatalf("question %q", q)
	}
	h.press(500, h.buttonData("editMessageText", "Measure"))
	h.bot.wg.Wait()
	e := h.edited()
	if got := h.be.speedExits; len(got) != 1 || got[0] != "nl-main" {
		t.Fatalf("measured %q", got)
	}
	if !strings.Contains(e[len(e)-2], "through <b>nl-main</b> (2 of 2)") ||
		!strings.Contains(e[len(e)-1], "Through <b>nl-main</b>: ↓ 88 Mbit/s · 40 ms") ||
		!strings.Contains(e[len(e)-1], "The route through <b>nl-main</b> keeps up with the line") {
		t.Fatalf("edits %q", e[len(e)-2:])
	}
	if again := h.buttonData("editMessageText", "Again"); again != "cq:speed:nl-main" {
		t.Fatalf("again %q", again)
	}
	// Cancelling a tunnel's question goes back to its card.
	h.press(500, "cq:speed:nl-main")
	h.press(500, h.buttonData("editMessageText", "Cancel"))
	if c := lastEdit(h); !strings.Contains(c, "<b>nl-main</b>") || !strings.Contains(c, "State:") {
		t.Fatalf("after cancel %q", c)
	}
}

// A button naming an exit that is not a kernel tunnel (stale, or forged) explains on the exit's
// card instead of asking.
func TestSpeedOfAnExitThatIsNotATunnel(t *testing.T) {
	h := newHarness(t, owner)
	h.press(500, "cq:speed:nl-main")
	if c := lastEdit(h); !strings.Contains(c, "cannot be measured on its own") || strings.Contains(c, "Measure the speed") {
		t.Fatalf("got %q", c)
	}
	if h.be.speedRuns != 0 {
		t.Fatal("measured")
	}
}
