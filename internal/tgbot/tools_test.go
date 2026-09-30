package tgbot

import (
	"strings"
	"testing"
	"time"
)

func sampleTrace() Trace {
	return Trace{
		IPs:  []string{"192.0.2.14", "192.0.2.46", "192.0.2.78", "192.0.2.110", "192.0.2.142"},
		Live: map[string]int{"nl-main": 2, "direct": 1},
		Configured: []TraceMatch{
			{Kind: "list", ID: "rl-stream", Name: "Streaming", Why: "domain_suffix youtube.com", Via: "fast"},
			{Kind: "rule", ID: "r3", Why: "domain youtube.com", Via: "nl-main"},
		},
		Maybe: []TraceMatch{{Kind: "rule", ID: "r9", Why: "geosite:google", Via: "block"}},
	}
}

func TestCleanTarget(t *testing.T) {
	for in, want := range map[string]string{
		"youtube.com":                         "youtube.com",
		"  YouTube.COM. ":                     "youtube.com",
		"https://www.youtube.com/watch?v=abc": "www.youtube.com",
		"youtube.com/feed":                    "youtube.com",
		"1.1.1.1:443":                         "1.1.1.1",
		"[2606:4700::1111]":                   "2606:4700::1111",
		"2606:4700::1111":                     "2606:4700::1111",
	} {
		if got := cleanTarget(in); got != want {
			t.Errorf("cleanTarget(%q) = %q, want %q", in, got, want)
		}
	}
	for _, s := range []string{"youtube.com", "https://x.org/a", "1.1.1.1", "2606:4700::1111"} {
		if !looksLikeHost(s) {
			t.Errorf("%q should look like a host", s)
		}
	}
	for _, s := range []string{"hello", "how are you.", "-x.com", "/status", "ok thanks", "."} {
		if looksLikeHost(s) {
			t.Errorf("%q should not look like a host", s)
		}
	}
}

func TestRouteCommandShowsWhereASiteGoes(t *testing.T) {
	h := newHarness(t, owner)
	h.be.trace = sampleTrace()
	h.text(500, "private", "/route https://www.youtube.com/watch?v=x", "en")
	if len(h.be.traced) != 1 || h.be.traced[0] != "www.youtube.com" {
		t.Fatalf("traced %v", h.be.traced)
	}
	got := h.sent()[0]
	for _, want := range []string{
		"🔎 <b>www.youtube.com</b>",
		"Resolves to <code>192.0.2.14, 192.0.2.46, 192.0.2.78, 192.0.2.110</code> …and 1 more",
		"<b>Now:</b> 3 connection(s), through <b>nl-main</b> ×2 · <b>direct (the provider)</b>",
		"• list «Streaming» → <b>fast-eu</b>",
		"• rule «r3» → <b>nl-main</b>",
		"May also match",
		"• rule «r9» → <b>blocked</b> <i>(geosite:google)</i>",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("trace lacks %q:\n%s", want, got)
		}
	}
	// "Again" re-runs the same target by its ref and edits the message.
	var again string
	for _, row := range h.api.lastKeyboard(t, "sendMessage") {
		for _, b := range row {
			if strings.HasPrefix(b.CallbackData, cbRouteAg) {
				again = b.CallbackData
			}
		}
	}
	h.press(500, again)
	if len(h.be.traced) != 2 || h.be.traced[1] != "www.youtube.com" || len(h.edited()) != 1 {
		t.Fatalf("again: traced %v, edited %d", h.be.traced, len(h.edited()))
	}
}

func TestBareSiteNameIsARouteQuestion(t *testing.T) {
	h := newHarness(t, owner)
	h.text(500, "private", "instagram.com", "en")
	if len(h.be.traced) != 1 || h.be.traced[0] != "instagram.com" {
		t.Fatalf("a bare site name was not traced: %v", h.be.traced)
	}
	h.text(500, "private", "thanks!", "en")
	if len(h.be.traced) != 1 {
		t.Fatal("chatter was traced")
	}
}

func TestRouteButtonAsksAndTheReplyAnswers(t *testing.T) {
	h := newHarness(t, owner)
	h.press(500, cbRoute)
	c := h.api.callsTo("sendMessage")
	if len(c) != 1 || !strings.Contains(string(c[0].Raw), `"force_reply":true`) || !strings.Contains(c[0].Params["text"].(string), "Which site") {
		t.Fatalf("prompt %s", c[0].Raw)
	}
	// A reply without a dot still answers the question it was asked for.
	h.text(500, "private", "localhost", "en")
	if len(h.be.traced) != 1 || h.be.traced[0] != "localhost" {
		t.Fatalf("the answer was not traced: %v", h.be.traced)
	}
	// The question is answered once.
	h.text(500, "private", "localhost", "en")
	if len(h.be.traced) != 1 {
		t.Fatal("a second plain message was taken as another answer")
	}
}

func TestQuestionExpires(t *testing.T) {
	h := newHarness(t, owner)
	now := testNow
	h.bot.now = func() time.Time { return now }
	h.press(500, cbRoute)
	now = now.Add(askFor + time.Second)
	h.text(500, "private", "localhost", "en")
	if len(h.be.traced) != 0 {
		t.Fatal("an expired question took an answer")
	}
}

func TestBadRouteTarget(t *testing.T) {
	h := newHarness(t, owner)
	h.text(500, "private", "/route $(reboot)", "en")
	if got := h.sent(); len(got) != 1 || !strings.Contains(got[0], "not a domain name or an IP address") {
		t.Fatalf("got %q", got)
	}
}

func TestDevices(t *testing.T) {
	h := newHarness(t, owner)
	h.be.devices = []Device{
		{Name: "Sam-phone", IP: "192.168.1.23", Group: "Kids"},
		{IP: "192.168.1.55"},
	}
	h.text(500, "private", "/devices", "ru")
	got := h.sent()[0]
	for _, want := range []string{"<b>Devices on the LAN</b> (2)", "• <b>Sam-phone</b> · <code>192.168.1.23</code> · group «Kids»", "• <i>no name</i> · <code>192.168.1.55</code>"} {
		if !strings.Contains(got, want) {
			t.Fatalf("devices lack %q:\n%s", want, got)
		}
	}
	h.be.devices = nil
	h.press(500, cbDevices)
	if e := h.edited(); len(e) != 1 || !strings.Contains(e[0], "knows no devices") {
		t.Fatalf("empty list %q", e)
	}
}

// "Why is the internet slow?": where the router measures it, the busiest devices come first with
// their speeds, the idle after without numbers, and the header says how many are busy.
func TestDevicesShowWhoIsUsingTheLine(t *testing.T) {
	h := newHarness(t, owner)
	h.be.devices = []Device{
		{Name: "Sam-phone", IP: "192.168.1.23", Down: 90_000, Up: 15_000},
		{Name: "Printer", IP: "192.168.1.60", Down: 100, Up: 50},
		{Name: "Living-room-TV", IP: "192.168.1.40", Down: 1_550_000, Up: 40_000, Group: "TV"},
	}
	h.be.measured = true
	h.text(500, "private", "/devices", "en")
	got := h.sent()[0]
	tv := strings.Index(got, "Living-room-TV")
	phone := strings.Index(got, "Sam-phone")
	printer := strings.Index(got, "Printer")
	if !(tv < phone && phone < printer) {
		t.Fatalf("not busiest first:\n%s", got)
	}
	for _, want := range []string{"<b>Devices on the LAN</b> (3) · 2 active now",
		"• <b>Living-room-TV</b> · <code>192.168.1.40</code> · ↓ 12.4 Mbit/s ↑ 320 kbit/s · group «TV»",
		"• <b>Printer</b> · <code>192.168.1.60</code>\n"} {
		if !strings.Contains(got+"\n", want) {
			t.Fatalf("lacks %q:\n%s", want, got)
		}
	}
	// Not measured (no connection table, or no byte counts): the plain list, no claim of idleness.
	h.be.measured = false
	h.press(500, cbDevices)
	if e := h.edited(); len(e) != 1 || strings.Contains(e[0], "active") || strings.Contains(e[0], "↓") ||
		strings.Index(e[0], "Sam-phone") > strings.Index(e[0], "Living-room-TV") {
		t.Fatalf("unmeasured list %q", e)
	}
}

func TestDiagnosticsReportFindingsFirst(t *testing.T) {
	h := newHarness(t, owner)
	h.be.checks = []Check{
		{ID: "time", Label: "Router clock is correct", Status: "pass"},
		{ID: "dns", Label: "Encrypted DNS (DoH)", Status: "warn", Summary: "1 of 3 resolvers answered", Fix: "check the DoH servers"},
		{ID: "unknown-new", Label: "A check the bot has no name for", Status: "fail", Summary: "broken"},
		{ID: "offload", Label: "Flow offload (fast path)", Status: "na"},
	}
	h.text(500, "private", "/diag", "en")
	if s := h.sent(); len(s) != 1 || !strings.Contains(s[0], "Running the checks") {
		t.Fatalf("progress %q", s)
	}
	res := h.edited()[0]
	for _, want := range []string{"🔴 <b>Diagnostics</b> · 14:32", "✅ 1 passed · ⚠️ 1 to look at · ❌ 1 failed",
		"❌ <b>A check the bot has no name for</b>\nbroken", "⚠️ <b>Encrypted DNS (DoH)</b>\n1 of 3 resolvers answered",
		"<i>Fix: check the DoH servers</i>", "✅ Router clock is correct", "1 check(s) did not apply here"} {
		if !strings.Contains(res, want) {
			t.Fatalf("diag lacks %q:\n%s", want, res)
		}
	}
	if strings.Index(res, "❌ <b>A check") > strings.Index(res, "⚠️ <b>Encrypted") {
		t.Fatalf("failures come before warnings:\n%s", res)
	}
	ru := view{lang: "ru", now: testNow}
	if ru.checkLabel(Check{ID: "time", Label: "Router clock is correct"}) != "Часы роутера верны" ||
		ru.checkLabel(Check{ID: "brand-new", Label: "Brand new"}) != "Brand new" {
		t.Fatal("check labels: known ids are translated, unknown ones keep the router's label")
	}
}

// Two presses at once must not run the battery twice on a small router.
func TestDiagnosticsRunOneAtATime(t *testing.T) {
	h := newHarness(t, owner)
	gate := make(chan struct{})
	h.be.diagGate = gate
	done := make(chan struct{})
	go func() { h.press(500, cbDiag); close(done) }()
	for i := 0; i < 500; i++ {
		h.be.mu.Lock()
		runs := h.be.diagRuns
		h.be.mu.Unlock()
		if runs == 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	h.press(500, cbDiag)
	a := h.api.callsTo("answerCallbackQuery")
	if last := a[len(a)-1]; last.Params["text"] != "The checks are already running." {
		t.Fatalf("second press: %v", last.Params)
	}
	close(gate)
	<-done
	if h.be.diagRuns != 1 {
		t.Fatalf("runs %d", h.be.diagRuns)
	}
}

func TestPingAndDNS(t *testing.T) {
	h := newHarness(t, owner)
	h.text(500, "private", "/ping 1.1.1.1", "en")
	h.text(500, "private", "/ping", "en")
	h.text(500, "private", "/dns youtube.com", "en")
	got := h.sent()
	if got[0] != "📶 <code>1.1.1.1</code> answers · 23 ms on average" {
		t.Fatalf("ping %q", got[0])
	}
	if !strings.Contains(got[1], "Send /ping and a host") {
		t.Fatalf("usage %q", got[1])
	}
	if got[2] != "🌐 <code>youtube.com</code> → <code>192.0.2.14</code>\nan alias of <code>edge.cdn.example.net</code>" {
		t.Fatalf("dns %q", got[2])
	}
}

func TestToolsMenuFromTheStatus(t *testing.T) {
	h := newHarness(t, owner)
	h.press(500, cbMore)
	if e := h.edited(); len(e) != 1 || !strings.Contains(e[0], "Tools") {
		t.Fatalf("menu %q", e)
	}
	kb := h.api.lastKeyboard(t, "editMessageText")
	var datas []string
	for _, row := range kb {
		for _, b := range row {
			datas = append(datas, b.CallbackData)
		}
	}
	if joined := strings.Join(datas, ","); !strings.Contains(joined, cbRoute) || !strings.Contains(joined, cbDevices) || !strings.Contains(joined, cbDiag) {
		t.Fatalf("menu buttons %v", datas)
	}
}

func TestAlertsOnlyChatHasNoTools(t *testing.T) {
	h := newHarness(t, alertsChat)
	h.text(-700, "group", "/route youtube.com", "en")
	h.text(-700, "group", "youtube.com", "en")
	if len(h.be.traced) != 0 {
		t.Fatal("an alerts-only chat ran a trace")
	}
}

func TestTraceWithoutResolution(t *testing.T) {
	v := view{lang: "en", now: testNow, ref: func(s string) string { return s }}
	text, _ := v.Trace(Trace{Target: "nonexistent.invalid", ResolveError: "no such host"}, sampleStatus())
	if !strings.Contains(text, "could not resolve") || strings.Contains(text, "default route") {
		t.Fatalf("got:\n%s", text)
	}
	text, _ = v.Trace(Trace{Target: "example.org", IPs: []string{"192.0.2.10"}}, sampleStatus())
	if !strings.Contains(text, "No live connections") || !strings.Contains(text, "follows the default route") {
		t.Fatalf("got:\n%s", text)
	}
}

// A device whose traffic the fast path hides is neither shown as idle nor counted as active: it says
// so, after the busy ones and before the idle.
func TestDevicesOnTheFastPath(t *testing.T) {
	v := view{lang: "en", now: testNow}
	text, _ := v.Devices(DeviceList{Measured: true, Devices: []Device{
		{Name: "idle", IP: "192.168.1.9"},
		{Name: "tv", IP: "192.168.1.40", FastPath: true},
		{Name: "phone", IP: "192.168.1.23", Down: 150_000, Up: 20_000, FastPath: true},
		{Name: "laptop", IP: "192.168.1.30", Down: 400_000, Up: 30_000},
	}})
	lines := strings.Split(text, "\n")
	var order []string
	for _, l := range lines {
		if strings.HasPrefix(l, "• ") {
			order = append(order, l)
		}
	}
	if len(order) != 4 || !strings.Contains(order[0], "laptop") || !strings.Contains(order[1], "phone") ||
		!strings.Contains(order[1], "↓ 1.2 Mbit/s ↑ 160 kbit/s · more on the fast path, not counted") ||
		!strings.Contains(order[2], "<b>tv</b> · <code>192.168.1.40</code> · on the fast path, not counted") ||
		!strings.Contains(order[3], "idle") || !strings.Contains(lines[0], "2 active now") {
		t.Fatalf("got:\n%s", text)
	}
}
