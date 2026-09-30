package tgbot

import (
	"strings"
	"testing"
	"time"
)

// rendered is an alert as one chat would see it.
func rendered(a Alert, lang, role string) (string, *Keyboard) { return a.Render(lang, role) }

func texts(as []Alert) []string {
	var out []string
	for _, a := range as {
		t, _ := a.Render("en", roleOwner)
		out = append(out, t)
	}
	return out
}

func evAt(sec int, kind, id, name string) Event {
	return Event{At: testNow.Add(time.Duration(sec) * time.Second), Kind: kind, ID: id, Name: name}
}

// logOf returns events newest first, as the monitor does.
func logOf(evs ...Event) EventLog {
	out := make([]Event, len(evs))
	for i, e := range evs {
		out[len(evs)-1-i] = e
	}
	return EventLog{Known: true, Events: out}
}

func TestWatcherBaselineIsNotNews(t *testing.T) {
	w := newWatcher()
	old := logOf(evAt(-600, "down", "de-backup", "de-backup"))
	p := Pulse{LocalFault: true, Core: CorePulse{Supervised: true, Alive: true, Restarts: 4}, FailSafe: FailSafePulse{Pending: true, Phase: "armed"}}
	if got := w.step(testNow, p, old, sampleStatus); len(got) != 0 {
		t.Fatalf("the first step announced the past: %q", texts(got))
	}
	if got := w.step(testNow.Add(5*time.Second), p, old, sampleStatus); len(got) != 0 {
		t.Fatalf("an unchanged second step announced %q", texts(got))
	}
}

func TestWatcherExitDownThenUp(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	down := evAt(10, "down", "de-backup", "de-backup")
	got := w.step(testNow.Add(10*time.Second), Pulse{}, logOf(down), sampleStatus)
	if len(got) != 1 || got[0].Kind != KindExits || got[0].Sev != SevWarning || got[0].Incident != "exit:de-backup" || got[0].Resolves {
		t.Fatalf("down: %+v", got)
	}
	text, kb := rendered(got[0], "en", roleOwner)
	for _, want := range []string{"🔴 <b>de-backup</b> is down", "Cause: handshake did not complete", "Fix: check the server key",
		"Group fast-eu now goes through <b>nl-main</b>"} {
		if !strings.Contains(text, want) {
			t.Fatalf("down text lacks %q:\n%s", want, text)
		}
	}
	if len(kb.Rows[0]) != 2 || kb.Rows[0][1].CallbackData != cbMute+"60" {
		t.Fatalf("a warning offers a mute: %+v", kb)
	}
	// The same log again is not news.
	if again := w.step(testNow.Add(15*time.Second), Pulse{}, logOf(down), sampleStatus); len(again) != 0 {
		t.Fatalf("repeated: %q", texts(again))
	}
	up := evAt(12*60+10, "up", "de-backup", "de-backup")
	up.LatencyMs = 51
	got = w.step(testNow.Add(13*time.Minute), Pulse{}, logOf(down, up), sampleStatus)
	if len(got) != 1 || !got[0].Resolves || got[0].Sev != SevInfo || got[0].Incident != "exit:de-backup" {
		t.Fatalf("up: %+v", got)
	}
	if text, _ := rendered(got[0], "ru", roleOwner); text != "🟢 <b>de-backup</b> снова в строю · не работал 12 мин · 51 мс" {
		t.Fatalf("up text %q", text)
	}
}

func TestWatcherTwoEventsInOneMillisecond(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	a, b := evAt(10, "down", "a", "a"), evAt(10, "down", "b", "b")
	got := w.step(testNow.Add(10*time.Second), Pulse{}, logOf(a, b), sampleStatus)
	if len(got) != 2 {
		t.Fatalf("got %q", texts(got))
	}
	c := evAt(10, "switch", "g", "g")
	got = w.step(testNow.Add(15*time.Second), Pulse{}, logOf(a, b, c), sampleStatus)
	if len(got) != 1 || got[0].Kind != KindSwitches {
		t.Fatalf("a late event at the same millisecond: %q", texts(got))
	}
}

func TestWatcherLastMemberDownSaysSo(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	st := func() Status {
		s := sampleStatus()
		s.Groups[0].Elected = "nl-main"
		return s
	}
	got := w.step(testNow.Add(10*time.Second), Pulse{}, logOf(evAt(10, "down", "nl-main", "nl-main")), st)
	if text, _ := rendered(got[0], "en", roleOwner); !strings.Contains(text, "Group fast-eu has no working member left") {
		t.Fatalf("got:\n%s", text)
	}
}

// Found on the demo: with the election unknown, the alert claimed the group had nothing left while
// other members were up. An unknown election says nothing.
func TestWatcherUnknownElectionClaimsNothing(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	st := func() Status {
		s := sampleStatus()
		s.Groups[0].Elected = ""
		return s
	}
	got := w.step(testNow.Add(10*time.Second), Pulse{}, logOf(evAt(10, "down", "de-backup", "de-backup")), st)
	if text, _ := rendered(got[0], "en", roleOwner); strings.Contains(text, "Group") {
		t.Fatalf("claimed something about a group whose election is unknown:\n%s", text)
	}
}

func TestWatcherUplinkSwallowsTheExits(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{Known: true}, sampleStatus)
	d1, d2 := evAt(10, "down", "a", "a"), evAt(10, "down", "b", "b")
	got := w.step(testNow.Add(10*time.Second), Pulse{LocalFault: true}, logOf(d1, d2), sampleStatus)
	if len(got) != 1 || got[0].Kind != KindUplink || got[0].Sev != SevCritical || got[0].Incident != "uplink" {
		t.Fatalf("uplink lost: %q", texts(got))
	}
	u1, u2 := evAt(7*60, "up", "a", "a"), evAt(7*60+5, "up", "b", "b")
	got = w.step(testNow.Add(7*time.Minute+10*time.Second), Pulse{}, logOf(d1, d2, u1), sampleStatus)
	if len(got) != 1 || !got[0].Resolves || got[0].Kind != KindUplink {
		t.Fatalf("uplink back: %q", texts(got))
	}
	if text, _ := rendered(got[0], "en", roleOwner); text != "🟢 <b>Internet is back</b> · was out 7 min" {
		t.Fatalf("text %q", text)
	}
	// The straggler recovery a few seconds later belongs to the same incident.
	if got = w.step(testNow.Add(7*time.Minute+15*time.Second), Pulse{}, logOf(d1, d2, u1, u2), sampleStatus); len(got) != 0 {
		t.Fatalf("straggler announced: %q", texts(got))
	}
	// Much later, an exit going down is news again.
	d3 := evAt(20*60, "down", "a", "a")
	if got = w.step(testNow.Add(20*time.Minute), Pulse{}, logOf(d1, d2, u1, u2, d3), sampleStatus); len(got) != 1 || got[0].Kind != KindExits {
		t.Fatalf("later exit down: %q", texts(got))
	}
}

func TestWatcherCore(t *testing.T) {
	w := newWatcher()
	ok := CorePulse{Supervised: true, Alive: true, Restarts: 2}
	w.step(testNow, Pulse{Core: ok}, EventLog{}, sampleStatus)
	crashed := CorePulse{Supervised: true, Alive: true, Restarts: 3}
	got := w.step(testNow.Add(5*time.Second), Pulse{Core: crashed}, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Kind != KindCore || got[0].Sev != SevWarning {
		t.Fatalf("restart: %q", texts(got))
	}
	if text, _ := rendered(got[0], "en", roleOwner); text != "⚠️ sing-box crashed and was restarted (3 since WayHop started)" {
		t.Fatalf("text %q", text)
	}
	down := CorePulse{Supervised: true, Alive: false, Restarts: 3, Failed: 1, LastError: "exec format error"}
	if got = w.step(testNow.Add(10*time.Second), Pulse{Core: down}, EventLog{}, sampleStatus); len(got) != 0 {
		t.Fatalf("a core down for seconds is not an incident yet: %q", texts(got))
	}
	got = w.step(testNow.Add(75*time.Second), Pulse{Core: down}, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Sev != SevCritical || got[0].Incident != "core" {
		t.Fatalf("down: %q", texts(got))
	}
	if text, _ := rendered(got[0], "en", roleOwner); !strings.Contains(text, "for 1 min already") || !strings.Contains(text, "<code>exec format error</code>") {
		t.Fatalf("text %q", text)
	}
	if got = w.step(testNow.Add(80*time.Second), Pulse{Core: down}, EventLog{}, sampleStatus); len(got) != 0 {
		t.Fatalf("repeated: %q", texts(got))
	}
	got = w.step(testNow.Add(3*time.Minute), Pulse{Core: CorePulse{Supervised: true, Alive: true, Restarts: 3}}, EventLog{}, sampleStatus)
	if len(got) != 1 || !got[0].Resolves || got[0].Incident != "core" {
		t.Fatalf("up: %q", texts(got))
	}
}

func TestWatcherApplyWindow(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{}, sampleStatus)

	armed := Pulse{FailSafe: FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 300}}
	got := w.step(testNow.Add(5*time.Second), armed, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Sev != SevAction || got[0].Incident != "apply" {
		t.Fatalf("armed: %q", texts(got))
	}
	text, kb := rendered(got[0], "en", roleOwner)
	if !strings.Contains(text, "rolls back by itself in 5:00") || kb.Rows[0][0].CallbackData != cbKeep || kb.Rows[0][1].CallbackData != cbRollback {
		t.Fatalf("owner view %q %+v", text, kb)
	}
	if _, kb := rendered(got[0], "en", roleViewer); len(kb.Rows) != 1 || kb.Rows[0][0].CallbackData != cbStatus {
		t.Fatalf("a viewer must not get Keep/Roll back: %+v", kb)
	}

	armed.FailSafe.SecondsLeft = 270
	if got = w.step(testNow.Add(20*time.Second), armed, EventLog{}, sampleStatus); len(got) != 0 {
		t.Fatalf("countdown too early: %q", texts(got))
	}
	armed.FailSafe.SecondsLeft, armed.FailSafe.Phase = 262, "degraded"
	got = w.step(testNow.Add(38*time.Second), armed, EventLog{}, sampleStatus)
	if len(got) != 2 || got[0].Sev != SevWarning || !got[1].Edit {
		t.Fatalf("degraded + countdown: %+v", got)
	}
	if text, _ := rendered(got[1], "en", roleOwner); !strings.Contains(text, "4:22") || !strings.Contains(text, "check is failing") {
		t.Fatalf("countdown text %q", text)
	}

	rolled := Pulse{FailSafe: FailSafePulse{Phase: "rolled_back", Checked: true}}
	got = w.step(testNow.Add(2*time.Minute), rolled, EventLog{}, sampleStatus)
	if len(got) != 1 || !got[0].Resolves || got[0].Edit || got[0].Sev != SevCritical || got[0].Closed == nil {
		t.Fatalf("rolled back: %+v", got)
	}
}

// Found on the demo: a rollback somebody pressed was announced as "connectivity was lost". Only
// the fail-safe's own rollback, after a failed check, is that news.
func TestWatcherManualRollbackIsNotAnOutage(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{}, sampleStatus)
	w.step(testNow.Add(5*time.Second), Pulse{FailSafe: FailSafePulse{Pending: true, Live: true, Phase: "armed", Checked: true, CheckOK: true}}, EventLog{}, sampleStatus)
	got := w.step(testNow.Add(20*time.Second), Pulse{FailSafe: FailSafePulse{Phase: "rolled_back", Checked: true, CheckOK: true}}, EventLog{}, sampleStatus)
	if len(got) != 1 || got[0].Sev != SevInfo || !got[0].Edit || !got[0].Resolves {
		t.Fatalf("manual rollback: %+v", got)
	}
	if text, _ := rendered(got[0], "en", roleOwner); strings.Contains(text, "Connectivity was lost") {
		t.Fatalf("manual rollback read as an outage: %q", text)
	}
}

func TestWatcherApplyKeptAndUnsaved(t *testing.T) {
	w := newWatcher()
	w.step(testNow, Pulse{}, EventLog{}, sampleStatus)
	armed := Pulse{FailSafe: FailSafePulse{Pending: true, Live: true, Phase: "armed", SecondsLeft: 300}}
	w.step(testNow.Add(5*time.Second), armed, EventLog{}, sampleStatus)

	unsaved := Pulse{FailSafe: FailSafePulse{Live: true, Phase: "live_unsaved"}}
	got := w.step(testNow.Add(6*time.Minute), unsaved, EventLog{}, sampleStatus)
	if len(got) != 2 || !got[0].Resolves || !got[0].Edit || got[1].Sev != SevAction || got[1].Incident != "apply" {
		t.Fatalf("window passed: %+v", got)
	}
	if text, kb := rendered(got[0], "en", roleOwner); !strings.Contains(text, "window passed") || kb != nil {
		t.Fatalf("closed armed message %q %+v", text, kb)
	}

	kept := Pulse{FailSafe: FailSafePulse{Phase: "committed"}}
	got = w.step(testNow.Add(7*time.Minute), kept, EventLog{}, sampleStatus)
	if len(got) != 1 || !got[0].Resolves || !got[0].Edit {
		t.Fatalf("kept later: %+v", got)
	}
	if text, _ := rendered(got[0], "ru", roleOwner); !strings.Contains(text, "подтверждено") {
		t.Fatalf("text %q", text)
	}
}

func TestWatcherMemory(t *testing.T) {
	w := newWatcher()
	hi := Pulse{Mem: MemPulse{Known: true, UsedPct: 95}}
	w.step(testNow, Pulse{Mem: MemPulse{Known: true, UsedPct: 50}}, EventLog{}, sampleStatus)
	var got []Alert
	for i := 1; i <= 4; i++ {
		got = append(got, w.step(testNow.Add(time.Duration(i)*5*time.Second), hi, EventLog{}, sampleStatus)...)
	}
	if len(got) != 1 || got[0].Kind != KindSystem || got[0].Incident != "mem" {
		t.Fatalf("high: %q", texts(got))
	}
	if got = w.step(testNow.Add(time.Minute), Pulse{Mem: MemPulse{Known: true, UsedPct: 88}}, EventLog{}, sampleStatus); len(got) != 0 {
		t.Fatalf("between the thresholds nothing changes: %q", texts(got))
	}
	got = w.step(testNow.Add(2*time.Minute), Pulse{Mem: MemPulse{Known: true, UsedPct: 60}}, EventLog{}, sampleStatus)
	if len(got) != 1 || !got[0].Resolves {
		t.Fatalf("back to normal: %q", texts(got))
	}
}

func TestBootAlert(t *testing.T) {
	start := testNow.Add(-time.Minute)
	cases := []struct {
		name string
		bi   BootInfo
		want string
		sev  Severity
	}{
		{"power cut", BootInfo{DaemonStart: start, RouterUp: 2 * time.Minute, LastSeen: testNow.Add(-2*time.Hour - 30*time.Minute), Version: "0.5.6"},
			"started at 14:29; last heard from at 12:02 (offline about 2h 27 min)", SevWarning},
		{"short reboot", BootInfo{DaemonStart: start, RouterUp: 2 * time.Minute, LastSeen: testNow.Add(-8 * time.Minute)},
			"(offline about 5 min)", SevInfo},
		{"reboot, no record", BootInfo{DaemonStart: start, RouterUp: time.Minute}, "The router restarted</b> at 14:30", SevInfo},
		{"daemon only", BootInfo{DaemonStart: start, RouterUp: 40 * 24 * time.Hour, Version: "0.5.7"}, "WayHop restarted (0.5.7)", SevInfo},
		{"stale record", BootInfo{DaemonStart: start, RouterUp: time.Minute, LastSeen: testNow.Add(-30 * 24 * time.Hour)}, "The router restarted", SevInfo},
	}
	for _, c := range cases {
		a := bootAlert(c.bi, testNow)
		text, _ := a.Render("en", roleOwner)
		if !strings.Contains(text, c.want) || a.Sev != c.sev || a.Kind != KindBoot {
			t.Errorf("%s: sev %d\n%s", c.name, a.Sev, text)
		}
	}
}
