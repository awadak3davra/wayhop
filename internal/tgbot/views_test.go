package tgbot

import (
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

var (
	verbRE   = regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z%]`)
	tagRE    = regexp.MustCompile(`</?[a-z]+`)
	markupRE = regexp.MustCompile(`</?[a-z]+( [^>]*)?>|&(amp|lt|gt|quot|#[0-9]+);`)
)

func verbs(s string) string { return strings.Join(verbRE.FindAllString(s, -1), ",") }

// tags is the set of HTML tags in s; a translation may move them, not drop or add one.
func tags(s string) string {
	t := tagRE.FindAllString(s, -1)
	sort.Strings(t)
	return strings.Join(t, " ")
}

// Every language of a key must take the same arguments, or one of them renders %!d(MISSING), and
// carry the same tags and no bare &, < or >, or Telegram refuses the whole message as unparseable.
func TestTranslationsAgree(t *testing.T) {
	for key, v := range msgs {
		if v[0] == "" {
			t.Errorf("%s: no English text", key)
		}
		for _, tr := range []struct{ lang, s string }{{"en", v[0]}, {"ru", v[1]}, {"uk", msgsUK[key]}} {
			if strings.ContainsAny(markupRE.ReplaceAllString(tr.s, ""), "<>&") {
				t.Errorf("%s: a bare &, < or > in %s: %q", key, tr.lang, tr.s)
			}
			if tr.lang == "en" {
				continue
			}
			if tr.s == "" {
				t.Errorf("%s: no %s text", key, tr.lang)
				continue
			}
			if en, s := verbs(v[0]), verbs(tr.s); en != s {
				t.Errorf("%s: en takes %q, %s takes %q", key, en, tr.lang, s)
			}
			if en, s := tags(v[0]), tags(tr.s); en != s {
				t.Errorf("%s: en has tags %q, %s has %q", key, en, tr.lang, s)
			}
		}
		// Russian and Ukrainian share the one|few|many rule, so a plural key has three forms in both.
		if ru, uk := strings.Count(v[1], "|"), strings.Count(msgsUK[key], "|"); ru != uk {
			t.Errorf("%s: %d plural forms in ru, %d in uk", key, ru+1, uk+1)
		}
	}
	for key := range msgsUK {
		if _, ok := msgs[key]; !ok {
			t.Errorf("%s: a Ukrainian text for a key the bot does not have", key)
		}
	}
}

// Ukrainian reads its own months and weekdays, plural forms and a decimal comma.
func TestUkrainianForms(t *testing.T) {
	v := view{lang: "uk", now: testNow}
	if got := v.date(testNow); got != "ср, 23 вересня" {
		t.Errorf("date %q", got)
	}
	if got := v.date(testNow.AddDate(0, 3, -1)); got != "вт, 22 грудня" {
		t.Errorf("date %q", got)
	}
	for n, want := range map[int]string{1: "1 збій", 3: "3 збої", 5: "5 збоїв", 11: "11 збоїв", 21: "21 збій", 24: "24 збої"} {
		if got := Count("uk", n, "n.outage"); got != want {
			t.Errorf("Count(uk, %d) = %q, want %q", n, got, want)
		}
	}
	if got := Speed("uk", 1_550_000); got != "12,4 Мбіт/с" {
		t.Errorf("speed %q", got)
	}
}

func TestLangFor(t *testing.T) {
	for code, want := range map[string]string{"ru": "ru", "ru-RU": "ru", "be": "ru", "kk": "ru", "en": "en", "de": "en", "": "en", "uk": "uk", "uk-UA": "uk"} {
		if got := LangFor(code); got != want {
			t.Errorf("LangFor(%q) = %q, want %q", code, got, want)
		}
	}
}

func TestSpeedAndDuration(t *testing.T) {
	cases := []struct {
		lang string
		bps  int64
		want string
	}{
		{"en", 0, "0 bit/s"}, {"en", 100, "800 bit/s"}, {"en", 1_550_000, "12.4 Mbit/s"},
		{"ru", 1_550_000, "12,4 Мбит/с"}, {"en", 125_000_000, "1 Gbit/s"}, {"en", 2000, "16 kbit/s"},
	}
	for _, c := range cases {
		if got := Speed(c.lang, c.bps); got != c.want {
			t.Errorf("Speed(%s,%d) = %q, want %q", c.lang, c.bps, got, c.want)
		}
	}
	durs := []struct {
		lang string
		d    time.Duration
		want string
	}{
		{"en", 0, "just now"}, {"en", 45 * time.Second, "45 s"}, {"en", 12 * time.Minute, "12 min"},
		{"en", 3*time.Hour + 12*time.Minute, "3h 12 min"}, {"en", 2 * time.Hour, "2h"},
		{"en", 6*24*time.Hour + 4*time.Hour + 5*time.Minute, "6d 4h"}, {"ru", 6*24*time.Hour + 4*time.Hour, "6 д 4 ч"},
	}
	for _, c := range durs {
		if got := Duration(c.lang, c.d); got != c.want {
			t.Errorf("Duration(%s,%v) = %q, want %q", c.lang, c.d, got, c.want)
		}
	}
	if got := Countdown(4*time.Minute + 38*time.Second); got != "4:38" {
		t.Error(got)
	}
}

func TestFlag(t *testing.T) {
	if Flag("nl") != "🇳🇱" || Flag("NL") != "🇳🇱" || Flag("") != "" || Flag("N1") != "" || Flag("NLD") != "" {
		t.Fatal("flag")
	}
}

func TestVerdicts(t *testing.T) {
	base := sampleStatus()
	cases := []struct {
		name string
		mut  func(*Status)
		want Health
	}{
		{"degraded", func(*Status) {}, HealthDegraded},
		{"good", func(s *Status) { s.Exits = s.Exits[:1] }, HealthGood},
		{"all down", func(s *Status) { s.Exits = s.Exits[1:] }, HealthDown},
		{"local fault wins over counts", func(s *Status) { s.LocalFault = true }, HealthLocalFault},
		{"core crashed", func(s *Status) { s.Core.Running = false }, HealthDown},
		{"native only needs no core", func(s *Status) { s.Core.Running = false; s.Core.NativeOnly = true; s.Exits = s.Exits[:1] }, HealthGood},
		{"testing", func(s *Status) { s.Exits = s.Exits[:1]; s.FailSafe = FailSafe{Armed: true, Remaining: time.Minute} }, HealthTesting},
	}
	for _, c := range cases {
		s := base
		s.Exits = append([]Exit(nil), base.Exits...)
		c.mut(&s)
		if got := s.Verdict(); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}

// Names come from share links and subscriptions: whatever a provider put there must not become
// Telegram markup.
func TestViewsEscapeNames(t *testing.T) {
	s := sampleStatus()
	s.Exits[0].Name = `<b>evil</b> & "co"`
	s.Groups[0].Name = "<i>g</i>"
	v := view{lang: "en", now: testNow, ref: func(id string) string { return id }}
	for _, text := range []string{first(v.Status(s)), first(v.Exits(s, 0)), first(v.Exit(s.Exits[0], ""))} {
		if strings.Contains(text, "<b>evil</b>") || strings.Contains(text, "<i>g</i>") {
			t.Fatalf("unescaped name:\n%s", text)
		}
	}
}

func first(s string, _ *Keyboard) string { return s }

func TestStatusStatesPendingFailsafeAndUpdate(t *testing.T) {
	s := sampleStatus()
	s.Changes = Changes{Known: true, Pending: true, Count: 3}
	s.FailSafe = FailSafe{Armed: true, Remaining: 278 * time.Second}
	s.Update = SelfUpdate{Available: true, Latest: "0.5.7"}
	text, _ := view{lang: "en", now: testNow}.Status(s)
	for _, want := range []string{"<b>3 not applied</b>", "rolls back in 4:38", "WayHop 0.5.7 is available"} {
		if !strings.Contains(text, want) {
			t.Fatalf("lacks %q:\n%s", want, text)
		}
	}
	// Counts read in the number's own form: "2 не применено" and "1 restarts" were both wrong.
	s.Core.Restarts = 1
	if text, _ := (view{lang: "ru", now: testNow}).Status(s); !strings.Contains(text, "<b>не применено: 3</b>") ||
		!strings.Contains(text, "перезапусков: 1") || !strings.Contains(text, "нагрузка 0,32") {
		t.Fatalf("ru counts:\n%s", text)
	}
	if text, _ := (view{lang: "uk", now: testNow}).Status(s); !strings.Contains(text, "<b>не застосовано: 3</b>") ||
		!strings.Contains(text, "перезапусків: 1") || !strings.Contains(text, "навантаження 0,32") {
		t.Fatalf("uk counts:\n%s", text)
	}
	if text, _ := (view{lang: "en", now: testNow}).Status(s); !strings.Contains(text, "restarts: 1") ||
		!strings.Contains(text, "load 0.32") {
		t.Fatalf("en counts:\n%s", text)
	}
	s.Core.Restarts = 0
	s.Changes = Changes{}
	if text, _ := (view{lang: "en", now: testNow}).Status(s); strings.Contains(text, "Changes:") {
		t.Fatal("unreadable change state must not be shown as an answer")
	}
	s.Changes = Changes{Known: true, Pending: true}
	if text, _ := (view{lang: "en", now: testNow}).Status(s); !strings.Contains(text, "saved, not applied") {
		t.Fatalf("uncounted pending changes:\n%s", text)
	}
	s.Changes = Changes{Known: true}
	if text, _ := (view{lang: "en", now: testNow}).Status(s); !strings.Contains(text, "Changes: all applied") {
		t.Fatalf("nothing pending:\n%s", text)
	}
}

// A routing list whose feed keeps failing is named: not after one failure, which is often a blip of
// the feed's host, but after two in a row, with since when and, for an owner, why. Several are named
// up to three. The daily summary says the same.
func TestStatusNamesListsWhoseFeedsKeepFailing(t *testing.T) {
	s := sampleStatus()
	s.Feeds = []FeedIssue{{List: "Streaming", Fails: 1, Since: testNow.Add(-time.Hour), Err: "https://feeds.example/…: status 502 Bad Gateway"}}
	if text, _ := (view{lang: "en", now: testNow, role: roleOwner}).Status(s); strings.Contains(text, "not updating") {
		t.Fatalf("named after one failure:\n%s", text)
	}
	s.Feeds[0].Fails = 2
	owner, _ := view{lang: "en", now: testNow, role: roleOwner}.Status(s)
	if !strings.Contains(owner, "⚠️ List «Streaming» is not updating: its feed has failed 2 times in a row, since 13:32.") ||
		!strings.Contains(owner, "<i>https://feeds.example/…: status 502 Bad Gateway</i>") {
		t.Fatalf("owner:\n%s", owner)
	}
	if viewer, _ := (view{lang: "en", now: testNow, role: roleViewer}).Status(s); !strings.Contains(viewer, "«Streaming» is not updating") ||
		strings.Contains(viewer, "502") {
		t.Fatalf("viewer:\n%s", viewer)
	}
	// A list that has nothing from its feed does not keep anything: it has not loaded.
	s.Feeds[0].Empty = true
	if text, _ := (view{lang: "ru", now: testNow}).Status(s); !strings.Contains(text,
		"⚠️ Список «Streaming» не загрузился: загрузка не удалась 2 раза подряд, с 13:32, так что из источника в нём пока ничего нет.") {
		t.Fatalf("never loaded:\n%s", text)
	}

	s.Feeds = nil
	for _, name := range []string{"A", "B", "C", "D", "E"} {
		s.Feeds = append(s.Feeds, FeedIssue{List: name, Fails: 3, Since: testNow.Add(-26 * time.Hour)})
	}
	s.Feeds = append(s.Feeds, FeedIssue{List: "Blip", Fails: 1, Since: testNow})
	if text, _ := (view{lang: "ru", now: testNow}).Status(s); !strings.Contains(text, "⚠️ Не обновляются 5 списков: «A», «B», «C» и ещё 2.") {
		t.Fatalf("ru, several:\n%s", text)
	}
	if text, _ := (view{lang: "uk", now: testNow}).Status(s); !strings.Contains(text, "⚠️ Не оновлюються 5 списків: «A», «B», «C» і ще 2.") {
		t.Fatalf("uk, several:\n%s", text)
	}
	if text, _ := (view{lang: "en", now: testNow}).Digest(digest{At: testNow, Status: s}); !strings.Contains(text, "⚠️ 5 lists are not updating: «A», «B», «C» and 2 more.") {
		t.Fatalf("digest:\n%s", text)
	}
}

func TestStatusWithoutExitIPOrExits(t *testing.T) {
	s := Status{At: testNow, Core: Core{Available: false}}
	text, _ := view{lang: "ru", now: testNow}.Status(s)
	for _, want := range []string{"Выход: пока не определён", "Выходы: не настроены", "Ядро: sing-box не установлен"} {
		if !strings.Contains(text, want) {
			t.Fatalf("lacks %q:\n%s", want, text)
		}
	}
}

// Found on the demo: the monitor probes groups like exits, so groups were listed twice and counted
// as exits ("8 up" with five real exits).
func TestGroupsAreNotExits(t *testing.T) {
	s := sampleStatus()
	s.Groups[0].Elected = ""
	s.Exits = append(s.Exits, Exit{ID: "fast", Name: "fast-eu", State: StateAlive, LatencyMs: 117, Group: true})
	if up, down := s.ExitCounts(); up != 1 || down != 1 {
		t.Fatalf("counts %d/%d", up, down)
	}
	v := view{lang: "en", now: testNow, ref: func(id string) string { return id }}
	st, _ := v.Status(s)
	if !strings.Contains(st, "  🟢 fast-eu · 117 ms") || !strings.Contains(st, "Exits: 1 up · 1 down") {
		t.Fatalf("status:\n%s", st)
	}
	ex, kb := v.Exits(s, 0)
	if strings.Count(ex, "fast-eu") != 1 || !strings.Contains(ex, "🟢 fast-eu: elected member unknown") {
		t.Fatalf("exits:\n%s", ex)
	}
	for _, row := range kb.Rows {
		for _, b := range row {
			if b.CallbackData == cbExit+"fast" {
				t.Fatal("a group got an exit button")
			}
		}
	}
}

// The two causes the monitor words itself read in the chat's language, in the list, on the card
// and in the alert; a knowledge-base entry keeps its own words, as in the panel; English keeps the
// monitor's text, which is the source.
func TestCausesInTheChatsLanguage(t *testing.T) {
	down := Exit{ID: "hy", Name: "Hysteria2 JP", State: StateDown, CauseID: "no-response",
		Cause: "No response (timed out or blocked)", Fix: "Run Diagnostics (ping/traceroute) to the server."}
	ru := view{lang: "ru", now: testNow, ref: func(id string) string { return id }}
	if card, _ := ru.Exit(down, ""); !strings.Contains(card, "Причина: Нет ответа (тайм-аут или блокировка)") ||
		!strings.Contains(card, "Запустите Диагностику") {
		t.Fatalf("ru card:\n%s", card)
	}
	if list, _ := ru.Exits(Status{Exits: []Exit{down}}, 0); !strings.Contains(list, "Нет ответа (тайм-аут") {
		t.Fatalf("ru list:\n%s", list)
	}
	alert, _ := exitDown(Event{ID: "hy", Name: "Hysteria2 JP", Kind: "down"}, Status{Exits: []Exit{down}}).Render("uk", roleViewer)
	if !strings.Contains(alert, "Немає відповіді (тайм-аут або блокування)") {
		t.Fatalf("uk alert:\n%s", alert)
	}
	kbEntry := Exit{State: StateDown, CauseID: "sb-tun-file-exists", Cause: "TUN interface already exists", Fix: "Stop any other sing-box."}
	if c, f := causeIn("ru", kbEntry); c != kbEntry.Cause || f != kbEntry.Fix {
		t.Fatalf("a kb entry was reworded: %q %q", c, f)
	}
	if c, _ := causeIn("en", down); c != down.Cause {
		t.Fatalf("en: %q", c)
	}
}

// Why a rule or list names a site reads in the chat's language: the keywords and fixed sentences are
// translated, what they name stays as written, and a form not known here stays English.
func TestWhyInTheChatsLanguage(t *testing.T) {
	for in, want := range map[string]string{
		"domain youtube.com":        "домен youtube.com",
		"domain_suffix youtube.com": "youtube.com и поддомены",
		"ip ∈ 142.250.0.0/15":       "ip ∈ 142.250.0.0/15",
		"remote rule-set — its contents are a sing-box artifact, not read here": "удалённый набор правил, здесь не читается",
		"feed has never been fetched — nothing to match against yet":            "список ещё ни разу не загружался",
		"geosite: youtube, google — needs the on-router dataset":                "geosite: youtube, google, нужна база на роутере",
		"something new": "something new",
	} {
		if got := whyIn("ru", in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if got := whyIn("en", "domain_suffix youtube.com"); got != "domain_suffix youtube.com" {
		t.Errorf("en: %q", got)
	}
}

// An owner's own commands stand in the list with the others, not after the paragraph below it.
func TestHelpByRole(t *testing.T) {
	v := view{lang: "en", now: testNow}
	owner, _ := v.Help(roleOwner)
	ping, speed, maint, alerts, more := strings.Index(owner, "/ping"), strings.Index(owner, "/speed"), strings.Index(owner, "/maint"),
		strings.Index(owner, "/alerts"), strings.Index(owner, "Alerts arrive")
	if !(ping < speed && speed < maint && maint < alerts && alerts < more) {
		t.Fatalf("owner help order:\n%s", owner)
	}
	viewer, _ := view{lang: "uk", now: testNow}.Help(roleViewer)
	if strings.Contains(viewer, "/speed") || strings.Contains(viewer, "/maint") || !strings.HasSuffix(viewer, "Цей чат <b>лише для перегляду</b>.") {
		t.Fatalf("viewer help:\n%s", viewer)
	}
}
