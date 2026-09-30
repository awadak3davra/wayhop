package tgbot

import (
	"fmt"
	"html"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Callback data. Telegram caps it at 64 bytes; object ids go through the ref table, which keeps
// long ids out of the button payload.
const (
	cbStatus    = "st"   // status, refreshed in place
	cbExits     = "ex"   // exit list
	cbExitsPage = "ep:"  // + page: a later page of the exit list
	cbExit      = "ex:"  // + ref: one exit's card
	cbTest      = "et:"  // + ref: test an exit now
	cbEvents    = "ev:"  // + page
	cbHelp      = "hp"   // help
	cbLang      = "lg:"  // + language
	cbNoop      = "noop" // a label-only button
	pageSize    = 10     // events per page
	exitsPage   = 20     // exits per page of the list, each with its button
	maxNameR    = 28     // runes of an exit name on a button
)

// view renders messages for one chat: its language, its clock, and the bot's ref table.
type view struct {
	lang  string
	now   time.Time
	ref   func(id string) string
	role  string    // the chat's role: owners get the buttons that change things
	muted time.Time // the chat's alerts are muted until then (zero: not muted)
}

// esc makes untrusted text safe for a message: HTML-escaped, and on one line. A name from a share
// link can hold a newline ("NL%0AAmsterdam" imports as two lines), and the views build lines that
// open and close their own tags; a newline inside a name split one of them, and the summary after
// quiet hours, which takes each alert's first line, sent "<b>NL" and was refused as broken HTML.
func esc(s string) string {
	return html.EscapeString(strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		}
		return r
	}, s))
}

func (v view) t(key string, args ...any) string { return T(v.lang, key, args...) }

func btn(text, data string) InlineButton { return InlineButton{Text: text, CallbackData: data} }

func stateIcon(state string) string {
	switch state {
	case StateAlive:
		return "🟢"
	case StateDown:
		return "🔴"
	}
	return "⚪"
}

func (v view) stateWord(state string) string {
	switch state {
	case StateAlive:
		return v.t("state.alive")
	case StateDown:
		return v.t("state.down")
	}
	return v.t("state.unk")
}

func headline(h Health) (icon, key string) {
	switch h {
	case HealthTesting:
		return "⏳", "h.testing"
	case HealthDegraded:
		return "🟡", "h.degraded"
	case HealthLocalFault:
		return "🟠", "h.localfault"
	case HealthDown:
		return "🔴", "h.down"
	}
	return "🟢", "h.good"
}

// clock is a wall-clock time in the router's zone: "14:32" today, "2 Jan 14:32" otherwise.
func (v view) clock(t time.Time) string {
	t = t.In(v.now.Location())
	y1, m1, d1 := t.Date()
	y2, m2, d2 := v.now.Date()
	if y1 == y2 && m1 == m2 && d1 == d2 {
		return t.Format("15:04")
	}
	if v.lang == "ru" || v.lang == "uk" {
		return t.Format("02.01 15:04")
	}
	return t.Format("2 Jan 15:04")
}

var (
	ruMonths   = [...]string{"января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября", "октября", "ноября", "декабря"}
	ruWeekdays = [...]string{"вс", "пн", "вт", "ср", "чт", "пт", "сб"}
	ukMonths   = [...]string{"січня", "лютого", "березня", "квітня", "травня", "червня", "липня", "серпня", "вересня", "жовтня", "листопада", "грудня"}
	ukWeekdays = [...]string{"нд", "пн", "вт", "ср", "чт", "пт", "сб"}
)

// date is a day as people write it, in the router's zone: "Thu, 24 Sep", "чт, 24 сентября",
// "чт, 24 вересня".
func (v view) date(t time.Time) string {
	t = t.In(v.now.Location())
	switch v.lang {
	case "ru":
		return ruWeekdays[t.Weekday()] + ", " + strconv.Itoa(t.Day()) + " " + ruMonths[t.Month()-1]
	case "uk":
		return ukWeekdays[t.Weekday()] + ", " + strconv.Itoa(t.Day()) + " " + ukMonths[t.Month()-1]
	}
	return t.Format("Mon, 2 Jan")
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// exitLabel is an exit's name, falling back to its id.
func exitLabel(s Status, id string) string {
	if e, ok := s.ExitByID(id); ok && e.Name != "" {
		return e.Name
	}
	return id
}

// Status renders the Dashboard in miniature.
func (v view) Status(s Status) (string, *Keyboard) {
	var b strings.Builder
	icon, key := headline(s.Verdict())
	fmt.Fprintf(&b, "%s <b>%s</b> · %s", icon, v.t(key), v.clock(s.At))
	if s.Demo {
		fmt.Fprintf(&b, " · <i>%s</i>", v.t("st.demo"))
	}
	b.WriteString("\n")
	if s.LocalFault {
		b.WriteString("<i>" + v.t("st.localfault") + "</i>\n")
	}
	b.WriteString("\n")

	if s.ExitIP.Known && s.ExitIP.IP != "" {
		place := strings.TrimSpace(strings.Join(nonEmpty(s.ExitIP.Country, s.ExitIP.City), ", "))
		where := strings.TrimSpace(Flag(s.ExitIP.Code) + " " + esc(place))
		if where != "" {
			where += " · "
		}
		b.WriteString(v.t("st.exitip", where+"<code>"+esc(s.ExitIP.IP)+"</code>") + "\n")
	} else {
		b.WriteString(v.t("st.exitip.unknown") + "\n")
	}
	for _, g := range s.Groups {
		if line := v.groupLine(s, g); line != "" {
			b.WriteString("  " + line + "\n")
		}
	}
	if len(s.Exits) == 0 {
		b.WriteString(v.t("st.exits.none") + "\n")
	} else {
		up, down := s.ExitCounts()
		b.WriteString(v.t("st.exits", up, down) + "\n")
	}
	switch {
	case s.Core.NativeOnly:
		b.WriteString(v.t("st.core.native"))
	case s.Core.Running:
		b.WriteString(v.t("st.core.running"))
	case s.Core.Available:
		b.WriteString(v.t("st.core.stopped"))
	default:
		b.WriteString(v.t("st.core.absent"))
	}
	if s.Core.Restarts > 0 {
		b.WriteString(v.t("st.core.restarts", s.Core.Restarts))
	}
	b.WriteString("\n")
	if s.Traffic.Known {
		b.WriteString(v.t("st.traffic", Speed(v.lang, s.Traffic.Down), Speed(v.lang, s.Traffic.Up)) + "\n")
	}
	if s.System.Known {
		line := v.t("st.system", int(s.System.MemUsedPct+0.5), fixed(v.lang, s.System.Load1, 2),
			Duration(v.lang, time.Duration(s.System.UptimeS)*time.Second))
		if s.System.TempC > 0 {
			line += fmt.Sprintf(" · %d°C", int(s.System.TempC+0.5))
		}
		b.WriteString(line + "\n")
	}
	switch {
	case !s.Changes.Known:
	case s.Changes.Pending && s.Changes.Count > 0:
		b.WriteString(v.t("st.pending", s.Changes.Count) + "\n")
	case s.Changes.Pending:
		b.WriteString(v.t("st.pending.some") + "\n")
	default:
		b.WriteString(v.t("st.pending.none") + "\n")
	}
	if feeds := s.FailingFeeds(); len(feeds) > 0 {
		b.WriteString(v.feedsLine(feeds) + "\n")
	}
	if s.FailSafe.Armed {
		b.WriteString("\n" + v.t("st.failsafe", Countdown(s.FailSafe.Remaining)) + "\n")
	}
	if s.Update.Available {
		b.WriteString("\n" + v.t("st.update", esc(s.Update.Latest)) + "\n")
	}
	if !v.muted.IsZero() {
		b.WriteString("\n" + v.t("st.muted", v.clock(v.muted)) + "\n")
	}
	kb := &Keyboard{Rows: [][]InlineButton{
		{btn(v.t("b.refresh"), cbStatus), btn(v.t("b.exits"), cbExits)},
		{btn(v.t("b.events"), cbEvents+"0"), btn(v.t("b.more"), cbMore)},
	}}
	if s.FailSafe.Armed && v.role == roleOwner {
		kb.Rows = append([][]InlineButton{{btn(v.t("b.keep"), cbKeep), btn(v.t("b.rollback"), cbRollback)}}, kb.Rows...)
	}
	if !v.muted.IsZero() {
		kb.Rows = append(kb.Rows, []InlineButton{btn(v.t("b.unmute"), cbMute+"0")})
	}
	return strings.TrimRight(b.String(), "\n"), kb
}

// feedNames is how many failing lists feedsLine names before "and N more".
const feedNames = 3

// feedsLine names the routing lists whose feeds keep failing: one with how long and, for an owner,
// why; several by name.
func (v view) feedsLine(feeds []FeedIssue) string {
	if len(feeds) == 1 {
		f, key := feeds[0], "st.feed"
		if f.Empty {
			key = "st.feed.empty"
		}
		line := v.t(key, "«"+esc(f.List)+"»", Count(v.lang, f.Fails, "n.time"), v.clock(f.Since))
		if v.role == roleOwner && f.Err != "" {
			line += "\n<i>" + esc(truncate(f.Err, 120)) + "</i>"
		}
		return line
	}
	names := make([]string, 0, feedNames)
	for _, f := range feeds[:min(len(feeds), feedNames)] {
		names = append(names, "«"+esc(f.List)+"»")
	}
	list := strings.Join(names, ", ")
	if len(feeds) > feedNames {
		list += v.t("st.feeds.more", len(feeds)-feedNames)
	}
	return v.t("st.feeds", Count(v.lang, len(feeds), "n.list"), list)
}

// groupLine is one group: the member it goes through when the election is known ("fast-eu →
// 🟢 nl-main · 42 ms"), otherwise the group's own probe ("🟢 fast-eu · 117 ms"), otherwise nothing.
func (v view) groupLine(s Status, g Group) string {
	if g.Elected != "" {
		member := esc(exitLabel(s, g.Elected))
		if e, ok := s.ExitByID(g.Elected); ok {
			member = stateIcon(e.State) + " " + member
			if e.State == StateAlive && e.LatencyMs > 0 {
				member += " · " + v.t("ex.latency", e.LatencyMs)
			}
		}
		return v.t("st.group", esc(g.Name), member)
	}
	h, ok := s.ExitByID(g.ID)
	if !ok || h.State == StateUnknown || h.State == "" {
		return ""
	}
	line := stateIcon(h.State) + " " + esc(g.Name)
	if h.State == StateAlive && h.LatencyMs > 0 {
		line += " · " + v.t("ex.latency", h.LatencyMs)
	}
	return line
}

func nonEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// sortedExits orders exits for display: down first (they are what someone opens this for), then
// up, then unknown; by name inside each.
func sortedExits(in []Exit) []Exit {
	out := append([]Exit(nil), in...)
	rank := func(state string) int {
		switch state {
		case StateDown:
			return 0
		case StateAlive:
			return 1
		}
		return 2
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := rank(out[i].State), rank(out[j].State)
		if ri != rj {
			return ri < rj
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// Exits is the exit list with one button per exit, a page at a time: a subscription can bring a
// hundred exits, and a message holds 4096 characters. Down exits sort first, so the first page is
// the one that matters, and it also carries the groups.
func (v view) Exits(s Status, page int) (string, *Keyboard) {
	var b strings.Builder
	b.WriteString(v.t("ex.title") + "\n")
	if len(s.Exits) == 0 {
		b.WriteString("\n" + v.t("ex.none"))
		return b.String(), &Keyboard{Rows: [][]InlineButton{{btn(v.t("b.status"), cbStatus)}}}
	}
	var exits []Exit
	for _, e := range sortedExits(s.Exits) {
		if !e.Group {
			exits = append(exits, e)
		}
	}
	pages := max(1, (len(exits)+exitsPage-1)/exitsPage)
	page = min(max(page, 0), pages-1)
	if page == 0 && len(s.Groups) > 0 {
		b.WriteString("\n" + v.t("ex.groups") + "\n")
		for _, g := range s.Groups {
			h, probed := s.ExitByID(g.ID)
			icon := "▫️"
			if probed && h.State != StateUnknown && h.State != "" {
				icon = stateIcon(h.State)
			}
			now := v.t("ex.noelected")
			if g.Elected != "" {
				now = v.t("ex.elected", "<b>"+esc(exitLabel(s, g.Elected))+"</b>")
			}
			fmt.Fprintf(&b, "%s %s: %s\n", icon, esc(g.Name), now)
		}
	}
	b.WriteString("\n")
	var rows [][]InlineButton
	var row []InlineButton
	for _, e := range exits[page*exitsPage : min(len(exits), (page+1)*exitsPage)] {
		line := stateIcon(e.State) + " <b>" + esc(e.Name) + "</b>"
		switch e.State {
		case StateAlive:
			if e.LatencyMs > 0 {
				line += " · " + v.t("ex.latency", e.LatencyMs)
			}
			if e.SuccessRate > 0 && e.SuccessRate < 100 {
				line += " · " + v.t("ex.success", e.SuccessRate)
			}
		case StateDown:
			if cause, _ := causeIn(v.lang, e); cause != "" {
				line += " · <i>" + esc(truncate(cause, 60)) + "</i>"
			}
		}
		b.WriteString(line + "\n")
		row = append(row, btn(stateIcon(e.State)+" "+truncate(e.Name, maxNameR), cbExit+v.ref(e.ID)))
		if len(row) == 2 {
			rows = append(rows, row)
			row = nil
		}
	}
	if len(row) > 0 {
		rows = append(rows, row)
	}
	refresh := cbExits
	if pages > 1 {
		var nav []InlineButton
		if page > 0 {
			nav = append(nav, btn(v.t("b.prevpage"), cbExitsPage+strconv.Itoa(page-1)))
		}
		nav = append(nav, btn(v.t("ev.page", page+1, pages), cbNoop))
		if page < pages-1 {
			nav = append(nav, btn(v.t("b.nextpage"), cbExitsPage+strconv.Itoa(page+1)))
		}
		rows = append(rows, nav)
		refresh = cbExitsPage + strconv.Itoa(page)
	}
	rows = append(rows, []InlineButton{btn(v.t("b.refresh"), refresh), btn(v.t("b.status"), cbStatus)})
	return strings.TrimRight(b.String(), "\n"), &Keyboard{Rows: rows}
}

// causeIn is why an exit is down, and what to do, in lang. The two causes the monitor words itself
// are translated; a knowledge-base entry, matched from the engine's own log and technical by nature,
// keeps its words, as in the panel.
func causeIn(lang string, e Exit) (cause, fix string) {
	if lang != Languages[0] && e.CauseID != "" {
		if _, ok := msgs["cause."+e.CauseID]; ok {
			return T(lang, "cause."+e.CauseID), T(lang, "cause."+e.CauseID+".fix")
		}
	}
	return e.Cause, e.Fix
}

// Exit renders one exit's card. note is an extra line (the result of a test), may be empty.
func (v view) Exit(e Exit, note string) (string, *Keyboard) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s <b>%s</b>", stateIcon(e.State), esc(e.Name))
	if e.Kind != "" {
		fmt.Fprintf(&b, " <i>(%s)</i>", esc(e.Kind))
	}
	b.WriteString("\n\n")
	b.WriteString(v.t("ex.state", v.stateWord(e.State)))
	if e.State == StateAlive && e.UptimeS > 0 {
		b.WriteString(" · " + v.t("ex.up_for", Duration(v.lang, time.Duration(e.UptimeS)*time.Second)))
	}
	b.WriteString("\n")
	if e.LatencyMs > 0 || e.AvgLatency > 0 || e.SuccessRate > 0 {
		lat, avg := "—", "—"
		if e.LatencyMs > 0 {
			lat = v.t("ex.latency", e.LatencyMs)
		}
		if e.AvgLatency > 0 {
			avg = v.t("ex.latency", e.AvgLatency)
		}
		b.WriteString(v.t("ex.avg", lat, avg, v.t("ex.success", e.SuccessRate)) + "\n")
	}
	if e.RateUp > 0 || e.RateDown > 0 {
		b.WriteString(v.t("ex.rate", Speed(v.lang, e.RateDown), Speed(v.lang, e.RateUp)) + "\n")
	}
	if e.State == StateDown {
		cause, fix := causeIn(v.lang, e)
		if cause != "" {
			b.WriteString("\n" + v.t("ex.cause", esc(cause)) + "\n")
		}
		if fix != "" {
			b.WriteString(v.t("ex.fix", esc(fix)) + "\n")
		}
	}
	if note != "" {
		b.WriteString("\n<i>" + note + "</i>\n")
	}
	row := []InlineButton{btn(v.t("b.test"), cbTest+v.ref(e.ID))}
	if v.role == roleOwner && e.Tunnel && e.State != StateDown {
		// A kernel tunnel can be measured on its own; a down one would only time out, and Test now
		// is the question to ask it.
		row = append(row, btn(v.t("b.speed"), cbAsk+actSpeed+":"+v.ref(e.ID)))
	}
	kb := &Keyboard{Rows: [][]InlineButton{append(row, btn(v.t("b.back"), cbExits))}}
	return strings.TrimRight(b.String(), "\n"), kb
}

// Events renders one page of the failover log, newest first.
func (v view) Events(log EventLog, page int) (string, *Keyboard) {
	var b strings.Builder
	b.WriteString(v.t("ev.title") + "\n")
	back := []InlineButton{btn(v.t("b.refresh"), cbEvents+strconv.Itoa(page)), btn(v.t("b.status"), cbStatus)}
	if !log.Known {
		b.WriteString("\n" + v.t("ev.unknown"))
		return b.String(), &Keyboard{Rows: [][]InlineButton{back}}
	}
	if !log.Since.IsZero() {
		b.WriteString("<i>" + v.t("ev.since", v.clock(log.Since), Duration(v.lang, v.now.Sub(log.Since))) + "</i>\n")
	}
	if len(log.Events) == 0 {
		b.WriteString("\n" + v.t("ev.empty"))
		return b.String(), &Keyboard{Rows: [][]InlineButton{back}}
	}
	pages := (len(log.Events) + pageSize - 1) / pageSize
	if page < 0 {
		page = 0
	}
	if page >= pages {
		page = pages - 1
	}
	b.WriteString("\n")
	for _, e := range log.Events[page*pageSize : min(len(log.Events), (page+1)*pageSize)] {
		b.WriteString("<code>" + v.clock(e.At) + "</code> " + v.eventLine(e) + "\n")
	}
	if page == pages-1 && log.Total > len(log.Events) {
		b.WriteString("\n<i>" + v.t("ev.dropped") + "</i>\n")
	}
	var nav []InlineButton
	if page < pages-1 {
		nav = append(nav, btn(v.t("b.older"), cbEvents+strconv.Itoa(page+1)))
	}
	if pages > 1 {
		nav = append(nav, btn(v.t("ev.page", page+1, pages), cbNoop))
	}
	if page > 0 {
		nav = append(nav, btn(v.t("b.newer"), cbEvents+strconv.Itoa(page-1)))
	}
	rows := [][]InlineButton{back}
	if len(nav) > 0 {
		rows = [][]InlineButton{nav, back}
	}
	return strings.TrimRight(b.String(), "\n"), &Keyboard{Rows: rows}
}

func (v view) eventLine(e Event) string {
	name := esc(e.Name)
	if name == "" {
		name = esc(e.ID)
	}
	switch e.Kind {
	case "down":
		return v.t("ev.down", name)
	case "up":
		s := v.t("ev.up", name)
		if e.LatencyMs > 0 {
			s += v.t("ev.lat", e.LatencyMs)
		}
		return s
	case "switch":
		return v.t("ev.switch", name, esc(e.From), esc(e.To))
	}
	return esc(e.Kind) + " " + name
}

// Help renders the command list for a role.
func (v view) Help(role string) (string, *Keyboard) {
	s := v.t("help")
	if role == roleOwner {
		s += v.t("help.owner")
	}
	s += v.t("help.tail") + v.t("help.more")
	if role == roleViewer {
		s += v.t("help.viewer")
	}
	return s, &Keyboard{Rows: [][]InlineButton{{btn(v.t("b.status"), cbStatus), btn(v.t("b.exits"), cbExits)}}}
}

// Lang renders the language picker.
func (v view) Lang() (string, *Keyboard) {
	return v.t("lang.pick"), &Keyboard{Rows: [][]InlineButton{{btn("English", cbLang+"en"), btn("Русский", cbLang+"ru"), btn("Українська", cbLang+"uk")}}}
}
