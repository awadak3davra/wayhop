package tgbot

import (
	"context"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"wayhop/internal/config"
)

// The daily digest (scenario S10): once a day, at a time the owner picks, what the last day held.
// Alerts tell of each outage as it happens; the digest is for the people who turned those off, and
// for the morning question "did anything happen overnight?".

const (
	digestTick = 30 * time.Second
	// digestWindow is how late the digest may still go out, in minutes. A router that was off at
	// 08:30 and back at 08:40 still sends the morning summary; one back at noon does not send it at
	// lunch.
	digestWindow = 30
	// digestEvents asks for the whole failover log, which holds a few hundred entries at most.
	digestEvents = 1000
	// digestTraffic, digestOutages and digestSwitches cap their lists; the rest are counted. A
	// subscription can bring a hundred exits, and one bad night must still fit one message.
	digestTraffic  = 8
	digestOutages  = 10
	digestSwitches = 5
)

// digestDay reports whether the digest is due at now and the date it belongs to. A window that
// crosses midnight belongs to the day it started on.
func digestDay(t config.Telegram, now time.Time) (string, bool) {
	at, ok := clockMinutes(t.Digest)
	if !ok {
		return "", false
	}
	late := (now.Hour()*60 + now.Minute() - at + 24*60) % (24 * 60)
	if late >= digestWindow {
		return "", false
	}
	return now.Add(-time.Duration(late) * time.Minute).Format("2006-01-02"), true
}

// counters are the running totals the digest reports as differences: what each exit carried and how
// often the core crashed. They are read when the bot starts and again at each digest.
type counters struct {
	at       time.Time
	bytes    map[string][2]int64 // exit id -> down, up
	restarts int
}

func countersOf(s Status, at time.Time) counters {
	c := counters{at: at, bytes: map[string][2]int64{}, restarts: s.Core.Restarts}
	for _, e := range s.Exits {
		if !e.Group {
			c.bytes[e.ID] = [2]int64{e.BytesDown, e.BytesUp}
		}
	}
	return c
}

// digest is one day's summary, gathered once and rendered for each chat.
type digest struct {
	At       time.Time
	OnDemand bool // asked for with /summary, not sent at the digest's time
	Status   Status
	// The outage and switch lines cover From..At: a day, or less when the log is younger (it lives
	// in memory and starts with the daemon). LogKnown is false when there is no log at all.
	LogKnown bool
	From     time.Time
	FullDay  bool
	Outages  []outage
	Switches []switched
	// Traffic and Restarts cover TrafficFrom..At: since the previous digest or the bot's start.
	Traffic     []traffic
	TrafficFrom time.Time
	Restarts    int
}

type outage struct {
	ID, Name string
	Group    bool
	Count    int
	Down     time.Duration
	Open     bool // still down at the end of the window
}

type switched struct {
	Name, Now string
	Count     int
}

type traffic struct {
	Name     string
	Down, Up int64
}

// outages folds the failover log (newest first, as Events returns it) into the outages that overlap
// from..to. An exit whose first entry is a recovery was already down when the log began, so that
// outage counts from the window's start. Worst first: the longest total downtime leads.
func outages(log EventLog, from, to time.Time, groups map[string]bool) []outage {
	type track struct {
		o     outage
		down  bool
		since time.Time
		seen  bool
	}
	byID := map[string]*track{}
	var order []string
	get := func(e Event) *track {
		tr := byID[e.ID]
		if tr == nil {
			tr = &track{o: outage{ID: e.ID, Group: groups[e.ID]}}
			byID[e.ID] = tr
			order = append(order, e.ID)
		}
		tr.o.Name = e.Name // oldest to newest: the last name wins
		return tr
	}
	for i := len(log.Events) - 1; i >= 0; i-- {
		e := log.Events[i]
		if e.At.After(to) {
			continue
		}
		switch e.Kind {
		case "down":
			tr := get(e)
			if !tr.down {
				tr.down, tr.since = true, e.At
			}
			tr.seen = true
		case "up":
			tr := get(e)
			start := tr.since
			if !tr.down {
				if tr.seen {
					continue // a recovery with no outage before it: nothing to close
				}
				start = log.Since
			}
			if e.At.After(from) {
				tr.o.Count++
				tr.o.Down += e.At.Sub(later(start, from))
			}
			tr.down, tr.seen = false, true
		}
	}
	var out []outage
	for _, id := range order {
		tr := byID[id]
		if tr.down {
			tr.o.Count++
			tr.o.Down += to.Sub(later(tr.since, from))
			tr.o.Open = true
		}
		if tr.o.Count > 0 {
			out = append(out, tr.o)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Down > out[j].Down })
	return out
}

// switches counts each group's elections in from..to and names the member it ended on.
func switches(log EventLog, from, to time.Time) []switched {
	byID := map[string]*switched{}
	var order []string
	for i := len(log.Events) - 1; i >= 0; i-- {
		e := log.Events[i]
		if e.Kind != "switch" || !e.At.After(from) || e.At.After(to) {
			continue
		}
		s := byID[e.ID]
		if s == nil {
			s = &switched{}
			byID[e.ID] = s
			order = append(order, e.ID)
		}
		s.Name, s.Now = e.Name, e.To
		s.Count++
	}
	out := make([]switched, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// trafficSince is what each exit carried since base, busiest first. A total that went backwards was
// reset (the tunnel was rebuilt by an Apply): what it has counted since is the best there is.
func trafficSince(s Status, base counters) []traffic {
	var out []traffic
	for _, e := range s.Exits {
		if e.Group {
			continue
		}
		down, up := e.BytesDown, e.BytesUp
		if was, ok := base.bytes[e.ID]; ok {
			if down >= was[0] {
				down -= was[0]
			}
			if up >= was[1] {
				up -= was[1]
			}
		}
		if down > 0 || up > 0 {
			out = append(out, traffic{Name: e.Name, Down: down, Up: up})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Down+out[i].Up > out[j].Down+out[j].Up })
	return out
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// digestLoop sends the digest when it is due. It reads the settings on every tick, so a time set in
// the panel applies at once, and a time set within the last half hour sends today's summary now.
func (b *Bot) digestLoop(ctx context.Context) {
	tick := time.NewTicker(digestTick)
	defer tick.Stop()
	b.digestStep(ctx, b.now())
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			b.digestStep(ctx, b.now())
		}
	}
}

// cbSummary asks for the digest now, from the More menu or its own Refresh button.
const cbSummary = "sm"

// baseCounters is the totals the next digest measures from. The map inside is never written after
// countersOf builds it, so the copy can be read without the lock.
func (b *Bot) baseCounters() counters {
	b.digestMu.Lock()
	defer b.digestMu.Unlock()
	return b.counters
}

func (b *Bot) setCounters(c counters) {
	b.digestMu.Lock()
	b.counters = c
	b.digestMu.Unlock()
}

// digestStep is one tick: the first one only reads the counters the first digest measures from. A
// panic is contained, as in the watcher: a summary must never take the router's daemon down.
func (b *Bot) digestStep(ctx context.Context, now time.Time) {
	defer func() {
		if r := recover(); r != nil {
			b.logf("telegram: digest panic: %v\n%s", r, debug.Stack())
		}
	}()
	if b.baseCounters().at.IsZero() {
		b.setCounters(countersOf(b.status(ctx), now))
		return
	}
	t := b.st.Telegram()
	day, due := digestDay(t, now)
	if !due || day == b.digestSent || len(t.Chats) == 0 {
		return
	}
	b.digestSent = day
	if !b.be.ClaimDigest(day) {
		return // the process before this one sent it
	}
	b.Notify(digestAlert(b.collectDigest(ctx, now)))
}

// collectDigest reads what the daily digest needs and moves the counters on to now.
func (b *Bot) collectDigest(ctx context.Context, now time.Time) digest {
	d, s := b.gatherDigest(ctx, now, b.baseCounters())
	b.setCounters(countersOf(s, now))
	return d
}

// gatherDigest reads what a summary needs, measuring traffic and crashes from base. It changes
// nothing: that is what lets /summary run between two daily digests without shortening the next.
func (b *Bot) gatherDigest(ctx context.Context, now time.Time, base counters) (digest, Status) {
	s := b.status(ctx)
	d := digest{At: now, Status: s}
	if log := b.be.Events(digestEvents); log.Known {
		d.LogKnown = true
		d.From, d.FullDay = now.Add(-24*time.Hour), true
		if log.Since.After(d.From) {
			d.From, d.FullDay = log.Since, false
		}
		groups := map[string]bool{}
		for _, e := range s.Exits {
			if e.Group {
				groups[e.ID] = true
			}
		}
		d.Outages = outages(log, d.From, now, groups)
		d.Switches = switches(log, d.From, now)
	}
	if !base.at.IsZero() { // before the first reading there is nothing to measure from
		d.Traffic, d.TrafficFrom = trafficSince(s, base), base.at
		if d.Restarts = s.Core.Restarts - base.restarts; d.Restarts < 0 {
			d.Restarts = s.Core.Restarts
		}
	}
	return d, s
}

// summary is the digest on demand ("did anything happen overnight?"), shown in place of the menu
// it was asked from, or as a new message for /summary.
func (b *Bot) summary(ctx context.Context, v view, chat int64, m *Message) {
	d, _ := b.gatherDigest(ctx, b.now(), b.baseCounters())
	d.OnDemand = true
	text, kb := v.Digest(d)
	if m != nil {
		b.show(ctx, m, text, kb)
		return
	}
	b.reply(ctx, chat, "", func() (string, *Keyboard) { return text, kb })
}

func digestAlert(d digest) Alert {
	return Alert{Kind: KindDigest, Sev: SevInfo, At: d.At, Scheduled: true,
		Render: func(lang, role string) (string, *Keyboard) {
			return view{lang: lang, now: d.At, role: role}.Digest(d)
		},
		Line: func(lang string) string { return T(lang, "digest.line") },
	}
}

// Digest is the daily summary.
func (v view) Digest(d digest) (string, *Keyboard) {
	var b strings.Builder
	if d.OnDemand {
		b.WriteString(v.t("digest.title.now", v.date(d.At)+", "+v.clock(d.At)))
	} else {
		b.WriteString(v.t("digest.title", v.date(d.At)))
	}
	if d.Status.Demo {
		b.WriteString(" · <i>" + v.t("st.demo") + "</i>")
	}
	icon, key := headline(d.Status.Verdict())
	b.WriteString("\n" + icon + " " + v.t(key))
	if up, down := d.Status.ExitCounts(); up+down > 0 {
		b.WriteString(" · " + v.t("digest.exits", up, up+down))
	}
	b.WriteString("\n")

	if d.LogKnown {
		if d.FullDay {
			b.WriteString("\n" + v.t("digest.day") + "\n")
		} else {
			b.WriteString("\n" + v.t("digest.since", v.clock(d.From)) + "\n")
		}
		for i, o := range d.Outages {
			if i == digestOutages {
				b.WriteString(v.t("digest.more", len(d.Outages)-digestOutages) + "\n")
				break
			}
			k := "digest.outage"
			if o.Group {
				k = "digest.outage.group"
			}
			line := v.t(k, "<b>"+esc(o.Name)+"</b>", Count(v.lang, o.Count, "n.outage"), Duration(v.lang, o.Down))
			if o.Open {
				line += v.t("digest.open")
			}
			b.WriteString(line + "\n")
		}
		for i, s := range d.Switches {
			if i == digestSwitches {
				b.WriteString(v.t("digest.more", len(d.Switches)-digestSwitches) + "\n")
				break
			}
			b.WriteString(v.t("digest.switched", "<b>"+esc(s.Name)+"</b>", Count(v.lang, s.Count, "n.time"), esc(s.Now)) + "\n")
		}
		if d.Restarts > 0 {
			b.WriteString(v.t("digest.restarts", Count(v.lang, d.Restarts, "n.time")) + "\n")
		}
		if len(d.Outages) == 0 && len(d.Switches) == 0 && d.Restarts == 0 {
			b.WriteString(v.t("digest.calm") + "\n")
		}
	}

	if len(d.Traffic) > 0 {
		if d.At.Sub(d.TrafficFrom) >= 23*time.Hour {
			b.WriteString("\n" + v.t("digest.traffic.day") + "\n")
		} else {
			b.WriteString("\n" + v.t("digest.traffic.since", v.clock(d.TrafficFrom)) + "\n")
		}
		for i, t := range d.Traffic {
			if i == digestTraffic {
				b.WriteString(v.t("digest.more", len(d.Traffic)-digestTraffic) + "\n")
				break
			}
			b.WriteString(v.t("digest.traffic", esc(t.Name), Bytes(v.lang, t.Down), Bytes(v.lang, t.Up)) + "\n")
		}
	}

	var tail []string
	if up := d.Status.System.UptimeS; d.Status.System.Known && up > 0 {
		tail = append(tail, v.t("digest.uptime", Duration(v.lang, time.Duration(up)*time.Second)))
	}
	switch c := d.Status.Changes; {
	case c.Known && c.Pending && c.Count > 0:
		tail = append(tail, "📝 "+v.t("st.pending", c.Count))
	case c.Known && c.Pending:
		tail = append(tail, "📝 "+v.t("st.pending.some"))
	}
	if feeds := d.Status.FailingFeeds(); len(feeds) > 0 {
		tail = append(tail, v.feedsLine(feeds))
	}
	if d.Status.Update.Available {
		tail = append(tail, v.t("st.update", esc(d.Status.Update.Latest)))
	}
	if len(tail) > 0 {
		b.WriteString("\n" + strings.Join(tail, "\n") + "\n")
	}
	kb := &Keyboard{Rows: [][]InlineButton{{btn(v.t("b.status"), cbStatus), btn(v.t("b.events"), cbEvents+"0")}}}
	if d.OnDemand {
		kb = &Keyboard{Rows: [][]InlineButton{{btn(v.t("b.refresh"), cbSummary), btn(v.t("b.status"), cbStatus)}}}
	}
	if v.role == roleAlerts {
		kb = nil
	}
	return strings.TrimRight(b.String(), "\n"), kb
}
