package tgbot

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Callback data of the tools.
const (
	cbRoute   = "rt"  // ask which destination to trace
	cbRouteAg = "rt:" // + ref: trace this destination again
	cbDevices = "dv"  // the device list
	cbDiag    = "dg"  // run the Diagnostics battery
	cbMore    = "mo"  // the tools menu
)

const (
	maxDevices = 30 // lines in /devices; more than this is not a phone screen
	maxIPs     = 4  // resolved addresses listed in /route before "+N"
	maxMatches = 6  // configured matches listed in /route
)

// tagLabel names an outbound tag the way the panel does: the exit's or group's name, or what
// "direct" and "block" mean.
func (v view) tagLabel(s Status, tag string) string {
	switch tag {
	case "direct":
		return v.t("tag.direct")
	case "block":
		return v.t("tag.block")
	case "":
		return "—"
	}
	if e, ok := s.ExitByID(tag); ok && e.Name != "" {
		return e.Name
	}
	for _, g := range s.Groups {
		if g.ID == tag && g.Name != "" {
			return g.Name
		}
	}
	return tag
}

// Trace renders where a destination goes: what it resolves to, where its live connections left,
// and what in the configuration references it.
func (v view) Trace(tr Trace, s Status) (string, *Keyboard) {
	var b strings.Builder
	fmt.Fprintf(&b, "🔎 <b>%s</b>\n", esc(tr.Target))
	switch {
	case tr.ResolveError != "":
		b.WriteString(v.t("rt.noresolve") + "\n")
	case len(tr.IPs) > 0:
		ips := tr.IPs
		more := ""
		if len(ips) > maxIPs {
			more = " " + v.t("rt.more", len(ips)-maxIPs)
			ips = ips[:maxIPs]
		}
		b.WriteString(v.t("rt.ips", "<code>"+esc(strings.Join(ips, ", "))+"</code>"+more) + "\n")
	}

	total := 0
	for _, n := range tr.Live {
		total += n
	}
	b.WriteString("\n")
	if total > 0 {
		tags := make([]string, 0, len(tr.Live))
		for tag := range tr.Live {
			tags = append(tags, tag)
		}
		sort.Slice(tags, func(i, j int) bool {
			if tr.Live[tags[i]] != tr.Live[tags[j]] {
				return tr.Live[tags[i]] > tr.Live[tags[j]]
			}
			return tags[i] < tags[j]
		})
		var parts []string
		for _, tag := range tags {
			p := "<b>" + esc(v.tagLabel(s, tag)) + "</b>"
			if tr.Live[tag] > 1 {
				p += " ×" + strconv.Itoa(tr.Live[tag])
			}
			parts = append(parts, p)
		}
		b.WriteString(v.t("rt.live", total, strings.Join(parts, " · ")) + "\n")
	} else {
		b.WriteString(v.t("rt.nolive") + "\n")
	}

	if len(tr.Configured) > 0 {
		b.WriteString("\n" + v.t("rt.configured") + "\n")
		for i, m := range tr.Configured {
			if i == maxMatches {
				b.WriteString(v.t("rt.more", len(tr.Configured)-maxMatches) + "\n")
				break
			}
			b.WriteString(v.matchLine(m, s) + "\n")
		}
	} else if tr.ResolveError == "" {
		b.WriteString("\n" + v.t("rt.default") + "\n")
	}
	if len(tr.Maybe) > 0 {
		b.WriteString("\n<i>" + v.t("rt.maybe") + "</i>\n")
		for i, m := range tr.Maybe {
			if i == maxMatches {
				b.WriteString(v.t("rt.more", len(tr.Maybe)-maxMatches) + "\n")
				break
			}
			b.WriteString(v.matchLine(m, s) + "\n")
		}
	}
	kb := &Keyboard{Rows: [][]InlineButton{
		{btn(v.t("b.again"), cbRouteAg+v.ref(tr.Target)), btn(v.t("b.route.other"), cbRoute)},
		{btn(v.t("b.status"), cbStatus)},
	}}
	return strings.TrimRight(b.String(), "\n"), kb
}

// whyIn says in lang why a rule or list names the site. The router words it in English
// (internal/server/trace.go: matchDomainIP, traceCandidates, geoMatcherWhy); its keywords and fixed
// sentences are translated, and what they name, a domain, a network or a geosite category, stays as
// written. A form not known here stays English rather than being guessed at.
func whyIn(lang, why string) string {
	const remote = "remote rule-set — its contents are a sing-box artifact, not read here"
	const unfetched = "feed has never been fetched — nothing to match against yet"
	const geo = " — needs the on-router dataset"
	if lang == Languages[0] {
		return why
	}
	switch {
	case strings.HasPrefix(why, "domain_suffix "):
		return T(lang, "why.suffix", strings.TrimPrefix(why, "domain_suffix "))
	case strings.HasPrefix(why, "domain "):
		return T(lang, "why.domain", strings.TrimPrefix(why, "domain "))
	case why == remote:
		return T(lang, "why.remote")
	case why == unfetched:
		return T(lang, "why.unfetched")
	case strings.HasSuffix(why, geo):
		return T(lang, "why.geo", strings.TrimSuffix(why, geo))
	}
	return why
}

func (v view) matchLine(m TraceMatch, s Status) string {
	name := m.Name
	if name == "" {
		name = m.ID
	}
	kind := v.t("rt.kind." + m.Kind)
	if strings.HasPrefix(kind, "rt.kind.") {
		kind = esc(m.Kind)
	}
	line := "• " + kind + " «" + esc(name) + "» → <b>" + esc(v.tagLabel(s, m.Via)) + "</b>"
	if m.Why != "" {
		line += " <i>(" + esc(truncate(whyIn(v.lang, m.Why), 60)) + ")</i>"
	}
	return line
}

// RoutePrompt asks for the destination to trace.
func (v view) RoutePrompt() string { return v.t("rt.prompt") }

// Devices renders the LAN clients.
// busyBytes is more than a trickle: keep-alives and a chat app idling stay below it.
const busyBytes = 2000

func busy(d Device) bool { return d.Down+d.Up >= busyBytes }

// Devices is who is on the LAN and, where the router can measure it, who is using the line right
// now ("why is the internet slow?"): the busiest first with their speeds, the idle after.
func (v view) Devices(l DeviceList) (string, *Keyboard) {
	devs := append([]Device(nil), l.Devices...)
	active := 0
	if l.Measured {
		// The busiest first, then those whose traffic the fast path hides, then the idle.
		rank := func(d Device) int {
			switch {
			case busy(d):
				return 2
			case d.FastPath:
				return 1
			}
			return 0
		}
		sort.SliceStable(devs, func(i, j int) bool {
			if ri, rj := rank(devs[i]), rank(devs[j]); ri != rj {
				return ri > rj
			}
			return devs[i].Down+devs[i].Up > devs[j].Down+devs[j].Up
		})
		for _, d := range devs {
			if busy(d) {
				active++
			}
		}
	}
	var b strings.Builder
	b.WriteString(v.t("dv.title", len(devs)))
	if l.Measured && len(devs) > 0 {
		b.WriteString(v.t("dv.active", active))
	}
	b.WriteString("\n")
	row := []InlineButton{btn(v.t("b.refresh"), cbDevices)}
	if v.role == roleOwner {
		// The other half of "why is the internet slow?": who is using the line, then the line.
		row = append(row, btn(v.t("b.speed"), cbAsk+actSpeed))
	}
	kb := &Keyboard{Rows: [][]InlineButton{append(row, btn(v.t("b.status"), cbStatus))}}
	if len(devs) == 0 {
		b.WriteString("\n" + v.t("dv.none"))
		return b.String(), kb
	}
	b.WriteString("\n")
	for i, d := range devs {
		if i == maxDevices {
			b.WriteString(v.t("rt.more", len(devs)-maxDevices) + "\n")
			break
		}
		name := "<b>" + esc(d.Name) + "</b>"
		if d.Name == "" {
			name = "<i>" + v.t("dv.noname") + "</i>"
		}
		line := "• " + name + " · <code>" + esc(d.IP) + "</code>"
		switch {
		case l.Measured && busy(d) && d.FastPath:
			line += " · ↓ " + Speed(v.lang, d.Down) + " ↑ " + Speed(v.lang, d.Up) + " · " + v.t("dv.fast.more")
		case l.Measured && busy(d):
			line += " · ↓ " + Speed(v.lang, d.Down) + " ↑ " + Speed(v.lang, d.Up)
		case l.Measured && d.FastPath:
			line += " · " + v.t("dv.fast")
		}
		if d.Group != "" {
			line += " · " + v.t("dv.group", esc(d.Group))
		}
		b.WriteString(line + "\n")
	}
	return strings.TrimRight(b.String(), "\n"), kb
}

// Diag renders the Diagnostics battery: what needs attention in full, what passed in one line.
func (v view) Diag(checks []Check, at time.Time) (string, *Keyboard) {
	var b strings.Builder
	var pass, warn, fail, na int
	var passed []string
	var findings []Check
	for _, c := range checks {
		switch c.Status {
		case "pass":
			pass++
			passed = append(passed, v.checkLabel(c))
		case "warn":
			warn++
			findings = append(findings, c)
		case "fail":
			fail++
			findings = append(findings, c)
		default:
			na++
		}
	}
	icon := "🟢"
	switch {
	case fail > 0:
		icon = "🔴"
	case warn > 0:
		icon = "🟡"
	}
	fmt.Fprintf(&b, "%s <b>%s</b> · %s\n", icon, v.t("dg.title"), v.clock(at))
	b.WriteString(v.t("dg.counts", pass, warn, fail) + "\n")
	// Failures first, then warnings.
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Status == "fail" && findings[j].Status != "fail" })
	for _, c := range findings {
		mark := "⚠️"
		if c.Status == "fail" {
			mark = "❌"
		}
		fmt.Fprintf(&b, "\n%s <b>%s</b>\n%s", mark, esc(v.checkLabel(c)), esc(c.Summary))
		if c.Fix != "" {
			b.WriteString("\n<i>" + v.t("ex.fix", esc(c.Fix)) + "</i>")
		}
		b.WriteString("\n")
	}
	if len(passed) > 0 {
		b.WriteString("\n✅ " + esc(strings.Join(passed, " · ")) + "\n")
	}
	if na > 0 {
		b.WriteString("\n<i>" + v.t("dg.na", na) + "</i>\n")
	}
	kb := &Keyboard{Rows: [][]InlineButton{{btn(v.t("b.again"), cbDiag), btn(v.t("b.status"), cbStatus)}}}
	return strings.TrimRight(b.String(), "\n"), kb
}

// checkLabel is a check's name in the chat's language when the bot knows it.
func (v view) checkLabel(c Check) string {
	if s := v.t("hc." + c.ID); !strings.HasPrefix(s, "hc.") {
		return s
	}
	if c.Label != "" {
		return c.Label
	}
	return c.ID
}

// Ping renders one ping.
func (v view) Ping(p PingResult) string {
	switch {
	case !p.Ran:
		return v.t("pg.norun", "<code>"+esc(p.Target)+"</code>")
	case !p.OK:
		return v.t("pg.fail", "<code>"+esc(p.Target)+"</code>")
	}
	s := v.t("pg.ok", "<code>"+esc(p.Target)+"</code>")
	if p.AvgMs >= 0 {
		s += " · " + v.t("pg.avg", strconv.FormatFloat(p.AvgMs, 'f', 0, 64))
	}
	if p.LossPct > 0 {
		s += " · " + v.t("pg.loss", p.LossPct)
	}
	return s
}

// Lookup renders one DNS lookup.
func (v view) Lookup(l LookupResult) string {
	if l.Err != "" || len(l.IPs) == 0 {
		return v.t("dn.fail", "<code>"+esc(l.Target)+"</code>")
	}
	s := v.t("dn.ok", "<code>"+esc(l.Target)+"</code>", "<code>"+esc(strings.Join(l.IPs, ", "))+"</code>")
	if l.CNAME != "" && strings.TrimSuffix(l.CNAME, ".") != strings.TrimSuffix(l.Target, ".") {
		s += "\n" + v.t("dn.cname", "<code>"+esc(strings.TrimSuffix(l.CNAME, "."))+"</code>")
	}
	return s
}

// More is the tools menu under the status. Owners also get the way into Maintenance.
func (v view) More() (string, *Keyboard) {
	rows := [][]InlineButton{
		{btn(v.t("b.route"), cbRoute), btn(v.t("b.devices"), cbDevices)},
		{btn(v.t("b.diag"), cbDiag), btn(v.t("b.summary"), cbSummary)},
	}
	own := []InlineButton{btn(v.t("b.alerts"), cbAlertsMenu)}
	if v.role == roleOwner {
		own = append(own, btn(v.t("b.speed"), cbAsk+actSpeed))
		rows = append(rows, own)
		own = []InlineButton{btn(v.t("b.maint"), cbMaint)}
	}
	rows = append(rows, own, []InlineButton{btn(v.t("b.help"), cbHelp), btn(v.t("b.status"), cbStatus)})
	return v.t("mo.title"), &Keyboard{Rows: rows}
}
