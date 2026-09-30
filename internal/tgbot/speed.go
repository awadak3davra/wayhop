package tgbot

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"
)

const (
	actSpeed  = "speed"
	speedWait = 2 * time.Minute
)

// speedAsk is the question before a speed test of the default route (ref "") or of one exit's
// tunnel. A test spends about 30 MB of the line and slows the network for up to a minute, so it is
// asked for like a maintenance action.
func (b *Bot) speedAsk(ctx context.Context, v view, chat int64, ref string) (string, *Keyboard) {
	text, arg := v.t("sp.ask"), ""
	if ref != "" {
		id, ok := b.refs.resolve(ref)
		var e Exit
		if ok {
			e, ok = b.status(ctx).ExitByID(id)
		}
		switch {
		case !ok:
			text, kb := v.Exits(b.status(ctx), 0)
			return "<i>" + v.t("ex.gone") + "</i>\n\n" + text, kb
		case !e.Tunnel:
			return v.Exit(e, v.t("sp.cannot"))
		}
		text, arg = v.t("sp.ask.exit", esc(e.Name)), e.ID
	}
	nonce := b.confirms.issue(chat, actSpeed, arg, b.now())
	return text, &Keyboard{Rows: [][]InlineButton{{btn(v.t("sp.ok"), cbConfirm+nonce), btn(v.t("b.cancel"), cbCancel+nonce)}}}
}

// speed runs a confirmed test of the default route (exit "") or of one exit's tunnel. The message
// says which leg is running, as the backend starts it (a refused test never claims a leg), then
// holds the result.
func (b *Bot) speed(ctx context.Context, v view, m *Message, exit string) {
	via := "WayHop"
	if exit != "" {
		if e, ok := b.status(ctx).ExitByID(exit); ok {
			via = "<b>" + esc(e.Name) + "</b>"
		}
	}
	cctx, cancel := context.WithTimeout(ctx, speedWait)
	rep, err := b.be.SpeedTest(cctx, exit, func(leg string) {
		switch leg {
		case LegLine:
			b.show(ctx, m, v.t("sp.run.line"), nil)
		case LegRoute:
			b.show(ctx, m, v.t("sp.run.route", via), nil)
		}
	})
	cancel()
	again := v.speedAgain(exit)
	switch {
	case errors.Is(err, ErrBusy):
		b.show(ctx, m, v.t("sp.busy"), again)
	case errors.Is(err, ErrUnavailable):
		b.show(ctx, m, v.t("sp.cannot"), again)
	case err != nil:
		b.show(ctx, m, v.t("err.backend", esc(err.Error())), again)
	default:
		b.show(ctx, m, v.Speed(rep), again)
	}
}

// speedAgain is the keyboard under a result: the same test again (asked again, as every run spends
// the line), and the way back to where it was started.
func (v view) speedAgain(exit string) *Keyboard {
	if exit == "" {
		return &Keyboard{Rows: [][]InlineButton{{btn(v.t("b.again"), cbAsk+actSpeed), btn(v.t("b.devices"), cbDevices)}, {btn(v.t("b.status"), cbStatus)}}}
	}
	ref := v.ref(exit)
	return &Keyboard{Rows: [][]InlineButton{{btn(v.t("b.again"), cbAsk+actSpeed+":"+ref), btn(v.t("b.back"), cbExit+ref)}, {btn(v.t("b.status"), cbStatus)}}}
}

// speedRoute names the second leg: the exit measured on its own, or the default route by the
// configured rules ("Auto (fastest) → nl-main"); plain "WayHop" when neither is known.
func speedRoute(r SpeedReport) string {
	switch {
	case r.Exit != "":
		return "<b>" + esc(r.Exit) + "</b>"
	case r.Via != "":
		return "<b>" + esc(r.Via) + "</b>"
	}
	return "WayHop"
}

// Speed renders a speed test: the provider's line, the route through WayHop or one exit's tunnel,
// and what the two say together ("is it the line or the tunnel?"). A leg that is not what its label
// says is not shown under that label: a line that left by a tunnel is that tunnel, and a site that
// goes straight out has no route through WayHop to measure.
func (v view) Speed(r SpeedReport) string {
	var b strings.Builder
	b.WriteString(v.t("sp.title") + "\n\n")
	if r.Line.Through != "" {
		b.WriteString(v.t("sp.line.tunnel", "<b>"+esc(r.Line.Through)+"</b>", v.speedLeg(r.Line)) + "\n")
	} else {
		b.WriteString(v.t("sp.line", v.speedLeg(r.Line)) + "\n")
	}
	via := speedRoute(r)
	switch {
	case r.Direct && r.ByRule:
		b.WriteString(v.t("sp.direct.rule") + "\n")
	case r.Direct:
		b.WriteString(v.t("sp.direct") + "\n")
	case r.Blocked:
		b.WriteString(v.t("sp.blocked") + "\n")
	case r.Route.Skipped && r.Native:
		b.WriteString(v.t("sp.native") + "\n")
	case r.Route.Skipped:
		b.WriteString(v.t("sp.nocore") + "\n")
	default:
		b.WriteString(v.t("sp.via", via, v.speedLeg(r.Route)) + "\n")
	}
	if s := v.speedVerdict(r, via); s != "" {
		b.WriteString("\n" + s + "\n")
	}
	b.WriteString("\n<i>" + v.t("sp.hint") + "</i>")
	return b.String()
}

// speedLeg is one leg's numbers: "↓ 94.2 Mbit/s ↑ 38.1 Mbit/s · 12 ms".
func (v view) speedLeg(l SpeedLeg) string {
	switch {
	case l.NoAnswer:
		return v.t("sp.fail", v.t("sp.noanswer"))
	case l.Err != "":
		return v.t("sp.fail", esc(truncate(l.Err, 120)))
	}
	s := "↓ " + Speed(v.lang, mbps(l.DownMbps))
	switch {
	case l.UpMbps > 0:
		s += " ↑ " + Speed(v.lang, mbps(l.UpMbps))
	case l.UpMissed:
		s += " ↑ " + v.t("sp.up.none")
	}
	if l.LatencyMs >= 0 {
		s += " · " + v.t("ex.latency", l.LatencyMs)
	}
	return s
}

// mbps turns megabits per second into the bytes per second Speed formats.
func mbps(f float64) int64 { return int64(math.Round(f * 1e6 / 8)) }

// speedVerdict compares the two downloads. The thresholds are coarse on purpose: one 10 MB sample
// on each path, taken while the family may be using the line, supports "about" and no more.
func (v view) speedVerdict(r SpeedReport, via string) string {
	if r.Route.Skipped || r.Line.Through != "" || r.Line.Err != "" || r.Route.Err != "" || r.Line.DownMbps <= 0 {
		return ""
	}
	ratio := r.Route.DownMbps / r.Line.DownMbps
	switch pct := int(math.Round(ratio * 100)); {
	case ratio >= 1.3:
		// The provider slows what it can see and not what it cannot: a throttled destination.
		return v.t("sp.faster", via)
	case ratio >= 0.8:
		return v.t("sp.good", via)
	case ratio >= 0.4:
		return v.t("sp.share", via, pct)
	default:
		return v.t("sp.slow", pct)
	}
}
