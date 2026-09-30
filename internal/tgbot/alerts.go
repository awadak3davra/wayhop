package tgbot

import (
	"strings"
	"time"
)

// Alert kinds: the switches in Settings → Telegram, stored in config.Telegram.AlertsOff.
const (
	KindExits    = "exits"    // an exit went down or came back
	KindSwitches = "switches" // a group moved to another member
	KindUplink   = "uplink"   // every exit failed at once: the provider, not the tunnels
	KindCore     = "core"     // sing-box crashed, restarted, or stays down
	KindApply    = "apply"    // the test-Apply window: started, kept, rolled back
	KindBoot     = "boot"     // the router or the daemon came back
	KindSystem   = "system"   // RAM almost full
	KindUpdates  = "updates"  // a new WayHop release

	// KindDigest is the daily summary. It has its own switch (the time it arrives at), so it is not
	// among the alert kinds the panel toggles.
	KindDigest = "digest"
	// KindBot is news about the bot itself, for owners: a chat that stopped accepting its messages.
	// Nobody switches it off, since it says that alerts are not arriving.
	KindBot = "bot"
)

// AlertKinds lists every kind, in the order the panel shows them.
var AlertKinds = []string{KindExits, KindSwitches, KindUplink, KindCore, KindApply, KindBoot, KindSystem, KindUpdates}

// Severity decides how an alert is delivered.
type Severity int

// Severities, from quiet to loud.
const (
	// SevInfo arrives silently (no sound) and waits out quiet hours and mutes.
	SevInfo Severity = iota
	// SevWarning arrives with a sound, but waits out quiet hours and mutes.
	SevWarning
	// SevCritical always arrives at once: quiet hours and mutes do not hold it.
	SevCritical
	// SevAction asks an owner to decide something now (keep or roll back); never held.
	SevAction
)

// Alert is one thing worth telling the chats.
type Alert struct {
	Kind string
	Sev  Severity
	At   time.Time
	// Incident ties an opening alert to the later ones about the same thing, so a recovery arrives
	// as a reply to the outage and a countdown edits the message it counts down in. "" = one-off.
	Incident string
	// Incidents are several incidents told in one message: exits failing, or coming back, together.
	// Each one's later news replies to that message, and a resolving alert closes them all.
	Incidents []string
	// Resolves marks the alert that ends its incident.
	Resolves bool
	// Edit updates the incident's opening message in place instead of sending anything; chats that
	// never got the opening message get nothing.
	Edit bool
	// Scheduled is news the owner asked for at a set time (the daily digest). Quiet hours and mutes
	// do not hold it, since its time is itself the owner's choice, and it always arrives silently.
	Scheduled bool
	// Owners limits the alert to owner chats.
	Owners bool
	// Render is the full message for one chat's language and role.
	Render func(lang, role string) (string, *Keyboard)
	// Line is the same news in one line, for the summary after quiet hours or a mute.
	Line func(lang string) string
	// Closed, when set on a resolving alert, replaces the opening message's text and removes its
	// buttons, so a stale Keep button cannot be pressed after the window ended.
	Closed func(lang string) string
}

// Callback data for alert buttons.
const (
	cbMute     = "mu:" // + minutes; 0 unmutes
	cbKeep     = "ak"  // keep the test Apply
	cbRollback = "ar"  // roll the test Apply back
)

// alertKeyboard is the standard row under an alert: the status, and a mute for the kinds that can
// wait.
func alertKeyboard(lang string, sev Severity) *Keyboard {
	row := []InlineButton{btn(T(lang, "b.status"), cbStatus)}
	if sev == SevInfo || sev == SevWarning {
		row = append(row, btn(T(lang, "b.mute"), cbMute+"60"))
	}
	return &Keyboard{Rows: [][]InlineButton{row}}
}

// applyKeyboard offers Keep and Roll back to owners, and only the status to everyone else.
func applyKeyboard(lang, role string) *Keyboard {
	if role != roleOwner {
		return &Keyboard{Rows: [][]InlineButton{{btn(T(lang, "b.status"), cbStatus)}}}
	}
	return &Keyboard{Rows: [][]InlineButton{
		{btn(T(lang, "b.keep"), cbKeep), btn(T(lang, "b.rollback"), cbRollback)},
		{btn(T(lang, "b.status"), cbStatus)},
	}}
}

// simpleAlert builds an alert whose text does not depend on the role.
func simpleAlert(kind string, sev Severity, at time.Time, text func(lang string) string) Alert {
	return Alert{Kind: kind, Sev: sev, At: at,
		Render: func(lang, _ string) (string, *Keyboard) { return text(lang), alertKeyboard(lang, sev) },
		Line:   func(lang string) string { return firstLine(text(lang)) },
	}
}

// incidents is every incident the alert opens, continues or resolves.
func (a Alert) incidents() []string {
	if a.Incident == "" {
		return a.Incidents
	}
	return append([]string{a.Incident}, a.Incidents...)
}

// firstLine is the headline of a message, for summaries.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
