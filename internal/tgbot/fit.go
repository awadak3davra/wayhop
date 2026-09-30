package tgbot

import (
	"html"
	"strings"
)

// maxText is Telegram's limit for a message, 4096 characters after entities are parsed, less a
// margin for the "…" that says a message was cut.
const maxText = 4000

// maxAnswer is Telegram's limit for the text of an answer to a button press.
const maxAnswer = 200

// fit shortens an HTML message that would be over Telegram's limit. A refused message is simply
// lost, so this is the last line of defence behind the views' own limits (pages, capped lists): it
// keeps the whole lines that fit and says the rest was cut. Every view closes its tags within the
// line that opens them, so a cut between lines leaves valid HTML.
func fit(s string) string {
	if textLen(s) <= maxText {
		return s
	}
	var b strings.Builder
	n := 0
	for _, line := range strings.Split(s, "\n") {
		l := textLen(line) + 1
		if n+l > maxText {
			break
		}
		b.WriteString(line)
		b.WriteByte('\n')
		n += l
	}
	if b.Len() > 0 {
		return b.String() + "…"
	}
	// A single line longer than a whole message: no line fits, so cut its plain text instead.
	n = 0
	var plain strings.Builder
	for _, r := range html.UnescapeString(stripTags(s)) {
		if n += units(r); n > maxText {
			break
		}
		plain.WriteRune(r)
	}
	return html.EscapeString(plain.String()) + "…"
}

// textLen counts what Telegram counts: the text without tags, an entity as one character, in UTF-16
// code units (a character beyond the Basic Multilingual Plane, most emoji among them, is two).
func textLen(s string) int {
	n := 0
	for _, r := range html.UnescapeString(stripTags(s)) {
		n += units(r)
	}
	return n
}

func units(r rune) int {
	if r > 0xFFFF {
		return 2
	}
	return 1
}

// stripTags drops the markup. The views escape every '<' in text, so each one opens a tag.
func stripTags(s string) string {
	var b strings.Builder
	in := false
	for _, r := range s {
		switch {
		case r == '<':
			in = true
		case r == '>' && in:
			in = false
		case !in:
			b.WriteRune(r)
		}
	}
	return b.String()
}
