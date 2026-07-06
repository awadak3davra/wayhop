package iptv

import "strings"

// Render emits a clean M3U8 playlist from channels that have already been filtered/deduped/sorted.
// urlTvg, when non-empty, is written as the #EXTM3U url-tvg="…" header so the EPG guide passes
// through to the player. Each channel becomes:
//
//	#EXTINF:-1 tvg-id="…" tvg-logo="…" group-title="…" <preserved extra attrs>,<Name>
//	<preserved #EXTVLCOPT/#EXTHTTP/#KODIPROP lines, verbatim>
//	<URL>
//
// The extra attrs are Channel.Extra — every EXTINF attribute Parse didn't model (tvg-chno, catchup*,
// tvg-shift, tvg-name, …), so provider channel numbers / catch-up / EPG shift survive the passthrough.
// Empty attributes are omitted. Output is UTF-8, LF line endings, NO BOM. A channel with an empty
// URL is skipped (unplayable — the filter normally removes these, but Render is defensive).
func Render(chs []Channel, urlTvg string) []byte {
	var b strings.Builder
	b.WriteString("#EXTM3U")
	if urlTvg != "" {
		b.WriteString(` url-tvg="`)
		b.WriteString(attrValue(urlTvg))
		b.WriteByte('"')
	}
	b.WriteByte('\n')
	for _, c := range chs {
		if c.URL == "" {
			continue
		}
		b.WriteString("#EXTINF:-1")
		writeAttr(&b, "tvg-id", c.TvgID)
		writeAttr(&b, "tvg-logo", c.Logo)
		writeAttr(&b, "group-title", c.Group)
		for _, kv := range c.Extra { // preserved provider attrs (tvg-chno, catchup*, tvg-shift, …)
			writeAttr(&b, kv[0], kv[1])
		}
		b.WriteByte(',')
		b.WriteString(c.Name)
		b.WriteByte('\n')
		for _, h := range c.Headers {
			b.WriteString(h)
			b.WriteByte('\n')
		}
		b.WriteString(c.URL)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func writeAttr(b *strings.Builder, key, val string) {
	if val == "" {
		return
	}
	b.WriteByte(' ')
	b.WriteString(key)
	b.WriteString(`="`)
	b.WriteString(attrValue(val))
	b.WriteByte('"')
}

// attrValue strips characters that would break an EXTINF attribute or line: a double-quote (ends the
// value early) and any newline. iptv-org values don't contain these, but Render stays defensive.
func attrValue(s string) string {
	return strings.NewReplacer(`"`, "", "\n", " ", "\r", "").Replace(s)
}
