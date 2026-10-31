package importer

import (
	"encoding/json"
	"fmt"
	"strings"

	"wayhop/internal/model"
)

// linkFinalMask reads a link's Xray finalmask (fm=, model.ParseFinalMask) into e. It used to be
// dropped without a word, so a link whose server undoes a mask imported as a connection that failed
// every handshake with nothing to say why (QA-136). Now such a link is refused, naming the mask, and
// so is one whose fm Xray itself would refuse. The rest imports and keeps fm as it came, to be
// exported again; the Apply review names the masks that only the sending side applies, which
// sing-box leaves out.
func linkFinalMask(e *model.Endpoint, raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	fm, err := model.ParseFinalMask(raw)
	if err != nil {
		return fmt.Errorf("fm= (Xray finalmask) is %v", err)
	}
	if len(fm.Peer) > 0 {
		return fmt.Errorf("fm= (Xray finalmask) asks for the %s mask, which the server undoes and sing-box does not implement",
			strings.Join(fm.Peer, ", "))
	}
	e.Params[model.ParamFinalMask] = raw
	return nil
}

// linkQueryValue reads key from a share link's raw query as v2rayN reads it (Utils.ParseQueryString,
// 7.25.6): pairs split on '&' alone, a pair without '=' skipped, the key cut from the value at the
// first '=', both percent-decoded leniently (Uri.UnescapeDataString: '+' stays '+', and an escape that
// is not %XX stays as written), keys matched without regard to case, the first pair for a key kept.
// fm= is read this way because url.Values drops a pair holding a raw ';' or a bad escape, matches
// keys exactly and reads '+' as a space: a mask v2rayN applies could import without a word, or come
// back changed when the link was shared again.
func linkQueryValue(rawQuery, key string) string {
	for _, part := range strings.Split(rawQuery, "&") {
		k, v, ok := strings.Cut(part, "=")
		if ok && strings.EqualFold(lenientUnescape(k), key) {
			return lenientUnescape(v)
		}
	}
	return ""
}

// lenientUnescape decodes every %XX in s and leaves the rest, a '+' or a '%' not followed by two hex
// digits included, as written.
func lenientUnescape(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	hexval := func(c byte) (byte, bool) {
		switch {
		case '0' <= c && c <= '9':
			return c - '0', true
		case 'a' <= c && c <= 'f':
			return c - 'a' + 10, true
		case 'A' <= c && c <= 'F':
			return c - 'A' + 10, true
		}
		return 0, false
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := hexval(s[i+1])
			lo, ok2 := hexval(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// vmessFinalMask returns a VMess JSON's "fm" as finalmask JSON: 3x-ui writes it as a string; an
// object is taken as written out.
func vmessFinalMask(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case map[string]any:
		if b, err := json.Marshal(t); err == nil {
			return string(b)
		}
	}
	// Anything else is no finalmask, and ParseFinalMask says so.
	return asString(v)
}
