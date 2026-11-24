package keenetic

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"wayhop/internal/awg"
)

// asc31.go writes the AmneziaWG 3.x tail of `wireguard asc`, in the order KeeneticOS 5.2 prints it
// (Named31 in wgasc.go has the evidence): after the 16 arguments of the 2.0 form, the header
// protection key, then the content padding and the five timers each as a start and an end, then
// RandomTrailers and DisableCookies as 1 or 0.

// asc31Ranges is the order of the six range arguments, under the names the model stores them by.
var asc31Ranges = []string{
	"content_padding_addition", "rekey_after_time", "rekey_timeout",
	"reject_after_time", "keepalive_timeout", "max_handshake_attempts",
}

// ascMaxRange bounds each range end, as the plugin bounds them (math.MaxUint16).
const ascMaxRange = math.MaxUint16

// asc31Tail renders the 3.x arguments for params. missing lists the settings the line cannot be
// written without: the header protection key and the five timers. A timer or key the connection
// does not carry is not filled with a guess - a made-up value is a tunnel the server never answers -
// so the line is not written at all. The content padding and the two switches default to off, which
// is what unset means everywhere else. err is a value that does not read as one.
func asc31Tail(p map[string]any) (tail, missing []string, err error) {
	key := strings.TrimSpace(str(p, "header_protection_key"))
	if key == "" {
		missing = append(missing, "header_protection_key")
	} else {
		tail = append(tail, wgKey(key))
	}
	for _, k := range asc31Ranges {
		v := strings.TrimSpace(numStr(p[k]))
		if v == "" {
			if k == "content_padding_addition" {
				v = "0"
			} else {
				missing = append(missing, k)
				continue
			}
		}
		lo, hi, perr := awg.ParseRange(v, ascMaxRange)
		if perr != nil {
			return nil, nil, fmt.Errorf("%s: %v", k, perr)
		}
		tail = append(tail, strconv.FormatUint(uint64(lo), 10), strconv.FormatUint(uint64(hi), 10))
	}
	for _, k := range []string{"random_trailers", "disable_cookies"} {
		on := false
		switch v := p[k].(type) {
		case nil:
		case bool:
			on = v
		default:
			if text := strings.TrimSpace(numStr(v)); text != "" {
				b, perr := awg.ParseBool(text)
				if perr != nil {
					return nil, nil, fmt.Errorf("%s: %v", k, perr)
				}
				on = b
			}
		}
		if on {
			tail = append(tail, "1")
		} else {
			tail = append(tail, "0")
		}
	}
	return tail, missing, nil
}

// ASC31Missing lists, in order, the settings an endpoint with AmneziaWG 3.x settings still has to
// carry before its `wireguard asc` line can be written (see asc31Tail). Empty for an endpoint with no
// 3.x setting, and for one that is complete. The planner asks it so such an endpoint stays on
// WayHop's own AmneziaWG engine rather than reaching the writer and failing there.
func ASC31Missing(p map[string]any) []string {
	if awg.Need(p) <= awg.Gen2 {
		return nil
	}
	_, missing, _ := asc31Tail(p)
	return missing
}
