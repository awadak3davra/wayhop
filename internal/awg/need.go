package awg

import (
	"sort"
	"strconv"
	"strings"
)

// What a connection needs is read from the settings it carries, each against the generation that
// introduced it. One table serves every caller that has to agree on it: the plugin, which picks the
// kernel module or amneziawg-go by it, and the native planners, which must not hand a router's own
// AmneziaWG a connection whose settings its writer would drop. Upstream requires every setting except
// Jc/Jmin/Jmax to match the server's, so a dropped setting is not a lost refinement - the server stops
// answering, while the router reports the tunnel as configured.

// settingGen is the generation that introduced each setting a connection's Params can carry, under
// the name the importer stores it by, which is the name UAPI uses too. It follows the attribute each
// setting was added as in upstream's src/uapi/wireguard.h: J, S1, S2 and single H values are
// generation 1; S3, S4, I1-I5 and H ranges arrived with generation 2; the header protection key,
// content padding and the five timers with 3.0; RandomTrailers and DisableCookies with 3.1.
var settingGen = map[string]Generation{
	"jc": Gen1, "jmin": Gen1, "jmax": Gen1, "s1": Gen1, "s2": Gen1,
	"h1": Gen1, "h2": Gen1, "h3": Gen1, "h4": Gen1,
	"s3": Gen2, "s4": Gen2,
	"i1": Gen2, "i2": Gen2, "i3": Gen2, "i4": Gen2, "i5": Gen2,
	"header_protection_key": Gen30, "content_padding_addition": Gen30,
	"rekey_after_time": Gen30, "rekey_timeout": Gen30, "reject_after_time": Gen30,
	"keepalive_timeout": Gen30, "max_handshake_attempts": Gen30,
	"random_trailers": Gen31, "disable_cookies": Gen31,
}

// Settings lists, sorted, every setting Need knows. A writer's tests walk it to prove the writer
// expresses each setting up to the generation it claims, and nothing is left out by accident.
func Settings() []string {
	out := make([]string, 0, len(settingGen))
	for key := range settingGen {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// settingNeed is the generation a setting asks for with the value it carries: GenNone when it asks
// for nothing. That is an unset value, and a 3.1 switch that is off - what every earlier generation
// does anyway, so a config that spells the default out still runs anywhere. An H value written as a
// range is a 2.0 setting even though H itself is 1.0.
func settingNeed(key string, value any) Generation {
	gen, known := settingGen[key]
	if !known {
		return GenNone
	}
	if gen == Gen31 {
		if on, ok := settingBool(value); ok && on {
			return gen
		}
		return GenNone
	}
	text := settingText(value)
	if text == "" {
		return GenNone
	}
	if gen == Gen1 && key[0] == 'h' && strings.Contains(text, "-") {
		return Gen2
	}
	return gen
}

// Need is the lowest generation that carries every setting in params, a connection's Params as the
// model stores them (strings from an import, numbers from the API or a JSON round trip). It is never
// below Gen1: even a connection with no AmneziaWG settings needs the amneziawg family to exist.
func Need(params map[string]any) Generation {
	need := Gen1
	for key, value := range params {
		if g := settingNeed(key, value); g > need {
			need = g
		}
	}
	return need
}

// Beyond lists, sorted, the settings in params that need a newer generation than g: what a writer
// that expresses g would drop.
func Beyond(params map[string]any, g Generation) []string {
	var out []string
	for key, value := range params {
		if settingNeed(key, value) > g {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// settingText reads a value the way the plugin renders it: numbers in decimal, strings as stored.
// A float64 goes through int64, not int - H values routinely exceed 2^31 and int is 32 bits on the
// mips and arm routers.
func settingText(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatInt(int64(v), 10)
	}
	return ""
}

// settingBool reads a switch in any shape the model stores one: a JSON bool, or text and numbers in
// the forms ParseBool accepts. ok is false for an unset or unreadable value; the plugin refuses the
// unreadable ones when it translates the config, so here they ask for nothing.
func settingBool(value any) (on, ok bool) {
	if b, isBool := value.(bool); isBool {
		return b, true
	}
	text := settingText(value)
	if text == "" {
		return false, false
	}
	b, err := ParseBool(text)
	if err != nil {
		return false, false
	}
	return b, true
}
