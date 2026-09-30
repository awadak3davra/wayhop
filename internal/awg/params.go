package awg

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The value grammars here are the ones the userspace path hands to amneziawg-go verbatim, read from
// the pinned source: device/obf*.go and device/noise-types.go at v3.1.20260828 for the grammar,
// amneziawg-tools src/config.c and src/type.c at v3.1.20260812 for the .conf spellings a config
// arrives in.

// MaxDatagram is the largest UDP payload an IPv4 socket can send (65535 - 20 - 8). A junk packet and
// an I-packet each leave as one datagram, so anything larger can never be sent - and amneziawg-go
// allocates the whole buffer before it finds that out.
const MaxDatagram = 65507

// ParseRange reads an H1-H4, timing or keepalive value the way both upstream parsers do: "n" or
// "lo-hi" in decimal, lo <= hi. max is the field's own bound.
func ParseRange(s string, max uint32) (lo, hi uint32, err error) {
	a, b, isRange := strings.Cut(s, "-")
	l, err := strconv.ParseUint(a, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("%q is neither a number nor a lo-hi range", s)
	}
	h := l
	if isRange {
		if h, err = strconv.ParseUint(b, 10, 32); err != nil {
			return 0, 0, fmt.Errorf("%q is neither a number nor a lo-hi range", s)
		}
	}
	if h < l {
		return 0, 0, fmt.Errorf("range %q runs backwards", s)
	}
	if h > uint64(max) {
		return 0, 0, fmt.Errorf("%q is above %d", s, max)
	}
	return uint32(l), uint32(h), nil
}

// ParseBool reads RandomTrailers and DisableCookies as amneziawg-tools does (parse_bool in
// src/config.c): on or off in any case, or a decimal number where anything but 0 is on. true and
// false are accepted as well, because an API caller writes them; the tools would refuse them, but
// nothing reads them two ways.
func ParseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on", "true":
		return true, nil
	case "off", "false":
		return false, nil
	}
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return false, fmt.Errorf("%q is neither on/off nor a number", s)
	}
	return n != 0, nil
}

// GoIPacket prepares an I1-I5 value for amneziawg-go: the spec to send ("" when there is nothing to
// send) and a note for the operator when the value had to be changed.
//
// Three shapes are rewritten rather than refused, because each already runs on the kernel path or is
// skipped by every implementation, and refusing would take down a tunnel that works today:
//   - a value with no tag at all ("0xa1b2..."): neither upstream parser builds anything from it, so
//     it is not sent. AmneziaVPN writes I1-I5 this way, and the packets were never on the wire.
//   - <c>, the kernel module's 4-byte packet counter, which amneziawg-go does not have and refuses:
//     sent as <r 4>, which keeps the packet's length - the thing a length-matching censor sees.
//   - text between tags, which both parsers skip: dropped.
//
// What upstream would refuse is refused here with the reason (an unknown tag, a malformed one), and
// so is what it would not refuse but should: a negative length, on which amneziawg-go panics
// allocating the packet, and a packet too large to leave as one datagram.
func GoIPacket(spec string) (out, note string, err error) {
	rest := strings.TrimSpace(spec)
	if rest == "" {
		return "", "", nil
	}
	var b strings.Builder
	var notes []string
	// int64, because int is 32 bits on the mips routers: a <r 2147483647> added to a few bytes
	// would wrap negative there and slip under the datagram check below.
	var size int64
	stray := false
	for {
		start := strings.IndexByte(rest, '<')
		if start < 0 {
			stray = stray || strings.TrimSpace(rest) != ""
			break
		}
		stray = stray || strings.TrimSpace(rest[:start]) != ""
		end := strings.IndexByte(rest[start:], '>')
		if end < 0 {
			return "", "", errors.New("a tag is missing its closing >")
		}
		end += start
		fields := strings.Fields(rest[start+1 : end])
		rest = rest[end+1:]
		if len(fields) == 0 {
			return "", "", errors.New("empty tag <>")
		}
		if len(fields) > 2 {
			return "", "", fmt.Errorf("<%s> takes at most one value, not %q", fields[0], strings.Join(fields[1:], " "))
		}
		key, val := fields[0], ""
		if len(fields) > 1 {
			val = fields[1]
		}
		switch key {
		case "b":
			h := strings.TrimPrefix(val, "0x")
			if h == "" || len(h)%2 != 0 {
				return "", "", errors.New("<b> needs an even, non-zero number of hex digits")
			}
			if _, err := hex.DecodeString(h); err != nil {
				return "", "", fmt.Errorf("<b %s> is not hex", val)
			}
			size += int64(len(h) / 2)
			b.WriteString("<b 0x" + h + ">")
		case "t", "d", "ds":
			if val != "" {
				return "", "", fmt.Errorf("<%s> takes no value", key)
			}
			if key == "t" {
				size += 4 // a 32-bit timestamp; <d> and <ds> carry the packet's data, and an I-packet has none
			}
			b.WriteString("<" + key + ">")
		case "r", "rc", "rd", "dz":
			n, err := strconv.ParseUint(val, 10, 31)
			if err != nil {
				return "", "", fmt.Errorf("<%s> needs a length in bytes, not %q", key, val)
			}
			size += int64(n)
			fmt.Fprintf(&b, "<%s %d>", key, n)
		case "c":
			if val != "" {
				return "", "", errors.New("<c> takes no value")
			}
			size += 4
			b.WriteString("<r 4>")
			notes = append(notes, "<c> (the kernel module's packet counter) does not exist in amneziawg-go; sent as <r 4>, same length")
		default:
			return "", "", fmt.Errorf("unknown tag <%s>", key)
		}
		if size > MaxDatagram {
			return "", "", fmt.Errorf("the packet is over %d bytes, the most one UDP datagram carries", MaxDatagram)
		}
	}
	if b.Len() == 0 {
		return "", "no <tag> in it, so neither amneziawg-go nor the kernel module builds a packet from it (write it as <b 0x...>); not sent", nil
	}
	if stray {
		notes = append(notes, "text outside the <tags> is skipped by amneziawg-go; dropped")
	}
	return b.String(), strings.Join(notes, "; "), nil
}
