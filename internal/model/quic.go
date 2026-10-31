package model

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// QUIC tuning on a Hysteria2 or TUIC connection: two Params that sing-box carries from 1.14 as the
// outbound's "QUIC Fields" (docs/configuration/shared/quic.md, option.QUICOptions embedded in
// Hysteria2OutboundOptions and TUICOutboundOptions):
//
//	initial_packet_size         the size QUIC starts at and never goes below, in bytes. quic-go reads
//	                            1200 to 1452 (it raises a smaller value to 1200 and cuts a larger one
//	                            to 1452); unset, it starts at 1280. Saving refuses another size
//	                            (QUICTuningProblem); an import clamps one (QUICEffectiveInitialPacketSize).
//	disable_path_mtu_discovery  true: never probe for a larger size, so packets stay at the initial one.
//
// Both are for links that lose large UDP packets without saying so (PPPoE, LTE, a VPN inside a VPN):
// path MTU discovery there settles on a size the path then drops, and the connection stalls after it
// starts. On Hysteria2 the client parrots Chrome's QUIC handshake unless disable_chrome_parrot is set,
// and Chrome's own initial size (1250) then replaces initial_packet_size; disable_path_mtu_discovery
// applies either way. A core older than 1.14 refuses both keys at decode ("json: unknown field"), so
// the generator leaves them out there and the Apply review says so (generator.QUICTuningNeedsNewerCore).
const (
	ParamQUICInitialPacketSize = "initial_packet_size"
	ParamQUICDisablePMTUD      = "disable_path_mtu_discovery"

	// QUICMinInitialPacketSize and QUICMaxInitialPacketSize are quic-go's own bounds
	// (protocol.MinInitialPacketSize, protocol.MaxPacketBufferSize in the quic-go sing-box builds).
	QUICMinInitialPacketSize = 1200
	QUICMaxInitialPacketSize = 1452
)

// CarriesQUICTuning reports whether proto's sing-box outbound has the QUIC fields.
func CarriesQUICTuning(proto Protocol) bool {
	return proto == ProtoHysteria2 || proto == ProtoTUIC
}

// QUICTuningOf returns e's QUIC tuning: the initial packet size (0 when unset or outside
// QUICMinInitialPacketSize..QUICMaxInitialPacketSize, which is then left out rather than guessed at)
// and whether path MTU discovery is off. Both are zero for a protocol without the fields.
func QUICTuningOf(e *Endpoint) (initialPacketSize int, noPathMTUDiscovery bool) {
	if e == nil || !CarriesQUICTuning(e.Protocol) {
		return 0, false
	}
	if n, ok := paramWholeNumber(e.Params[ParamQUICInitialPacketSize]); ok && ValidQUICInitialPacketSize(n) {
		initialPacketSize = n
	}
	return initialPacketSize, ParamBool(e.Params, ParamQUICDisablePMTUD)
}

// HasQUICTuning reports whether e sets either QUIC field to something the generator emits.
func HasQUICTuning(e *Endpoint) bool {
	n, off := QUICTuningOf(e)
	return n > 0 || off
}

// ValidQUICInitialPacketSize reports whether n is a size quic-go uses as given.
func ValidQUICInitialPacketSize(n int) bool {
	return n >= QUICMinInitialPacketSize && n <= QUICMaxInitialPacketSize
}

// QUICTuningProblem says what is wrong with a Hysteria2 or TUIC connection's initial_packet_size, ""
// when nothing is. A size outside 1200..1452 is refused at save: sing-box takes it, quic-go then runs
// with another one, and the generator, which emits only a size used as given, would leave it out
// with nothing to show for it. Absent, empty or 0 (sing-box's own "unset") is no size at all.
func QUICTuningProblem(e *Endpoint) string {
	if e == nil || !CarriesQUICTuning(e.Protocol) {
		return ""
	}
	v, ok := e.Params[ParamQUICInitialPacketSize]
	if !ok || v == nil {
		return ""
	}
	if s, isStr := v.(string); isStr && strings.TrimSpace(s) == "" {
		return ""
	}
	if n, whole := paramWholeNumber(v); whole && (n == 0 || ValidQUICInitialPacketSize(n)) {
		return ""
	}
	return fmt.Sprintf("%s %v out of range (%d-%d)", ParamQUICInitialPacketSize, v, QUICMinInitialPacketSize, QUICMaxInitialPacketSize)
}

// QUICEffectiveInitialPacketSize is the size a sing-box 1.14 core starts at when its config says n:
// 0 (the default) for n not above 0, else n cut to 16 bits (sing-quic's ApplyQUICOptions converts
// with uint16) and clamped into quic-go's range, as quic-go's validateConfig does. An imported config
// is read through it, so the connection keeps the size the source ran with.
func QUICEffectiveInitialPacketSize(n int) int {
	if n <= 0 {
		return 0
	}
	v := n & 0xffff
	if v == 0 {
		return 0
	}
	return min(max(v, QUICMinInitialPacketSize), QUICMaxInitialPacketSize)
}

// paramWholeNumber reads a whole number from the shapes a param takes: int from an import, float64
// after a JSON store round-trip, a string from the API.
func paramWholeNumber(v any) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		if t >= math.MinInt32 && t <= math.MaxInt32 {
			return int(t), true
		}
	case float64:
		if t == math.Trunc(t) && t >= math.MinInt32 && t <= math.MaxInt32 {
			return int(t), true
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n, true
		}
	}
	return 0, false
}
