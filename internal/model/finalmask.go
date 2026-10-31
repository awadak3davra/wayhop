package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Xray's finalmask (StreamSettings.finalmask, Xray-core transport/internet/finalmask): masks that
// transform a stream's connection beneath TLS, in a "tcp" list and a "udp" list of {type, settings},
// beside "quicParams", QUIC tuning that only Xray's QUIC transports read. v2rayN and 3x-ui carry it in
// a share link as fm=<JSON> (VLESS, Trojan, Shadowsocks, AnyTLS; v2rayN reads it on TUIC and Hysteria2
// links too), and 3x-ui as the "fm" string of a VMess link's JSON. sing-box implements no mask, so
// what each one does decides whether a connection works without it. The type names are Xray's
// (infra/conf/transport_finalmask.go, matched without regard to case), the behaviour each mask's
// config.go, both at v26.10.29:
//
//   - filter does nothing on a client: its client wrappers return the connection unchanged.
//   - fragment (only Write is wrapped), noise (only WriteTo) and udphop (its server wrapper refuses:
//     "udphop: client only") change only what the client sends. The server reads the connection as
//     usual, so it works without them, without that evasion.
//   - Every other mask transforms the connection at both ends (header-custom, mkcp-legacy,
//     salamander and its gecko form, sudoku, xdns, xicmp, xmc, realm): the server undoes it, and
//     without it every connection fails.
//
// Xray refuses the config over a type it does not know for that list, and over JSON its loader cannot
// decode: a list or a mask that is not one, or a value of the wrong JSON type in "quicParams" or in a
// mask's "settings" (infra/conf/loader.go and serial/loader.go decode with encoding/json, which, as
// in Xray, ignores keys it does not know). The importers refuse those too, checking the settings of
// the masks they accept, and a link with a mask the server undoes; the rest is kept as the link held
// it, in ParamFinalMask, to be exported again. What a mask's Build then checks of the values (a
// fragment length of 0, a noise script that does not compile) is not repeated: sing-box applies none
// of it.

// ParamFinalMask holds a link's fm= as it came: Xray's finalmask JSON, kept only to be exported.
const ParamFinalMask = "fm"

// finalMaskKind is what a mask does on a client (see above).
type finalMaskKind int

const (
	finalMaskNoop   finalMaskKind = iota // nothing on a client
	finalMaskSender                      // only what the client sends
	finalMaskPeer                        // both ends: the server undoes it
)

// finalMaskTypes are Xray's mask types per list (tcpmaskLoader, udpmaskLoader).
var finalMaskTypes = map[string]map[string]finalMaskKind{
	"tcp": {"filter": finalMaskNoop, "header-custom": finalMaskPeer, "fragment": finalMaskSender,
		"sudoku": finalMaskPeer, "xmc": finalMaskPeer},
	"udp": {"filter": finalMaskNoop, "header-custom": finalMaskPeer, "mkcp-legacy": finalMaskPeer,
		"noise": finalMaskSender, "salamander": finalMaskPeer, "sudoku": finalMaskPeer, "xdns": finalMaskPeer,
		"xicmp": finalMaskPeer, "realm": finalMaskPeer, "udphop": finalMaskSender},
}

// FinalMask is what a finalmask asks of a client, by mask type, each named once in the order given.
type FinalMask struct {
	Sender []string // masks that change only what the client sends
	Peer   []string // masks the server undoes, which the connection cannot work without
}

// ParseFinalMask reads a finalmask's JSON. The error never quotes the value: a mask's settings hold
// its password.
func ParseFinalMask(raw string) (FinalMask, error) {
	var out FinalMask
	if !bytes.HasPrefix(bytes.TrimSpace([]byte(raw)), []byte("{")) {
		return out, errors.New("not a JSON object")
	}
	type mask struct {
		Type     string          `json:"type"`
		Settings json.RawMessage `json:"settings"`
	}
	var fm struct {
		TCP        []mask         `json:"tcp"`
		UDP        []mask         `json:"udp"`
		QuicParams *finalMaskQUIC `json:"quicParams"`
	}
	if err := json.Unmarshal([]byte(raw), &fm); err != nil {
		var se *json.SyntaxError
		var te *json.UnmarshalTypeError
		switch {
		case errors.As(err, &se):
			return out, errors.New("not valid JSON")
		case errors.As(err, &te) && strings.HasPrefix(te.Field, "quicParams"):
			return out, errors.New(`not Xray's finalmask: "quicParams" holds a value of the wrong type`)
		}
		return out, errors.New(`not Xray's finalmask: "tcp" and "udp" are lists of {"type", "settings"}`)
	}
	seen := map[string]bool{}
	for _, l := range []struct {
		name  string
		masks []mask
	}{{"tcp", fm.TCP}, {"udp", fm.UDP}} {
		for _, m := range l.masks {
			typ := strings.ToLower(m.Type)
			kind, ok := finalMaskTypes[l.name][typ]
			if !ok {
				if len(typ) > 24 {
					typ = typ[:24] + "..."
				}
				return FinalMask{}, fmt.Errorf("unknown %s mask %q", l.name, typ)
			}
			if shape := finalMaskSettings[typ]; shape != nil && len(m.Settings) > 0 {
				if err := json.Unmarshal(m.Settings, shape()); err != nil {
					return FinalMask{}, fmt.Errorf("the %s mask's settings are not what Xray reads", typ)
				}
			}
			if seen[typ] {
				continue
			}
			seen[typ] = true
			switch kind {
			case finalMaskSender:
				out.Sender = append(out.Sender, typ)
			case finalMaskPeer:
				out.Peer = append(out.Peer, typ)
			}
		}
	}
	return out, nil
}

// finalMaskSettings are the settings of the masks a client may carry without the server (Filter,
// FragmentMask, NoiseMask and UDPHop in transport_finalmask.go) as JSON shapes: decoding into one
// fails where Xray's loader fails. A mask the server undoes is refused by its type alone.
var finalMaskSettings = map[string]func() any{
	"filter": func() any {
		return &struct {
			BlockedSourceIPs []string `json:"blockedSourceIPs"`
			AllowedSourceIPs []string `json:"allowedSourceIPs"`
		}{}
	},
	"fragment": func() any {
		return &struct {
			Packets  string           `json:"packets"`
			Length   finalMaskRange   `json:"length"`
			Delay    finalMaskRange   `json:"delay"`
			Lengths  []finalMaskRange `json:"lengths"`
			Delays   []finalMaskRange `json:"delays"`
			MaxSplit finalMaskRange   `json:"maxSplit"`
		}{}
	},
	"noise": func() any {
		return &struct {
			Reset finalMaskRange `json:"reset"`
			Noise []struct {
				Rand      finalMaskRange  `json:"rand"`
				RandRange *finalMaskRange `json:"randRange"`
				Type      string          `json:"type"`
				Packet    json.RawMessage `json:"packet"`
				Delay     finalMaskRange  `json:"delay"`
			} `json:"noise"`
			Script string `json:"script"`
		}{}
	},
	"udphop": func() any {
		return &struct {
			Mode        string         `json:"mode"`
			Interval    finalMaskRange `json:"interval"`
			RemoteIPs   []string       `json:"remoteIPs"`
			RemotePorts finalMaskPorts `json:"remotePorts"`
		}{}
	},
}

// finalMaskQUIC is QuicParamsConfig's JSON shape; brutalUp and brutalDown are Bandwidth, a string.
type finalMaskQUIC struct {
	Congestion                    string `json:"congestion"`
	Debug                         bool   `json:"debug"`
	BbrProfile                    string `json:"bbrProfile"`
	BrutalUp                      string `json:"brutalUp"`
	BrutalDown                    string `json:"brutalDown"`
	BrutalDisableLossCompensation bool   `json:"brutalDisableLossCompensation"`
	InitStreamReceiveWindow       uint64 `json:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow        uint64 `json:"maxStreamReceiveWindow"`
	InitConnectionReceiveWindow   uint64 `json:"initConnectionReceiveWindow"`
	MaxConnectionReceiveWindow    uint64 `json:"maxConnectionReceiveWindow"`
	MaxIdleTimeout                int64  `json:"maxIdleTimeout"`
	KeepAlivePeriod               int64  `json:"keepAlivePeriod"`
	DisablePathMTUDiscovery       bool   `json:"disablePathMTUDiscovery"`
	DisableChromeParrot           bool   `json:"disableChromeParrot"`
	DisableGSO                    bool   `json:"disableGSO"`
	MaxIncomingStreams            int64  `json:"maxIncomingStreams"`
	DisableStatelessReset         bool   `json:"disableStatelessReset"`
}

var errFinalMaskValue = errors.New("not what Xray reads")

// finalMaskRange decodes as Xray's Int32Range (infra/conf/common.go): a string holding a number, a
// range ("1-2", "-5-10") or nothing, or else a number that fits in 32 bits.
type finalMaskRange struct{}

func (*finalMaskRange) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		if finalMaskRangeString(s) {
			return nil
		}
		return errFinalMaskValue
	}
	var n int32
	return json.Unmarshal(b, &n)
}

// finalMaskRangeString reports whether Xray's ParseRangeString takes s: a leading '-' belongs to the
// first number.
func finalMaskRangeString(s string) bool {
	if _, err := strconv.Atoi(s); err == nil || s == "" {
		return true
	}
	pair := strings.SplitN(s, "-", 2)
	if strings.HasPrefix(s, "-") {
		p := strings.SplitN(s, "-", 3)
		if len(p) != 3 {
			return false
		}
		pair = []string{"-" + p[1], p[2]}
	}
	if len(pair) != 2 {
		return false
	}
	_, e1 := strconv.Atoi(pair[0])
	_, e2 := strconv.Atoi(pair[1])
	return e1 == nil && e2 == nil
}

// finalMaskPorts decodes as Xray's PortList: a number, or a string of ports and ranges joined by
// commas, each port at most 65535. A part starting "env:" names an environment variable the client
// reads, so it is not checked here.
type finalMaskPorts struct{}

func (*finalMaskPorts) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) != nil {
		var n uint32
		return json.Unmarshal(b, &n)
	}
	port := func(p string) bool {
		v, err := strconv.ParseUint(p, 10, 32)
		return err == nil && v <= 65535
	}
	for _, part := range strings.Split(s, ",") {
		p := strings.TrimSpace(part)
		switch {
		case p == "", strings.HasPrefix(p, "env:"):
		case strings.Contains(p, "-") || strings.Contains(p, "env:"):
			from, to, _ := strings.Cut(p, "-")
			if !port(from) || (strings.Contains(p, "-") && !port(to)) {
				return errFinalMaskValue
			}
		default:
			var n uint32
			if json.Unmarshal([]byte(p), &n) != nil || n > 65535 {
				return errFinalMaskValue
			}
		}
	}
	return nil
}
