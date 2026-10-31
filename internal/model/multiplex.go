package model

import (
	"fmt"
	"strings"
)

// Multiplex (sing-mux) rules, measured on sing-box 1.12.17, 1.13.21, 1.14.4 and 1.15.0-alpha.13,
// whose multiplex options are identical:
//
//   - Only the vless, vmess, trojan and shadowsocks outbounds have the field. On any other one
//     `sing-box check` fails the whole config with `json: unknown field "multiplex"`.
//   - An unknown protocol with enabled true fails the load ("unknown protocol: mux.cool"); with
//     enabled false it is ignored.
//   - Brutal with an upload or download rate of 0 or none fails the load ("brutal: invalid
//     upload/download speed"); a negative one wraps silently when sing-box converts it to uint64.
//   - max_streams beside max_connections or min_streams passes check, but sing-box documents the
//     pair as conflicting and sing-mux ignores max_streams once max_connections is set.
//   - Shadowsocks with udp_over_tcp never builds the multiplex client, so there it does nothing.

// MuxProtocols are the multiplex protocols sing-box accepts. "" is its default, h2mux.
var MuxProtocols = map[string]bool{"h2mux": true, "smux": true, "yamux": true}

// BrutalMaxMbps bounds a TCP Brutal rate. sing-box needs at least 65536 bytes a second, which 1 Mbps
// is; 100 Gbps is far past anything a router sends and keeps a typo from reading as a rate.
const BrutalMaxMbps = 100000

// MultiplexCapable reports whether a protocol's sing-box outbound takes a multiplex block.
func MultiplexCapable(p Protocol) bool {
	switch p {
	case ProtoVLESS, ProtoVMess, ProtoTrojan, ProtoShadowsocks:
		return true
	}
	return false
}

// BrutalRateOK reports whether a TCP Brutal rate (Mbps) is one sing-box loads as asked.
func BrutalRateOK(mbps int) bool { return mbps >= 1 && mbps <= BrutalMaxMbps }

// ParamBool reads a switch from an endpoint's params as the generator does (its boolp): a JSON bool,
// or the string "true", "1" or "yes" that a hand-edited or restored profile can carry. Anything that
// asks what the generator will emit for a switch reads it here, so the two cannot disagree.
func ParamBool(params map[string]any, k string) bool {
	switch v := params[k].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1" || v == "yes"
	}
	return false
}

// MuxUoTIgnored reports whether multiplex is on for a Shadowsocks connection that sends UDP over TCP,
// where sing-box never builds the multiplex client. udp_over_tcp is read as the generator writes it.
func MuxUoTIgnored(e *Endpoint) bool {
	if e.Multiplex == nil || !e.Multiplex.Enabled || e.Protocol != ProtoShadowsocks {
		return false
	}
	return ParamBool(e.Params, "udp_over_tcp")
}

// muxProblem names a multiplex setting refused at save, in Validate's words; "" when there is none or
// multiplex is off. It is asked on save (EndpointParamProblem), not by Validate: the generator leaves
// out what the core would refuse, so one that reached the profile another way (a restored backup, a
// hand-edited file) costs that connection its multiplex, which the Apply review says, and not every
// Apply.
func muxProblem(e *Endpoint) string {
	m := e.Multiplex
	if m == nil || !m.Enabled {
		return ""
	}
	if !MultiplexCapable(e.Protocol) {
		return fmt.Sprintf("multiplex works only on vless, vmess, trojan and shadowsocks, not %s", e.Protocol)
	}
	if m.Protocol != "" && !MuxProtocols[m.Protocol] {
		return fmt.Sprintf("unknown multiplex protocol %q (want h2mux, smux or yamux)", m.Protocol)
	}
	if m.MaxConnections < 0 || m.MinStreams < 0 || m.MaxStreams < 0 {
		return "multiplex connection and stream counts cannot be negative"
	}
	if m.MaxStreams > 0 && (m.MaxConnections > 0 || m.MinStreams > 0) {
		return "multiplex max streams cannot be combined with max connections or min streams"
	}
	if b := m.Brutal; b != nil && b.Enabled {
		if !BrutalRateOK(b.UpMbps) || !BrutalRateOK(b.DownMbps) {
			return fmt.Sprintf("TCP Brutal needs an upload and a download rate of 1 to %d Mbps", BrutalMaxMbps)
		}
		// Brutal holds one connection and the generator leaves the pool out, so a pool beside it
		// would be a setting that does nothing, and a change to it a review row that changes nothing.
		if m.MaxConnections != 0 || m.MinStreams != 0 || m.MaxStreams != 0 {
			return "multiplex connection and stream counts cannot be combined with TCP Brutal, which holds one connection"
		}
	}
	return ""
}

// NormalizeMultiplex is what an importer keeps of a multiplex block it read: nil when it is off, the
// protocol cannot carry it, or its mux protocol is not one sing-box has (most likely an Xray server's
// mux.cool, which no sing-mux setting reaches). Of the rest it keeps what sing-mux acts on: negative
// counts are dropped, max_streams yields to max_connections and min_streams to max_streams (with no
// max_connections sing-mux never reads min_streams), Brutal goes when a rate is out of range, and the
// pool goes when Brutal stays, as Brutal holds one connection.
// The result is never refused by muxProblem. note says what was left out, "" when nothing was.
func NormalizeMultiplex(p Protocol, m *Multiplex) (out *Multiplex, note string) {
	if m == nil || !m.Enabled {
		return nil, ""
	}
	if !MultiplexCapable(p) {
		return nil, fmt.Sprintf("multiplex dropped: sing-box has it only on vless, vmess, trojan and shadowsocks, not %s", p)
	}
	proto := strings.ToLower(strings.TrimSpace(m.Protocol))
	if proto != "" && !MuxProtocols[proto] {
		return nil, fmt.Sprintf("multiplex dropped: %q is not a sing-mux protocol (h2mux, smux, yamux)", m.Protocol)
	}
	c := Multiplex{Enabled: true, Protocol: proto, Padding: m.Padding}
	nonNeg := func(n int) int {
		if n < 0 {
			return 0
		}
		return n
	}
	c.MaxConnections, c.MinStreams, c.MaxStreams = nonNeg(m.MaxConnections), nonNeg(m.MinStreams), nonNeg(m.MaxStreams)
	switch {
	case c.MaxConnections > 0:
		c.MaxStreams = 0
	case c.MaxStreams > 0:
		c.MinStreams = 0
	}
	if b := m.Brutal; b != nil && b.Enabled {
		if BrutalRateOK(b.UpMbps) && BrutalRateOK(b.DownMbps) {
			c.Brutal = &Brutal{Enabled: true, UpMbps: b.UpMbps, DownMbps: b.DownMbps}
			c.MaxConnections, c.MinStreams, c.MaxStreams = 0, 0, 0
		} else {
			note = fmt.Sprintf("TCP Brutal dropped: it needs an upload and a download rate of 1 to %d Mbps", BrutalMaxMbps)
		}
	}
	return &c, note
}
