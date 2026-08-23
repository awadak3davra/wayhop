package server

import (
	"math"
	"time"

	"wayhop/internal/model"
)

// This file is the ONLY place demo (non-router) data is synthesized. `wayhop --demo` has no
// procfs, no sing-box, and no real exits, so every dashboard data source would otherwise read
// "unavailable" and the UI would render an empty shell. The handlers below branch to these
// helpers when s.config().Demo is set, producing believable BUT ENTIRELY SYNTHETIC data:
// every address is an RFC-5737 documentation IP (203.0.113/198.51.100), every ASN is in the
// AS64496-64511 documentation range, and provider names are generic. Nothing here reflects any
// real host, key, or topology — it exists so the demo one-liner and the README screenshots show
// a live-looking dashboard on any OS.

// demoEpochMs is subtracted from wall-clock so synthetic cumulative byte counters stay small
// (well under 2^53, where float64 is still integer-exact) instead of growing into the petabytes.
// It is a fixed constant (2026-01-01 UTC in ms), so successive samples share one time base and
// the client's delta math produces a continuous rate curve across seed history + live polls.
const demoEpochMs = 1767225600000

// demoIface describes one synthetic interface's smooth, always-positive throughput. The cumulative
// counter is the closed-form integral of rate(t) = base*(1 + 0.5*sin(t/period + phase)), i.e.
// base*(t - 0.5*period*cos(...)); its derivative never drops below base/2, so counters are strictly
// monotonic (a decreasing counter would read as a negative rate on the graph).
type demoIface struct {
	name             string
	rxBase, txBase   float64 // bytes/s midline (down, up)
	rxPer, txPer     float64 // oscillation period, seconds
	rxPhase, txPhase float64
	speed            int // /sys link speed advertised (0 = tunnel)
}

// The kernel interfaces that appear as graph lines. Proxy exits (VLESS/Hysteria2) have no kernel
// interface and get their own lines from the per-outbound rate map (demoOutboundRates), keyed to
// the matching DemoProfile endpoint ids so tile colours and graph lines line up.
var demoIfaces = []demoIface{
	{name: "wan", rxBase: 2.6e6, txBase: 9.0e5, rxPer: 41, txPer: 37, rxPhase: 0.0, txPhase: 1.3, speed: 1000},
	{name: "awg-example", rxBase: 1.3e6, txBase: 6.5e5, rxPer: 53, txPer: 47, rxPhase: 2.1, txPhase: 0.7},
}

// demoIfaceCountersAt returns each synthetic interface's cumulative rx/tx byte counters at t.
func demoIfaceCountersAt(t time.Time) []Iface {
	s := float64(t.UnixMilli()-demoEpochMs) / 1000.0
	out := make([]Iface, len(demoIfaces))
	for i, d := range demoIfaces {
		rx := d.rxBase * (s - 0.5*d.rxPer*math.Cos(s/d.rxPer+d.rxPhase))
		tx := d.txBase * (s - 0.5*d.txPer*math.Cos(s/d.txPer+d.txPhase))
		out[i] = Iface{Name: d.name, RxBytes: int64(rx), TxBytes: int64(tx), Up: true, SpeedMbps: d.speed}
	}
	return out
}

// demoSystemInfo synthesizes the host-resource strip (RAM/CPU/uptime/temp) + the interface counters
// that drive the live graph. Values orbit believable router figures for a 256 MB device.
func demoSystemInfo(t time.Time) systemInfo {
	s := float64(t.UnixMilli()-demoEpochMs) / 1000.0
	const memTotalKB = 256 * 1024
	usedPct := 44 + 7*math.Sin(s/29)
	avail := int64(float64(memTotalKB) * (100 - usedPct) / 100)
	return systemInfo{
		Available:  true,
		MemTotalKB: memTotalKB,
		MemAvailKB: avail,
		MemUsedPct: usedPct,
		Load1:      0.32 + 0.18*math.Sin(s/17+1),
		UptimeS:    6*24*3600 + int64(s)%(24*3600), // ~6-day uptime, ticking
		TempC:      47 + 3*math.Sin(s/31),
		Interfaces: demoIfaceCountersAt(t),
	}
}

// demoIfaceHistory synthesizes the last 5 minutes of interface counter snapshots at the 5s cadence
// the live sampler uses, so a freshly-loaded demo dashboard paints a full graph immediately instead
// of drawing itself in over the first few minutes.
func demoIfaceHistory(now time.Time) []ifaceSnap {
	const window = 5 * time.Minute
	const step = 5 * time.Second
	n := int(window/step) + 1
	out := make([]ifaceSnap, 0, n)
	for k := n - 1; k >= 0; k-- {
		ts := now.Add(-time.Duration(k) * step)
		out = append(out, ifaceSnap{T: ts.UnixMilli(), Ifaces: demoIfaceCountersAt(ts)})
	}
	return out
}

// demoExitTiles is the per-egress grid for the demo dashboard: one tile per DemoProfile exit, with a
// documentation IP + generic geo. IDs match DemoProfile endpoint ids so each tile's live rate + dot
// colour come from the same series as its graph line (kernel exit → its interface; proxy exit → its
// outbound rate).
func demoExitTiles() []exitTile {
	return []exitTile{
		{ID: "vless-de", Name: "Reality DE", IP: "203.0.113.10", CC: "DE", Country: "Germany", ISP: "Example Hosting", ASN: "AS64500", Hosting: true, Probed: true},
		{ID: "awg-example", Name: "AmneziaWG NL", IP: "198.51.100.20", CC: "NL", Country: "Netherlands", ISP: "Example VPS", ASN: "AS64501", Hosting: true, Probed: true},
		{ID: "hy2-jp", Name: "Hysteria2 JP", IP: "203.0.113.23", CC: "JP", Country: "Japan", ISP: "Example Telecom", ASN: "AS64502", Probed: false},
	}
}

// demoOutboundRates gives the two proxy exits (no kernel interface) a live throughput, the same way
// the Clash-derived sampler would on a real router. Keyed by endpoint id = sing-box outbound tag.
func demoOutboundRates(t time.Time) map[string]float64 {
	s := float64(t.UnixMilli()-demoEpochMs) / 1000.0
	return map[string]float64{
		"vless-de": 1.1e6 + 4.0e5*math.Sin(s/13+0.4),
		"hy2-jp":   6.5e5 + 2.5e5*math.Sin(s/11+2.0),
	}
}

// DemoProfile is the sample connection set seeded into a fresh `--demo` store so the Connections,
// Failover, and Routing pages render populated (and the health monitor synthesizes per-endpoint
// state for the exit tiles' health rings). Three exits — a VLESS-Reality proxy, a kernel-routed
// AmneziaWG tunnel, and a Hysteria2 proxy — an automatic failover group over them, and two routing
// lists. Every server is a documentation IP; no keys or secrets are included.
func DemoProfile() model.Profile {
	autoTest := &model.Health{URL: "http://cp.cloudflare.com/generate_204", Interval: 30, Tolerance: 800}
	return model.Profile{
		Endpoints: []model.Endpoint{
			{
				ID: "vless-de", Name: "Reality DE", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
				Server: "203.0.113.10", Port: 443, Enabled: true,
				Params: map[string]any{"flow": "xtls-rprx-vision"},
			},
			{
				ID: "awg-example", Name: "AmneziaWG NL", Engine: model.EngineExternal, Protocol: model.ProtoAmneziaWG,
				Server: "198.51.100.20", Port: 51820, Enabled: true,
				Params: map[string]any{"interface": "awg-example", "endpoint_ip": "198.51.100.20"},
			},
			{
				ID: "hy2-jp", Name: "Hysteria2 JP", Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
				Server: "203.0.113.23", Port: 8443, Enabled: true,
			},
		},
		Groups: []model.Group{
			{
				ID: "auto", Name: "Auto (fastest)", Type: model.GroupURLTest,
				Members: []string{"vless-de", "awg-example", "hy2-jp"}, Test: autoTest,
			},
		},
		RoutingLists: []model.RoutingList{
			{
				ID: "streaming", Name: "Streaming unblock", Outbound: "auto", Enabled: true,
				Manual: []string{"netflix.com", "youtube.com", "disneyplus.com"},
			},
			{
				ID: "ads", Name: "Ads & trackers", Outbound: "block", Enabled: true,
				Manual: []string{"doubleclick.net", "googlesyndication.com"},
			},
		},
		// The demo profile had no DNS plane, so handleGetDNS answered configured:false, renderDNS
		// never reached dnsQueryPath, and the query-path table it draws did not exist. The ui-wide
		// gate declares `.qp-brhead` as part of the alignment contract and could therefore never
		// measure it — a selector nobody renders is a column of the contract silently unchecked.
		//
		// Shaped like secureDNSTemplate so the demo shows the arrangement the product recommends:
		// IP-pinned DoH riding the profile's primary route, a `local` server for domestic names,
		// encrypted-only, ipv4_only because the tunnels are. The rules give the table data rows as
		// well as a catch-all, and they reuse the RoutingList IDs above so the DNS path and the
		// traffic path agree — which is the whole point the page exists to show.
		DNS: &model.DNSSettings{
			Enabled: true,
			Servers: []model.DNSServer{
				{Tag: "dns_secure", Type: "https", Server: "1.1.1.1", Path: "/dns-query", Detour: "auto", Enabled: true},
				{Tag: "dns_secure_bk", Type: "https", Server: "9.9.9.9", Path: "/dns-query", Detour: "auto", Enabled: true},
				{Tag: "dns_local", Type: "local", Enabled: true},
			},
			Rules: []model.DNSRule{
				{ID: "streaming", RuleSets: []string{"streaming"}, Server: "dns_secure"},
				{ID: "ads", RuleSets: []string{"ads"}, Server: "reject"},
			},
			Final:     "dns_secure",
			Strategy:  "ipv4_only",
			LeakProof: true,
		},
	}
}
