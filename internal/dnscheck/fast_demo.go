package dnscheck

import "time"

// The demo's numbers are the ones measured in November 2026 through a tunnel and on a provider's line that
// blocks some resolvers by connection. "clock" shows a router whose clock or CA bundle fails every certificate.

type demoFast struct {
	id                 string
	dohMs, dotMs       int
	dohStatus, dotStat string
}

var demoFastTunnel = []demoFast{
	{"cloudflare", 56, 53, "", ""}, {"cloudflare-security", 63, 60, "", ""}, {"cloudflare-family", 65, 59, "", ""},
	{"google", 93, 67, "", ""}, {"quad9", 77, 62, "", ""}, {"quad9-plain", 79, 63, "", ""},
	{"adguard", 60, 59, "", ""}, {"adguard-plain", 92, 60, "", ""}, {"adguard-family", 83, 59, "", ""},
	{"mullvad", 94, 99, "", ""}, {"mullvad-adblock", 60, 106, "", ""}, {"dnssb", 84, 77, "", ""},
	{"controld", 148, 0, "", ""}, {"controld-ads", 90, 0, "", ""}, {"opendns", 205, 77, "", ""},
	{"nextdns", 80, 59, "", ""}, {"cleanbrowsing", 82, 61, "", ""}, {"applied-privacy", 0, 87, FastOther, ""},
	{"wikimedia", 225, 220, FastBadCert, FastBadCert},
}

var demoFastWAN = []demoFast{
	{"cloudflare", 25, 23, "", ""}, {"cloudflare-security", 30, 22, "", ""}, {"cloudflare-family", 27, 28, "", ""},
	{"google", 60, 49, "", ""}, {"quad9", 46, 39, "", ""}, {"quad9-plain", 49, 47, "", ""},
	{"adguard", 60, 65, "", ""}, {"adguard-plain", 0, 0, FastTimeout, FastTimeout}, {"adguard-family", 60, 58, "", ""},
	{"mullvad", 0, 37, FastTimeout, ""}, {"mullvad-adblock", 0, 42, FastTimeout, ""}, {"dnssb", 90, 68, "", ""},
	{"controld", 62, 0, "", ""}, {"controld-ads", 66, 0, "", ""}, {"opendns", 46, 45, "", ""},
	{"nextdns", 0, 0, FastTimeout, FastRefused}, {"cleanbrowsing", 53, 45, "", ""}, {"applied-privacy", 72, 84, "", ""},
	{"wikimedia", 60, 62, "", ""},
}

func demoFastResults(rows []demoFast) []FastResult {
	entries := make(map[string]FastEntry, len(FastCatalog))
	for _, e := range FastCatalog {
		entries[e.ID] = e
	}
	yes, no := true, false
	out := make([]FastResult, 0, len(rows))
	for _, row := range rows {
		e := entries[row.id]
		r := FastResult{ID: row.id}
		add := func(proto string, ms int, status string) {
			if status == "" {
				status = FastOK
			}
			t := FastTransport{Proto: proto, Status: status}
			if status == FastOK {
				t.Ms, t.ConnectMs, t.CertName, t.Issuer, t.CertDays = ms, ms*3, e.Host, "Demo CA", 60
				if !r.Alive || ms < r.Ms {
					r.Alive, r.Best, r.Ms = true, proto, ms
				}
			}
			r.Transports = append(r.Transports, t)
		}
		if e.DoHPath != "" {
			add("doh", row.dohMs, row.dohStatus)
		}
		if e.DoT {
			add("dot", row.dotMs, row.dotStat)
		}
		if r.Alive {
			r.Validates = &yes
			if e.Filter == "ads" {
				r.Validates = &no
			}
		}
		out = append(out, r)
	}
	SortFast(out)
	return out
}

// DemoFastState answers GET /api/dns/fast on the demo.
func DemoFastState(via string) FastState {
	vias := []FastVia{
		{ID: "demo-tunnel", Label: "Norway", Kind: PathTunnel, Iface: "nwg1"},
		{ID: "direct", Label: "Provider", Kind: PathWAN, Iface: "eth3"},
		{ID: "demo-clock", Label: "Wrong clock (demo)", Kind: PathTunnel, Iface: "nwg0"},
	}
	if via == "" {
		via = vias[0].ID
	}
	now := time.Now().UTC()
	rep := &FastReport{Via: via, Demo: true, StartedAt: now.Add(-9 * time.Second), FinishedAt: now}
	switch via {
	case "direct":
		rep.Path = Path{Iface: "eth3", Kind: PathWAN, Label: "Provider"}
		rep.Results = demoFastResults(demoFastWAN)
	case "demo-clock":
		rep.Path = Path{Iface: "nwg0", Kind: PathTunnel, Label: "Wrong clock (demo)"}
		rows := make([]demoFast, 0, len(demoFastTunnel))
		for _, row := range demoFastTunnel {
			rows = append(rows, demoFast{id: row.id, dohStatus: FastBadCert, dotStat: FastBadCert})
		}
		rep.Results = demoFastResults(rows)
		rep.CertsUnreliable = true
	default:
		rep.Path = Path{Iface: "nwg1", Kind: PathTunnel, Label: "Norway"}
		rep.Results = demoFastResults(demoFastTunnel)
	}
	return FastState{Catalog: FastCatalog, Vias: vias, Default: vias[0].ID, Report: rep}
}
