package model

// RealityDest is a curated VLESS-Reality camouflage target — a real, public site whose SNI a
// Reality inbound "borrows" as cover. A good dest is genuinely TLS 1.3 + HTTP/2, reachable
// worldwide with high uptime, geopolitically neutral (not the censor's own infra), and popular
// enough that traffic to it blends in. The UI offers these as one-click picks for the Reality
// `dest`/`server_name` field; the user should still verify the chosen one with POST /api/probe/tls
// (TCP-reachability + TLS-1.3 from the ROUTER's own vantage — reachability varies by region/ISP)
// before saving. Host is a bare hostname: a Reality dest is always :443 and server_name is a bare
// SNI, so every entry is safe to feed straight into the probe.
type RealityDest struct {
	Host     string `json:"host"`           // bare SNI hostname (dest is always :443)
	Name     string `json:"name"`           // human label
	Category string `json:"category"`       // grouping for the picker
	Note     string `json:"note,omitempty"` // why it's a solid pick
}

// RealityDests returns the curated catalog of recommended Reality camouflage SNIs. Researched
// 2026-07-19: each is a widely-deployed vendor/CDN origin serving real TLS 1.3 + HTTP/2, chosen to
// be geopolitically neutral and high-availability. This is a safe starting set, NOT exhaustive —
// and NOT a guarantee: always probe the chosen dest from the router (reachability + a genuine TLS
// 1.3 handshake) before relying on it, since any single site can be regionally blocked or change.
func RealityDests() []RealityDest {
	const (
		vendor = "Vendor origin (TLS 1.3 + h2)"
		cdn    = "CDN / cloud"
		apple  = "Apple CDN (permissive SNI)"
	)
	d := func(host, name, cat, note string) RealityDest {
		return RealityDest{Host: host, Name: name, Category: cat, Note: note}
	}
	return []RealityDest{
		// Major vendor front pages — TLS 1.3 + HTTP/2, global anycast, extremely high uptime.
		d("www.microsoft.com", "Microsoft", vendor, "Global, TLS 1.3 + h2, ubiquitous — traffic blends in anywhere."),
		d("www.apple.com", "Apple", vendor, "Global CDN origin, TLS 1.3 + h2, very high uptime."),
		d("www.amazon.com", "Amazon", vendor, "Global, TLS 1.3 + h2; huge traffic volume to blend into."),
		d("www.nvidia.com", "NVIDIA", vendor, "TLS 1.3 + h2, geopolitically neutral, stable."),
		d("www.samsung.com", "Samsung", vendor, "TLS 1.3 + h2, global consumer-electronics origin."),
		d("www.tesla.com", "Tesla", vendor, "TLS 1.3 + h2, neutral, stable front page."),
		// CDN / cloud infrastructure — designed for arbitrary high-volume TLS.
		d("www.cloudflare.com", "Cloudflare", cdn, "TLS 1.3 + h2 by design; anycast everywhere."),
		d("dl.google.com", "Google download CDN", cdn, "TLS 1.3 + h2, massive download CDN — high, neutral volume."),
		d("www.bing.com", "Bing", cdn, "TLS 1.3 + h2, Microsoft anycast; common, unremarkable traffic."),
		// Apple software/iCloud CDNs — historically permissive on SNI, TLS 1.3 + h2, evergreen picks.
		d("swcdn.apple.com", "Apple software CDN", apple, "Apple SW-update CDN: permissive SNI, TLS 1.3 + h2 — a classic Reality dest."),
		d("gateway.icloud.com", "iCloud gateway", apple, "iCloud edge, TLS 1.3 + h2, permissive and globally reachable."),
		d("www.icloud.com", "iCloud", apple, "TLS 1.3 + h2, Apple global edge."),
	}
}
