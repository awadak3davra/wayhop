package model

// RoutingPreset is a curated, ready-to-use rule-set the UI offers as a one-click
// routing list. All sources are sing-box rule-sets (mostly compiled .srs) that
// sing-box consumes directly as a remote rule_set — no conversion needed. Suggest
// hints the default outbound: "proxy" (route via the user's chosen tunnel),
// "direct", or "block".
type RoutingPreset struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Source string `json:"source"`
	// CIDRSource is a plain-text IP/CIDR feed, one prefix per line. A preset built on one needs no
	// proxy core at all: the router's own kernel plane carries IP prefixes, so these work on a
	// Keenetic with nothing but ipset and iptables installed.
	CIDRSource  string `json:"cidr_source,omitempty"`
	Format      string `json:"format"` // "binary" (.srs) | "source" (.json)
	Kind        string `json:"kind"`   // "domain" | "ip" | "mixed"
	Category    string `json:"category"`
	Description string `json:"description"`
	Suggest     string `json:"suggest"` // "proxy" | "direct" | "block"
	// RequiresCore is true for every sing-box rule-set. Domain and geo matchers have no kernel
	// equivalent, so such a preset is unusable until an engine is installed — and offering it anyway
	// produces a saved list that blocks every Apply with "the proxy core is unavailable", which reads
	// as a broken product rather than a missing package.
	RequiresCore bool `json:"requires_core"`
	// DomainSource is a plain-text feed of names for the resolver plane — the coreless counterpart of
	// a .srs rule-set. A preset carrying one is kernel-routable: RequiresCore stays false.
	DomainSource string `json:"domain_source,omitempty"`
	// RefreshHours is the cadence this feed is worth re-fetching at, carried with the preset because
	// the catalog is what knows how fast each source actually moves. The panel offers it as the
	// list's auto-update interval when the preset is added; the user can change it afterwards like
	// any other list, and the refresh loop clamps whatever it is given to a flash-safe floor.
	RefreshHours int `json:"refresh_hours,omitempty"`
}

// RoutingPresets returns the curated catalog of pre-defined GitHub rule-sets,
// focused on un-blocking the Russian internet (RKN/antifilter/DPI). Researched
// 2026; all are sing-box .srs rule-sets fetched over HTTPS.
func RoutingPresets() []RoutingPreset {
	const (
		ruBlocked = "RU-blocked (route abroad)"
		antiGeo   = "Anti-geoblock (sites that block RU)"
		service   = "Per-service"
		junk      = "Ads / adult (block)"
	)
	const kernelCat = "IP lists (no proxy core needed)"
	srs := func(id, name, url, kind, cat, desc, suggest string) RoutingPreset {
		return RoutingPreset{ID: id, Name: name, Source: url, Format: "binary", Kind: kind,
			Category: cat, Description: desc, Suggest: suggest, RequiresCore: true}
	}
	// cidr builds a preset the kernel plane can carry on its own. The feeds are plain-text prefix
	// lists, refreshed upstream, and have been carried on a live Keenetic — so they are known to
	// exist, stay maintained, and parse.
	cidr := func(id, name, url, cat, desc, suggest string) RoutingPreset {
		return RoutingPreset{ID: id, Name: name, CIDRSource: url, Kind: "ip",
			Category: cat, Description: desc, Suggest: suggest}
	}
	// domains builds a preset the RESOLVER plane carries: a plain-text feed of names, which dnsmasq
	// turns into set members as they are looked up. It needs no proxy core — what needed one was the
	// .srs FORMAT, not domain matching, and these projects publish both files.
	//
	// Only curated feeds belong here. Every name costs a resolver directive, so a registry-sized dump
	// (measured: 1.57M names, 28.8 MB) is refused by the fetcher; its coverage is on the CIDR side.
	domains := func(id, name, url, cat, desc, suggest string) RoutingPreset {
		return RoutingPreset{ID: id, Name: name, DomainSource: url, Kind: "domain",
			Category: cat, Description: desc, Suggest: suggest}
	}
	presets := []RoutingPreset{
		// ---- Kernel-native: IP/CIDR only, no sing-box ------------------------------------------
		cidr("cidr-antifilter", "Antifilter: everything blocked in RU", "https://antifilter.download/list/allyouneed.lst",
			kernelCat, "Every network Roskomnadzor blocks, as IP prefixes. The broadest kernel-routable list — the IP-only counterpart of the RU bundle.", "proxy"),
		cidr("cidr-telegram", "Telegram networks", "https://raw.githubusercontent.com/lord-alfred/ipranges/main/telegram/ipv4_merged.txt",
			kernelCat, "Telegram's own IPv4 ranges, merged. Carries calls too, which a domain list cannot: voice goes to raw UDP addresses.", "proxy"),
		cidr("cidr-meta", "Meta networks (IG/FB/WA)", "https://raw.githubusercontent.com/lord-alfred/ipranges/main/facebook/ipv4_merged.txt",
			kernelCat, "Instagram / Facebook / WhatsApp IPv4 ranges, merged.", "proxy"),
		cidr("cidr-twitter", "Twitter / X networks", "https://raw.githubusercontent.com/lord-alfred/ipranges/main/twitter/ipv4_merged.txt",
			kernelCat, "Twitter / X IPv4 ranges, merged.", "proxy"),
		cidr("cidr-discord", "Discord networks", "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/discord_ips.lst",
			kernelCat, "Discord server IPs including voice, which the domain list misses.", "proxy"),
		cidr("cidr-refilter", "Re:filter networks", "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/ipsum.lst",
			kernelCat, "Networks blocked or throttled for RU users (Re:filter ipsum), as plain prefixes.", "proxy"),

		// ---- sing-box rule-sets: domain and geo matchers, need the core ------------------------
		// All-in-one + RKN blocklists — route these abroad through a tunnel.
		srs("ru-bundle", "RU bundle (recommended)", "https://github.com/legiz-ru/sb-rule-sets/raw/main/ru-bundle.srs",
			"mixed", ruBlocked, "All-in-one: itdoginfo-inside + no-russia-hosts + antifilter-community + RKN ASN block. The easy default.", "proxy"),
		// Same list itdoginfo compiles into russia_inside.srs, taken as the text file it is generated
		// from: ~1.2k curated names, which the resolver carries without a core. Verified live before
		// it went in — 200, 1183 names, 16 KB.
		domains("ru-inside", "RU inside (itdoginfo)", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst",
			ruBlocked, "Domains blocked inside Russia (RKN-relevant), curated by itdoginfo. Carried by the router's own resolver — no proxy core needed.", "proxy"),
		srs("refilter-domains", "Re:filter domains", "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-domain-refilter_domains.srs",
			"domain", ruBlocked, "Curated domains blocked / throttled for RU users (Re:filter).", "proxy"),
		srs("refilter-ip", "Re:filter IPs", "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-ip-refilter_ipsum.srs",
			"ip", ruBlocked, "IP/CIDR networks blocked in RU (Re:filter ipsum).", "proxy"),
		srs("antizapret", "Antizapret (full RKN)", "https://github.com/savely-krasovsky/antizapret-sing-box/releases/latest/download/antizapret.srs",
			"mixed", ruBlocked, "The full official Roskomnadzor blocklist (domains + IPs) from the z-i dump.", "proxy"),
		srs("rkn", "RKN domains (vernette)", "https://raw.githubusercontent.com/vernette/rulesets/master/srs/rkn.srs",
			"domain", ruBlocked, "Large RKN-blocked domain set.", "proxy"),
		// Sites that geo-BLOCK Russian IPs — also route abroad to reach them.
		srs("no-russia", "Sites that block RU", "https://github.com/legiz-ru/sb-rule-sets/raw/main/no-russia-hosts.srs",
			"domain", antiGeo, "ChatGPT/Spotify-class services that refuse Russian IPs (dartraiden no-russia-hosts).", "proxy"),
		domains("ru-outside", "RU outside (itdoginfo)", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/outside-raw.lst",
			antiGeo, "RU services that geo-restrict foreigners — the ones to send back INTO Russia. Resolver-carried, no proxy core needed.", "proxy"),
		// Per-service — pick a tunnel per service.
		srs("svc-discord", "Discord", "https://github.com/itdoginfo/allow-domains/releases/latest/download/discord.srs", "domain", service, "Discord domains.", "proxy"),
		srs("svc-discord-voice", "Discord voice IPs", "https://github.com/legiz-ru/sb-rule-sets/raw/main/discord-voice-ip-list.srs", "ip", service, "Discord voice server IPs.", "proxy"),
		srs("svc-telegram", "Telegram", "https://github.com/itdoginfo/allow-domains/releases/latest/download/telegram.srs", "domain", service, "Telegram domains.", "proxy"),
		srs("svc-telegram-calls", "Telegram calls (voice IPs)", "https://raw.githubusercontent.com/vernette/rulesets/master/srs/telegram-voice-chats.srs", "ip", service, "Telegram voice/call server IPs — calls use raw UDP IPs the Telegram domain list misses, so add this too to keep calls on the tunnel.", "proxy"),
		srs("svc-youtube", "YouTube", "https://github.com/itdoginfo/allow-domains/releases/latest/download/youtube.srs", "domain", service, "YouTube domains.", "proxy"),
		srs("svc-meta", "Meta (IG/FB/WA)", "https://github.com/itdoginfo/allow-domains/releases/latest/download/meta.srs", "domain", service, "Instagram / Facebook / WhatsApp.", "proxy"),
		srs("svc-twitter", "Twitter / X", "https://github.com/itdoginfo/allow-domains/releases/latest/download/twitter.srs", "domain", service, "Twitter / X domains.", "proxy"),
		srs("svc-tiktok", "TikTok", "https://github.com/itdoginfo/allow-domains/releases/latest/download/tiktok.srs", "domain", service, "TikTok domains.", "proxy"),
		// The text file itdoginfo compiles into google_ai.srs. As a .srs the list needed the core, and a
		// Keenetic in routing mode "fast" (no core TUN) dropped it with nothing routed.
		domains("svc-ai", "Google AI", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/google_ai.lst",
			service, "Google AI (Gemini) domains. Carried by the router's own resolver — no proxy core needed.", "proxy"),
		srs("svc-hdrezka", "HDrezka", "https://github.com/itdoginfo/allow-domains/releases/latest/download/hdrezka.srs", "domain", service, "HDrezka streaming.", "proxy"),
		srs("svc-crypto", "Crypto / exchanges", "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-category-cryptocurrency.srs", "domain", service, "Crypto exchanges, wallets, DeFi/dapps, block explorers and node RPCs (v2fly cryptocurrency category via sing-geosite). Route via a tunnel to reach services that geo-block, or to keep crypto traffic off the local ISP.", "proxy"),
		// Streaming geo-unblock: these refuse datacenter/VPN IPs, so pair them with a CLEAN residential-ish
		// egress (e.g. a Cloudflare WARP or Windscribe WG endpoint added under Connections), not a bare VPS.
		srs("svc-netflix", "Netflix", "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-netflix.srs", "domain", service, "Netflix domains — route via a clean/residential egress (e.g. WARP) to bypass its datacenter-IP block.", "proxy"),
		srs("svc-disney", "Disney+", "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-disney.srs", "domain", service, "Disney+ domains — route via a clean egress to reach it where it geo-restricts.", "proxy"),
		srs("svc-primevideo", "Amazon Prime Video", "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-primevideo.srs", "domain", service, "Amazon Prime Video domains — route via a clean egress to bypass geo/VPN blocks.", "proxy"),
		srs("svc-spotify", "Spotify", "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-spotify.srs", "domain", service, "Spotify domains — route abroad where it is unavailable.", "proxy"),
		// Blocklists.
		srs("block-ads", "Ads (block)", "https://github.com/itdoginfo/allow-domains/releases/latest/download/block.srs", "domain", junk, "Known ad/track domains — reject.", "block"),
		srs("block-porn", "Adult (block)", "https://github.com/itdoginfo/allow-domains/releases/latest/download/porn.srs", "domain", junk, "Adult domains — reject.", "block"),
	}
	// Recommended cadence, chosen by what each feed actually DOES rather than one number for all.
	// A list added without one refreshes daily by the loop's own default, which is right for most of
	// them and wrong at both ends: a blocking registry moves faster than that, and a company's IP
	// ranges do not move for months. Every value here clears MinCIDRRefreshHours, so nothing a user
	// can pick from the catalog can hammer the flash.
	//
	//   12h  registries: the RKN/antifilter/Re:filter/antizapret feeds regenerate at least daily and
	//        a blocked site the operator cannot reach is the failure this whole page exists to avoid
	//   168h service ranges and geo-unblock/ads lists: measured in weeks, so a weekly fetch is honest
	//        traffic rather than a daily no-op download
	//   24h  everything else
	registry := map[string]bool{
		"cidr-antifilter": true, "cidr-refilter": true, "refilter-domains": true, "refilter-ip": true,
		"antizapret": true, "rkn": true, "ru-bundle": true, "ru-inside": true,
	}
	slowRanges := map[string]bool{
		"cidr-telegram": true, "cidr-meta": true, "cidr-twitter": true, "cidr-discord": true,
	}
	for i := range presets {
		p := &presets[i]
		switch {
		case registry[p.ID]:
			p.RefreshHours = 12
		case slowRanges[p.ID] || p.Category == service || p.Category == junk || p.Category == antiGeo:
			p.RefreshHours = 168
		default:
			p.RefreshHours = 24
		}
	}
	return presets
}
