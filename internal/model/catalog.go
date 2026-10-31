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
	// a .srs rule-set. A preset carrying one is kernel-routable on KeeneticOS (dnsmasq fills its set),
	// so RequiresCore stays false here; the server raises it on platforms with no resolver plane.
	DomainSource string `json:"domain_source,omitempty"`
	// RefreshHours is the cadence this feed is worth re-fetching at, carried with the preset because
	// the catalog is what knows how fast each source actually moves. The panel offers it as the
	// list's auto-update interval when the preset is added; the user can change it afterwards like
	// any other list, and the refresh loop clamps whatever it is given to a flash-safe floor.
	RefreshHours int `json:"refresh_hours,omitempty"`
}

// RoutingPresets returns the curated catalog of pre-defined GitHub rule-sets,
// focused on un-blocking the Russian internet (RKN/antifilter/DPI). Researched
// 2026; all are fetched over HTTPS, and every source was re-checked live in October 2026
// (status, size, last upstream change).
func RoutingPresets() []RoutingPreset {
	const (
		ruBlocked = "RU-blocked (route abroad)"
		uaBlocked = "UA-blocked (route abroad)"
		antiGeo   = "Anti-geoblock (sites that block RU)"
		service   = "Per-service"
		junk      = "Ads / adult (block)"
		ruDirect  = "RU services (keep on your ISP)"
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
		// What Telegram's five ASNs announce, from RIPEstat (every holder is Telegram Messenger Inc).
		// Neither file-based list is complete: Telegram's published cidr.txt and the lord-alfred mirror
		// both omit a /20 that AS62041 announces; itdoginfo's adds a /16 another operator announces. The routing table is the source the others are copied from.
		cidr("cidr-telegram", "Telegram networks", "asn:62041,59930,62014,44907,211157",
			kernelCat, "Every network Telegram's own ASNs announce, IPv4 and IPv6. Carries calls too, which a domain list cannot: voice goes to raw UDP addresses.", "proxy"),
		cidr("cidr-meta", "Meta networks (IG/FB/WA)", "https://raw.githubusercontent.com/lord-alfred/ipranges/main/facebook/ipv4_merged.txt",
			kernelCat, "Instagram / Facebook / WhatsApp IPv4 ranges, merged.", "proxy"),
		// Twitter's three ASNs rather than lord-alfred's merged file, unchanged since 2025-03: measured
		// 2026-10-30 (RIPEstat), one of its /19s is now announced by Cloudflare, so Cloudflare traffic
		// went out by the Twitter exit, four of its networks are announced by nobody, and the live ones
		// outside AS13414 sit in AS35995 and AS63179.
		cidr("cidr-twitter", "Twitter / X networks", "asn:13414,35995,63179",
			kernelCat, "Every network Twitter / X's own ASNs announce, IPv4 and IPv6.", "proxy"),
		cidr("cidr-discord", "Discord networks", "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/discord_ips.lst",
			kernelCat, "Discord server IPs including voice, which the domain list misses.", "proxy"),
		// Roblox's game servers are raw UDP addresses its domain list cannot reach. Its own ASN rather than
		// itdoginfo's two-line list: measured 2026-10-29 (RIPEstat), AS22697 announces three networks
		// besides its /17 that the list misses, and the list's other network is announced by nobody.
		cidr("cidr-roblox", "Roblox networks", "asn:22697",
			kernelCat, "Every network Roblox's own ASN announces, IPv4 and IPv6: the game servers, raw UDP addresses the domain list misses.", "proxy"),
		// Google publishes Meet's media ranges (the Workspace admin article "Prepare your network for Meet",
		// step 3); itdoginfo's list is exactly its three IPv4 ranges (checked 2026-10-29).
		cidr("cidr-google-meet", "Google Meet media", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv4/google_meet.lst",
			kernelCat, "Meet's audio and video servers, Google's published ranges: a call goes to these addresses, not to a name, so the domain list alone misses it.", "proxy"),
		cidr("cidr-refilter", "Re:filter networks", "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/ipsum.lst",
			kernelCat, "Networks blocked or throttled for RU users (Re:filter ipsum), as plain prefixes.", "proxy"),
		// Foreign hosting and CDN networks, from itdoginfo's weekly Subnets feeds. Russian ISPs throttle
		// connections into these networks, so a site hosted there stalls on the WAN whatever its domain;
		// routing the network is the coreless way to reach all of them. svc-hodca below is the
		// narrower, per-site alternative.
		cidr("cidr-cloudflare", "Cloudflare networks", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv4/cloudflare.lst",
			kernelCat, "Every Cloudflare IPv4 range. Sites behind Cloudflare that stall from Russia load through the tunnel; so does everything else on Cloudflare.", "proxy"),
		cidr("cidr-cloudfront", "Amazon CloudFront networks", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv4/cloudfront.lst",
			kernelCat, "Amazon CloudFront edge ranges (itdoginfo).", "proxy"),
		// Hetzner's three ASNs rather than itdoginfo's hetzner.lst: measured 2026-10-30 (RIPEstat), that
		// file covers AS24940 (Hetzner Online) completely but none of Hetzner Cloud's AS213230 and
		// AS212317 - 596 announced IPv4 prefixes, about 353k addresses (5.161.x, 87.99.x, 5.78.x), so a
		// Hetzner Cloud server there never matched.
		cidr("cidr-hetzner", "Hetzner networks", "asn:24940,213230,212317",
			kernelCat, "Every network Hetzner's own ASNs announce (Hetzner Online and Hetzner Cloud), IPv4 and IPv6.", "proxy"),
		cidr("cidr-digitalocean", "DigitalOcean networks", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv4/digitalocean.lst",
			kernelCat, "DigitalOcean's IPv4 ranges (itdoginfo).", "proxy"),
		cidr("cidr-ovh", "OVH networks", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv4/ovh.lst",
			kernelCat, "OVH's IPv4 ranges (itdoginfo).", "proxy"),

		// ---- sing-box rule-sets: domain and geo matchers, need the core ------------------------
		// All-in-one + RKN blocklists — route these abroad through a tunnel.
		srs("ru-bundle", "RU bundle (recommended)", "https://github.com/legiz-ru/sb-rule-sets/raw/main/ru-bundle.srs",
			"mixed", ruBlocked, "All-in-one: itdoginfo-inside + no-russia-hosts + antifilter-community + RKN ASN block. The easy default.", "proxy"),
		// Same list itdoginfo compiles into russia_inside.srs, taken as the text file it is generated
		// from: ~1.2k curated names, which the resolver carries without a core. Verified live before
		// it went in — 200, 1183 names, 16 KB.
		domains("ru-inside", "RU inside (itdoginfo)", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst",
			ruBlocked, "Domains blocked inside Russia (RKN-relevant), curated by itdoginfo. Carried by the router's own resolver — no proxy core needed.", "proxy"),
		// The mirror image for a router in Ukraine: the Russian services blocked there, as a resolver-carried
		// feed. itdoginfo still maintains this list (its "Update lists" commits of 2026-09-14 and 10-19 touch
		// only Ukraine/), 1555 names when added.
		domains("ua-inside", "UA inside (itdoginfo)", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Ukraine/inside-raw.lst",
			uaBlocked, "Domains blocked inside Ukraine (mostly Russian services), curated by itdoginfo. Carried by the router's own resolver on KeeneticOS, by the proxy core elsewhere.", "proxy"),
		srs("refilter-domains", "Re:filter domains", "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-domain-refilter_domains.srs",
			"domain", ruBlocked, "Curated domains blocked / throttled for RU users (Re:filter).", "proxy"),
		srs("refilter-ip", "Re:filter IPs", "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-ip-refilter_ipsum.srs",
			"ip", ruBlocked, "IP/CIDR networks blocked in RU (Re:filter ipsum).", "proxy"),
		// runetfreedom rebuilds these every six hours. They replace antizapret-sing-box (last release
		// 2026-03-26) and vernette's rkn.srs (unchanged since 2026-02-02), both still served but frozen.
		srs("ru-blocked", "RU blocked domains (runetfreedom)", "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-ru-blocked.srs",
			"domain", ruBlocked, "Domains blocked in Russia: antifilter community + Re:filter, rebuilt every 6 hours.", "proxy"),
		srs("ru-blocked-all", "RU blocked, everything (runetfreedom)", "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-ru-blocked-all.srs",
			"domain", ruBlocked, "Every known domain blocked in Russia, from all sources (700k+ names, ~10 MB rule-set). Needs memory; prefer RU blocked domains on small routers.", "proxy"),
		// itdoginfo's list of sites hosted on the networks Russian ISPs throttle (Hetzner, OVH,
		// DigitalOcean, Cloudflare, AWS, Akamai) - the per-site alternative to the cidr-* hosting presets.
		domains("svc-hodca", "Sites on throttled hosting (itdoginfo)", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/hodca.lst",
			ruBlocked, "Sites on Hetzner, OVH, DigitalOcean, Cloudflare, AWS and Akamai that stall from Russia. Resolver-carried, no proxy core needed.", "proxy"),
		domains("ru-news", "Independent news (itdoginfo)", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/news.lst",
			ruBlocked, "News sites blocked in Russia. Resolver-carried, no proxy core needed.", "proxy"),
		domains("ru-anime", "Anime sites (itdoginfo)", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/anime.lst",
			ruBlocked, "Anime streaming and catalogue sites blocked in Russia. Resolver-carried, no proxy core needed.", "proxy"),
		// Sites that geo-BLOCK Russian IPs — also route abroad to reach them.
		srs("no-russia", "Sites that block RU", "https://github.com/legiz-ru/sb-rule-sets/raw/main/no-russia-hosts.srs",
			"domain", antiGeo, "ChatGPT/Spotify-class services that refuse Russian IPs (dartraiden no-russia-hosts).", "proxy"),
		domains("ru-geoblock", "Sites that block RU (itdoginfo)", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/geoblock.lst",
			antiGeo, "Services that refuse Russian IPs, curated by itdoginfo (~470 names). Resolver-carried, no proxy core needed.", "proxy"),
		domains("ru-outside", "RU outside (itdoginfo)", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/outside-raw.lst",
			antiGeo, "RU services that geo-restrict foreigners — the ones to send back INTO Russia. Resolver-carried, no proxy core needed.", "proxy"),
		// RU services that must keep the subscriber's own Russian address while everything else goes
		// through a tunnel: banks and Mir/SBP refuse or flag foreign addresses, Gosuslugi and FNS
		// geo-restrict. kyoresuas/ru-direct (MIT) rebuilds its `release` branch daily (its GitHub
		// release asset lags, so the branch is the source); checked 2026-10-30: lite 481 names and 354
		// IPv4 prefixes, standard 1638 names and 618 prefixes, plain lines, nothing shorter than /8.
		// For a router abroad "direct" means the RU exit, so the operator picks the target.
		domains("ru-direct", "RU services, lite (kyoresuas ru-direct)", "https://raw.githubusercontent.com/kyoresuas/ru-direct/release/ru-lite.domains.txt",
			ruDirect, "Banks, Mir and SBP, Gosuslugi, FNS, VK, OK, Mail.ru, MAX, Dzen, Rutube (~480 names), kept on your ISP while the rest goes through a tunnel. Resolver-carried, no proxy core needed.", "direct"),
		domains("ru-direct-standard", "RU services, standard (kyoresuas ru-direct)", "https://raw.githubusercontent.com/kyoresuas/ru-direct/release/ru-standard.domains.txt",
			ruDirect, "Lite plus Ozon, Wildberries, Yandex, Avito, 2GIS, operators, streaming and delivery (~1.6k names). Resolver-carried, no proxy core needed.", "direct"),
		cidr("cidr-ru-direct", "RU services' networks, standard (kyoresuas ru-direct)", "https://raw.githubusercontent.com/kyoresuas/ru-direct/release/ru-standard.ipv4.txt",
			ruDirect, "The networks of the standard tier (~620 IPv4 prefixes), for apps that connect by address. Kernel-carried, no proxy core needed.", "direct"),
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
		domains("svc-roblox", "Roblox", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/roblox.lst",
			service, "Roblox domains. Resolver-carried, no proxy core needed.", "proxy"),
		domains("svc-google-meet", "Google Meet", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/google_meet.lst",
			service, "Google Meet calls. Resolver-carried, no proxy core needed.", "proxy"),
		domains("svc-google-play", "Google Play", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/google_play.lst",
			service, "Google Play store and downloads. Also carries Android's connectivity check, so phones report no internet while the tunnel is down. Resolver-carried, no proxy core needed.", "proxy"),
		srs("svc-hdrezka", "HDrezka", "https://github.com/itdoginfo/allow-domains/releases/latest/download/hdrezka.srs", "domain", service, "HDrezka streaming.", "proxy"),
		srs("svc-crypto", "Crypto / exchanges", "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-category-cryptocurrency.srs", "domain", service, "Crypto exchanges, wallets, DeFi/dapps, block explorers and node RPCs (v2fly cryptocurrency category via sing-geosite). Route via a tunnel to reach services that geo-block, or to keep crypto traffic off the local ISP.", "proxy"),
		// Streaming geo-unblock: these refuse datacenter/VPN IPs, so pair them with a CLEAN residential-ish
		// egress (e.g. a Cloudflare WARP or Mullvad WG endpoint added under Connections), not a bare VPS.
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
	//   12h  registries that regenerate at least daily (antifilter's Last-Modified is the same day;
	//        runetfreedom's release branch is rebuilt daily): a blocked site the operator cannot reach
	//        is the failure this whole page exists to avoid
	//   168h service ranges and geo-unblock/ads lists: measured in weeks, so a weekly fetch is honest
	//        traffic rather than a daily no-op download
	//   24h  everything else, including the RU lists that change irregularly, not daily (measured
	//        2026-10-30: Re:filter's ipsum.lst and releases 2026-07-01, 08-01, 10-11, 10-19; legiz
	//        ru-bundle 07-09, 08-10, 10-27; itdoginfo's Russia/inside lists last 06-16)
	registry := map[string]bool{
		"cidr-antifilter": true, "ru-blocked": true, "ru-blocked-all": true,
	}
	slowRanges := map[string]bool{
		"cidr-telegram": true, "cidr-meta": true, "cidr-twitter": true, "cidr-discord": true,
		"cidr-cloudflare": true, "cidr-cloudfront": true, "cidr-hetzner": true, "cidr-digitalocean": true,
		"cidr-ovh": true, "cidr-roblox": true, "cidr-google-meet": true,
	}
	for i := range presets {
		p := &presets[i]
		switch {
		case registry[p.ID]:
			p.RefreshHours = 12
		case slowRanges[p.ID] || p.Category == service || p.Category == junk || p.Category == antiGeo || p.Category == uaBlocked:
			p.RefreshHours = 168
		default:
			p.RefreshHours = 24
		}
	}
	return presets
}
