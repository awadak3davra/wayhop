package model

// RoutingPreset is a curated, ready-to-use rule-set the UI offers as a one-click
// routing list. All sources are sing-box rule-sets (mostly compiled .srs) that
// sing-box consumes directly as a remote rule_set — no conversion needed. Suggest
// hints the default outbound: "proxy" (route via the user's chosen tunnel),
// "direct", or "block".
type RoutingPreset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Source      string `json:"source"`
	Format      string `json:"format"` // "binary" (.srs) | "source" (.json)
	Kind        string `json:"kind"`   // "domain" | "ip" | "mixed"
	Category    string `json:"category"`
	Description string `json:"description"`
	Suggest     string `json:"suggest"` // "proxy" | "direct" | "block"
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
	srs := func(id, name, url, kind, cat, desc, suggest string) RoutingPreset {
		return RoutingPreset{ID: id, Name: name, Source: url, Format: "binary", Kind: kind, Category: cat, Description: desc, Suggest: suggest}
	}
	return []RoutingPreset{
		// All-in-one + RKN blocklists — route these abroad through a tunnel.
		srs("ru-bundle", "RU bundle (recommended)", "https://github.com/legiz-ru/sb-rule-sets/raw/main/ru-bundle.srs",
			"mixed", ruBlocked, "All-in-one: itdoginfo-inside + no-russia-hosts + antifilter-community + RKN ASN block. The easy default.", "proxy"),
		srs("ru-inside", "RU inside (itdoginfo)", "https://github.com/itdoginfo/allow-domains/releases/latest/download/russia_inside.srs",
			"domain", ruBlocked, "Domains blocked inside Russia (RKN-relevant). Maintained by itdoginfo.", "proxy"),
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
		srs("ru-outside", "RU outside (itdoginfo)", "https://github.com/itdoginfo/allow-domains/releases/latest/download/russia_outside.srs",
			"domain", antiGeo, "RU services that geo-restrict foreigners.", "proxy"),
		// Per-service — pick a tunnel per service.
		srs("svc-discord", "Discord", "https://github.com/itdoginfo/allow-domains/releases/latest/download/discord.srs", "domain", service, "Discord domains.", "proxy"),
		srs("svc-discord-voice", "Discord voice IPs", "https://github.com/legiz-ru/sb-rule-sets/raw/main/discord-voice-ip-list.srs", "ip", service, "Discord voice server IPs.", "proxy"),
		srs("svc-telegram", "Telegram", "https://github.com/itdoginfo/allow-domains/releases/latest/download/telegram.srs", "domain", service, "Telegram domains.", "proxy"),
		srs("svc-telegram-calls", "Telegram calls (voice IPs)", "https://raw.githubusercontent.com/vernette/rulesets/master/srs/telegram-voice-chats.srs", "ip", service, "Telegram voice/call server IPs — calls use raw UDP IPs the Telegram domain list misses, so add this too to keep calls on the tunnel.", "proxy"),
		srs("svc-youtube", "YouTube", "https://github.com/itdoginfo/allow-domains/releases/latest/download/youtube.srs", "domain", service, "YouTube domains.", "proxy"),
		srs("svc-meta", "Meta (IG/FB/WA)", "https://github.com/itdoginfo/allow-domains/releases/latest/download/meta.srs", "domain", service, "Instagram / Facebook / WhatsApp.", "proxy"),
		srs("svc-twitter", "Twitter / X", "https://github.com/itdoginfo/allow-domains/releases/latest/download/twitter.srs", "domain", service, "Twitter / X domains.", "proxy"),
		srs("svc-tiktok", "TikTok", "https://github.com/itdoginfo/allow-domains/releases/latest/download/tiktok.srs", "domain", service, "TikTok domains.", "proxy"),
		srs("svc-ai", "Google AI", "https://github.com/itdoginfo/allow-domains/releases/latest/download/google_ai.srs", "domain", service, "Google AI (Gemini) domains.", "proxy"),
		srs("svc-hdrezka", "HDrezka", "https://github.com/itdoginfo/allow-domains/releases/latest/download/hdrezka.srs", "domain", service, "HDrezka streaming.", "proxy"),
		// Blocklists.
		srs("block-ads", "Ads (block)", "https://github.com/itdoginfo/allow-domains/releases/latest/download/block.srs", "domain", junk, "Known ad/track domains — reject.", "block"),
		srs("block-porn", "Adult (block)", "https://github.com/itdoginfo/allow-domains/releases/latest/download/porn.srs", "domain", junk, "Adult domains — reject.", "block"),
	}
}
