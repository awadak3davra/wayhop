package iptv

import (
	"sort"
	"strings"
)

// Country is one selectable source in the compiled-in catalog: an ISO 3166-1 alpha-2 code, its
// English name, and a flag emoji computed from the code.
type Country struct {
	Code string `json:"code"` // lowercase ISO 3166-1 alpha-2
	Name string `json:"name"`
	Flag string `json:"flag"`
}

// countryNames is the HARD compiled-in source allowlist. Only these ISO codes can be turned into a
// fetch URL, and that URL is ALWAYS iptv-org's per-country playlist (hosts hard-coded in
// countryM3UTemplates). It is simultaneously:
//   - the LEGAL boundary — iptv-org per-country sources only, no free-text aggregator URL in v1;
//   - the SSRF boundary — no user-supplied host/path ever reaches the fetcher.
//
// A code iptv-org happens not to publish simply 404s at fetch time (handled gracefully upstream), so
// the list can stay broad (full ISO set) without risk.
var countryNames = map[string]string{
	"ad": "Andorra", "ae": "United Arab Emirates", "af": "Afghanistan", "al": "Albania",
	"am": "Armenia", "ao": "Angola", "ar": "Argentina", "at": "Austria", "au": "Australia",
	"az": "Azerbaijan", "ba": "Bosnia and Herzegovina", "bd": "Bangladesh", "be": "Belgium",
	"bf": "Burkina Faso", "bg": "Bulgaria", "bh": "Bahrain", "bo": "Bolivia", "br": "Brazil",
	"by": "Belarus", "ca": "Canada", "cd": "DR Congo", "cg": "Congo", "ch": "Switzerland",
	"ci": "Côte d'Ivoire", "cl": "Chile", "cm": "Cameroon", "cn": "China", "co": "Colombia",
	"cr": "Costa Rica", "cu": "Cuba", "cy": "Cyprus", "cz": "Czechia", "de": "Germany",
	"dk": "Denmark", "do": "Dominican Republic", "dz": "Algeria", "ec": "Ecuador", "ee": "Estonia",
	"eg": "Egypt", "es": "Spain", "et": "Ethiopia", "fi": "Finland", "fr": "France",
	"gb": "United Kingdom", "ge": "Georgia", "gh": "Ghana", "gr": "Greece", "gt": "Guatemala",
	"hk": "Hong Kong", "hn": "Honduras", "hr": "Croatia", "hu": "Hungary", "id": "Indonesia",
	"ie": "Ireland", "il": "Israel", "in": "India", "iq": "Iraq", "ir": "Iran",
	"is": "Iceland", "it": "Italy", "jm": "Jamaica", "jo": "Jordan", "jp": "Japan",
	"ke": "Kenya", "kg": "Kyrgyzstan", "kh": "Cambodia", "kr": "South Korea", "kw": "Kuwait",
	"kz": "Kazakhstan", "la": "Laos", "lb": "Lebanon", "lk": "Sri Lanka", "lt": "Lithuania",
	"lu": "Luxembourg", "lv": "Latvia", "ly": "Libya", "ma": "Morocco", "md": "Moldova",
	"me": "Montenegro", "mk": "North Macedonia", "mn": "Mongolia", "mt": "Malta", "mx": "Mexico",
	"my": "Malaysia", "ng": "Nigeria", "nl": "Netherlands", "no": "Norway", "np": "Nepal",
	"nz": "New Zealand", "om": "Oman", "pa": "Panama", "pe": "Peru", "ph": "Philippines",
	"pk": "Pakistan", "pl": "Poland", "pr": "Puerto Rico", "ps": "Palestine", "pt": "Portugal",
	"py": "Paraguay", "qa": "Qatar", "ro": "Romania", "rs": "Serbia", "ru": "Russia",
	"sa": "Saudi Arabia", "se": "Sweden", "sg": "Singapore", "si": "Slovenia", "sk": "Slovakia",
	"sn": "Senegal", "sv": "El Salvador", "sy": "Syria", "th": "Thailand", "tn": "Tunisia",
	"tr": "Turkey", "tw": "Taiwan", "tz": "Tanzania", "ua": "Ukraine", "ug": "Uganda",
	"us": "United States", "uy": "Uruguay", "uz": "Uzbekistan", "ve": "Venezuela", "vn": "Vietnam",
	"ye": "Yemen", "za": "South Africa", "zm": "Zambia", "zw": "Zimbabwe",
}

// iptvOrgPlaylist builds the primary + mirror URLs for an iptv-org playlist given its path tail
// (e.g. "countries/us", "languages/rus", "categories/news"), in priority order. The canonical GitHub
// Pages host is tried first; a jsDelivr CDN mirror carrying the SAME iptv-org gh-pages content is tried
// next, because GitHub Pages is routinely DPI-blocked/throttled in censored regions (the RU-connected
// router this project targets) — without a mirror the fetch just fails there. Every URL is a
// compile-time shape (only the allowlisted tail varies), preserving BOTH the legal boundary (iptv-org
// content only) and the SSRF boundary (no user-supplied host/path).
func iptvOrgPlaylist(tail string) []string {
	return []string{
		"https://iptv-org.github.io/iptv/" + tail + ".m3u",
		"https://cdn.jsdelivr.net/gh/iptv-org/iptv@gh-pages/" + tail + ".m3u",
	}
}

func normCode(code string) string { return strings.ToLower(strings.TrimSpace(code)) }

// KnownCountry reports whether code is in the compiled-in allowlist (case-insensitive).
func KnownCountry(code string) bool {
	_, ok := countryNames[normCode(code)]
	return ok
}

// CountryName returns the catalog display name for an allowlisted code ("" if not in the allowlist).
func CountryName(code string) string { return countryNames[normCode(code)] }

// CountryFlag returns the flag emoji for a 2-letter country code ("" for a non-alpha-2 code).
func CountryFlag(code string) string { return flagEmoji(code) }

// CountryM3U returns the canonical (primary) iptv-org playlist URL for an allowlisted country. ok is
// false for any code not in the catalog — the sole path by which a fetch URL is constructed, so no
// user-supplied string ever reaches the fetcher's host or path. See CountryM3Us for the mirror list.
func CountryM3U(code string) (string, bool) {
	c := normCode(code)
	if _, ok := countryNames[c]; !ok {
		return "", false
	}
	return iptvOrgPlaylist("countries/" + c)[0], true
}

// CountryM3Us returns the iptv-org playlist URLs for an allowlisted country in priority order — the
// canonical host first, then CDN mirror(s) carrying identical content — so a caller can fall through
// to a mirror when the primary is DPI-blocked. ok is false for any code not in the catalog. Every URL
// is built from a compile-time template, so the SSRF+legal boundary holds across all mirrors.
func CountryM3Us(code string) ([]string, bool) {
	c := normCode(code)
	if _, ok := countryNames[c]; !ok {
		return nil, false
	}
	return iptvOrgPlaylist("countries/" + c), true
}

// catalogKinds are the iptv-org taxonomies BEYOND per-country: category + language playlists, each a
// single publicly-listed, auto-updating iptv-org list — the same trusted source + legal posture as the
// country catalog, just a different slice. Regions are deliberately excluded (a region playlist is
// huge — often megabytes — and redundant with the countries it contains). A List references these as
// "kind:code" tokens (e.g. "language:rus", "category:news"); code sets were verified live against
// iptv-org (a code it stops publishing simply 404s at fetch time, handled gracefully upstream).
var catalogKinds = []struct {
	kind, label, path string
	names             map[string]string
}{
	{"language", "Language", "languages", map[string]string{
		"rus": "Russian", "eng": "English", "ara": "Arabic", "fas": "Persian", "spa": "Spanish",
		"fra": "French", "deu": "German", "por": "Portuguese", "ita": "Italian", "tur": "Turkish",
		"hin": "Hindi", "zho": "Chinese", "ukr": "Ukrainian", "pol": "Polish", "ron": "Romanian",
		"ell": "Greek", "nld": "Dutch", "ces": "Czech", "hun": "Hungarian", "srp": "Serbian",
		"hrv": "Croatian", "bul": "Bulgarian", "heb": "Hebrew", "tha": "Thai", "vie": "Vietnamese",
		"ind": "Indonesian", "msa": "Malay", "jpn": "Japanese", "kor": "Korean", "aze": "Azerbaijani",
		"kaz": "Kazakh", "uzb": "Uzbek", "hye": "Armenian", "kat": "Georgian", "tgk": "Tajik",
		"kir": "Kyrgyz", "tuk": "Turkmen", "ben": "Bengali", "urd": "Urdu", "tam": "Tamil",
	}},
	{"category", "Category", "categories", map[string]string{
		"news": "News", "sports": "Sports", "movies": "Movies", "music": "Music", "kids": "Kids",
		"entertainment": "Entertainment", "documentary": "Documentary", "general": "General",
		"comedy": "Comedy", "culture": "Culture", "education": "Education", "lifestyle": "Lifestyle",
		"science": "Science", "series": "Series", "travel": "Travel", "weather": "Weather",
		"religious": "Religious", "cooking": "Cooking", "outdoor": "Outdoor", "relax": "Relax",
		"business": "Business", "animation": "Animation", "classic": "Classic", "family": "Family",
	}},
}

// CatalogM3Us resolves a "kind:code" catalog token (e.g. "language:rus") to its iptv-org playlist URLs
// (primary + mirror). ok is false for an unknown kind or code — the sole URL-construction path for
// these sources, so no user-supplied host/path ever reaches the fetcher.
func CatalogM3Us(token string) ([]string, bool) {
	kind, code, ok := strings.Cut(token, ":")
	if !ok {
		return nil, false
	}
	kind, code = normCode(kind), normCode(code)
	for _, k := range catalogKinds {
		if k.kind == kind {
			if _, ok := k.names[code]; ok {
				return iptvOrgPlaylist(k.path + "/" + code), true
			}
			return nil, false
		}
	}
	return nil, false
}

// KnownCatalog reports whether a "kind:code" token is in the compiled-in allowlist.
func KnownCatalog(token string) bool { _, ok := CatalogM3Us(token); return ok }

// CatalogLabel returns a human label for a token ("Russian", "News"), or "" if unknown.
func CatalogLabel(token string) string {
	kind, code, ok := strings.Cut(token, ":")
	if !ok {
		return ""
	}
	kind, code = normCode(kind), normCode(code)
	for _, k := range catalogKinds {
		if k.kind == kind {
			return k.names[code]
		}
	}
	return ""
}

// CatalogKind is one non-country taxonomy for the picker: its kind key, display label, and entries.
type CatalogKind struct {
	Kind    string    `json:"kind"`
	Label   string    `json:"label"`
	Entries []Country `json:"entries"` // reuses {Code,Name}; Flag is empty for category/language
}

// CatalogKinds returns the category + language picker data, entries sorted by name.
func CatalogKinds() []CatalogKind {
	out := make([]CatalogKind, 0, len(catalogKinds))
	for _, k := range catalogKinds {
		entries := make([]Country, 0, len(k.names))
		for code, name := range k.names {
			entries = append(entries, Country{Code: code, Name: name})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
		out = append(out, CatalogKind{Kind: k.kind, Label: k.label, Entries: entries})
	}
	return out
}

// flagEmoji maps a 2-letter country code to its flag (two Unicode regional-indicator symbols); "" for
// a non-alpha-2 code.
func flagEmoji(code string) string {
	c := normCode(code)
	if len(c) != 2 || c[0] < 'a' || c[0] > 'z' || c[1] < 'a' || c[1] > 'z' {
		return ""
	}
	const base = 0x1F1E6 // 🇦 (regional indicator symbol letter A)
	return string(rune(base+int(c[0]-'a'))) + string(rune(base+int(c[1]-'a')))
}

// Catalog returns the allowlisted countries sorted by name, each with a computed flag, for the UI's
// country picker.
func Catalog() []Country {
	out := make([]Country, 0, len(countryNames))
	for code, name := range countryNames {
		out = append(out, Country{Code: code, Name: name, Flag: flagEmoji(code)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
