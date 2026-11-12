package dnscheck

import (
	"sort"
	"time"
)

// FastEntry is one encrypted resolver in the quick list. Every entry was measured alive with a valid
// certificate in November 2026. The address is pinned and the name goes in the TLS handshake, so using one
// needs no plaintext lookup to find it.
//
// An operator a state owns, funds or has a way to read stays out, however fast: this list exists to take
// lookups away from whoever can compel them. Yandex, AliDNS, DNSPod and DNS4EU were here and were removed.
type FastEntry struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Country string `json:"country,omitempty"` // the operator's jurisdiction, when it is plain
	Filter  string `json:"filter"`            // none | malware | ads | family
	IP      string `json:"ip"`
	Host    string `json:"host"`               // the name its certificate holds
	DoHPath string `json:"doh_path,omitempty"` // "" = no DoH here
	DoT     bool   `json:"dot,omitempty"`
}

// FastCatalog is the quick list. The order is only the order before anything is measured.
var FastCatalog = []FastEntry{
	{ID: "cloudflare", Name: "Cloudflare", Country: "US", Filter: "none", IP: "1.1.1.1", Host: "one.one.one.one", DoHPath: "/dns-query", DoT: true},
	{ID: "cloudflare-security", Name: "Cloudflare Security", Country: "US", Filter: "malware", IP: "1.1.1.2", Host: "security.cloudflare-dns.com", DoHPath: "/dns-query", DoT: true},
	{ID: "cloudflare-family", Name: "Cloudflare Family", Country: "US", Filter: "family", IP: "1.1.1.3", Host: "family.cloudflare-dns.com", DoHPath: "/dns-query", DoT: true},
	{ID: "google", Name: "Google", Country: "US", Filter: "none", IP: "8.8.8.8", Host: "dns.google", DoHPath: "/dns-query", DoT: true},
	{ID: "quad9", Name: "Quad9", Country: "CH", Filter: "malware", IP: "9.9.9.9", Host: "dns.quad9.net", DoHPath: "/dns-query", DoT: true},
	{ID: "quad9-plain", Name: "Quad9 unfiltered", Country: "CH", Filter: "none", IP: "9.9.9.10", Host: "dns10.quad9.net", DoHPath: "/dns-query", DoT: true},
	{ID: "adguard", Name: "AdGuard", Country: "CY", Filter: "ads", IP: "94.140.14.14", Host: "dns.adguard-dns.com", DoHPath: "/dns-query", DoT: true},
	{ID: "adguard-plain", Name: "AdGuard unfiltered", Country: "CY", Filter: "none", IP: "94.140.14.140", Host: "unfiltered.adguard-dns.com", DoHPath: "/dns-query", DoT: true},
	{ID: "adguard-family", Name: "AdGuard Family", Country: "CY", Filter: "family", IP: "94.140.14.15", Host: "family.adguard-dns.com", DoHPath: "/dns-query", DoT: true},
	{ID: "mullvad", Name: "Mullvad", Country: "SE", Filter: "none", IP: "194.242.2.2", Host: "dns.mullvad.net", DoHPath: "/dns-query", DoT: true},
	{ID: "mullvad-adblock", Name: "Mullvad adblock", Country: "SE", Filter: "ads", IP: "194.242.2.3", Host: "adblock.dns.mullvad.net", DoHPath: "/dns-query", DoT: true},
	{ID: "dnssb", Name: "DNS.SB", Filter: "none", IP: "185.222.222.222", Host: "dns.sb", DoHPath: "/dns-query", DoT: true},
	{ID: "controld", Name: "Control D", Country: "CA", Filter: "none", IP: "76.76.2.0", Host: "freedns.controld.com", DoHPath: "/p0"},
	{ID: "controld-ads", Name: "Control D ads", Country: "CA", Filter: "ads", IP: "76.76.2.2", Host: "freedns.controld.com", DoHPath: "/p2"},
	{ID: "opendns", Name: "OpenDNS", Country: "US", Filter: "malware", IP: "208.67.222.222", Host: "dns.opendns.com", DoHPath: "/dns-query", DoT: true},
	{ID: "nextdns", Name: "NextDNS", Country: "US", Filter: "none", IP: "45.90.28.0", Host: "dns.nextdns.io", DoHPath: "/dns-query", DoT: true},
	{ID: "cleanbrowsing", Name: "CleanBrowsing", Country: "US", Filter: "malware", IP: "185.228.168.9", Host: "security-filter-dns.cleanbrowsing.org", DoHPath: "/doh/security-filter/", DoT: true},
	{ID: "applied-privacy", Name: "Applied Privacy", Country: "AT", Filter: "none", IP: "146.255.56.98", Host: "doh.applied-privacy.net", DoHPath: "/query", DoT: true},
	{ID: "wikimedia", Name: "Wikimedia", Country: "US", Filter: "none", IP: "185.71.138.138", Host: "wikimedia-dns.org", DoHPath: "/dns-query", DoT: true},
}

// Transport outcomes. Only bad_cert is evidence against a resolver: the rest may be the path.
const (
	FastOK        = "ok"
	FastBadCert   = "bad_cert"   // it answered and its certificate does not hold for the name
	FastTimeout   = "timeout"    // nothing came back, or the handshake stalled: lines block this way
	FastRefused   = "refused"    // connection refused or reset
	FastBadAnswer = "bad_answer" // the channel is fine, the answer was an error or empty
	FastOther     = "other"
)

// FastTransport is one protocol measured to one resolver.
type FastTransport struct {
	Proto     string `json:"proto"` // doh | dot
	Status    string `json:"status"`
	Ms        int    `json:"ms,omitempty"`         // one lookup over the open connection: what a client feels
	ConnectMs int    `json:"connect_ms,omitempty"` // the first lookup with its connection and handshake
	CertName  string `json:"cert_name,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	CertDays  int    `json:"cert_days,omitempty"`
}

// FastResult is one resolver measured on one path.
type FastResult struct {
	ID         string          `json:"id"`
	Alive      bool            `json:"alive"` // some transport passed: the certificate held and a real answer came back
	Best       string          `json:"best,omitempty"`
	Ms         int             `json:"ms,omitempty"`        // the best transport's
	Validates  *bool           `json:"validates,omitempty"` // refused a broken DNSSEC name; nil when it did not say
	Transports []FastTransport `json:"transports"`
}

// FastVia is a way out the list can be measured through. A proxy outbound has no link to bind to, so it
// cannot be one.
type FastVia struct {
	ID    string   `json:"id"`
	Label string   `json:"label"`
	Kind  PathKind `json:"kind"` // wan | tunnel
	Iface string   `json:"iface,omitempty"`
}

// FastReport is one finished measurement.
type FastReport struct {
	Via        string       `json:"via"`
	Path       Path         `json:"path"`
	Demo       bool         `json:"demo,omitempty"`
	StartedAt  time.Time    `json:"started_at"`
	FinishedAt time.Time    `json:"finished_at"`
	Results    []FastResult `json:"results"` // alive first, fastest first
	// CertsUnreliable: every resolver failed on its certificate, which says something about this router's
	// clock or CA bundle and nothing about the resolvers.
	CertsUnreliable bool `json:"certs_unreliable,omitempty"`
}

// FastState is what GET /api/dns/fast answers.
type FastState struct {
	Catalog  []FastEntry `json:"catalog"`
	Vias     []FastVia   `json:"vias"`
	Default  string      `json:"default,omitempty"` // the via the DNS plane would ride
	Running  bool        `json:"running"`
	Progress Progress    `json:"progress"`
	Report   *FastReport `json:"report,omitempty"` // for the via asked about, if measured
}

// FastRequest starts a measurement.
type FastRequest struct {
	Via string `json:"via"`
}

// SortFast orders results the way the list shows them: alive and fastest first, ties broken by the
// catalog's order so the list does not shuffle between runs. The rest keep the catalog's order.
func SortFast(results []FastResult) {
	rank := make(map[string]int, len(FastCatalog))
	for i, e := range FastCatalog {
		rank[e.ID] = i
	}
	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.Alive != b.Alive {
			return a.Alive
		}
		if a.Alive && a.Ms != b.Ms {
			return a.Ms < b.Ms
		}
		return rank[a.ID] < rank[b.ID]
	})
}
