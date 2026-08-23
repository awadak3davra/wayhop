// Package cidrfeed parses plain-text IP/CIDR feeds into normalized entries — the
// foundation of the RU/remote CIDR auto-refresh (so a routing list's kernel CIDRs can be
// sourced from a maintained feed instead of a hand-curated static list that rots). The
// fetch layer (HTTP feed URLs + RIPEstat ASN→prefix queries) and the refresh loop are
// later increments; ParseList is the format-independent core they all feed.
package cidrfeed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
)

// RIPEstatBase is the announced-prefixes endpoint the asn: source queries; the ASN number
// is appended. A package var so tests can point it at an httptest server.
var RIPEstatBase = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS"

// maxFeedBytes caps a single feed/RIPEstat response (DoS guard, mirrors the subscription
// fetcher); RIPEstat announced-prefixes for the biggest RU ASNs are well under this.
const maxFeedBytes = 8 << 20

// ParseList extracts IP/CIDR entries from a plain-text feed: one entry per line, with '#'
// or ';' starting a comment (whole-line or inline), surrounding whitespace ignored, and a
// trailing label after the CIDR tolerated ("1.2.3.0/24 SomeBank"). Bare IPs normalize to
// /32 (or /128); CIDRs are masked to their network address. Returns the normalized,
// de-duplicated entries in first-seen order plus the count of non-empty, non-comment lines
// that were NOT a valid IP/CIDR (for "fetched N, skipped M" reporting). Overlap-collapse
// and the v4/v6 split happen downstream (pbr.classifyCIDRs), so a feed mixing families and
// overlapping aggregates is fine here.
func ParseList(text string) (cidrs []string, skipped int) {
	// Strip a leading UTF-8 BOM (U+FEFF) — common on feeds authored/exported on Windows. It is NOT
	// whitespace (unicode.IsSpace is false), so TrimSpace leaves it on the first token and normalize
	// then rejects the BOM-prefixed CIDR, silently dropping the first (often largest) prefix and
	// leaking its traffic to the WAN.
	text = strings.TrimPrefix(text, "\uFEFF")
	seen := map[string]bool{}
	for _, raw := range strings.Split(text, "\n") {
		line := raw
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i] // strip inline / whole-line comment
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		tok := strings.Fields(line)[0] // tolerate "CIDR  label"
		norm, ok := normalize(tok)
		if !ok {
			skipped++
			continue
		}
		if !seen[norm] {
			seen[norm] = true
			cidrs = append(cidrs, norm)
		}
	}
	return cidrs, skipped
}

// ParseRIPEstat extracts the announced prefixes from a RIPEstat announced-prefixes JSON
// body (data.prefixes[].prefix), normalized + de-duplicated, plus a skipped-count for any
// malformed prefix. RIPEstat returns both v4 and v6; the v4/v6 split is left to
// pbr.classifyCIDRs downstream.
func ParseRIPEstat(body []byte) (cidrs []string, skipped int, err error) {
	var r struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, 0, fmt.Errorf("ripestat json: %w", err)
	}
	seen := map[string]bool{}
	for _, p := range r.Data.Prefixes {
		norm, ok := normalize(strings.TrimSpace(p.Prefix))
		if !ok {
			skipped++
			continue
		}
		if !seen[norm] {
			seen[norm] = true
			cidrs = append(cidrs, norm)
		}
	}
	return cidrs, skipped, nil
}

// Fetch retrieves and parses a CIDR source using the supplied client (the caller passes an
// SSRF-guarded one). source is either:
//
//	"https://…" / "http://…"  → a plain-text CIDR feed   (ParseList)
//	"asn:13238,47541,47764"   → RIPEstat announced-prefixes for each ASN (ParseRIPEstat),
//	                            merged + de-duplicated across ASNs
//
// Returns the normalized CIDRs + a skipped-count. The asn: path is ATOMIC: if any ASN
// fetch/parse fails the whole call errors (so the caller keeps its last-good set for ALL
// ASNs rather than shrinking a carve-out to a partial result).
func Fetch(ctx context.Context, client *http.Client, source string) (cidrs []string, skipped int, err error) {
	source = strings.TrimSpace(source)
	switch {
	case strings.HasPrefix(source, "asn:"):
		return fetchASNs(ctx, client, strings.TrimPrefix(source, "asn:"))
	case strings.HasPrefix(source, "https://"), strings.HasPrefix(source, "http://"):
		body, err := get(ctx, client, source)
		if err != nil {
			return nil, 0, err
		}
		c, s := ParseList(string(body))
		return c, s, nil
	default:
		return nil, 0, fmt.Errorf("unsupported cidr source %q (want https://… or asn:N,N)", source)
	}
}

func fetchASNs(ctx context.Context, client *http.Client, list string) (cidrs []string, skipped int, err error) {
	seen := map[string]bool{}
	n := 0
	for _, a := range strings.Split(list, ",") {
		a = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(a)), "AS")
		if a == "" {
			continue
		}
		if !isDigits(a) {
			return nil, 0, fmt.Errorf("invalid asn %q (want digits, optional AS prefix)", a)
		}
		body, err := get(ctx, client, RIPEstatBase+a)
		if err != nil {
			return nil, 0, fmt.Errorf("asn %s: %w", a, err)
		}
		c, s, err := ParseRIPEstat(body)
		if err != nil {
			return nil, 0, fmt.Errorf("asn %s: %w", a, err)
		}
		// RIPEstat can answer HTTP 200 with the real status in the JSON body (which ParseRIPEstat
		// doesn't surface), yielding zero prefixes. Treat that as an error rather than silently
		// contributing nothing — otherwise the documented all-or-nothing atomicity is broken and the
		// routing list under-fetches, leaking the traffic it was meant to steer.
		if len(c) == 0 {
			return nil, 0, fmt.Errorf("asn %s: no prefixes returned (RIPEstat error or empty result)", a)
		}
		skipped += s
		for _, x := range c {
			if !seen[x] {
				seen[x] = true
				cidrs = append(cidrs, x)
			}
		}
		n++
	}
	if n == 0 {
		return nil, 0, fmt.Errorf("no asns in %q", list)
	}
	return cidrs, skipped, nil
}

// get performs a capped GET and returns the body, erroring on non-200.
func get(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wayhop")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: status %s", url, resp.Status)
	}
	// Read ONE byte past the cap so an oversized feed is DETECTED, not silently truncated. A plain
	// LimitReader stops at the cap with no error; for a line-oriented CIDR feed that yields a
	// non-empty-but-incomplete set the caller accepts as a complete refresh, dropping every CIDR past
	// the cap from the carve-out (a routing leak). Fail CLOSED so the caller keeps its last-good set.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxFeedBytes {
		return nil, fmt.Errorf("%s: feed exceeds %d bytes — refusing a truncated read", url, int64(maxFeedBytes))
	}
	return body, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// normalize parses a token as a CIDR (masked to its network) or a bare IP (→ /32 or /128),
// returning the canonical string. ok=false for anything that is not a valid IP/CIDR.
func normalize(s string) (string, bool) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", false
		}
		return p.Masked().String(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	bits := 32
	if a.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(a, bits).String(), true
}

// MaxDomains bounds a domain feed. The limit is not about bandwidth: every domain becomes a dnsmasq
// directive the resolver holds in memory, so a feed's size lands on the router as resolver RSS and
// reload time — where a CIDR feed of the same coverage lands in a kernel hash set and costs almost
// nothing. Measured on the open feeds: a curated list is ~1.2k lines, a mid-size one ~81k, and a full
// registry dump 1.57M (28.8 MB). Refusing above this keeps the last-good cache and says why, rather
// than letting one paste take the resolver down.
const MaxDomains = 100000

// ParseDomains reads a plain-text domain feed: one name per line, `#`/`;`/`//` comments and blanks
// ignored. A leading dot ("​.ua") is stripped — dnsmasq matches a name and its subdomains either way —
// and everything that is not a plain domain (an address, a URL, a line with spaces) is skipped and
// counted rather than passed through to the resolver config.
func ParseDomains(text string) (domains []string, skipped int) {
	text = strings.TrimPrefix(text, "\uFEFF") // same BOM guard as ParseList
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		s := strings.TrimSpace(line)
		if i := strings.IndexAny(s, "#;"); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
		if strings.HasPrefix(s, "//") {
			continue
		}
		if s == "" {
			continue
		}
		s = strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(s, "."), "."))
		if !validDomain(s) {
			skipped++
			continue
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		domains = append(domains, s)
	}
	return domains, skipped
}

// validDomain accepts what the resolver plane can actually use as a match: labels of letters, digits
// and hyphens, at least two of them, no scheme, no path, no address.
func validDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, " \t/:@") {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	// A bare TLD list entry ("ua") is legitimate upstream but matches an entire zone here, so it is
	// only accepted when it was written as one (".ua" → "ua" has one label and was rejected above).
	return true
}

// FetchDomains fetches a plain-text domain feed. Same contract as Fetch: an https/http source only,
// bounded read, and a result the caller compares against the last-good cache before persisting.
func FetchDomains(ctx context.Context, client *http.Client, source string) (domains []string, skipped int, err error) {
	source = strings.TrimSpace(source)
	if !strings.HasPrefix(source, "https://") && !strings.HasPrefix(source, "http://") {
		return nil, 0, fmt.Errorf("unsupported domain source %q (want https://…)", source)
	}
	body, err := get(ctx, client, source)
	if err != nil {
		return nil, 0, err
	}
	d, s := ParseDomains(string(body))
	if len(d) > MaxDomains {
		return nil, s, fmt.Errorf("domain feed has %d names, over the %d limit this router can carry in its resolver — use the IP-list version of this feed instead", len(d), MaxDomains)
	}
	return d, s, nil
}
