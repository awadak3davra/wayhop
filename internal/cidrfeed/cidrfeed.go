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
	req.Header.Set("User-Agent", "velinx")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: status %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
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
