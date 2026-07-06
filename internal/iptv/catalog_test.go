package iptv

import (
	"sort"
	"strings"
	"testing"
)

func TestCountryM3UAllowlist(t *testing.T) {
	// Allowlisted codes (any case) build the canonical URL.
	for _, code := range []string{"us", "US", "ru", "gb", " fr "} {
		got, ok := CountryM3U(code)
		if !ok {
			t.Fatalf("CountryM3U(%q) not allowlisted", code)
		}
		want := "https://iptv-org.github.io/iptv/countries/" + strings.ToLower(strings.TrimSpace(code)) + ".m3u"
		if got != want {
			t.Fatalf("CountryM3U(%q) = %q, want %q", code, got, want)
		}
		if !strings.HasPrefix(got, "https://iptv-org.github.io/") {
			t.Fatalf("URL host not hard-coded to iptv-org: %q", got)
		}
	}
	// Anything not in the allowlist (junk / injection / empty) is refused — the SSRF+legal boundary.
	for _, bad := range []string{"", "zz", "x", "usa", "../etc", "us/../evil", "http://evil", "u;rm"} {
		if url, ok := CountryM3U(bad); ok {
			t.Fatalf("CountryM3U(%q) must be refused, got %q", bad, url)
		}
	}
}

func TestCountryM3Us(t *testing.T) {
	urls, ok := CountryM3Us("US")
	if !ok {
		t.Fatal("CountryM3Us(US) not allowlisted")
	}
	if len(urls) < 2 {
		t.Fatalf("expected primary + at least one mirror, got %v", urls)
	}
	// Primary must equal CountryM3U (the canonical URL), and every URL must be a hard-coded
	// reputable host for the same country file — the legal+SSRF boundary across mirrors.
	primary, _ := CountryM3U("us")
	if urls[0] != primary {
		t.Fatalf("CountryM3Us[0] = %q, want primary %q", urls[0], primary)
	}
	for _, u := range urls {
		if !strings.HasSuffix(u, "/us.m3u") {
			t.Fatalf("mirror URL not the us country file: %q", u)
		}
		if !strings.HasPrefix(u, "https://iptv-org.github.io/") && !strings.HasPrefix(u, "https://cdn.jsdelivr.net/") {
			t.Fatalf("mirror host not on the compiled-in allowlist: %q", u)
		}
	}
	// Unknown code is refused (no URL leaks).
	if got, ok := CountryM3Us("zz"); ok || got != nil {
		t.Fatalf("CountryM3Us(zz) must be refused, got %v", got)
	}
}

func TestCatalogM3Us(t *testing.T) {
	// language + category tokens (any case) resolve to primary + mirror URLs on the allowlisted hosts.
	for _, tok := range []string{"language:rus", "category:news", "LANGUAGE:RUS"} {
		urls, ok := CatalogM3Us(tok)
		if !ok || len(urls) < 2 {
			t.Fatalf("CatalogM3Us(%q) = %v, %v", tok, urls, ok)
		}
		for _, u := range urls {
			if !strings.HasPrefix(u, "https://iptv-org.github.io/") && !strings.HasPrefix(u, "https://cdn.jsdelivr.net/") {
				t.Fatalf("catalog URL off the allowlist: %q", u)
			}
		}
	}
	if u, _ := CatalogM3Us("language:rus"); !strings.Contains(u[0], "/languages/rus.m3u") {
		t.Fatalf("wrong path: %q", u[0])
	}
	if u, _ := CatalogM3Us("category:news"); !strings.Contains(u[0], "/categories/news.m3u") {
		t.Fatalf("wrong path: %q", u[0])
	}
	// unknown kind / code / malformed → refused (no URL leaks)
	for _, bad := range []string{"region:eur", "language:zzz", "category:", "foo", "language", ":rus", ""} {
		if urls, ok := CatalogM3Us(bad); ok {
			t.Fatalf("CatalogM3Us(%q) must be refused, got %v", bad, urls)
		}
	}
	if !KnownCatalog("language:rus") || KnownCatalog("language:zzz") {
		t.Fatal("KnownCatalog wrong")
	}
	if CatalogLabel("language:rus") != "Russian" || CatalogLabel("category:news") != "News" || CatalogLabel("bad") != "" {
		t.Fatal("CatalogLabel wrong")
	}
}

func TestCatalogKinds(t *testing.T) {
	kinds := CatalogKinds()
	if len(kinds) != 2 {
		t.Fatalf("expected 2 kinds (language, category), got %d", len(kinds))
	}
	for _, k := range kinds {
		if k.Kind == "" || k.Label == "" || len(k.Entries) == 0 {
			t.Fatalf("incomplete kind: %+v", k)
		}
		if !sort.SliceIsSorted(k.Entries, func(i, j int) bool { return k.Entries[i].Name < k.Entries[j].Name }) {
			t.Fatalf("%s entries not sorted by name", k.Kind)
		}
		if _, ok := CatalogM3Us(k.Kind + ":" + k.Entries[0].Code); !ok { // every listed entry must resolve
			t.Fatalf("entry doesn't resolve: %s:%s", k.Kind, k.Entries[0].Code)
		}
	}
}

func TestKnownCountry(t *testing.T) {
	if !KnownCountry("Ua") || KnownCountry("zz") {
		t.Fatal("KnownCountry case/allowlist wrong")
	}
}

func TestFlagEmoji(t *testing.T) {
	// 🇺🇸 = U+1F1FA U+1F1F8.
	got := []rune(flagEmoji("us"))
	if len(got) != 2 || got[0] != 0x1F1FA || got[1] != 0x1F1F8 {
		t.Fatalf("flagEmoji(us) = %q (%U)", string(got), got)
	}
	if flagEmoji("x") != "" || flagEmoji("u1") != "" {
		t.Fatal("flagEmoji should reject non-alpha-2 codes")
	}
}

func TestCatalogSortedAndComplete(t *testing.T) {
	cat := Catalog()
	if len(cat) < 100 {
		t.Fatalf("catalog unexpectedly small: %d", len(cat))
	}
	if !sort.SliceIsSorted(cat, func(i, j int) bool { return cat[i].Name < cat[j].Name }) {
		t.Fatal("catalog not sorted by name")
	}
	for _, c := range cat {
		if c.Code == "" || c.Name == "" || c.Flag == "" {
			t.Fatalf("incomplete catalog entry: %+v", c)
		}
		if _, ok := CountryM3U(c.Code); !ok {
			t.Fatalf("catalog code %q is not allowlisted by CountryM3U", c.Code)
		}
	}
}
