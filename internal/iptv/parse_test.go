package iptv

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseBasic(t *testing.T) {
	in := bom + "#EXTM3U url-tvg=\"https://example.test/epg.xml\"\n" +
		"#EXTINF:-1 tvg-id=\"CNN.us\" tvg-logo=\"https://l.test/cnn.png\" group-title=\"News\",CNN\n" +
		"https://s.test/cnn/index.m3u8\n" +
		"#EXTINF:-1 tvg-id=\"bbc\" group-title=\"News\" tvg-name=\"BBC One\",\n" + // empty display name → falls back to tvg-name
		"https://s.test/bbc.m3u8\n"
	pl, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pl.URLTvg != "https://example.test/epg.xml" {
		t.Errorf("url-tvg = %q", pl.URLTvg)
	}
	if len(pl.Channels) != 2 {
		t.Fatalf("channels = %d, want 2", len(pl.Channels))
	}
	want0 := Channel{TvgID: "CNN.us", Name: "CNN", Logo: "https://l.test/cnn.png", Group: "News", URL: "https://s.test/cnn/index.m3u8"}
	if !reflect.DeepEqual(pl.Channels[0], want0) {
		t.Errorf("ch0 = %#v, want %#v", pl.Channels[0], want0)
	}
	if pl.Channels[1].Name != "BBC One" {
		t.Errorf("ch1 name = %q, want BBC One (tvg-name fallback)", pl.Channels[1].Name)
	}
}

// TestParseExtraAttrs: provider metadata not modeled as a dedicated field (channel number, catch-up,
// EPG shift) is preserved verbatim in Extra, in source order; tvg-id/tvg-logo/group-title are NOT
// duplicated into Extra (they have their own fields).
func TestParseExtraAttrs(t *testing.T) {
	in := "#EXTM3U\n" +
		"#EXTINF:-1 tvg-chno=\"105\" tvg-id=\"sky.uk\" group-title=\"UK\" catchup=\"default\" " +
		"catchup-source=\"http://s/cu?ch=105&t=${start}\" catchup-days=\"7\" tvg-shift=\"-2\",Sky\n" +
		"http://s/sky\n"
	pl, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(pl.Channels) != 1 {
		t.Fatalf("channels = %d", len(pl.Channels))
	}
	c := pl.Channels[0]
	if c.TvgID != "sky.uk" || c.Group != "UK" {
		t.Fatalf("modeled attrs wrong: %+v", c)
	}
	// Extra keeps the non-modeled attrs in source order; the modeled ones are excluded.
	want := [][2]string{
		{"tvg-chno", "105"},
		{"catchup", "default"},
		{"catchup-source", "http://s/cu?ch=105&t=${start}"},
		{"catchup-days", "7"},
		{"tvg-shift", "-2"},
	}
	if !reflect.DeepEqual(c.Extra, want) {
		t.Fatalf("Extra = %#v, want %#v", c.Extra, want)
	}
	// And it must survive render → the emitted M3U carries the channel number + catch-up.
	out := string(Render(pl.Channels, ""))
	for _, s := range []string{`tvg-chno="105"`, `catchup="default"`, `catchup-source="http://s/cu?ch=105&t=${start}"`, `tvg-shift="-2"`} {
		if !strings.Contains(out, s) {
			t.Fatalf("render dropped %q:\n%s", s, out)
		}
	}
	// Modeled attrs must not be duplicated (exactly one tvg-id in the output).
	if n := strings.Count(out, "tvg-id="); n != 1 {
		t.Fatalf("tvg-id emitted %d times, want 1:\n%s", n, out)
	}
}

// TestParseExtraAttrsRoundTrip: a playlist with extra attrs is idempotent under parse→render→parse.
func TestParseExtraAttrsRoundTrip(t *testing.T) {
	src := "#EXTM3U\n#EXTINF:-1 tvg-id=\"a\" tvg-chno=\"7\" catchup=\"append\" group-title=\"G\",Alpha\nhttp://s/a\n"
	first, _ := Parse(strings.NewReader(src))
	second, _ := Parse(strings.NewReader(string(Render(first.Channels, first.URLTvg))))
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("extra-attr round-trip changed the playlist:\nfirst=%#v\nsecond=%#v", first, second)
	}
}

// TestParseAttrCaseAndBoundary guards two attribute-matching bugs: (1) a mixed-case modeled key
// (TVG-ID, Group-Title) — which the case-sensitive extAttr doesn't capture — must be preserved verbatim
// in Extra rather than dropped by both paths; (2) a key that merely CONTAINS a modeled key
// (x-group-title) must NOT fabricate a phantom modeled attribute.
func TestParseAttrCaseAndBoundary(t *testing.T) {
	pl, _ := Parse(strings.NewReader("#EXTM3U\n#EXTINF:-1 TVG-ID=\"upper\" Group-Title=\"G\" tvg-chno=\"5\",Name\nhttp://s/x\n"))
	if len(pl.Channels) != 1 {
		t.Fatalf("channels = %d", len(pl.Channels))
	}
	out := string(Render(pl.Channels, ""))
	for _, want := range []string{`TVG-ID="upper"`, `Group-Title="G"`, `tvg-chno="5"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("mixed-case attr not preserved verbatim: %q missing from %q", want, out)
		}
	}

	pl2, _ := Parse(strings.NewReader("#EXTM3U\n#EXTINF:-1 x-group-title=\"STOLEN\" tvg-chno=\"5\",Name\nhttp://s/y\n"))
	if c := pl2.Channels[0]; c.Group != "" {
		t.Fatalf("x-group-title fabricated a modeled group: %q", c.Group)
	}
	out2 := string(Render(pl2.Channels, ""))
	if strings.Contains(out2, ` group-title="STOLEN"`) { // leading space = a STANDALONE group-title attr
		t.Fatalf("phantom standalone group-title emitted: %q", out2)
	}
	if !strings.Contains(out2, `x-group-title="STOLEN"`) {
		t.Fatalf("x-group-title not preserved: %q", out2)
	}
}

func TestParseNameWithComma(t *testing.T) {
	in := "#EXTM3U\n#EXTINF:-1 tvg-id=\"x\" group-title=\"Movies\",Action, Drama & More\nhttp://s/x\n"
	pl, _ := Parse(strings.NewReader(in))
	if len(pl.Channels) != 1 || pl.Channels[0].Name != "Action, Drama & More" {
		t.Fatalf("name with comma mis-split: %+v", pl.Channels)
	}
}

func TestParseHeaderOptions(t *testing.T) {
	in := "#EXTM3U\n" +
		"#EXTINF:-1,UA Chan\n" +
		"#EXTVLCOPT:http-user-agent=Mozilla/5.0 (SmartTV)\n" +
		"#EXTVLCOPT:http-referrer=https://ref.test/\n" +
		"http://s/ua\n" +
		"#EXTINF:-1,JSON Chan\n" +
		"#EXTHTTP:{\"User-Agent\":\"VLC/3.0\",\"Referer\":\"https://j.test/\"}\n" +
		"#KODIPROP:inputstream.adaptive.license_type=clearkey\n" +
		"http://s/json\n"
	pl, _ := Parse(strings.NewReader(in))
	if len(pl.Channels) != 2 {
		t.Fatalf("channels = %d, want 2", len(pl.Channels))
	}
	c0 := pl.Channels[0]
	if c0.UserAgent != "Mozilla/5.0 (SmartTV)" || c0.Referrer != "https://ref.test/" {
		t.Errorf("EXTVLCOPT not lifted: ua=%q ref=%q", c0.UserAgent, c0.Referrer)
	}
	if len(c0.Headers) != 2 {
		t.Errorf("headers not preserved verbatim: %v", c0.Headers)
	}
	c1 := pl.Channels[1]
	if c1.UserAgent != "VLC/3.0" || c1.Referrer != "https://j.test/" {
		t.Errorf("EXTHTTP not lifted: ua=%q ref=%q", c1.UserAgent, c1.Referrer)
	}
	if len(c1.Headers) != 2 { // EXTHTTP + KODIPROP both preserved
		t.Errorf("json chan headers = %v, want 2 (EXTHTTP+KODIPROP)", c1.Headers)
	}
}

func TestParseMalformed(t *testing.T) {
	in := "#EXTM3U\n" +
		"#EXTINF:-1,Orphan (no url)\n" + // no URL follows before the next EXTINF → dropped
		"#EXTINF:-1,Good\n" +
		"http://s/good\n" +
		"http://s/bare-url-no-extinf\n" + // bare URL with no preceding #EXTINF → dropped
		"garbage line\n" +
		"#SOME-UNKNOWN-DIRECTIVE\n"
	pl, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse err: %v", err)
	}
	if len(pl.Channels) != 1 || pl.Channels[0].Name != "Good" {
		t.Fatalf("lenient parse wrong: %+v", pl.Channels)
	}
}

func TestParseEmpty(t *testing.T) {
	pl, err := Parse(strings.NewReader(""))
	if err != nil || len(pl.Channels) != 0 {
		t.Fatalf("empty input: err=%v channels=%d", err, len(pl.Channels))
	}
}

func TestParseURLFallbackName(t *testing.T) {
	// EXTINF with no attrs and no name → the URL becomes the name so it isn't blank.
	in := "#EXTM3U\n#EXTINF:-1,\nhttp://s/nameless\n"
	pl, _ := Parse(strings.NewReader(in))
	if len(pl.Channels) != 1 || pl.Channels[0].Name != "http://s/nameless" {
		t.Fatalf("nameless fallback: %+v", pl.Channels)
	}
}

// FuzzParse hardens the untrusted-input path: Parse (and the whole pure pipeline behind it) runs on
// upstream M3U from iptv-org AND user-supplied provider URLs, so it must never panic, must terminate,
// and must bound its output on arbitrary/malformed bytes. It also fuzzes the parse→pipeline→render
// round-trip.
func FuzzParse(f *testing.F) {
	f.Add("")
	f.Add("#EXTM3U\n")
	f.Add(bom + "#EXTM3U url-tvg=\"http://epg\"\n#EXTINF:-1 tvg-id=\"a\" group-title=\"News\",Alpha\nhttp://s/a\n")
	f.Add("#EXTINF:-1,\xff\xfe partial no url")
	f.Add("#EXTINF:-1 tvg-id=\"x\n#EXTVLCOPT:http-user-agent=UA\n#EXTHTTP:{\"user-agent\":\"Z\"}\nhttp://s/x\n")
	f.Add(strings.Repeat("#EXTINF:-1,a\nhttp://s\n", 200))
	f.Fuzz(func(t *testing.T, data string) {
		pl, err := Parse(strings.NewReader(data))
		if err != nil {
			return // a scanner error (e.g. a >1 MiB line) is a valid, bounded outcome
		}
		if pl == nil {
			t.Fatal("Parse returned (nil, nil)")
		}
		// A channel needs at least an #EXTINF line + a URL line, so it can't exceed the input length.
		if len(pl.Channels) > len(data)+1 {
			t.Fatalf("unbounded parse: %d channels from %d bytes", len(pl.Channels), len(data))
		}
		// The whole pure pipeline must survive adversarial input without panicking.
		block := map[string]bool{}
		filtered, _ := Filter(pl.Channels, FilterOptions{Blocklist: block})
		deduped, _ := Dedup(filtered)
		Sort(deduped)
		_ = Categorize(deduped)
		rendered := Render(deduped, pl.URLTvg)
		// Render must be re-parseable (round-trip) without panic.
		if _, err := Parse(strings.NewReader(string(rendered))); err != nil {
			return
		}
	})
}
