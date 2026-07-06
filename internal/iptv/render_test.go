package iptv

import (
	"reflect"
	"strings"
	"testing"
)

// TestRenderGolden pins the exact emitted M3U (a golden string).
func TestRenderGolden(t *testing.T) {
	chs := []Channel{
		{TvgID: "cnn.us", Name: "CNN", Logo: "http://l/cnn.png", Group: "News", URL: "http://s/cnn"},
		{Name: "Local (no attrs)", URL: "http://s/local"},
		{TvgID: "ua.tv", Name: "UA Chan", Group: "News", URL: "http://s/ua",
			Headers: []string{"#EXTVLCOPT:http-user-agent=SmartTV", "#EXTVLCOPT:http-referrer=http://ref/"}},
	}
	want := "#EXTM3U url-tvg=\"http://epg/guide.xml\"\n" +
		"#EXTINF:-1 tvg-id=\"cnn.us\" tvg-logo=\"http://l/cnn.png\" group-title=\"News\",CNN\n" +
		"http://s/cnn\n" +
		"#EXTINF:-1,Local (no attrs)\n" +
		"http://s/local\n" +
		"#EXTINF:-1 tvg-id=\"ua.tv\" group-title=\"News\",UA Chan\n" +
		"#EXTVLCOPT:http-user-agent=SmartTV\n" +
		"#EXTVLCOPT:http-referrer=http://ref/\n" +
		"http://s/ua\n"
	got := string(Render(chs, "http://epg/guide.xml"))
	if got != want {
		t.Fatalf("Render mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderNoURLTvg(t *testing.T) {
	got := string(Render([]Channel{{Name: "X", URL: "http://x"}}, ""))
	if !strings.HasPrefix(got, "#EXTM3U\n") {
		t.Fatalf("no url-tvg header expected, got %q", got)
	}
}

func TestRenderNoBOMAndSkipsEmptyURL(t *testing.T) {
	out := Render([]Channel{
		{Name: "Good", URL: "http://good"},
		{Name: "Bad (no url)", URL: ""},
	}, "")
	if len(out) >= 3 && out[0] == 0xEF && out[1] == 0xBB && out[2] == 0xBF {
		t.Fatal("output must not start with a UTF-8 BOM")
	}
	if strings.Contains(string(out), "Bad (no url)") {
		t.Fatal("empty-URL channel must be skipped")
	}
}

// TestRenderRoundTrip: parse → render → parse yields identical channels + url-tvg (Render is a
// faithful inverse of Parse for the fields M3U carries).
func TestRenderRoundTrip(t *testing.T) {
	src := "#EXTM3U url-tvg=\"http://epg/g.xml\"\n" +
		"#EXTINF:-1 tvg-id=\"a\" tvg-logo=\"http://l/a\" group-title=\"G\",Alpha\n" +
		"#EXTVLCOPT:http-user-agent=UA1\n" +
		"http://s/a\n" +
		"#EXTINF:-1 tvg-id=\"b\" group-title=\"G\",Beta, extra\n" +
		"http://s/b\n"
	first, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Parse(strings.NewReader(string(Render(first.Channels, first.URLTvg))))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("round-trip changed the playlist:\nfirst=%#v\nsecond=%#v", first, second)
	}
}

func TestRenderAttrSanitize(t *testing.T) {
	// A stray quote / newline in an attribute value must be stripped so it can't break the line.
	out := string(Render([]Channel{{Name: "N", Group: `Bad"Group`, URL: "http://x"}}, ""))
	if strings.Contains(out, `Bad"Group`) {
		t.Fatalf("quote not sanitized from attribute: %q", out)
	}
	if !strings.Contains(out, `group-title="BadGroup"`) {
		t.Fatalf("sanitized attr wrong: %q", out)
	}
}
