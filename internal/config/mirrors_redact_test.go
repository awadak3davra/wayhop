package config

import "testing"

func TestRedactedMasksMirrorPrefixes(t *testing.T) {
	c := Default()
	c.Updater.Mirrors = []string{"", "https://user:pw@proxy.example/tok123/", "http://mirror.example:8080/?key=abc"}
	r := c.Redacted()
	want := []string{"", "https://proxy.example/" + RedactedMark, "http://mirror.example/" + RedactedMark}
	for i, w := range want {
		if r.Updater.Mirrors[i] != w {
			t.Errorf("mirror %d = %q, want %q", i, r.Updater.Mirrors[i], w)
		}
	}
	if c.Updater.Mirrors[1] != "https://user:pw@proxy.example/tok123/" {
		t.Errorf("the original was mutated: %q", c.Updater.Mirrors[1])
	}
	if !MirrorsRedacted(r.Updater.Mirrors) || MirrorsRedacted(c.Updater.Mirrors) {
		t.Error("MirrorsRedacted does not tell a redacted list from a real one")
	}
	if got := redactMirrors(nil); got != nil {
		t.Errorf("nil list: %v", got)
	}
	if got := redactMirrors([]string{"not a url"}); got[0] != RedactedMark {
		t.Errorf("unparseable prefix: %q", got[0])
	}
}
