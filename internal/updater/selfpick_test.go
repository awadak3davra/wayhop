package updater

import "testing"

func TestPickSelfRelease(t *testing.T) {
	arm64 := []Asset{{Name: "wayhop-arm64.tar.gz"}}
	otherArch := []Asset{{Name: "wayhop-amd64.tar.gz"}}
	rel := func(tag string, pre bool, a []Asset) Release { return Release{Tag: tag, Prerelease: pre, Assets: a} }

	cases := []struct {
		name string
		rels []Release // newest-first, as GitHub returns
		want string    // expected tag; "" = no pick
	}{
		{"stable preferred over a newer prerelease", []Release{
			rel("v0.5.0-rc1", true, arm64), // newest but prerelease
			rel("v0.4.0", false, arm64),    // older stable -> chosen
		}, "v0.4.0"},
		{"newest stable wins", []Release{
			rel("v0.4.1", false, arm64),
			rel("v0.4.0", false, arm64),
		}, "v0.4.1"},
		{"prerelease fallback only when no stable has an arch asset", []Release{
			rel("v0.5.0-rc1", true, arm64),
			rel("v0.4.0", false, otherArch), // stable but no arm64 asset
		}, "v0.5.0-rc1"},
		{"skip releases lacking an arch asset", []Release{
			rel("v0.4.1", false, otherArch),
			rel("v0.4.0", false, arm64),
		}, "v0.4.0"},
		{"none carries an arch asset", []Release{rel("v0.4.0", false, otherArch)}, ""},
	}
	for _, c := range cases {
		got, ok := pickSelfRelease(c.rels, "arm64")
		if c.want == "" {
			if ok {
				t.Errorf("%s: expected no pick, got %q", c.name, got.Tag)
			}
			continue
		}
		if !ok || got.Tag != c.want {
			t.Errorf("%s: pickSelfRelease = (%q, %v), want %q", c.name, got.Tag, ok, c.want)
		}
	}
}
