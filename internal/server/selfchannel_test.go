package server

import (
	"testing"

	"wayhop/internal/updater"
)

// A build whose release list answers 404 at the source has no update channel — that is the
// private-repo case this build actually ships in, and the page must say so instead of reporting a
// failed check. Everything else is a fault or an unknown and must NOT be laundered into "nothing to
// update from".
//
// The mirror cases are the ones measured in the field: the direct request to api.github.com answered
// 404 while ghproxy.net answered 403 and a third mirror would not resolve. A rule that required every
// source to agree would never have fired on the router it was written for.
func TestSelfChannelMissing(t *testing.T) {
	for _, tc := range []struct {
		name string
		att  []updater.Attempt
		want bool
	}{
		{"direct 404", []updater.Attempt{
			{Source: "direct", Host: "https://api.github.com", Status: 404, Category: updater.CatHTTP},
		}, true},
		// Measured shape: GitHub says 404, one mirror refuses, one will not resolve.
		{"direct 404 with mirrors failing differently", []updater.Attempt{
			{Source: "direct", Host: "https://api.github.com", Status: 404, Category: updater.CatHTTP},
			{Source: "mirror", Host: "https://ghproxy.net", Status: 403, Category: updater.CatHTTP},
			{Source: "mirror", Host: "https://mirror.ghproxy.com", Category: updater.CatDNS},
		}, true},
		// A mirror's 404 is about the mirror: it may simply not carry the path.
		{"only a mirror says 404", []updater.Attempt{
			{Source: "mirror", Host: "https://ghproxy.net", Status: 404, Category: updater.CatHTTP},
		}, false},
		// A throttled check succeeds again later; calling it "no channel" would hide it forever.
		{"direct rate limited", []updater.Attempt{
			{Source: "direct", Host: "https://api.github.com", Status: 403, Category: updater.CatHTTP},
		}, false},
		{"direct server error", []updater.Attempt{
			{Source: "direct", Status: 502, Category: updater.CatHTTP},
		}, false},
		// The router could not ask at all — a network fault, which must keep reading as one.
		{"direct dns failure", []updater.Attempt{
			{Source: "direct", Category: updater.CatDNS},
		}, false},
		// Nothing was tried, so nothing was established.
		{"no attempts", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := selfChannelMissing(tc.att); got != tc.want {
				t.Fatalf("selfChannelMissing(%+v) = %v, want %v", tc.att, got, tc.want)
			}
		})
	}
}
