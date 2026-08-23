package server

import (
	"net/http"
	"strings"
	"testing"

	"wayhop/internal/updater"
)

// TestBoundPathIsBlamedOnlyOnEvidence (L5): a failure message that names the wrong culprit costs the
// operator the change it advises plus the time to discover it changed nothing.
//
// Measured on a live Keenetic. /api/updater/self/fit answered:
//
//	release metadata: 3 source(s) tried, all failed; 2 of them with an HTTP error status, the last
//	with a name that did not resolve — downloads are bound to "grp-primary" (nwg3); if that
//	path is down, change “Download components through” to the router's ordinary path
//
// The attempt list underneath says the opposite of the advice: direct → https://api.github.com,
// status 404, 1964 ms. That is a completed TLS request to the release host and an answer back, over
// the very path the message calls a suspect. The real cause is that the self repository is private,
// which the SAME daemon already reports correctly on /api/updater/self ("no_channel": true). The
// bound path was blamed because the suffix was appended to every source failure unconditionally.
func TestBoundPathIsBlamedOnlyOnEvidence(t *testing.T) {
	s := dnsSeed(t)
	s.updater = updater.New(t.TempDir(), "aarch64", nil).BindVia(func() string { return "nwg3" })

	// The measured shape: the release host itself answered, two mirrors did not.
	answered := &updater.FetchError{What: "release metadata", Attempts: []updater.Attempt{
		{Source: "direct", Host: "https://api.github.com", Status: 404, Category: updater.CatHTTP},
		{Source: "mirror", Host: "https://ghproxy.net", Status: 403, Category: updater.CatHTTP},
		{Source: "mirror", Host: "https://mirror.ghproxy.com", Category: updater.CatDNS},
	}}
	got := s.releaseSourceUnreachable("could not reach the release source: ", answered)
	if strings.Contains(got, "Download components through") {
		t.Errorf("the download path answered with HTTP 404 and must not be offered as the fix: %q", got)
	}
	if !strings.Contains(got, "404") || !strings.Contains(got, "the failure is at the source") {
		t.Errorf("the message must say the host answered, and with what: %q", got)
	}

	// The positive control: when NOTHING answered, the bound path is a real suspect and must be named.
	// Without this, deleting the suffix entirely would pass the assertion above.
	silent := &updater.FetchError{What: "release metadata", Attempts: []updater.Attempt{
		{Source: "direct", Host: "https://api.github.com", Category: updater.CatDNS},
		{Source: "mirror", Host: "https://ghproxy.net", Category: updater.CatTimeout},
	}}
	got = s.releaseSourceUnreachable("could not reach the release source: ", silent)
	if !strings.Contains(got, "Download components through") {
		t.Errorf("with no answer from any source the bound path must still be named: %q", got)
	}

	// A mirror's status proves nothing about the release host: a mirror is a third party, and its 403
	// is as likely to be the mirror refusing us as the path failing. The bound path stays named.
	mirrorOnly := &updater.FetchError{What: "release metadata", Attempts: []updater.Attempt{
		{Source: "direct", Host: "https://api.github.com", Category: updater.CatConnect},
		{Source: "mirror", Host: "https://ghproxy.net", Status: 403, Category: updater.CatHTTP},
	}}
	got = s.releaseSourceUnreachable("could not reach the release source: ", mirrorOnly)
	if !strings.Contains(got, "Download components through") {
		t.Errorf("only the direct source can clear the path; a mirror's status cannot: %q", got)
	}

	// A 200 that still failed is a transfer that died part-way — the classic symptom of a tunnel
	// dropping mid-body. The status alone must not clear the path. Found live: the sing-box row
	// answered "all failed ... the release host itself answered (HTTP 200)".
	//
	// The category here is CatHTTP on purpose, and it is the whole point of the case: categorize()
	// defaults to CatHTTP, so this is the shape production actually produces for a body that would
	// not decode. An earlier version of this case used CatInvalid, which nothing can emit — it
	// asserted about a state that cannot occur while the real one walked past it.
	truncated := &updater.FetchError{What: "release metadata", Attempts: []updater.Attempt{
		{Source: "direct", Host: "https://api.github.com", Status: 200, Category: updater.CatHTTP},
		{Source: "mirror", Host: "https://mirror.ghproxy.com", Category: updater.CatDNS},
	}}
	got = s.releaseSourceUnreachable("could not reach the release source: ", truncated)
	if !strings.Contains(got, "Download components through") {
		t.Errorf("a 200 that still failed does not prove the path carried the whole answer: %q", got)
	}
	if strings.Contains(got, "HTTP 200") {
		t.Errorf("and must not be reported as the host having answered: %q", got)
	}

	// An error that is not a FetchError at all must not be read as "the host answered".
	if n := directAnswered(http.ErrHandlerTimeout); n != 0 {
		t.Errorf("a plain error carries no status, got %d", n)
	}
}
