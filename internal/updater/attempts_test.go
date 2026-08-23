package updater

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A mirror prefix is operator-supplied, so it can carry a credential anywhere in it. This is the one
// the tests use: userinfo, a token in the path and another in the query, so any leak shows up as a
// literal string nobody can mistake for redacted output.
const secretMirror = "https://user:s3cr3t@mirror.example/tok/abcd1234?access_token=zzzz/"

const secretMarkers = "s3cr3t abcd1234 zzzz user:"

func leaks(t *testing.T, where, s string) {
	t.Helper()
	for _, m := range strings.Fields(secretMarkers) {
		if strings.Contains(s, m) {
			t.Errorf("%s leaked %q: %s", where, m, s)
		}
	}
}

// jsonServer answers the release-metadata shape on every path.
func jsonServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

func fetch(t *testing.T, mirrors []string) ([]Attempt, error) {
	t.Helper()
	u := New(t.TempDir(), "amd64", mirrors)
	var out []Release
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return u.apiGetAttempts(ctx, "/repos/x/y/releases", &out)
}

func TestApiGetAttempts_DirectSucceedsWithoutTouchingMirrors(t *testing.T) {
	ok := jsonServer(t, http.StatusOK, `[{"tag_name":"v1.0.0"}]`)
	// The direct source is expressed as a mirror prefix here so the test can point it at a local
	// server; what matters is that the FIRST source answering ends the loop.
	ats, err := fetch(t, []string{ok.URL + "/", secretMirror})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(ats) != 1 {
		t.Fatalf("a source answered, so nothing behind it may be tried; attempts: %+v", ats)
	}
	if ats[0].Category != CatOK || ats[0].Status != http.StatusOK {
		t.Errorf("attempt = %+v, want an ok/200", ats[0])
	}
}

// The case the fallback exists for: one source fails, the next answers, and the failure is still
// reported rather than swallowed.
func TestApiGetAttempts_FirstFailsSecondSucceeds(t *testing.T) {
	bad := jsonServer(t, http.StatusForbidden, `nope`)
	ok := jsonServer(t, http.StatusOK, `[{"tag_name":"v1.0.0"}]`)

	ats, err := fetch(t, []string{bad.URL + "/", ok.URL + "/"})
	if err != nil {
		t.Fatalf("a working source was available, so this must succeed: %v", err)
	}
	if len(ats) != 2 {
		t.Fatalf("both attempts must be recorded, got %+v", ats)
	}
	if ats[0].Category != CatHTTP || ats[0].Status != http.StatusForbidden {
		t.Errorf("the failed attempt is not described: %+v", ats[0])
	}
	if ats[1].Category != CatOK {
		t.Errorf("the successful attempt is not marked ok: %+v", ats[1])
	}
}

func TestApiGetAttempts_AllFailReportsEveryOne(t *testing.T) {
	bad1 := jsonServer(t, http.StatusForbidden, `nope`)
	bad2 := jsonServer(t, http.StatusInternalServerError, `nope`)

	ats, err := fetch(t, []string{bad1.URL + "/", bad2.URL + "/"})
	if err == nil {
		t.Fatal("every source failed and the call reported success")
	}
	var fe *FetchError
	if !errors.As(err, &fe) {
		t.Fatalf("a total failure must carry its attempts, got %T", err)
	}
	if len(ats) != 2 || len(fe.Attempts) != 2 {
		t.Fatalf("both attempts must be reported, got %+v", ats)
	}
	// The message has to say how many were tried and what mostly went wrong, or an operator cannot
	// tell "one mirror is down" from "this router has no route out".
	if !strings.Contains(err.Error(), "2 source(s) tried") {
		t.Errorf("the error does not state how many sources were tried: %v", err)
	}
	if !strings.Contains(err.Error(), "HTTP error status") {
		t.Errorf("the error does not name the dominant category: %v", err)
	}
	if s := fe.Summary(); s != "Update check refused by the server" {
		t.Errorf("Summary() = %q — the UI chip would show something else", s)
	}
}

// The requirement this file exists for: nothing that reaches the caller may carry the credential the
// operator put in the mirror prefix.
func TestApiGetAttempts_NothingLeaksTheMirrorCredential(t *testing.T) {
	ats, err := fetch(t, []string{secretMirror})
	if err == nil {
		t.Fatal("the fixture mirror does not resolve, so this must fail")
	}
	leaks(t, "the error message", err.Error())
	var fe *FetchError
	if errors.As(err, &fe) {
		leaks(t, "the summary", fe.Summary())
	}
	if len(ats) != 1 {
		t.Fatalf("one source, one attempt, got %+v", ats)
	}
	leaks(t, "the attempt host", ats[0].Host)
	leaks(t, "the attempt detail", ats[0].Detail)
	// Redacted, not blanked: an operator still has to be able to tell WHICH source failed.
	if ats[0].Host != "https://mirror.example" {
		t.Errorf("Host = %q, want the scheme and host only", ats[0].Host)
	}
	if ats[0].Source != "mirror" {
		t.Errorf("Source = %q, want mirror", ats[0].Source)
	}
	// The detail has to name the host that did not resolve, intact. The first version sliced two
	// characters off a string it had just prefixed differently and produced "cannot resolve
	// tps://mirror.example" — which every leak assertion above passed, because a mangled hostname
	// carries no credential. Only running it showed the text was wrong.
	if ats[0].Category != CatDNS {
		t.Fatalf("Category = %q, want dns", ats[0].Category)
	}
	if ats[0].Detail != "cannot resolve mirror.example" {
		t.Errorf("Detail = %q, want it to name the host exactly", ats[0].Detail)
	}
}

// A wedged source must not consume the whole budget: the sources behind it are the reason a fallback
// list exists at all.
func TestApiGetAttempts_OneWedgedSourceDoesNotBlockTheRest(t *testing.T) {
	prev := attemptTimeout
	attemptTimeout = 300 * time.Millisecond
	t.Cleanup(func() { attemptTimeout = prev })

	stuck := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // never answers
	}))
	t.Cleanup(stuck.Close)
	ok := jsonServer(t, http.StatusOK, `[{"tag_name":"v1.0.0"}]`)

	started := time.Now()
	ats, err := fetch(t, []string{stuck.URL + "/", ok.URL + "/"})
	elapsed := time.Since(started)

	if err != nil {
		t.Fatalf("the second source answers, so the fetch must succeed: %v", err)
	}
	if len(ats) != 2 || ats[0].Category != CatTimeout {
		t.Fatalf("the wedged source must be recorded as a timeout, got %+v", ats)
	}
	if elapsed > 5*time.Second {
		t.Errorf("took %v — the per-attempt deadline is not bounding the wedged source", elapsed)
	}
}

func TestRedactHost(t *testing.T) {
	cases := map[string]string{
		secretMirror:                       "https://mirror.example",
		"https://api.github.com/repos/x/y": "https://api.github.com",
		"http://plain.example:8080/a?b=c":  "http://plain.example",
		"":                                 "(unparseable source)",
		"not a url":                        "(unparseable source)",
	}
	for in, want := range cases {
		if got := redactHost(in); got != want {
			t.Errorf("redactHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// Go's *url.Error puts the request URL in its message, which is how the credential reached the UI in
// the first place.
func TestScrubErr_RemovesTheURLGoPutsInTheMessage(t *testing.T) {
	inner := errors.New("dial tcp: lookup mirror.example: no such host")
	wrapped := &url.Error{Op: "Get", URL: secretMirror + "https://api.github.com/x", Err: inner}
	got := scrubErr(wrapped)
	leaks(t, "scrubErr", got)
	if !strings.Contains(got, "no such host") {
		t.Errorf("the cause was scrubbed away along with the URL: %q", got)
	}
}
