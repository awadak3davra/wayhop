package updater

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// directAt points an Updater's direct-API calls at a test server. apiGetDirect builds
// "https://api.github.com"+path itself, so the transport is redirected rather than the URL.
func directAt(t *testing.T, u *Updater, srv *httptest.Server) {
	t.Helper()
	base := srv.URL
	u.hc = &http.Client{Transport: rewriteTo(base, srv.Client().Transport)}
}

type rewriter struct {
	base string
	next http.RoundTripper
}

func rewriteTo(base string, next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return &rewriter{base: base, next: next}
}

func (r *rewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "api.github.com" {
		u := *req.URL
		rest := strings.TrimPrefix(r.base, "http://")
		u.Scheme, u.Host = "http", rest
		clone := req.Clone(req.Context())
		clone.URL = &u
		clone.Host = ""
		return r.next.RoundTrip(clone)
	}
	return r.next.RoundTrip(req)
}

// One page render asks for the same release repeatedly — the size measurement is one call per engine
// per render. Against an allowance of 60 an hour for the whole household address, asking again every
// time is what emptied it: a full verification run drove the panel to answer 502 for an hour. Repeats
// inside the window must cost nothing.
func TestDirectAPIRepeatsWithinTheWindowCostOneRequest(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		fmt.Fprint(w, `{"tag_name":"v1.13.19"}`)
	}))
	defer srv.Close()
	u := New(t.TempDir(), "arm64", nil)
	directAt(t, u, srv)

	for i := 0; i < 5; i++ {
		var rel Release
		if err := u.apiGetDirect(context.Background(), "/repos/x/y/releases/tags/v1.13.19", &rel); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if rel.Tag != "v1.13.19" {
			t.Fatalf("call %d decoded %q", i, rel.Tag)
		}
	}
	if hits != 1 {
		t.Fatalf("%d requests reached GitHub, want 1", hits)
	}

	// A DIFFERENT question is a different answer and must not be served from the first one.
	var other Release
	if err := u.apiGetDirect(context.Background(), "/repos/x/y/releases/latest", &other); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Fatalf("a different path took %d requests, want a second one", hits)
	}
}

// An expired entry is re-read, so the panel is never more than the window behind the world.
func TestDirectAPIAsksAgainOnceTheWindowPasses(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		fmt.Fprint(w, `{"tag_name":"v1"}`)
	}))
	defer srv.Close()
	u := New(t.TempDir(), "arm64", nil)
	directAt(t, u, srv)

	var rel Release
	if err := u.apiGetDirect(context.Background(), "/p", &rel); err != nil {
		t.Fatal(err)
	}
	u.ghMu.Lock()
	u.ghCache["/p"] = ghCacheEntry{at: time.Now().Add(-ghCacheTTL - time.Second), body: []byte(`{"tag_name":"stale"}`)}
	u.ghMu.Unlock()
	if err := u.apiGetDirect(context.Background(), "/p", &rel); err != nil {
		t.Fatal(err)
	}
	if hits != 2 || rel.Tag != "v1" {
		t.Fatalf("hits=%d tag=%q — a stale entry must be re-read, not served", hits, rel.Tag)
	}
}

// A refusal must never become the answer for the next ten minutes: caching it would turn one unlucky
// moment into a page that stays wrong long after the cause has gone.
func TestDirectAPIDoesNotCacheARefusal(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits == 1 {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fmt.Fprint(w, `{"tag_name":"v2"}`)
	}))
	defer srv.Close()
	u := New(t.TempDir(), "arm64", nil)
	directAt(t, u, srv)

	var rel Release
	if err := u.apiGetDirect(context.Background(), "/p", &rel); err == nil {
		t.Fatal("a 403 was reported as success")
	}
	if err := u.apiGetDirect(context.Background(), "/p", &rel); err != nil || rel.Tag != "v2" {
		t.Fatalf("the retry got %v / %q — a refusal was cached", err, rel.Tag)
	}
}

// The exhausted allowance is not a broken router, and "status 403" says nothing an operator can act
// on. The message has to name the cause and, when GitHub tells us, when it lifts.
func TestExhaustedAllowanceIsNamed(t *testing.T) {
	reset := time.Now().Add(37 * time.Minute)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprint(reset.Unix()))
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	u := New(t.TempDir(), "arm64", nil)
	directAt(t, u, srv)

	var rel Release
	err := u.apiGetDirect(context.Background(), "/p", &rel)
	if err == nil {
		t.Fatal("no error")
	}
	msg := err.Error()
	for _, want := range []string{"allowance", "used up", reset.Format("15:04"), "nothing is wrong with the router"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q does not carry %q", msg, want)
		}
	}
	if strings.Contains(msg, "status 403") {
		t.Fatalf("the bare status survived into the message: %q", msg)
	}
}

// Any OTHER refusal keeps its status: inventing a rate-limit explanation for a 404 would send the
// operator looking for a limit that is not the problem.
func TestOtherRefusalsKeepTheirStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	u := New(t.TempDir(), "arm64", nil)
	directAt(t, u, srv)

	var rel Release
	err := u.apiGetDirect(context.Background(), "/p", &rel)
	if err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("got %v, want a plain status 404", err)
	}
}

// The cache runs on a router with a 64 MiB soft limit, so it must not grow without bound: browsing a
// long version list asks for one release body per tag, and every one of them would otherwise stay
// resident until the daemon restarts.
func TestDirectAPICacheStaysBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v"}`)
	}))
	defer srv.Close()
	u := New(t.TempDir(), "arm64", nil)
	directAt(t, u, srv)

	for i := 0; i < ghCacheMax*3; i++ {
		var rel Release
		if err := u.apiGetDirect(context.Background(), fmt.Sprintf("/p/%d", i), &rel); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	u.ghMu.Lock()
	n := len(u.ghCache)
	u.ghMu.Unlock()
	if n > ghCacheMax {
		t.Fatalf("cache holds %d entries, cap is %d", n, ghCacheMax)
	}
	// The most recent question must still be answerable — evicting the newest would make the cache
	// useless exactly when it is busiest.
	last := fmt.Sprintf("/p/%d", ghCacheMax*3-1)
	if _, ok := u.ghCached(last); !ok {
		t.Fatalf("the newest entry (%s) was evicted", last)
	}
}

// An entry nobody asks for again is dropped rather than held for the life of the daemon.
func TestDirectAPICacheDropsExpiredEntriesOnWrite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v"}`)
	}))
	defer srv.Close()
	u := New(t.TempDir(), "arm64", nil)
	directAt(t, u, srv)

	var rel Release
	if err := u.apiGetDirect(context.Background(), "/stale", &rel); err != nil {
		t.Fatal(err)
	}
	u.ghMu.Lock()
	u.ghCache["/stale"] = ghCacheEntry{at: time.Now().Add(-ghCacheTTL - time.Minute), body: []byte(`{}`)}
	u.ghMu.Unlock()

	if err := u.apiGetDirect(context.Background(), "/fresh", &rel); err != nil {
		t.Fatal(err)
	}
	u.ghMu.Lock()
	_, stillThere := u.ghCache["/stale"]
	u.ghMu.Unlock()
	if stillThere {
		t.Fatal("an expired entry survived a later write")
	}
}
