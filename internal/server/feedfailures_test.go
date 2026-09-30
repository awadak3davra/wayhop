package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wayhop/internal/model"
)

// failingFeed is a feed host that answers 502 until healthy is set, then one CIDR.
func failingFeed(t *testing.T) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	var healthy atomic.Bool
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, "192.0.2.0/24\n")
	}))
	t.Cleanup(feed.Close)
	return feed, &healthy
}

func feedIssueLines(s *Server) []string {
	var out []string
	for _, f := range (tgBackend{s}).feedIssues() {
		out = append(out, f.List+"/"+strings.Repeat("x", f.Fails)+"/"+f.Err)
	}
	return out
}

// A list whose feed keeps failing is counted across manual and scheduled refreshes alike, from the
// first failure, with the reason as a person reads it and without the feed's credentials. Two
// failures count as two only an hour apart, so a second tap on Refresh is not a second failure.
// The first refresh that works clears the record.
func TestFeedFailuresAreCountedUntilARefreshWorks(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	feed, healthy := failingFeed(t)
	src := strings.Replace(feed.URL, "http://", "http://alice:s3cret@", 1) + "/private/feed.txt"
	rl := model.RoutingList{ID: "stream", Name: "Streaming", CIDRSource: src, Outbound: "direct", Enabled: true, RefreshHours: 6}
	if err := s.store.UpsertRoutingList(rl); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	s.refreshAll(ctx)
	first := s.feedFailuresNow()["stream"].since
	// The chat's refresh names the list, says it has nothing yet, and tells why without the feed's
	// address in full. A minute later it is the same failure, not a second one.
	r, err := (tgBackend{s}).RefreshLists(ctx)
	if err != nil || r.Lists != 1 || len(r.Failed) != 1 || r.Failed[0].List != "Streaming" || !r.Failed[0].Empty ||
		r.Failed[0].Fails != 1 || strings.Contains(r.Failed[0].Err, "s3cret") || strings.Contains(r.Failed[0].Err, "alice") ||
		strings.Contains(r.Failed[0].Err, "private") || strings.HasPrefix(r.Failed[0].Err, "refresh ") || !strings.Contains(r.Failed[0].Err, "502") {
		t.Fatalf("refresh from the chat: %+v, %v", r, err)
	}

	// The refresh loop, two hours on, counts the second failure, from the same first one.
	s.cidrRefreshTick(ctx, map[string]time.Time{}, time.Now().Add(2*time.Hour))
	if f := s.feedFailuresNow()["stream"]; f.fails != 2 || !f.since.Equal(first) {
		t.Fatalf("after a scheduled refresh: %+v", f)
	}
	if got := feedIssueLines(s); len(got) != 1 || !strings.HasPrefix(got[0], "Streaming/xx/") {
		t.Fatalf("issues %q", got)
	}

	// Switched off, it is not reported.
	rl.Enabled = false
	if err := s.store.UpsertRoutingList(rl); err != nil {
		t.Fatal(err)
	}
	if got := feedIssueLines(s); len(got) != 0 {
		t.Fatalf("a disabled list reported: %q", got)
	}
	rl.Enabled = true
	if err := s.store.UpsertRoutingList(rl); err != nil {
		t.Fatal(err)
	}

	healthy.Store(true)
	s.refreshAll(ctx)
	if got := feedIssueLines(s); len(got) != 0 {
		t.Fatalf("a refresh that worked left %q", got)
	}
}

// A list given new feeds starts over: what failed before says nothing about the new ones, which
// have not been tried yet.
func TestFeedFailuresOfOldFeedsAreNotTheNewOnes(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	feed, _ := failingFeed(t)
	rl := model.RoutingList{ID: "stream", Name: "Streaming", CIDRSource: feed.URL + "/old.txt", Outbound: "direct", Enabled: true}
	if err := s.store.UpsertRoutingList(rl); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.noteFeedRefresh(rl, now.Add(-3*time.Hour), errors.New("status 502"))
	s.noteFeedRefresh(rl, now.Add(-time.Hour), errors.New("status 502"))
	if got := feedIssueLines(s); len(got) != 1 {
		t.Fatalf("before: %q", got)
	}
	rl.CIDRSource = feed.URL + "/new.txt"
	if err := s.store.UpsertRoutingList(rl); err != nil {
		t.Fatal(err)
	}
	if got := feedIssueLines(s); len(got) != 0 {
		t.Fatalf("the old feed's failures were laid at the new one's door: %q", got)
	}
	s.noteFeedRefresh(rl, now, errors.New("status 404"))
	if f := s.feedFailuresNow()["stream"]; f.fails != 1 || !f.since.Equal(now) {
		t.Fatalf("the new feed did not start over: %+v", f)
	}
}

// A refresh that runs out of time stops there: the lists it did not ask are "not tried", not
// failed, so they are not counted against feeds that were never asked.
func TestARefreshOutOfTimeCountsNoListItDidNotAsk(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	feed, _ := failingFeed(t)
	for _, id := range []string{"a", "b"} {
		if err := s.store.UpsertRoutingList(model.RoutingList{ID: id, Name: id, CIDRSource: feed.URL + "/" + id, Outbound: "direct", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, errs := s.refreshAll(ctx)
	if len(errs) != 2 || !errors.Is(errs[0], errFeedNotTried) || !errors.Is(errs[1], errFeedNotTried) {
		t.Fatalf("errors %v", errs)
	}
	if got := s.feedFailuresNow(); len(got) != 0 {
		t.Fatalf("lists never asked were recorded as failed: %+v", got)
	}
	r, err := (tgBackend{s}).RefreshLists(ctx)
	if err != nil || r.Unreached != 2 || len(r.Failed) != 0 {
		t.Fatalf("from the chat: %+v, %v", r, err)
	}
}

// The refresh loop forgets the records of lists it no longer refreshes: a deleted list's failures
// are not waiting for a list of the same id that comes back.
func TestTheRefreshLoopForgetsDeletedLists(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	feed, _ := failingFeed(t)
	rl := model.RoutingList{ID: "preset", Name: "Preset", CIDRSource: feed.URL + "/p.txt", Outbound: "direct", Enabled: true}
	if err := s.store.UpsertRoutingList(rl); err != nil {
		t.Fatal(err)
	}
	s.cidrRefreshTick(context.Background(), map[string]time.Time{}, time.Now())
	if len(s.feedFailuresNow()) != 1 {
		t.Fatal("the failure was not recorded")
	}
	if err := s.store.DeleteRoutingList("preset"); err != nil {
		t.Fatal(err)
	}
	s.cidrRefreshTick(context.Background(), map[string]time.Time{}, time.Now())
	if got := s.feedFailuresNow(); len(got) != 0 {
		t.Fatalf("a deleted list's record stayed: %+v", got)
	}
}
