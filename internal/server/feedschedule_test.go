package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wayhop/internal/model"
)

// countingFeed serves body and counts its requests; failing answers 502 instead.
func countingFeed(t *testing.T, body string, failing bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if failing {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// A list given a new source in the panel is fetched on the next tick, not at its old due time: the
// store clears the feed's timestamp, and the loop takes a feed that has never loaded as due. Until
// then the list has nothing, and Apply refuses it.
func TestAReSourcedListIsFetchedOnTheNextTick(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	old, _ := countingFeed(t, "192.0.2.0/24\n", false)
	rl := model.RoutingList{ID: "l", Name: "L", CIDRSource: old.URL, Outbound: "direct", Enabled: true}
	if err := s.store.UpsertRoutingList(rl); err != nil {
		t.Fatal(err)
	}
	due, base := map[string]time.Time{}, time.Now()
	s.cidrRefreshTick(context.Background(), due, base)
	if c := cacheOf(t, s, "l"); len(c) != 1 {
		t.Fatalf("first load: %v", c)
	}
	fresh, hits := countingFeed(t, "198.51.100.0/24\n", false)
	rl = getList(t, s, "l")
	rl.CIDRSource = fresh.URL
	if err := s.store.UpsertRoutingList(rl); err != nil {
		t.Fatal(err)
	}
	s.cidrRefreshTick(context.Background(), due, base.Add(time.Hour))
	if hits.Load() != 1 || !slices.Equal(cacheOf(t, s, "l"), []string{"198.51.100.0/24"}) {
		t.Fatalf("new source asked %d times an hour later; cache %v", hits.Load(), cacheOf(t, s, "l"))
	}
}

// A feed that has never answered is asked on every tick until it does, rather than once a day: the
// list has nothing of it meanwhile.
func TestAFeedThatNeverLoadedIsAskedEveryTick(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	feed, hits := countingFeed(t, "", true)
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "l", Name: "L", CIDRSource: feed.URL, Outbound: "direct", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	due, base := map[string]time.Time{}, time.Now()
	for i := 0; i < 3; i++ {
		s.cidrRefreshTick(context.Background(), due, base.Add(time.Duration(i)*time.Hour))
	}
	if hits.Load() != 3 {
		t.Fatalf("asked %d times in three hourly ticks", hits.Load())
	}
}

// After a restart a list with a name feed only is scheduled from when that feed last loaded, like a
// list with an address feed, instead of being fetched again at every boot.
func TestANameFeedIsScheduledFromItsOwnLastLoad(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	feed, hits := countingFeed(t, "example.com\n", false)
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "n", Name: "N", DomainSource: feed.URL, Outbound: "direct", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	s.cidrRefreshTick(context.Background(), map[string]time.Time{}, time.Now())
	if hits.Load() != 1 || getList(t, s, "n").DomainRefreshed == 0 {
		t.Fatalf("first load: %d asks, refreshed %d", hits.Load(), getList(t, s, "n").DomainRefreshed)
	}
	s.cidrRefreshTick(context.Background(), map[string]time.Time{}, time.Now()) // a fresh schedule: the daemon restarted
	if hits.Load() != 1 {
		t.Fatalf("asked again right after a restart: %d", hits.Load())
	}
}

// A feed's credentials stay out of the daemon's log, the panel's refresh answer and the lists'
// status: those end up in screenshots and bug reports.
func TestFeedCredentialsStayOutOfLogsAndErrors(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	feed, _ := countingFeed(t, "", true)
	secret := strings.Replace(feed.URL, "http://", "http://alice:s3cret@", 1) + "/feeds/tok-123/list.txt?token=q-456"
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "l", Name: "L", CIDRSource: secret, Source: "http://bob:hunter2@127.0.0.1:1/rules/tok-789.srs",
		Outbound: "direct", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	s.cidrRefreshTick(context.Background(), map[string]time.Time{}, time.Now())

	rec := httptest.NewRecorder()
	s.handleRoutingRefresh(rec, httptest.NewRequest(http.MethodPost, "/api/routing/refresh", nil))
	var refreshed struct {
		Errors []string `json:"errors"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &refreshed)

	st := httptest.NewRecorder()
	s.handleRoutingStatus(st, httptest.NewRequest(http.MethodGet, "/api/routing/status", nil))

	for what, text := range map[string]string{"log": logged.String(), "refresh": strings.Join(refreshed.Errors, "\n"), "status": st.Body.String()} {
		if text == "" {
			t.Errorf("%s: nothing to check", what)
		}
		for _, leak := range []string{"alice", "s3cret", "tok-123", "q-456", "bob", "hunter2", "tok-789"} {
			if strings.Contains(text, leak) {
				t.Errorf("%s carries %q: %s", what, leak, text)
			}
		}
	}
}
