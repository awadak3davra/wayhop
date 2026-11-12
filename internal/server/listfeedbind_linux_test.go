//go:build linux

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"wayhop/internal/cidrfeed"
	"wayhop/internal/model"
)

// The socket really is bound: through the link the feed answers, and through a link that is not there
// the fetch fails rather than finding another way out. The second half is the whole point of the
// feature, and only a real socket can show it.
func TestListFetchClientBindsItsSocket(t *testing.T) {
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer h.Close()
	profile := model.Profile{Endpoints: []model.Endpoint{
		adopted("through-lo", "lo", true),
		adopted("gone", "wh-no-such-link", true),
	}}
	s := bindTestServer(t, profile, "")
	s.allowInternalFetch = true

	got, _, err := cidrfeed.Fetch(context.Background(), s.listFetchClient("through-lo"), h.URL)
	if err != nil || len(got) != 1 {
		t.Fatalf("through a link that reaches the feed: %v %v", got, err)
	}
	if got, _, err := cidrfeed.Fetch(context.Background(), s.listFetchClient("gone"), h.URL); err == nil {
		t.Fatalf("a socket bound to a missing link reached the feed: %v", got)
	}
}

// A tunnel that does not answer is the path being down, which is what sends the list back for another
// try at the next tick. A feed answering 502 through a working tunnel is the feed's own failure.
func TestBoundFetchThatGetsNoAnswerIsThePathBeingDown(t *testing.T) {
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer h.Close()
	dead := model.RoutingList{ID: "dead", Enabled: true, Outbound: "direct", CIDRSource: h.URL, DownloadVia: "gone"}
	bad := model.RoutingList{ID: "bad", Enabled: true, Outbound: "direct", CIDRSource: h.URL, DownloadVia: "through-lo"}
	profile := model.Profile{
		Endpoints:    []model.Endpoint{adopted("through-lo", "lo", true), adopted("gone", "wh-no-such-link", true)},
		RoutingLists: []model.RoutingList{dead, bad},
	}
	s := bindTestServer(t, profile, "")
	s.allowInternalFetch = true
	if _, _, err := s.fetchOne(context.Background(), dead); !errors.Is(err, errFeedPathDown) {
		t.Errorf("no answer through the tunnel: %v", err)
	}
	if _, _, err := s.fetchOne(context.Background(), bad); err == nil || errors.Is(err, errFeedPathDown) {
		t.Errorf("the feed's own 502: %v", err)
	}
}
