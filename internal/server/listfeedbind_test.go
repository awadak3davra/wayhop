package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wayhop/internal/model"
)

func feedProfile() model.Profile {
	return model.Profile{
		Endpoints: []model.Endpoint{
			adopted("fin", "nwg1", true),
			adopted("cyp", "nwg0", true),
			adopted("off", "nwg9", false),
			proxied("vless-de"),
		},
		Groups: []model.Group{
			{ID: "main", Name: "Main", Type: model.GroupFallback, Members: []string{"fin", "cyp"}},
			{ID: "main-wan", Name: "Main then WAN", Type: model.GroupFallback, Members: []string{"fin", "direct"}},
			{ID: "proxies", Name: "Proxies", Type: model.GroupFallback, Members: []string{"vless-de"}},
		},
	}
}

// The rule the feature states: where a feed leaves for each kind of via, and that a tunnel that is gone
// holds the feed back rather than sending it to the provider.
func TestFeedIfaceRule(t *testing.T) {
	s := bindTestServer(t, feedProfile(), "")
	for _, tc := range []struct {
		via, iface string
		down       bool
	}{
		{via: ""},
		{via: "direct"},
		{via: "fin", iface: "nwg1"},
		{via: "off", down: true},
		{via: "gone", down: true},
		{via: "vless-de"},         // no link to bind to
		{via: "proxies"},          // nor has anything in this group
		{via: "main", down: true}, // a monitor with nothing measured: no member known healthy
		{via: "main-wan"},         // the same, but the operator wrote "then the provider"
	} {
		iface, err := s.feedIface(tc.via)
		if iface != tc.iface || (err != nil) != tc.down {
			t.Errorf("via %q: iface %q err %v, want iface %q down %v", tc.via, iface, err, tc.iface, tc.down)
		}
		if tc.down && !errors.Is(err, errFeedPathDown) {
			t.Errorf("via %q: %v is not errFeedPathDown", tc.via, err)
		}
	}
}

func TestGroupFeedPathWalksTheOperatorsOrder(t *testing.T) {
	p := feedProfile()
	main, wan := p.GroupByID("main"), p.GroupByID("main-wan")
	for _, tc := range []struct {
		name  string
		g     *model.Group
		alive map[string]bool
		iface string
		down  bool
	}{
		{"first healthy", main, map[string]bool{"fin": true, "cyp": true}, "nwg1", false},
		{"fails over", main, map[string]bool{"cyp": true}, "nwg0", false},
		{"all down", main, nil, "", true},
		{"tunnel before direct", wan, map[string]bool{"fin": true}, "nwg1", false},
		{"then the provider", wan, nil, "", false},
	} {
		iface, err := groupFeedPath(&p, tc.g, tc.alive)
		if iface != tc.iface || (err != nil) != tc.down {
			t.Errorf("%s: iface %q err %v", tc.name, iface, err)
		}
	}
}

func boundFeedServer(t *testing.T, list model.RoutingList) (*Server, *atomic.Int32, model.RoutingList) {
	t.Helper()
	var hits atomic.Int32
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	t.Cleanup(h.Close)
	if list.CIDRSource == "x" {
		list.CIDRSource = h.URL
	}
	if list.DomainSource == "x" {
		list.DomainSource = h.URL
	}
	p := feedProfile()
	p.RoutingLists = []model.RoutingList{list}
	s := bindTestServer(t, p, "")
	s.allowInternalFetch = true
	return s, &hits, list
}

// A path that is down stops the fetch before a socket opens, and the list keeps what it has.
func TestFetchOneKeepsLastGoodWhenThePathIsDown(t *testing.T) {
	s, hits, rl := boundFeedServer(t, model.RoutingList{ID: "l", Enabled: true, Outbound: "direct",
		CIDRSource: "x", DownloadVia: "main", CIDRCache: []string{"198.51.100.0/24"}})
	got, changed, err := s.fetchOne(context.Background(), rl)
	if !errors.Is(err, errFeedPathDown) || changed || got != nil {
		t.Fatalf("got %v changed %v err %v", got, changed, err)
	}
	if hits.Load() != 0 {
		t.Fatal("a feed held back must not reach out at all")
	}
}

func TestFetchDomainsOneKeepsLastGoodWhenThePathIsDown(t *testing.T) {
	s, hits, rl := boundFeedServer(t, model.RoutingList{ID: "l", Enabled: true, Outbound: "direct", DomainSource: "x", DownloadVia: "main"})
	if _, changed, err := s.fetchDomainsOne(context.Background(), rl); !errors.Is(err, errFeedPathDown) || changed {
		t.Fatalf("changed %v err %v", changed, err)
	}
	if hits.Load() != 0 {
		t.Fatal("a feed held back must not reach out at all")
	}
}

// Nothing changes for a list that asked for nothing, and a proxy outbound keeps working as it did.
func TestFetchOneStaysOnTheOrdinaryPath(t *testing.T) {
	for _, via := range []string{"", "direct", "vless-de", "proxies", "main-wan"} {
		s, hits, rl := boundFeedServer(t, model.RoutingList{ID: "l", Enabled: true, Outbound: "direct", CIDRSource: "x", DownloadVia: via})
		got, changed, err := s.fetchOne(context.Background(), rl)
		if err != nil || !changed || len(got) != 1 {
			t.Errorf("via %q: %v %v %v", via, got, changed, err)
		}
		if hits.Load() != 1 {
			t.Errorf("via %q: %d requests", via, hits.Load())
		}
	}
}

// A profile-wide rule-set route is the list's route when it names none of its own, as for its rule sets.
func TestFeedViaFallsBackToTheProfileWideRoute(t *testing.T) {
	s, _, rl := boundFeedServer(t, model.RoutingList{ID: "l", Enabled: true, Outbound: "direct", CIDRSource: "x"})
	if got := s.feedVia(rl); got != "" {
		t.Fatalf("feedVia = %q", got)
	}
	s.cfg.RuleSetDetour = "off"
	if got := s.feedVia(rl); got != "off" {
		t.Fatalf("feedVia = %q", got)
	}
	if _, _, err := s.fetchOne(context.Background(), rl); !errors.Is(err, errFeedPathDown) {
		t.Fatalf("err = %v", err)
	}
	rl.DownloadVia = "direct"
	if got := s.feedVia(rl); got != "direct" {
		t.Fatalf("a list's own choice wins, got %q", got)
	}
}

// The refresh loop asks again at the next tick after a down path: it says nothing about the feed, and
// waiting out a 12 h interval would hold an old list long after the tunnel came back.
func TestRefreshTickRetriesSoonWhenThePathWasDown(t *testing.T) {
	s, _, rl := boundFeedServer(t, model.RoutingList{ID: "l", Enabled: true, Outbound: "direct", CIDRSource: "x", DownloadVia: "main", RefreshHours: 12,
		CIDRCache: []string{"198.51.100.0/24"}, CIDRRefreshed: 1})
	now := time.Now()
	due := map[string]time.Time{}
	s.cidrRefreshTick(context.Background(), due, now)
	if got := due[rl.ID]; !got.Equal(now) {
		t.Fatalf("due = %v, want the next tick (%v)", got, now)
	}
	// The same list on a working path waits out its interval as before.
	s2, _, rl2 := boundFeedServer(t, model.RoutingList{ID: "l", Enabled: true, Outbound: "direct", CIDRSource: "x", RefreshHours: 12,
		CIDRCache: []string{"203.0.113.0/24"}, CIDRRefreshed: 1})
	due2 := map[string]time.Time{}
	s2.cidrRefreshTick(context.Background(), due2, now)
	if got := due2[rl2.ID]; !got.Equal(now.Add(12 * time.Hour)) {
		t.Fatalf("due = %v", got)
	}
}

func TestFeedPathNote(t *testing.T) {
	s := bindTestServer(t, feedProfile(), "")
	feed := func(via string) model.RoutingList {
		return model.RoutingList{ID: "l", CIDRSource: "https://feed.example/x", DownloadVia: via}
	}
	for _, tc := range []struct {
		name string
		rl   model.RoutingList
		want string
	}{
		{"no feed", model.RoutingList{ID: "l", DownloadVia: "off"}, ""},
		{"direct", feed(""), ""},
		{"bound", feed("fin"), ""},
		{"down", feed("off"), "waiting"},
		{"group down", feed("main"), "waiting"},
		{"proxy", feed("vless-de"), "no network link"},
		{"the operator's own fallback", feed("main-wan"), ""},
	} {
		got := feedPathNote(s, tc.rl)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q, want it to say %q", tc.name, got, tc.want)
		}
	}
}

func TestPublicResolverAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"1.1.1.1:53": true, "[2606:4700:4700::1111]:53": true,
		"127.0.0.1:53": false, "[::1]:53": false, "10.20.30.1:53": false, "169.254.1.1:53": false, "junk": false,
	} {
		if got := publicResolverAddr(addr); got != want {
			t.Errorf("%s: %v", addr, got)
		}
	}
}
