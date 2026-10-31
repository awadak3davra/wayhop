package server

import (
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// upperHalf is the upper half of the IPv4 space, a /1, spelled from a documentation address.
var upperHalf = netip.MustParsePrefix("203.0.113.4/1").Masked().String()

// aggregate7 is a /7, the length of a country feed's aggregates, spelled from a documentation address.
var aggregate7 = netip.MustParsePrefix("198.51.100.0/7").Masked().String()

// refreshAnswer is POST /api/routing/refresh's answer, as far as these tests read it.
type refreshAnswer struct {
	Changed bool                `json:"changed"`
	Errors  []string            `json:"errors"`
	Refused map[string][]string `json:"refused"`
}

func postRefresh(t *testing.T, s *Server, id string) refreshAnswer {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleRoutingRefresh(rec, httptest.NewRequest("POST", "/api/routing/refresh", strings.NewReader(`{"id":"`+id+`"}`)))
	var a refreshAnswer
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &a) != nil {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body.String())
	}
	return a
}

// QA-111. A fetched feed reaches the kernel plane unreviewed: the refresh stages its cache and the
// review shows only a count. One line covering the whole address space (a typo's "/0", the v4-mapped
// spelling of the default route, two /1 halves) turned the list into a full tunnel or, with a direct
// outbound, a full bypass, and on the ipset plane, which refuses a /0, every Apply failed until the
// list was switched off. Such a line is now refused at the refresh: the feed's other networks still
// load and route, and the refresh's answer names what it refused apart from its errors: the feed did
// not fail. A country aggregate (a /7) is no such line and loads. The IPv6 case goes
// direct: the adopted tunnel is carried as IPv4 only, so it would hold no IPv6 set at all.
func TestFeedPrefixCoveringTheInternetNeverReachesTheKernelPlane(t *testing.T) {
	cases := []struct {
		name, body, outbound string
		v4, v6               []string // the zone the feed's usable prefixes make
		refused              []string // named in the answer, in the cache and in no set
	}{
		{"slash0_typo", "192.0.2.0/24 Example\n198.51.100.0/24\n203.0.113.4/0 label\n", "exit-awg1",
			[]string{"192.0.2.0/24", "198.51.100.0/24"}, nil, []string{"0.0.0.0/0"}},
		{"v4mapped_default", "::ffff:0.0.0.0/96\n198.51.100.0/24\n", "exit-awg1",
			[]string{"198.51.100.0/24"}, nil, []string{"::ffff:0.0.0.0/96"}},
		{"two_halves", "0.0.0.0/1\n203.0.113.4/1\n203.0.113.0/24\n", "exit-awg1",
			[]string{"203.0.113.0/24"}, nil, []string{"0.0.0.0/1", upperHalf}},
		{"shorter_than_4", "192.0.2.1/3\n198.51.100.0/7\n203.0.113.0/24\n", "exit-awg1",
			[]string{aggregate7, "203.0.113.0/24"}, nil, []string{"192.0.0.0/3"}},
		{"v6_default", "::/0\n2001:db8::/7\n2001:db8::/32\n", model.OutboundDirect,
			nil, []string{"2001:db8::/32"}, []string{"::/0", "2000::/7"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _ := sharehandlers_server(t)
			s.allowInternalFetch = true
			feed := feedServer(t, c.body)
			if err := s.store.Replace(model.Profile{
				Endpoints: []model.Endpoint{{ID: "exit-awg1", Name: "exit", Engine: model.EngineExternal, Server: "198.51.100.20",
					Enabled: true, Params: map[string]any{"interface": "awg1"}}},
				RoutingLists: []model.RoutingList{{ID: "feed", Name: "feed", CIDRSource: feed.URL, Outbound: c.outbound, Enabled: true}},
			}); err != nil {
				t.Fatal(err)
			}

			a := postRefresh(t, s, "feed")
			if !a.Changed || len(a.Errors) != 0 || len(a.Refused) != 1 || !slices.Equal(a.Refused["feed"], c.refused) {
				t.Errorf("answer %+v, want changed, no error, and the list's refused entries %v", a, c.refused)
			}
			// The list did load, so it is not a feed that stopped updating.
			if f, ok := s.feedFailuresNow()["feed"]; ok {
				t.Errorf("a feed that loaded is recorded as failing: %+v", f)
			}

			p := s.store.Profile()
			cache := p.RoutingListByID("feed").CIDRCache
			plan, _, err := pbr.Compile(&p, pbr.Options{})
			if err != nil {
				t.Fatal(err)
			}
			var z *pbr.Zone
			for i := range plan.Zones {
				if plan.Zones[i].Name == "list_feed" {
					z = &plan.Zones[i]
				}
			}
			if z == nil {
				t.Fatalf("no zone for the feed's usable prefixes (cache %v)", cache)
			}
			if !slices.Equal(z.V4, c.v4) || !slices.Equal(z.V6, c.v6) {
				t.Fatalf("zone v4=%v v6=%v, want v4=%v v6=%v (cache %v)", z.V4, z.V6, c.v4, c.v6, cache)
			}
			nft := plan.RenderNft()
			ips := plan.RenderIpsetRestore(pbr.IpsetOptions{WanIface: "eth0"})
			for _, r := range append([]string{"0.0.0.0/0", "::/0"}, c.refused...) {
				if slices.Contains(cache, r) || strings.Contains(nft, " "+r) || strings.Contains(ips, " "+r+" ") {
					t.Errorf("%s reached the plane (cache %v)", r, cache)
				}
			}

			// Refreshed again, the feed still carries the line: the cache stays as it is and the
			// answer names the line again, for as long as the feed has it.
			if a := postRefresh(t, s, "feed"); a.Changed || len(a.Errors) != 0 || !slices.Equal(a.Refused["feed"], c.refused) {
				t.Errorf("second refresh: %+v, want unchanged and the refusal named again", a)
			}
		})
	}
}

// A feed of nothing but such lines has no usable entry: the refresh fails as it does for an empty
// feed, the list keeps what it last loaded, and the failure says why.
func TestFeedOfOnlyBroadPrefixesKeepsLastGood(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	good := feedServer(t, "198.51.100.0/24\n")
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "feed", Name: "feed", CIDRSource: good.URL, Outbound: "direct", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if a := postRefresh(t, s, "feed"); len(a.Errors) != 0 {
		t.Fatalf("seed: %+v", a)
	}
	broad := feedServer(t, "0.0.0.0/1\n203.0.113.4/1\nnot-a-prefix\n")
	rl := getList(t, s, "feed")
	rl.CIDRSource = broad.URL
	if err := s.store.UpsertRoutingList(rl); err != nil {
		t.Fatal(err)
	}
	a := postRefresh(t, s, "feed")
	if a.Changed || len(a.Errors) != 1 || !strings.Contains(a.Errors[0], "0 valid entries (3 skipped, refused 2 entries") ||
		!strings.Contains(a.Errors[0], "0.0.0.0/1, "+upperHalf) {
		t.Fatalf("answer %+v, want a failure counting 3 skipped and naming the 2 refused", a)
	}
	if _, ok := s.feedFailuresNow()["feed"]; !ok {
		t.Error("a feed that gave nothing usable is not recorded as failing")
	}
}

// A refusal is not a failure, and the refresh's answer keeps them apart: the panel counted a list
// that loaded without its /0 as "1 failed", in red and unnamed, while the list's row stayed green.
// Refreshing every list, one whose feed loaded without such a line is named under refused with it,
// one whose feed failed is an error, and one with both (its address feed refused a line, its domain
// feed failed) is in both, its error being the failure alone.
func TestRefreshAnswerKeepsRefusalsApartFromFailures(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.allowInternalFetch = true
	refusing := feedServer(t, "0.0.0.0/0\n198.51.100.0/24\n")
	empty := feedServer(t, "# nothing\n")
	if err := s.store.Replace(model.Profile{RoutingLists: []model.RoutingList{
		{ID: "loaded", Name: "Loaded", CIDRSource: refusing.URL, Outbound: model.OutboundDirect, Enabled: true},
		{ID: "failed", Name: "Failed", CIDRSource: empty.URL, Outbound: model.OutboundDirect, Enabled: true},
		{ID: "both", Name: "Both", CIDRSource: refusing.URL, DomainSource: empty.URL, Outbound: model.OutboundDirect, Enabled: true},
	}}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.handleRoutingRefresh(rec, httptest.NewRequest("POST", "/api/routing/refresh", strings.NewReader(`{}`)))
	var a refreshAnswer
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &a) != nil {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body.String())
	}
	want := map[string][]string{"loaded": {"0.0.0.0/0"}, "both": {"0.0.0.0/0"}}
	errs := strings.Join(a.Errors, "\n")
	if !a.Changed || !reflect.DeepEqual(a.Refused, want) || len(a.Errors) != 2 || !strings.Contains(errs, `"failed"`) ||
		!strings.Contains(errs, `"both" domains`) || strings.Contains(errs, "refused") {
		t.Fatalf("answer %+v, want changed, refused %v, and the two failures alone as errors", a, want)
	}
}

// A long run of refused lines is counted in full and named in part, so the answer stays readable
// whatever a rewritten body carries.
func TestRefusedWordsBoundsTheNames(t *testing.T) {
	refused := []string{"0.0.0.0/1", "0.0.0.0/2", "0.0.0.0/3", "0.0.0.0/4", "0.0.0.0/5", "0.0.0.0/6", "0.0.0.0/7"}
	got := refusedWords(refused)
	if !strings.HasPrefix(got, "refused 7 entries too broad") || !strings.HasSuffix(got, "0.0.0.0/5 and 2 more") {
		t.Fatalf("refusedWords = %q", got)
	}
}
