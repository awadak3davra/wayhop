package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"wayhop/internal/clash"
	"wayhop/internal/model"
	"wayhop/internal/speedtest"
)

// speedSiteAddr is where these tests resolve the speed test's site: a documentation address, and no
// lookup leaves the machine.
const speedSiteAddr = "203.0.113.80"

// stubSpeedLookup answers the lookup speedRoute's trace starts with, and fails any other, so a test
// that reaches the network for a name says so.
func stubSpeedLookup(t *testing.T) {
	t.Helper()
	prev := traceLookupHost
	traceLookupHost = func(_ context.Context, host string) ([]string, error) {
		if host != speedHost {
			return nil, fmt.Errorf("unexpected lookup of %s", host)
		}
		return []string{speedSiteAddr}, nil
	}
	t.Cleanup(func() { traceLookupHost = prev })
}

// speedPathProfile is a split-tunnel profile: one exit, one rule that names a site other than the
// speed test's, and, unless withDefault, no default rule, so the core sends speed.cloudflare.com
// straight out.
func speedPathProfile(withDefault bool, route string) model.Profile {
	p := model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "nl", Name: "NL", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "198.51.100.10",
				Port: 443, Params: map[string]any{"uuid": "u"}, Enabled: true},
			{ID: "de", Name: "DE", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "198.51.100.11",
				Port: 443, Params: map[string]any{"uuid": "u"}, Enabled: true},
		},
		Groups: []model.Group{{ID: "sel", Name: "Pick", Type: model.GroupSelector, Members: []string{"nl", "de"}}},
		Rules:  []model.Rule{{ID: "r1", DomainSuffix: []string{"example.com"}, Outbound: route}},
	}
	if withDefault {
		p.Rules = append(p.Rules, model.Rule{ID: "def", Default: true, Outbound: route})
	}
	return p
}

// speedRunSeen is how the panel's last run went: through the core or not, and the kernel tunnel it
// was bound to ("" for none).
type speedRunSeen struct {
	proxy bool
	link  string
}

// fakeSpeedRun stands in for the run: it answers the way speedtest.Tester.Run does, naming the path
// after the flag it was given, and records how it was asked to run.
func fakeSpeedRun(seen *speedRunSeen) func(context.Context, bool, string, int) (speedtest.Result, error) {
	return func(_ context.Context, proxy bool, link string, _ int) (speedtest.Result, error) {
		*seen = speedRunSeen{proxy: proxy, link: link}
		via := "direct"
		if proxy {
			via = "proxy"
		}
		return speedtest.Result{Via: via, DownMbps: 19.24, LatencyMs: 85}, nil
	}
}

type speedAnswer struct {
	Via    string `json:"via"`
	Pinned bool   `json:"pinned"`
}

func postSpeed(t *testing.T, s *Server, body string) speedAnswer {
	t.Helper()
	w := servererrorpaths_post(s.handleSpeedtest, "/api/speedtest", body)
	if w.Code != http.StatusOK {
		t.Fatalf("speedtest %s: %d %s", body, w.Code, w.Body.String())
	}
	var a speedAnswer
	if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	return a
}

// QA-112. A run through the core goes wherever the core's rules send the test's site, so the answer
// names that route, not the request. On a split-tunnel profile (no default rule) the core sends
// speed.cloudflare.com straight out, and the panel showed the provider's line as "(proxy)". With a
// default route through a tunnel the answer still says proxy.
func TestPanelSpeedtestNamesThePathTheCoreSendsItBy(t *testing.T) {
	s := servererrorpaths_server(t)
	stubSpeedLookup(t)
	var seen speedRunSeen
	s.speedRunOf = fakeSpeedRun(&seen)

	if err := s.store.Replace(speedPathProfile(false, "nl")); err != nil {
		t.Fatal(err)
	}
	if a := postSpeed(t, s, `{"via":"proxy","bytes":20000}`); a.Via != "direct" || !seen.proxy || seen.link != "" {
		t.Errorf("split tunnel, asked for the proxy: ran %+v, answer says %q; want the core, \"direct\"", seen, a.Via)
	}

	if err := s.store.Replace(speedPathProfile(true, "nl")); err != nil {
		t.Fatal(err)
	}
	if a := postSpeed(t, s, `{"via":"proxy","bytes":20000}`); a.Via != "proxy" || !seen.proxy || seen.link != "" {
		t.Errorf("default route through a tunnel: ran %+v, answer says %q; want the core, \"proxy\"", seen, a.Via)
	}
	if a := postSpeed(t, s, `{"via":"direct","bytes":20000}`); a.Via != "direct" || seen.proxy || seen.link != "" {
		t.Errorf("asked for the line: ran %+v, answer says %q", seen, a.Via)
	}
}

// QA-112, a route through a kernel tunnel. In hybrid mode a list sending the test's site to an
// adopted tunnel is the kernel's: the core carries neither the list nor the tunnel and sends the site
// to its final, the provider's line, which the answer called "proxy". Such a route is measured as the
// Telegram bot measures it, bound to the tunnel and past the engine's redirect, and the answer names
// that exit, whether the router chooses or the proxy is asked for; asked for the line, it is the line.
func TestPanelSpeedtestBindsARouteThroughAKernelTunnel(t *testing.T) {
	s := servererrorpaths_server(t)
	s.cfg.RoutingMode = "hybrid"
	stubSpeedLookup(t)
	prev := speedBindDial
	speedBindDial = func(link string) func(context.Context, string, string) (net.Conn, error) {
		if link != "awg1" {
			return nil
		}
		return func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("no dial in a test") }
	}
	t.Cleanup(func() { speedBindDial = prev })
	var seen speedRunSeen
	s.speedRunOf = fakeSpeedRun(&seen)

	if err := s.store.Replace(model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "exit-awg1", Name: "awg", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true,
				Params: map[string]any{"interface": "awg1"}},
			{ID: "nl", Name: "NL", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "198.51.100.10",
				Port: 443, Params: map[string]any{"uuid": "u"}, Enabled: true},
		},
		Rules: []model.Rule{{ID: "r1", DomainSuffix: []string{"example.com"}, Outbound: "nl"}},
		RoutingLists: []model.RoutingList{{ID: "cf", Name: "Cloudflare", CIDRSource: "https://example.invalid/cf.lst",
			CIDRCache: []string{"203.0.113.0/24"}, Outbound: "exit-awg1", Enabled: true}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, via := range []string{"", "proxy"} {
		if a := postSpeed(t, s, `{"via":"`+via+`","bytes":20000}`); a.Via != "awg" || seen.proxy || seen.link != "awg1" {
			t.Errorf("via %q, route through awg1: ran %+v, answer says %q; want bound to awg1, \"awg\"", via, seen, a.Via)
		}
	}
	if a := postSpeed(t, s, `{"via":"direct","bytes":20000}`); a.Via != "direct" || seen.proxy || seen.link != "" {
		t.Errorf("asked for the line: ran %+v, answer says %q", seen, a.Via)
	}
}

// Left to choose, the panel measures the path the test's site takes: through the core only when the
// core's rules send it to a tunnel; when they send it straight out, the provider's line itself, past
// the core, which is what a direct test measures.
func TestSpeedPathFollowsTheRoute(t *testing.T) {
	for _, c := range []struct {
		via         string
		coreRunning bool
		route       string
		wantProxy   bool
		wantName    string
	}{
		{"", true, model.OutboundDirect, false, "direct"},
		{"", true, "", false, "direct"},
		{"", true, "nl", true, "proxy"},
		{"", true, model.OutboundBlock, true, "proxy"},
		{"", false, "nl", false, "direct"},
		{"proxy", false, model.OutboundDirect, true, "direct"},
		{"proxy", true, "nl", true, "proxy"},
		{"direct", true, "nl", false, "direct"},
	} {
		proxy, name := speedPath(c.via, c.coreRunning, c.route)
		if proxy != c.wantProxy || name != c.wantName {
			t.Errorf("speedPath(%q, core %v, route %q) = (%v, %q), want (%v, %q)", c.via, c.coreRunning, c.route, proxy, name, c.wantProxy, c.wantName)
		}
	}
}

// Pinning one exit of a selector measures that exit only when the test's site is routed through
// that selector. When the rules send the site elsewhere the selector is left alone and the answer
// says nothing was pinned, instead of switching a group the test never passes through.
func TestPanelSpeedtestPinsOnlyASelectorOnTheRoute(t *testing.T) {
	var mu sync.Mutex
	var selects []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/proxies":
			_, _ = w.Write([]byte(`{"proxies":{"sel":{"name":"sel","type":"Selector","now":"de","all":["nl","de"]}}}`))
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/proxies/"):
			var b struct{ Name string }
			_ = json.NewDecoder(r.Body).Decode(&b)
			mu.Lock()
			selects = append(selects, strings.TrimPrefix(r.URL.Path, "/proxies/")+"="+b.Name)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	s := servererrorpaths_server(t)
	stubSpeedLookup(t)
	cl, err := clash.New(strings.TrimPrefix(api.URL, "http://"), "")
	if err != nil {
		t.Fatal(err)
	}
	s.clash = cl
	var seen speedRunSeen
	s.speedRunOf = fakeSpeedRun(&seen)

	// The rules send the site straight out: the selector is not on its route.
	if err := s.store.Replace(speedPathProfile(false, "sel")); err != nil {
		t.Fatal(err)
	}
	a := postSpeed(t, s, `{"id":"nl","bytes":20000}`)
	mu.Lock()
	got := strings.Join(selects, ",")
	selects = nil
	mu.Unlock()
	if a.Pinned || a.Via != "direct" || got != "" {
		t.Errorf("selector off the route: pinned %v, via %q, selects %q; want nothing pinned, \"direct\"", a.Pinned, a.Via, got)
	}

	// The default route is the selector: the exit is pinned for the run and the old pick restored.
	if err := s.store.Replace(speedPathProfile(true, "sel")); err != nil {
		t.Fatal(err)
	}
	a = postSpeed(t, s, `{"id":"nl","bytes":20000}`)
	mu.Lock()
	got = strings.Join(selects, ",")
	mu.Unlock()
	if !a.Pinned || a.Via != "proxy" || !seen.proxy || got != "sel=nl,sel=de" {
		t.Errorf("selector on the route: pinned %v, via %q, ran %+v, selects %q; want pinned, \"proxy\", sel=nl,sel=de", a.Pinned, a.Via, seen, got)
	}
}
