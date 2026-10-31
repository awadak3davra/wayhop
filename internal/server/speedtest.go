package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"wayhop/internal/model"
	"wayhop/internal/speedtest"
)

// handleSpeedtest runs a throughput test. Body: {via, bytes, id}. When id is
// set and it belongs to a selector group the test's site is routed through, that
// endpoint is temporarily selected (then restored) so the test measures *that*
// tunnel; otherwise the test takes the site's own route (see speedPath), and the
// answer's via names where that route sends it: "direct", "proxy", or the exit's
// name when the route is one kernel tunnel and the test ran bound to it.
func (s *Server) handleSpeedtest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Via   string `json:"via"`
		Bytes int    `json:"bytes"`
		ID    string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if !s.speedMu.TryLock() {
		writeErr(w, http.StatusConflict, errSpeedBusy.Error())
		return
	}
	defer s.speedMu.Unlock()

	bytes := body.Bytes
	if bytes <= 0 {
		bytes = speedBytes
	}
	if bytes > 100_000_000 {
		bytes = 100_000_000
	}

	coreRunning := s.singbox != nil && s.singbox.Running()
	var p model.Profile
	if s.store != nil {
		p = s.store.Profile()
	}
	// Where the rules send the test's site, asked unless the line was (it starts with a lookup of the
	// site): a direct run has one way out whatever the rules say.
	route := model.OutboundDirect
	if body.Via != "direct" || body.ID != "" {
		route, _ = s.speedRoute(r.Context(), &p)
	}

	via := body.Via
	pinned := false
	if body.ID != "" && s.clash != nil && !speedRouteDirect(route) {
		if restore := s.selectEndpoint(r.Context(), &p, route, body.ID); restore != nil {
			pinned, via = true, "proxy"
			defer restore()
		}
	}
	viaProxy, name := speedPath(via, coreRunning, route)
	// A route that is one kernel tunnel is measured bound to it, core or no core, as the bot's test
	// is: in hybrid mode such a list and its tunnel are the kernel's, the core carries neither, and a
	// run through it left by the core's final, the provider's line, under the name "proxy".
	link := ""
	if via != "direct" {
		if e := p.EndpointByID(route); e != nil {
			native, known := s.currentNativeInterfaceBindings()
			if l := tunnelLink(*e, native, known); l != "" && speedBindDial(l) != nil {
				link, viaProxy, name = l, false, exitName(e)
			}
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	run := s.speedRunOf
	if run == nil {
		run = s.speedRun
	}
	res, err := run(ctx, viaProxy, link, bytes)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	res.Via = name
	writeJSON(w, http.StatusOK, struct {
		speedtest.Result
		Pinned bool   `json:"pinned"`
		ID     string `json:"id,omitempty"`
	}{res, pinned, body.ID})
}

// speedPath is how the panel's test runs (through the core's mixed inbound, or straight out past the
// engine's redirect) and what its answer calls the path, given the request's via ("proxy", "direct"
// or "" to let the router choose) and route, where the rules send the test's site (speedRoute).
//
// A run through the core goes wherever the core's rules send the site, so the name comes from that
// route and not from the request (QA-112). On a split-tunnel profile, with no default rule or a list
// sending Cloudflare straight out, the core sends speed.cloudflare.com out by the provider's line, and
// the answer called that line "proxy": the tunnel's throughput, as far as the panel could tell. Left
// to choose, the router now measures such a route as a direct test does, past the core, since that is
// the way the site leaves; asked for the proxy, the run still goes through the core and is named for
// where the core sends it. As in /route, a geo or remote list that may also catch the site is not
// evaluated.
func speedPath(via string, coreRunning bool, route string) (viaProxy bool, name string) {
	switch via {
	case "direct":
		return false, "direct"
	case "proxy":
		viaProxy = true
	default:
		viaProxy = coreRunning && !speedRouteDirect(route)
	}
	if !viaProxy || speedRouteDirect(route) {
		return viaProxy, "direct"
	}
	return true, "proxy"
}

// speedRouteDirect reports a route that leaves by the provider's line, the way the bot's test reads it.
func speedRouteDirect(route string) bool {
	return route == "" || strings.EqualFold(route, model.OutboundDirect)
}

// speedBytes is a test's download size; the upload is half of it.
const speedBytes = 10_000_000

// errSpeedBusy refuses a second test while one runs (see speedMu).
var errSpeedBusy = errors.New("a speed test is already running")

// speedTester measures through the engine's mixed inbound, or directly past the engine's
// transparent redirect (bypassDial), so a direct run measures the provider's line and not whichever
// outbound sing-box's rules would have picked for it.
func (s *Server) speedTester() *speedtest.Tester {
	t := speedtest.New(s.config().Ports.Mixed)
	t.Direct = bypassDial
	return t
}

// speedBindDial is the dialer of a test bound to one kernel tunnel (ifaceDial: bound to the link and
// past the engine's redirect; nil where a socket cannot be bound). A variable so the panel's choice
// of it can be tested off the router.
var speedBindDial = ifaceDial

// speedRun is the panel's test as the router runs it: bound to the kernel tunnel link when one is
// given, else through the core's mixed inbound or straight out past its redirect (speedTester).
func (s *Server) speedRun(ctx context.Context, viaProxy bool, link string, bytes int) (speedtest.Result, error) {
	if link != "" {
		if dial := speedBindDial(link); dial != nil {
			t := speedtest.New(0)
			t.Direct = dial
			return t.Run(ctx, false, bytes)
		}
	}
	return s.speedTester().Run(ctx, viaProxy, bytes)
}

// selectEndpoint temporarily selects id in a selector group that contains it and that route, the
// test site's route, passes through, returning a restore func (or nil if it can't be pinned, e.g.
// urltest groups). A selector off the route is left alone: switching it would change nothing the
// test measures, and the answer said "pinned" about a run that never went through it.
func (s *Server) selectEndpoint(ctx context.Context, p *model.Profile, route, id string) func() {
	for _, g := range p.Groups {
		if g.Type != model.GroupSelector || !groupOnRoute(p, route, g.ID) {
			continue
		}
		for _, m := range g.Members {
			if m != id {
				continue
			}
			// Capture the current selection FIRST; if we can't read it we can't restore it, so do
			// NOT pin — otherwise a failed pre-read leaves the group permanently selected onto the
			// speedtested endpoint (the restore func no-ops on an empty prev).
			px, err := s.clash.Proxies(ctx)
			if err != nil {
				return nil
			}
			prev := px[g.ID].Now
			if err := s.clash.Select(ctx, g.ID, id); err != nil {
				return nil
			}
			return func() {
				if prev != "" {
					rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_ = s.clash.Select(rctx, g.ID, prev)
				}
			}
		}
	}
	return nil
}

// groupOnRoute reports whether the group gid is route itself or a group route reaches through its
// members, nested groups included.
func groupOnRoute(p *model.Profile, route, gid string) bool {
	seen := map[string]bool{}
	var walk func(tag string) bool
	walk = func(tag string) bool {
		if tag == gid {
			return true
		}
		if seen[tag] {
			return false
		}
		seen[tag] = true
		if g := p.GroupByID(tag); g != nil {
			for _, m := range g.Members {
				if walk(m) {
					return true
				}
			}
		}
		return false
	}
	return walk(route)
}
