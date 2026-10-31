package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"wayhop/internal/generator"
	"wayhop/internal/model"
	"wayhop/internal/netdiag"
	"wayhop/internal/pbr"
)

// The per-exit service check (competitor gap 3): through each exit, who the internet sees and whether
// ChatGPT, Claude and YouTube Premium work. netdiag does the asking; this file picks, for each exit, a
// client whose connections really leave by it.
//
//   - an exit backed by a kernel interface: a client bound to that interface;
//   - an exit sing-box carries, and the WAN while the core runs (its direct outbound): a client proxied
//     through the probe inbound (generator/probe.go, and on KeeneticOS the fallback core's copy of it
//     in keenetic/fallback.go) with that exit's user;
//   - the WAN with no core: an unbound client. The user and password are read from the config the core is running, not
//     derived again, so a secret changed since the last Apply cannot make every exit look dead.

// serviceTimeout bounds one request through one exit; the whole check is bounded by the handler.
const serviceTimeout = 12 * time.Second

// checkServices is netdiag.CheckServices; tests replace it.
var checkServices = netdiag.CheckServices

// probeInbound is what the running config says about the probe inbound.
type probeInbound struct {
	port  int
	users map[string]string // user -> password
}

// runningProbeInbound reads the probe inbound from the config file the core runs. ok is false when
// the file has none: the router has not been Applied since the probe inbound existed.
func runningProbeInbound(path string) (probeInbound, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return probeInbound{}, false
	}
	var cfg struct {
		Inbounds []struct {
			Tag        string `json:"tag"`
			Listen     string `json:"listen"`
			ListenPort int    `json:"listen_port"`
			Users      []struct {
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"users"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return probeInbound{}, false
	}
	for _, in := range cfg.Inbounds {
		if in.Tag != generator.ProbeInboundTag || in.ListenPort <= 0 || in.Listen != "127.0.0.1" {
			continue
		}
		p := probeInbound{port: in.ListenPort, users: map[string]string{}}
		for _, u := range in.Users {
			p.users[u.Username] = u.Password
		}
		return p, true
	}
	return probeInbound{}, false
}

// exitServices is one exit's row in the answer.
type exitServices struct {
	Egress string `json:"egress"`
	Name   string `json:"name"`
	Via    string `json:"via,omitempty"` // "interface" (bound to Iface; "" = the WAN) or "core" (through sing-box)
	Iface  string `json:"iface,omitempty"`
	netdiag.ExitServices
	Err string `json:"err,omitempty"`
}

// Reasons an exit could not be checked, for the panel to translate.
const (
	servicesNeedApply   = "apply_needed" // sing-box exit, but the running config has no probe inbound yet
	servicesCoreDown    = "core_not_running"
	servicesNotReadable = "not_checkable"     // neither an interface nor a probe user for this exit
	servicesNoIface     = "interface_missing" // the exit's interface is not up on this host
)

// ifaceUp reports whether the host has this interface; tests replace it. Binding to one that is gone
// fails on Linux and is silently ignored elsewhere - either way the answer would be the WAN's.
var ifaceUp = func(name string) bool { _, err := net.InterfaceByName(name); return err == nil }

// ifaceClient is the client for an interface-backed exit, or the reason there is none.
func ifaceClient(iface string) (*http.Client, string, string, string) {
	if !ifaceUp(iface) {
		return nil, "interface", iface, servicesNoIface
	}
	c, err := netdiag.IfaceClient(iface, serviceTimeout)
	if err != nil {
		return nil, "interface", iface, err.Error()
	}
	return c, "interface", iface, ""
}

// groupLiveIface is the interface a kernel-routed group leaves by right now: the default route of
// its table in the APPLIED plan, as the router holds it (the list failover loop re-points it). "" when
// the group has no table of its own or the tables could not be read.
func (s *Server) groupLiveIface(ctx context.Context, tag string) string {
	base := s.appliedBaseline()
	if base == nil || base.Materialization.Kernel.Plan == nil {
		return ""
	}
	for _, e := range base.Materialization.Kernel.Plan.Egresses {
		if e.Tag != tag || e.Kind != pbr.EgressInterface || e.Table == 0 {
			continue
		}
		live, ok := s.liveTableDefaults(ctx, false)
		if !ok {
			return ""
		}
		return live[e.Table]
	}
	return ""
}

// probeCoreClient asks through the core's probe inbound as tag's user, so the core's own route for
// that tag decides where the requests leave.
func probeCoreClient(tag, password string, port int, coreUp bool) (*http.Client, string, string, string) {
	if !coreUp {
		return nil, "core", "", servicesCoreDown
	}
	proxy := &url.URL{Scheme: "http", User: url.UserPassword(generator.ProbeUser(tag), password),
		Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true, TLSHandshakeTimeout: serviceTimeout},
		Timeout:   serviceTimeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}, "core", "", ""
}

// serviceClient picks the client for one exit.
func (s *Server) serviceClient(ctx context.Context, tag string, probe probeInbound, haveProbe, coreUp bool) (*http.Client, string, string, string) {
	if _, ok := probe.users[generator.ProbeUser(tag)]; tag == model.OutboundDirect && !(haveProbe && ok && coreUp) {
		// The WAN without a running core to ask: an unbound client from the daemon itself. With a
		// core, its direct outbound is asked instead - in tun mode the daemon's own sockets may be
		// captured by the TUN and leave by whatever the default rule says.
		c, err := netdiag.IfaceClient("", serviceTimeout)
		if err != nil {
			return nil, "", "", err.Error()
		}
		return c, "interface", "", ""
	}
	prof := s.store.Profile()
	if prof.GroupByID(tag) != nil {
		// A group leaves by the member it is on NOW, not by its first member that has an interface:
		// a routing list's table names that member, and the core picks it for its own probe user.
		if iface := s.groupLiveIface(ctx, tag); iface != "" {
			return ifaceClient(iface)
		}
		if pw, ok := probe.users[generator.ProbeUser(tag)]; haveProbe && ok {
			return probeCoreClient(tag, pw, probe.port, coreUp)
		}
		// KeeneticOS routing natively has no core group: a routing list sent to the group leaves by the
		// member the plan was compiled onto, so that member answers for it. (A group holding the
		// default route sits on NDM's ladder, which moves on by itself when that member drops; the
		// check does not follow it there.)
		if m := s.keeneticGroupMember(tag); m != "" && prof.EndpointByID(m) != nil {
			return s.serviceClient(ctx, m, probe, haveProbe, coreUp)
		}
		// None of the three says which member it is on. Its first member with an interface is a guess
		// (QA-049: the demo's "auto" read "interface missing" for a tunnel it was not using), so the
		// group says it cannot be read rather than answering for another exit.
		if !haveProbe {
			return nil, "core", "", servicesNeedApply
		}
		return nil, "", "", servicesNotReadable
	}
	if iface := s.egressProbeIface(tag); iface != "" {
		return ifaceClient(iface)
	}
	if pw, ok := probe.users[generator.ProbeUser(tag)]; haveProbe && ok {
		return probeCoreClient(tag, pw, probe.port, coreUp)
	}
	// An exit the router runs outside the core: the device the applied native plan bound it to, as the
	// health monitor and the speed test resolve it (a KeeneticOS WireguardN is nwgN), else a
	// kernel-routed AmneziaWG's derived name. The derived name alone read every NDM-run AmneziaWG as
	// "interface missing", and an NDM-run WireGuard, which no core will ever carry, as "Apply once".
	native, known := s.currentNativeInterfaceBindings()
	for _, e := range prof.Endpoints {
		if e.ID == tag && e.Enabled {
			if link := tunnelLink(e, native, known); netdiag.ValidIface(link) {
				return ifaceClient(link)
			}
		}
	}
	if !haveProbe {
		return nil, "core", "", servicesNeedApply
	}
	return nil, "", "", servicesNotReadable
}

// keeneticGroupMember is the member the applied KeeneticOS plan compiled group tag onto when NDM, not
// the compatibility core, routes the profile; "" otherwise.
func (s *Server) keeneticGroupMember(tag string) string {
	base := s.appliedBaseline()
	if base == nil {
		return ""
	}
	target := base.Materialization.nativeTarget()
	if target == nil || target.Keenetic == nil || target.Keenetic.CompatibilityRouting {
		return ""
	}
	return target.Keenetic.GroupMember[tag]
}

// servicesProbe is the probe inbound the check may ask through: the running config's, unless the
// applied plan runs no core at all (a KeeneticOS native-only plan, say). Stopping the core leaves its
// config on disk, and that file's probe users would answer "core not running" for exits the router
// carries itself and the check can reach through their own devices.
func (s *Server) servicesProbe() (probeInbound, bool) {
	if base := s.appliedBaseline(); base != nil && base.Materialization.Core.Action == ExecutionEnsureAbsent {
		return probeInbound{}, false
	}
	return runningProbeInbound(s.config().SingBox.Config)
}

// handleNetDiagServices checks every exit (or the one named by "egress") and answers per exit.
func (s *Server) handleNetDiagServices(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Egress string `json:"egress"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	body.Egress = strings.TrimSpace(body.Egress)
	type egress struct{ tag, name string }
	egrs := []egress{{model.OutboundDirect, "WAN (direct)"}}
	prof := s.store.Profile()
	for _, e := range prof.Endpoints {
		if e.Enabled {
			name := e.Name
			if name == "" {
				name = e.ID
			}
			egrs = append(egrs, egress{e.ID, name})
		}
	}
	for _, g := range prof.Groups {
		egrs = append(egrs, egress{g.ID, "▣ " + g.Name})
	}
	if body.Egress != "" {
		var one []egress
		for _, e := range egrs {
			if e.tag == body.Egress {
				one = append(one, e)
			}
		}
		if len(one) == 0 {
			writeErr(w, http.StatusNotFound, "no such exit")
			return
		}
		egrs = one
	}

	probe, haveProbe := s.servicesProbe()
	up := s.coreUp()
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	results := make([]exitServices, len(egrs))
	sem := make(chan struct{}, 4) // each exit runs its four requests at once
	var wg sync.WaitGroup
	for i, e := range egrs {
		wg.Add(1)
		go func(i int, e egress) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			row := exitServices{Egress: e.tag, Name: e.name}
			c, via, iface, why := s.serviceClient(ctx, e.tag, probe, haveProbe, up)
			row.Via, row.Iface = via, iface
			if c == nil {
				row.Err = why
			} else {
				row.ExitServices = checkServices(ctx, c)
				c.CloseIdleConnections()
			}
			results[i] = row
		}(i, e)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"services": netdiag.ServiceIDs(), "results": results})
}
