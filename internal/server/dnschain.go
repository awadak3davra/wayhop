package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"wayhop/internal/model"
	"wayhop/internal/nativedns"
	"wayhop/internal/pbr"
)

// dnschain.go is the panel's path to the upstream chain of the dnsmasq that answers a Keenetic's
// clients; nativedns/chain.go holds the write itself and says why it replaces the main config's
// upstreams rather than adding a file beside them.
//
// A row names an outbound, never an interface, and the name is turned into `server=IP@iface` when the
// chain is written: every router's tunnels are named differently, and an operator picking from their
// own connections cannot type the wrong one. A group expands into its members in the operator's order,
// so failing over needs no daemon and no restart: dnsmasq already walks the rows. A member named
// `direct` becomes a row bound to nothing, which is how a last resort is written.
//
// The router's own lookups are not touched: /etc/resolv.conf and NDM's `ip name-server` stay as they
// are, because a tunnel endpoint given by name has to resolve before any tunnel is up.

const (
	keeneticDnsmasqBin   = "/opt/sbin/dnsmasq"
	keeneticMainConf     = "/opt/etc/dnsmasq.conf"
	keeneticConfDir      = "/opt/etc/dnsmasq.d"
	keeneticUpstreamConf = keeneticConfDir + "/00-upstream.conf"
)

// dnsPlatform is detectDNSPlatform, honouring the test injection point.
func (s *Server) dnsPlatform() string {
	if s.dnsPlatformOf != nil {
		return s.dnsPlatformOf()
	}
	return detectDNSPlatform()
}

// dnsRunner is dnsExecRunner, honouring the test injection point.
func (s *Server) dnsRunner() nativedns.Runner {
	if s.dnsRunnerOf != nil {
		return s.dnsRunnerOf
	}
	return dnsExecRunner
}

// chainHost is the real router's dnsmasq, or what a test injected.
func (s *Server) chainHost() nativedns.ChainHost {
	if s.chainHostOf != nil {
		return s.chainHostOf()
	}
	stateDir := filepath.Join(s.config().DataDir, "native-dns")
	return nativedns.ChainHost{
		MainConf:     keeneticMainConf,
		UpstreamConf: keeneticUpstreamConf,
		ConfDir:      keeneticConfDir,
		StateDir:     stateDir,
		Usable:       keeneticChainUsable,
		Test: func(ctx context.Context) (string, error) {
			cmd := exec.CommandContext(ctx, keeneticDnsmasqBin, "--test", "-C", keeneticMainConf)
			cmd.WaitDelay = 5 * time.Second
			out, err := cmd.CombinedOutput()
			return string(out), err
		},
		Restart: func(ctx context.Context) error {
			cmd := exec.CommandContext(ctx, keeneticDnsmasqInitScript, "restart")
			// The service daemonizes. If it kept the script's output open, waiting for it would never end.
			cmd.WaitDelay = 5 * time.Second
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		},
		Trial: func(ctx context.Context, row nativedns.ChainRow) error {
			return nativedns.TrialDnsmasq(ctx, keeneticDnsmasqBin, stateDir, keeneticMainConf, row)
		},
		Verify: func(ctx context.Context) error { return verifyDnsmasqAnswers(ctx, dnsExecRunner) },
	}
}

// keeneticChainUsable says why this router cannot take a chain from here.
func keeneticChainUsable() error {
	for _, need := range []struct{ path, what string }{
		{keeneticDnsmasqBin, "Entware's dnsmasq"},
		{keeneticDnsmasqInitScript, "its service script"},
		{keeneticMainConf, "its configuration"},
	} {
		if !dnsFileExists(need.path) {
			return fmt.Errorf("%s is not on this router (%s)", need.what, need.path)
		}
	}
	return nil
}

// verifyDnsmasqAnswers waits for the restarted service to listen, then asks it through the chain.
func verifyDnsmasqAnswers(ctx context.Context, run nativedns.Runner) error {
	ctx, cancel := context.WithTimeout(ctx, nativedns.VerifyTimeout)
	defer cancel()
	for {
		out, _ := run("netstat", "-tulnp")
		ep := nativedns.DetectEffectivePath("", out, "", "")
		if addr := nativedns.ListenerProbeAddr(ep.Listeners); addr != "" {
			return nativedns.ProbeResolver(ctx, addr)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("nothing is listening on port 53: %w", ctx.Err())
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// chainVia is one outbound a row can be bound to.
type chainVia struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Kind   string   `json:"kind"` // "endpoint" | "group"
	Ifaces []string `json:"ifaces"`
}

// chainRowView is one upstream as the page edits it.
type chainRowView struct {
	Address string `json:"address"`
	Port    int    `json:"port,omitempty"`
	// Via is the outbound whose link Iface is, when there is one. Iface alone is a binding the profile
	// does not know, written by hand: it is kept as it is, and offered as itself.
	Via   string `json:"via,omitempty"`
	Iface string `json:"iface,omitempty"`
	// Label names what the row really is when the address alone does not: a local DoH proxy.
	Label string `json:"label,omitempty"`
	// LinkAbsent says the interface this row is bound to does not exist right now.
	LinkAbsent bool `json:"link_absent,omitempty"`
}

// chainVias lists what a row can be bound to: enabled endpoints with a kernel link, and groups with at
// least one such member. A proxy outbound is missing on purpose: sing-box carries it, so dnsmasq has no
// interface to bind to.
func chainVias(p *model.Profile) []chainVia {
	out := []chainVia{}
	for i := range p.Endpoints {
		e := &p.Endpoints[i]
		if iface := pbr.KernelIface(e); iface != "" && e.Enabled {
			out = append(out, chainVia{ID: e.ID, Name: e.Name, Kind: "endpoint", Ifaces: []string{iface}})
		}
	}
	for i := range p.Groups {
		g := &p.Groups[i]
		ifaces := []string{}
		for _, id := range g.Members {
			if e := p.EndpointByID(id); e != nil && e.Enabled {
				if iface := pbr.KernelIface(e); iface != "" {
					ifaces = append(ifaces, iface)
				}
			}
		}
		if len(ifaces) > 0 {
			out = append(out, chainVia{ID: g.ID, Name: g.Name, Kind: "group", Ifaces: ifaces})
		}
	}
	return out
}

// chainViewOf is the `chain` member of GET /api/dns/native.
func (s *Server) chainViewOf(nd nativedns.NativeDNS, p *model.Profile) map[string]any {
	host := s.chainHost()
	view := map[string]any{"editable": false, "managed": host.Managed(), "vias": chainVias(p), "rows": []chainRowView{}}
	if host.Usable != nil {
		if err := host.Usable(); err != nil {
			view["reason"] = err.Error()
			return view
		}
	}
	view["editable"] = true
	view["rev"] = host.Rev()
	byIface := map[string]string{}
	for i := range p.Endpoints {
		if iface := pbr.KernelIface(&p.Endpoints[i]); iface != "" && p.Endpoints[i].Enabled {
			byIface[iface] = p.Endpoints[i].ID
		}
	}
	rows := []chainRowView{}
	for _, r := range nd.Resolvers {
		row := chainRowView{Address: r.Address, Port: r.Port, Iface: r.Iface, Via: byIface[r.Iface]}
		if r.Kind == nativedns.KindDoH { // Address is the proxy's URL; dnsmasq only knows its loopback port
			row.Address, row.Label = "127.0.0.1", nativedns.RedactAddress(r.Address)
		}
		if r.Iface != "" && s.ifindex(r.Iface) == 0 {
			row.LinkAbsent = true
		}
		rows = append(rows, row)
	}
	view["rows"] = rows
	return view
}

// ifindex is the interface's kernel index, 0 when it does not exist.
func (s *Server) ifindex(name string) int {
	if s.ifindexOf != nil {
		return s.ifindexOf(name)
	}
	if ifi, err := net.InterfaceByName(name); err == nil {
		return ifi.Index
	}
	return 0
}

// chainRowReq is one row as the page submits it.
type chainRowReq struct {
	Address string `json:"address"`
	Port    int    `json:"port,omitempty"`
	Via     string `json:"via,omitempty"`
	Iface   string `json:"iface,omitempty"`
}

// expandChainRows turns the page's rows into the lines to write. See the top of this file for what a
// via becomes. An identical line twice is one line.
func expandChainRows(p *model.Profile, reqs []chainRowReq) ([]nativedns.ChainRow, error) {
	var rows []nativedns.ChainRow
	seen := map[nativedns.ChainRow]bool{}
	add := func(r nativedns.ChainRow) {
		if !seen[r] {
			seen[r] = true
			rows = append(rows, r)
		}
	}
	for i, req := range reqs {
		base := nativedns.ChainRow{Address: strings.TrimSpace(req.Address), Port: req.Port}
		if req.Via == "" || req.Via == model.OutboundDirect {
			base.Iface = strings.TrimSpace(req.Iface)
			add(base)
			continue
		}
		if e := p.EndpointByID(req.Via); e != nil {
			iface := pbr.KernelIface(e)
			switch {
			case !e.Enabled:
				return nil, fmt.Errorf("upstream %d: %s is switched off", i+1, e.Name)
			case iface == "":
				return nil, fmt.Errorf("upstream %d: %s has no network link, and dnsmasq can only bind to one", i+1, e.Name)
			}
			base.Iface = iface
			add(base)
			continue
		}
		g := p.GroupByID(req.Via)
		if g == nil {
			return nil, fmt.Errorf("upstream %d: %q is no longer in the profile", i+1, req.Via)
		}
		before := len(rows)
		for _, id := range g.Members {
			if id == model.OutboundDirect {
				add(base) // the operator's own "then the provider"
				continue
			}
			if e := p.EndpointByID(id); e != nil && e.Enabled {
				if iface := pbr.KernelIface(e); iface != "" {
					r := base
					r.Iface = iface
					add(r)
				}
			}
		}
		if len(rows) == before && !seen[base] {
			return nil, fmt.Errorf("upstream %d: no member of %s has a network link", i+1, g.Name)
		}
	}
	return rows, nil
}

// chainWarnings are what the review says the chain will mean. Each of these is a choice the operator
// may well make, so they inform and do not refuse. dnsPort is the port WayHop's encrypted resolver
// listens on.
func chainWarnings(rows []nativedns.ChainRow, plan nativedns.ChainPlan, ans nativedns.Answering, dnsPort int) []string {
	var out []string
	if dnsPort > 0 && len(rows) == 1 && rows[0].Address == "127.0.0.1" && rows[0].Port == dnsPort {
		out = append(out, "WayHop's encrypted resolver is the only upstream. If sing-box stops, the household has no DNS. Add a fallback row behind it.")
	}
	switch {
	case ans.Plane == nativedns.PlaneUnknown:
		out = append(out, "WayHop could not read who holds port 53, so whether this chain reaches clients is unconfirmed.")
	case !strings.HasPrefix(ans.Process, "dnsmasq"):
		out = append(out, ans.Process+" holds port 53 right now, not dnsmasq, so this chain will not reach clients.")
	}
	public := func(r nativedns.ChainRow) bool {
		ip := net.ParseIP(r.Address)
		return r.Iface == "" && ip != nil && !ip.IsLoopback() && !ip.IsPrivate()
	}
	var last string
	bound := 0
	for _, r := range rows {
		if r.Iface != "" {
			bound++
		}
		if public(r) {
			last = r.Address
		}
	}
	switch {
	case len(rows) > 0 && public(rows[0]):
		out = append(out, "The first upstream is bound to nothing, so every lookup leaves over your provider in plaintext. The rows after it are asked only when it fails.")
	case last != "":
		// SERVFAIL as well, measured on 2.90 and 2.92: a name that fails DNSSEC walks the whole chain, so
		// the last resort sees it with every tunnel up. That is the row's real price, so the review names it.
		out = append(out, "Lookups fall to "+last+" in plaintext over your provider if every row before it fails, and also when those rows answer SERVFAIL, which a broken domain does while the tunnels are up. Without such a row the router stops resolving when the tunnels go down.")
	case bound == len(rows):
		out = append(out, "Every upstream is bound to a tunnel. If they are all down this router resolves nothing, and devices lose DNS until one returns.")
	}
	if bound > 0 {
		out = append(out, "Rows are asked in order. A tunnel that is up but silent costs each lookup a client retry, about 2 seconds, before the next row is asked; one that is down costs nothing.")
	}
	if len(plan.Foreign) > 0 {
		out = append(out, "Other files in the conf-dir add upstreams this page does not own, and dnsmasq asks them too: "+strings.Join(plan.Foreign, "; "))
	}
	return out
}

// chainBody decodes and expands a chain request. A false ok has written the answer.
func (s *Server) chainBody(w http.ResponseWriter, r *http.Request) (string, []nativedns.ChainRow, bool) {
	if s.dnsPlatform() != "keenetic" {
		writeErr(w, http.StatusBadRequest, "the upstream chain is set from here only on KeeneticOS")
		return "", nil, false
	}
	var body struct {
		Rows []chainRowReq `json:"rows"`
		Rev  string        `json:"rev"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid chain JSON")
		return "", nil, false
	}
	p := s.store.Profile()
	rows, err := expandChainRows(&p, body.Rows)
	if err == nil {
		err = nativedns.ValidateChain(rows)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return "", nil, false
	}
	return body.Rev, rows, true
}

// handleDNSChainPlan (POST /api/dns/native/chain/plan) is the review: what the write would do, changing
// nothing.
func (s *Server) handleDNSChainPlan(w http.ResponseWriter, r *http.Request) {
	_, rows, ok := s.chainBody(w, r)
	if !ok {
		return
	}
	plan, err := s.chainHost().Plan(rows)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	eff := nativedns.RunEffectivePath(s.dnsRunner())
	writeJSON(w, http.StatusOK, map[string]any{"plan": plan, "warnings": chainWarnings(rows, plan, eff.Answering(), s.config().Ports.DNS)})
}

// handleDNSChainSet (POST /api/dns/native/chain) writes the chain. It takes the same lock as Apply,
// which also writes the conf-dir and restarts this service. A failure is an answer with ok:false and
// the steps taken, not an HTTP error: the page shows what happened, and whether the router was put back.
func (s *Server) handleDNSChainSet(w http.ResponseWriter, r *http.Request) {
	rev, rows, ok := s.chainBody(w, r)
	if !ok {
		return
	}
	s.writeChainReport(w, rev, func(ctx context.Context, host nativedns.ChainHost) nativedns.ChainReport {
		return host.Apply(ctx, rows)
	})
}

// handleDNSChainRestore (POST /api/dns/native/chain/restore) undoes the page's chain.
func (s *Server) handleDNSChainRestore(w http.ResponseWriter, r *http.Request) {
	if s.dnsPlatform() != "keenetic" {
		writeErr(w, http.StatusBadRequest, "the upstream chain is set from here only on KeeneticOS")
		return
	}
	var body struct {
		Rev string `json:"rev"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s.writeChainReport(w, body.Rev, func(ctx context.Context, host nativedns.ChainHost) nativedns.ChainReport {
		return host.Restore(ctx)
	})
}

func (s *Server) writeChainReport(w http.ResponseWriter, rev string, do func(context.Context, nativedns.ChainHost) nativedns.ChainReport) {
	if !s.applyMu.TryLock() {
		writeErr(w, http.StatusConflict, "Apply in progress: finish it first, then make this change again.")
		return
	}
	defer s.applyMu.Unlock()
	host := s.chainHost()
	if rev == "" || rev != host.Rev() {
		writeErr(w, http.StatusConflict, "STALE_CONFIG: the router's dnsmasq configuration changed after this page read it. "+
			"Reload the DNS page to see what is there now, then make your change again.")
		return
	}
	// Not the request's context: a browser closing mid-write must not leave the files half way, with the
	// verification and the rollback cancelled.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	rep := do(ctx, host)
	log.Printf("dns chain: ok=%v rolled_back=%v %s", rep.OK, rep.RolledBack, rep.Error)
	writeJSON(w, http.StatusOK, rep)
}

// NativeDNSChainGuardLoop restarts dnsmasq when a tunnel its chain is bound to was recreated.
//
// Measured on dnsmasq 2.90: an interface that is absent at start is picked up when it appears, and one
// that goes link-down fails over and comes back, but one deleted and created again is never rebound.
// dnsmasq's socket stays tied to the old interface, the row is skipped from then on, and the lookups
// fall to the next row with nothing in the logs: if that row is the last resort, the house is back on
// plaintext until something restarts the service. A new index on the same name is what tells this apart.
func (s *Server) NativeDNSChainGuardLoop(ctx context.Context) {
	if s.config().Demo {
		return
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	seen := map[string]int{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.chainGuardTick(ctx, seen)
		}
	}
}

// chainGuardTick is one look. seen holds the last index of each bound interface, kept while it is
// absent so that its return with a new index counts. A restart that could not run keeps the old value,
// so the next tick tries again.
func (s *Server) chainGuardTick(ctx context.Context, seen map[string]int) {
	if s.dnsPlatform() != "keenetic" {
		return
	}
	host := s.chainHost()
	if !host.Managed() {
		clear(seen)
		return
	}
	data, err := os.ReadFile(host.UpstreamConf)
	if err != nil {
		return
	}
	now := map[string]int{}
	recreated := ""
	for _, iface := range nativedns.BoundIfaces(string(data)) {
		idx := s.ifindex(iface)
		if prev := seen[iface]; prev != 0 && idx != 0 && prev != idx {
			recreated = iface
		}
		if idx == 0 {
			idx = seen[iface]
		}
		now[iface] = idx
	}
	if recreated != "" {
		if !s.applyMu.TryLock() {
			return
		}
		defer s.applyMu.Unlock()
		log.Printf("dns chain: %s was recreated, restarting dnsmasq so it binds to the new interface", recreated)
		if err := host.Restart(ctx); err != nil {
			log.Printf("dns chain: restart dnsmasq: %v", err)
			return
		}
	}
	clear(seen)
	for iface, idx := range now {
		seen[iface] = idx
	}
}
