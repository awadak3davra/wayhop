package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"wayhop/internal/dnscheck"
	"wayhop/internal/model"
	"wayhop/internal/nativedns"
	"wayhop/internal/netdiag"
)

const (
	dnsCheckJobTimeout = 90 * time.Second
	dnsCheckSample     = 10 * time.Second
	dnsCheckCanaryWait = 1500 * time.Millisecond
)

// handleDNSCheckState (GET /api/dns/check) answers the running job's progress and the last report. The
// demo has no network to measure, so it serves canned reports, chosen with ?scenario=, which is how
// every state of the page gets seen.
func (s *Server) handleDNSCheckState(w http.ResponseWriter, r *http.Request) {
	if s.config().Demo {
		rep := dnscheck.DemoReport(r.URL.Query().Get("scenario"))
		writeJSON(w, http.StatusOK, dnscheck.State{Report: &rep, Scenarios: dnscheck.DemoScenarios()})
		return
	}
	writeJSON(w, http.StatusOK, s.dnsCheckState())
}

// handleDNSCheckStart (POST /api/dns/check) starts a check. Only one runs at a time.
func (s *Server) handleDNSCheckStart(w http.ResponseWriter, r *http.Request) {
	if s.config().Demo {
		writeJSON(w, http.StatusAccepted, dnscheck.State{Scenarios: dnscheck.DemoScenarios()})
		return
	}
	var req dnscheck.Request
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid DNS check JSON")
		return
	}
	if len(req.ExtraNames) > 10 {
		writeErr(w, http.StatusBadRequest, "at most 10 extra names may be checked")
		return
	}
	for i := range req.ExtraNames {
		req.ExtraNames[i] = strings.TrimSpace(req.ExtraNames[i])
		if !netdiag.ValidTarget(req.ExtraNames[i]) {
			writeErr(w, http.StatusBadRequest, "invalid extra name "+req.ExtraNames[i])
			return
		}
	}

	s.dnsCheckMu.Lock()
	if s.dnsCheckRunning {
		s.dnsCheckMu.Unlock()
		writeErr(w, http.StatusConflict, "a DNS check is already running")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsCheckJobTimeout)
	total := 1
	if req.Full {
		total = 4
	}
	s.dnsCheckRunning = true
	s.dnsCheckCancel = cancel
	s.dnsCheckProgress = dnscheck.Progress{Stage: "path", Total: total}
	s.dnsCheckMu.Unlock()
	go s.runDNSCheck(ctx, req)
	writeJSON(w, http.StatusAccepted, s.dnsCheckState())
}

func (s *Server) dnsCheckState() dnscheck.State {
	s.dnsCheckMu.Lock()
	defer s.dnsCheckMu.Unlock()
	return dnscheck.State{
		Running: s.dnsCheckRunning, Progress: s.dnsCheckProgress, Report: s.dnsCheckReport,
	}
}

func (s *Server) dnsCheckSetProgress(stage string, done, total int) {
	s.dnsCheckMu.Lock()
	s.dnsCheckProgress = dnscheck.Progress{Stage: stage, Done: done, Total: total}
	s.dnsCheckMu.Unlock()
}

func (s *Server) runDNSCheck(ctx context.Context, req dnscheck.Request) {
	started := time.Now().UTC()
	rep := dnscheck.Report{Version: 1, StartedAt: started, Full: req.Full}
	rep.Path.Exposure = dnscheck.ExposureUnknown
	s.dnsCheckMu.Lock()
	prev := s.dnsCheckReport
	s.dnsCheckMu.Unlock()
	total := 1
	if req.Full {
		total = 4
	}
	defer func() {
		rep.FinishedAt = time.Now().UTC()
		s.dnsCheckMu.Lock()
		s.dnsCheckReport = &rep
		s.dnsCheckRunning = false
		if s.dnsCheckCancel != nil {
			s.dnsCheckCancel() // ends the job's timer, which would otherwise hold on for its 90 s
		}
		s.dnsCheckCancel = nil
		s.dnsCheckProgress.Done = total
		s.dnsCheckMu.Unlock()
	}()

	if ctx.Err() != nil || s.dnsPlatform() == "" {
		rep.Level = dnscheck.LevelUnknown
		rep.Warnings, rep.Options = dnscheck.Advise(dnscheck.AdviseInput{InterceptOn: true})
		return
	}

	run := s.dnsRunner()
	prof := s.store.Profile()
	nd, adoptErr := nativedns.Adopt(run, s.dnsPlatform())
	if adoptErr != nil {
		nd = nativedns.NativeDNS{Platform: s.dnsPlatform()}
	}
	eff := nativedns.RunEffectivePath(run)
	tunnels := map[string]bool{}
	for _, iface := range kernelIfaceByEndpoint(&prof, s.appliedKernelDevices()) {
		tunnels[iface] = true
	}
	nd = nd.MarkTunnels(func(iface string) bool { return tunnels[iface] })

	input := dnsCheckAdviseInput(s, &prof, eff)
	input.Path = s.measureDNSCheckPath(ctx, run, eff, nd, tunnels, &prof)
	rep.Path = input.Path
	rep.Level = dnscheck.LevelOf(input)
	rep.Path.Exposure = dnsCheckExposure(rep.Level)
	input.Path.Exposure = rep.Path.Exposure

	if req.Full && ctx.Err() == nil {
		paths := s.dnsCheckPaths(&prof)
		listener := nativedns.ListenerProbeAddr(eff.Listeners)
		targets := dnsCheckTargets(nd, paths, listener)
		n := s.dnsCheckNet()
		if n != nil {
			opts := dnscheck.Options{
				Names: append([]string(nil), req.ExtraNames...), CanariesOnWAN: req.CanariesOnWAN,
				RouterHidden: dnsCheckRouterHidden(rep.Level, rep.Path),
			}
			stage := func(name string) {
				s.dnsCheckSetProgress(name, 0, 0)
				opts.OnProgress = func(done, count int) { s.dnsCheckSetProgress(name, done, count) }
			}
			stage("decoys")
			rep.Interception = dnscheck.Interceptions(ctx, n, paths, opts)
			input.Interception = rep.Interception
			opts.ProofPath = dnsCheckProofPath(rep.Interception)
			if ctx.Err() == nil {
				stage("resolvers")
				rep.Resolvers = dnscheck.Authenticate(ctx, n, targets, rep.Interception, opts)
				input.Resolvers = rep.Resolvers
			}
			if ctx.Err() == nil {
				stage("encrypted")
				rep.Encrypted = dnscheck.Encrypted(ctx, n, targets, opts)
				input.Encrypted = rep.Encrypted
			}
			if ctx.Err() == nil {
				now := time.Now().UTC()
				rep.FullAt = &now
			}
		}
	} else if !req.Full && prev != nil && (prev.Full || prev.FullAt != nil) {
		rep.Interception = prev.Interception
		rep.Resolvers = prev.Resolvers
		rep.Encrypted = prev.Encrypted
		rep.FullAt = prev.FullAt
		rep.Full = true
		input.Interception = rep.Interception
		input.Resolvers = rep.Resolvers
		input.Encrypted = rep.Encrypted
	}
	rep.Warnings, rep.Options = dnscheck.Advise(input)
}

func dnsCheckExposure(level dnscheck.Level) dnscheck.Exposure {
	switch level {
	case dnscheck.LevelProviderPlain:
		return dnscheck.ExposureProvider
	case dnscheck.LevelTunnelPlain:
		return dnscheck.ExposureExit
	case dnscheck.LevelProviderEncrypted, dnscheck.LevelTunnelEncrypted:
		return dnscheck.ExposureResolver
	default:
		return dnscheck.ExposureUnknown
	}
}

func dnsCheckRouterHidden(level dnscheck.Level, path dnscheck.PathReport) bool {
	if !path.Measured || (level != dnscheck.LevelTunnelPlain && level != dnscheck.LevelTunnelEncrypted) {
		return false
	}
	for _, u := range path.Upstreams {
		if u.LastResort {
			return false
		}
	}
	return true
}

func dnsCheckProofPath(interceptions []dnscheck.Interception) *dnscheck.Path {
	for _, i := range interceptions {
		if i.Path.Kind == dnscheck.PathTunnel && !i.Intercepted &&
			(i.Status == dnscheck.StatusPass || i.Status == dnscheck.StatusNoData) {
			path := i.Path
			return &path
		}
	}
	return nil
}

// measureDNSCheckPath watches the router's own connections. The unique lookup identifies the upstream
// that really answered; configuration is only a fallback when the connection table cannot be read.
func (s *Server) measureDNSCheckPath(ctx context.Context, run nativedns.Runner, eff nativedns.EffectivePath,
	nd nativedns.NativeDNS, tunnels map[string]bool, prof *model.Profile) dnscheck.PathReport {
	var ownResolv []string
	for _, u := range eff.Upstreams {
		if ip := net.ParseIP(u); ip != nil && ip.IsLoopback() {
			continue
		}
		ownResolv = append(ownResolv, u)
	}
	path := dnscheck.PathReport{
		Answering: eff.Answering().Process, Upstreams: dnsCheckUpstreams(nd, prof, kernelIfaceByEndpoint(prof, s.appliedKernelDevices()), run, tunnels),
		OwnResolvConf: ownResolv, Exposure: dnscheck.ExposureUnknown,
	}
	beforeText, err := readDNSConntrack(run)
	if err != nil {
		return path
	}
	addrText, addrErr := run("ip", "-o", "addr")
	if addrErr != nil && strings.TrimSpace(addrText) == "" {
		return path
	}
	path.Measured = true
	path.SampleSec = int(dnsCheckSample / time.Second)
	before := dnscheck.ParseConntrack(beforeText)
	all := map[dnsCheckFlowKey]dnscheck.ConnFlow{}
	mergeDNSFlows(all, before)

	elapsed := time.Duration(0)
	listener := nativedns.ListenerProbeAddr(eff.Listeners)
	if listener != "" && ctx.Err() == nil {
		name := "wh-" + s.dnsCheckRandom() + "-nx.com"
		started := time.Now()
		_ = s.dnsCheckProbe(ctx, listener, dnsCheckQuery(name))
		elapsed = dnsCheckCanaryWait
		if remaining := dnsCheckCanaryWait - time.Since(started); remaining > 0 {
			_ = s.dnsCheckWait(ctx, remaining)
		}
	} else {
		elapsed = dnsCheckCanaryWait
		_ = s.dnsCheckWait(ctx, elapsed)
	}
	afterText, err := readDNSConntrack(run)
	if err != nil {
		path.Measured, path.SampleSec, path.Flows = false, 0, nil
		return path
	}
	after := dnscheck.ParseConntrack(afterText)
	canary := dnscheck.DiffFlows(before, after)
	mergeDNSFlows(all, after)

	for elapsed < dnsCheckSample && ctx.Err() == nil {
		// A UDP flow stays in the table for half a minute, so there is no need to read it every second.
		step := 3 * time.Second
		if remaining := dnsCheckSample - elapsed; step > remaining {
			step = remaining
		}
		if err := s.dnsCheckWait(ctx, step); err != nil {
			break
		}
		elapsed += step
		text, err := readDNSConntrack(run)
		if err != nil {
			path.Measured, path.SampleSec, path.Flows = false, 0, nil
			return path
		}
		mergeDNSFlows(all, dnscheck.ParseConntrack(text))
	}
	if ctx.Err() != nil {
		path.SampleSec = int(elapsed / time.Second)
	}
	flows := make([]dnscheck.ConnFlow, 0, len(all))
	for _, f := range all {
		flows = append(flows, f)
	}
	path.Flows = dnscheck.SummarizeFlows(flows, addrText, tunnels, canary)
	if len(path.Upstreams) > 0 && ctx.Err() == nil {
		if first := path.Upstreams[0]; first.Kind == nativedns.KindLocal || first.Kind == nativedns.KindDoH || first.Kind == nativedns.KindDoT {
			if addr := dnsCheckFirstRowAddr(first); addr != "" {
				path.FirstRowAnswered = s.dnsCheckProbe(ctx, addr, dnsCheckQuery("wh-"+s.dnsCheckRandom()+"-nx.com")) == nil
			}
		}
	}
	return dnscheck.SettleMeasured(path)
}

type dnsCheckFlowKey struct {
	proto, src, dst string
	sport, dport    int
}

func dnsCheckKey(f dnscheck.ConnFlow) dnsCheckFlowKey {
	return dnsCheckFlowKey{proto: f.Proto, src: f.Src, dst: f.Dst, sport: f.Sport, dport: f.Dport}
}

func mergeDNSFlows(into map[dnsCheckFlowKey]dnscheck.ConnFlow, flows []dnscheck.ConnFlow) {
	for _, f := range flows {
		key := dnsCheckKey(f)
		if old, ok := into[key]; ok && old.Replied {
			f.Replied = true
		}
		into[key] = f
	}
}

// dnsCheckFirstRowAddr is where a local first row can be asked directly. Only a loopback row can: anything
// else is reached through a path this check cannot stand in for.
func dnsCheckFirstRowAddr(u dnscheck.Upstream) string {
	if u.Port == 0 {
		return ""
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(u.Port))
}

func readDNSConntrack(run nativedns.Runner) (string, error) {
	// Only lookups matter, and a busy router's whole table is megabytes, read several times over. Grep
	// exits 1 when nothing matches, which is an empty answer and not a failure.
	proc, procErr := run("sh", "-c", "test -r /proc/net/nf_conntrack && { grep -E 'dport=(53|853) ' /proc/net/nf_conntrack; true; }")
	if procErr == nil {
		return proc, nil
	}
	text, err := run("conntrack", "-L")
	if err == nil {
		return text, nil
	}
	return "", fmt.Errorf("read connection table: %w", errors.Join(procErr, err))
}

// dnsCheckUpstreams lists the resolvers the check reports. ifaceOf is kernelIfaceByEndpoint with the
// applied plan's devices, so a tunnel NDM created is labelled by its nwgN device.
func dnsCheckUpstreams(nd nativedns.NativeDNS, prof *model.Profile, ifaceOf map[string]string, run nativedns.Runner, tunnels map[string]bool) []dnscheck.Upstream {
	labels := map[string]string{}
	for id, iface := range ifaceOf {
		if e := prof.EndpointByID(id); e != nil {
			labels[iface] = e.Name
			if labels[iface] == "" {
				labels[iface] = id
			}
		}
	}
	var out []dnscheck.Upstream
	seenTunnel := false
	for _, r := range nd.Resolvers {
		u := dnscheck.Upstream{
			Address: r.Address, Port: r.Port, Iface: r.Iface, Kind: r.Kind,
			ViaTunnel: r.ViaTunnel, Label: labels[r.Iface],
		}
		if ip := net.ParseIP(dnsCheckTargetAddress(r.Address)); ip != nil && ip.IsLoopback() {
			u.Kind = nativedns.KindLocal
		}
		if r.Kind == nativedns.KindDoH || r.Kind == nativedns.KindDoT {
			if dev := dnsCheckRouteDev(run, dnsCheckTargetAddress(r.Address)); dev != "" {
				u.LeavesBy, u.ViaTunnel, u.Label = dev, tunnels[dev], labels[dev]
			}
			u.Address = nativedns.RedactAddress(u.Address)
		}
		if seenTunnel && r.Kind == nativedns.KindPlain && r.Iface == "" {
			u.LastResort = true
		}
		seenTunnel = seenTunnel || r.ViaTunnel || u.Kind == nativedns.KindLocal || u.Kind == nativedns.KindDoH || u.Kind == nativedns.KindDoT
		out = append(out, u)
	}
	return out
}

// dnsCheckRouteDev asks the routing table which interface an address leaves by. Only an address: a name
// would need a lookup, which is what is being measured.
func dnsCheckRouteDev(run nativedns.Runner, host string) string {
	if run == nil || net.ParseIP(host) == nil {
		return ""
	}
	out, err := run("ip", "route", "get", host)
	if err != nil {
		return ""
	}
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			return f[i+1]
		}
	}
	return ""
}

func dnsCheckAdviseInput(s *Server, prof *model.Profile, eff nativedns.EffectivePath) dnscheck.AdviseInput {
	interceptOn := eff.Hijack53
	encryptedEscape := !eff.DoTBypassBlocked || !eff.DoHBypassBlocked
	if eff.RulesUnknown {
		interceptOn = true
		encryptedEscape = false
	}
	in := dnscheck.AdviseInput{
		InterceptOn:     interceptOn,
		BypassGaps:      append([]string(nil), eff.Hijack53Gaps...),
		EncryptedEscape: encryptedEscape,
		IPv6Gaps:        append([]string(nil), eff.IPv6Gaps...),
		ProfileServes:   dnsCheckProfileServes(prof),
		ViaByIface:      map[string]string{},
		ChainLocked:     s.dnsPlatform() != "keenetic",
	}
	if prof.DNS != nil && prof.DNS.Enabled {
		for _, server := range prof.DNS.Servers {
			if server.Enabled && (server.Type == "https" || server.Type == "tls" || server.Type == "quic" || server.Type == "h3") {
				in.ProfileEncrypted = true
				break
			}
		}
		if final := prof.DNS.DefaultServer(false); final != nil {
			in.EncryptedDetour = final.Detour
			if in.EncryptedDetour == "" {
				in.EncryptedDetour = "direct"
			}
		}
	}
	in.TunnelVia = s.dnsCheckTunnelOrder(prof)
	for id, iface := range kernelIfaceByEndpoint(prof, s.appliedKernelDevices()) {
		if e := prof.EndpointByID(id); e != nil && e.Enabled {
			in.ViaByIface[iface] = id
		}
	}
	return in
}

// dnsCheckProfileServes says whether the page's encrypted resolvers answer clients at all.
func dnsCheckProfileServes(p *model.Profile) bool {
	return p.DNS != nil && p.DNS.Enabled && p.DNS.ServeClients
}

func (s *Server) dnsCheckTunnelOrder(prof *model.Profile) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if seen[id] {
			return
		}
		e := prof.EndpointByID(id)
		if e == nil || !e.Enabled {
			return
		}
		iface := kernelIfaceByEndpoint(prof, s.appliedKernelDevices())[id]
		if iface == "" || !s.dnsCheckInterfaceExists(iface) {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	primary := primaryDetour(prof)
	if group := prof.GroupByID(primary); group != nil {
		for _, id := range group.Members {
			add(id)
		}
	} else {
		add(primary)
	}
	for i := range prof.Endpoints {
		add(prof.Endpoints[i].ID)
	}
	return out
}

func (s *Server) dnsCheckPaths(prof *model.Profile) []dnscheck.Path {
	var paths []dnscheck.Path
	seen := map[string]bool{}
	if s.dnsCheckWANOf != nil {
		if iface, err := s.dnsCheckWANOf(); err == nil && iface != "" {
			paths = append(paths, dnscheck.Path{Iface: iface, Kind: dnscheck.PathWAN, Label: "provider"})
			seen[iface] = true
		}
	} else if iface, err := probeWANInterface(); err == nil && iface != "" {
		paths = append(paths, dnscheck.Path{Iface: iface, Kind: dnscheck.PathWAN, Label: "provider"})
		seen[iface] = true
	}
	for _, id := range s.dnsCheckTunnelOrder(prof) {
		if len(paths) == 5 {
			break
		}
		e := prof.EndpointByID(id)
		iface := kernelIfaceByEndpoint(prof, s.appliedKernelDevices())[id]
		if e == nil || seen[iface] {
			continue
		}
		label := e.Name
		if label == "" {
			label = id
		}
		paths = append(paths, dnscheck.Path{Iface: iface, Kind: dnscheck.PathTunnel, Label: label})
		seen[iface] = true
	}
	return paths
}

func (s *Server) dnsCheckInterfaceExists(iface string) bool {
	if s.dnsCheckIfaceExistsOf != nil {
		return s.dnsCheckIfaceExistsOf(iface)
	}
	if !validWANInterfaceName(iface) {
		return false
	}
	_, err := os.Stat("/sys/class/net/" + iface)
	return err == nil
}

func dnsCheckTargetAddress(address string) string {
	address = strings.TrimSpace(address)
	if strings.Contains(address, "://") {
		if u, err := url.Parse(address); err == nil {
			return u.Hostname()
		}
	}
	if host, _, err := net.SplitHostPort(address); err == nil {
		return host
	}
	if i := strings.IndexByte(address, '#'); i >= 0 {
		address = address[:i]
	}
	return strings.Trim(address, "[]")
}

func dnsCheckTargets(nd nativedns.NativeDNS, paths []dnscheck.Path, listener string) []dnscheck.Target {
	seen := map[string]bool{}
	var out []dnscheck.Target
	add := func(address string, path dnscheck.Path) {
		address = dnsCheckTargetAddress(address)
		if address == "" {
			return
		}
		if ip := net.ParseIP(address); ip != nil {
			address = ip.String()
		}
		key := strings.ToLower(address) + "\x00" + string(path.Kind) + "\x00" + path.Iface
		if !seen[key] {
			seen[key] = true
			out = append(out, dnscheck.Target{Address: address, Path: path})
		}
	}
	pathByIface := map[string]dnscheck.Path{}
	var wan dnscheck.Path
	for _, path := range paths {
		pathByIface[path.Iface] = path
		if path.Kind == dnscheck.PathWAN {
			wan = path
		}
	}
	for _, r := range nd.Resolvers {
		if r.Port != 0 && r.Port != 53 {
			continue
		}
		address := dnsCheckTargetAddress(r.Address)
		if ip := net.ParseIP(address); ip != nil && ip.IsLoopback() {
			continue
		}
		path := wan
		if r.Iface != "" {
			var ok bool
			path, ok = pathByIface[r.Iface]
			if !ok {
				continue
			}
		}
		if path.Kind != "" {
			add(address, path)
		}
	}
	for _, path := range paths {
		for _, address := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"} {
			add(address, path)
		}
	}
	if host, _, err := net.SplitHostPort(listener); err == nil {
		add(host, dnscheck.Path{Kind: dnscheck.PathRouter, Label: "router"})
	}
	return out
}

func (s *Server) dnsCheckNet() dnscheck.Net {
	if s.dnsCheckNetOf != nil {
		return s.dnsCheckNetOf()
	}
	return newDNSCheckNet()
}

func (s *Server) dnsCheckRandom() string {
	if s.dnsCheckRandomOf != nil {
		return s.dnsCheckRandomOf()
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("%016x", time.Now().UnixNano())
}

func (s *Server) dnsCheckProbe(ctx context.Context, addr string, query []byte) error {
	if s.dnsCheckProbeOf != nil {
		return s.dnsCheckProbeOf(ctx, addr, query)
	}
	probeCtx, cancel := context.WithTimeout(ctx, dnsCheckCanaryWait)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(probeCtx, "udp", addr)
	if err != nil {
		return fmt.Errorf("ask router DNS listener: %w", err)
	}
	defer conn.Close()
	if deadline, ok := probeCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(query); err != nil {
		return fmt.Errorf("send router DNS canary: %w", err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read router DNS canary: %w", err)
	}
	if n < 4 || buf[0] != query[0] || buf[1] != query[1] {
		return errors.New("router DNS canary answer has the wrong id")
	}
	// SERVFAIL means nothing behind this listener answered, and dnsmasq would move on to the next row.
	if rcode := buf[3] & 0x0f; rcode != 0 && rcode != 3 {
		return fmt.Errorf("router DNS canary answered with code %d", rcode)
	}
	return nil
}

func (s *Server) dnsCheckWait(ctx context.Context, duration time.Duration) error {
	if s.dnsCheckWaitOf != nil {
		return s.dnsCheckWaitOf(ctx, duration)
	}
	t := time.NewTimer(duration)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
