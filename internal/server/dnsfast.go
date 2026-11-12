package server

import (
	"context"
	"net/http"
	"time"

	"wayhop/internal/dnscheck"
	"wayhop/internal/model"
)

const (
	dnsFastJobTimeout = 60 * time.Second
	dnsFastMaxVias    = 8
)

type dnsFastMeasureFunc func(context.Context, dnscheck.FastNet, dnscheck.Path, []dnscheck.FastEntry, dnscheck.FastOptions) []dnscheck.FastResult

// handleDNSFastState (GET /api/dns/fast?via=) answers the quick list, the ways out it can be measured
// through, and the measurement for that way out, if there is one. The demo serves canned numbers.
func (s *Server) handleDNSFastState(w http.ResponseWriter, r *http.Request) {
	if s.config().Demo {
		writeJSON(w, http.StatusOK, dnscheck.DemoFastState(r.URL.Query().Get("via")))
		return
	}
	writeJSON(w, http.StatusOK, s.dnsFastState(r.URL.Query().Get("via")))
}

// handleDNSFastStart (POST /api/dns/fast) measures the list through one way out. One runs at a time.
func (s *Server) handleDNSFastStart(w http.ResponseWriter, r *http.Request) {
	if s.config().Demo {
		writeJSON(w, http.StatusAccepted, dnscheck.FastState{})
		return
	}
	if s.dnsPlatform() == "" {
		writeErr(w, http.StatusConflict, "this host cannot measure encrypted resolvers; run WayHop on a router")
		return
	}
	var req dnscheck.FastRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid encrypted-resolver measurement JSON")
		return
	}
	prof := s.store.Profile()
	vias := s.dnsFastVias(&prof)
	defaultVia := dnsFastDefault(&prof, vias)
	via := req.Via
	if via == "" {
		via = defaultVia
	}
	chosen, ok := dnsFastVia(vias, via)
	if !ok {
		writeErr(w, http.StatusBadRequest, "unknown DNS measurement via "+via)
		return
	}

	s.dnsFastMu.Lock()
	if s.dnsFastRunning {
		s.dnsFastMu.Unlock()
		writeErr(w, http.StatusConflict, "an encrypted-resolver measurement is already running")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsFastJobTimeout)
	started := time.Now().UTC()
	s.dnsFastRunning = true
	s.dnsFastCancel = cancel
	s.dnsFastProgress = dnscheck.Progress{Stage: "encrypted", Total: dnscheck.FastTransportCount(dnscheck.FastCatalog)}
	s.dnsFastMu.Unlock()

	path := dnscheck.Path{Iface: chosen.Iface, Kind: chosen.Kind, Label: chosen.Label}
	go s.runDNSFast(ctx, via, path, started)
	writeJSON(w, http.StatusAccepted, s.dnsFastState(via))
}

func (s *Server) dnsFastState(via string) dnscheck.FastState {
	prof := s.store.Profile()
	vias := s.dnsFastVias(&prof)
	defaultVia := dnsFastDefault(&prof, vias)
	if via == "" {
		via = defaultVia
	}
	s.dnsFastMu.Lock()
	defer s.dnsFastMu.Unlock()
	return dnscheck.FastState{
		Catalog:  dnscheck.FastCatalog,
		Vias:     vias,
		Default:  defaultVia,
		Running:  s.dnsFastRunning,
		Progress: s.dnsFastProgress,
		Report:   s.dnsFastReports[via],
	}
}

func (s *Server) runDNSFast(ctx context.Context, via string, path dnscheck.Path, started time.Time) {
	report := dnscheck.FastReport{Via: via, Path: path, StartedAt: started}
	total := dnscheck.FastTransportCount(dnscheck.FastCatalog)
	defer func() {
		report.FinishedAt = time.Now().UTC()
		report.CertsUnreliable = dnscheck.FastCertsUnreliable(report.Results)
		s.dnsFastMu.Lock()
		if s.dnsFastReports == nil {
			s.dnsFastReports = map[string]*dnscheck.FastReport{}
		}
		s.dnsFastReports[via] = &report
		s.dnsFastRunning = false
		s.dnsFastProgress.Done = total
		if s.dnsFastCancel != nil {
			s.dnsFastCancel()
		}
		s.dnsFastCancel = nil
		s.dnsFastMu.Unlock()
	}()

	n := s.dnsFastNet()
	if n == nil && s.dnsFastMeasureOf == nil {
		report.Results = dnsFastUnavailableResults(dnscheck.FastCatalog)
		return
	}
	opts := dnscheck.FastOptions{OnProgress: func(done, count int) {
		s.dnsFastMu.Lock()
		s.dnsFastProgress = dnscheck.Progress{Stage: "encrypted", Done: done, Total: count}
		s.dnsFastMu.Unlock()
	}}
	measure := s.dnsFastMeasureOf
	if measure == nil {
		measure = dnscheck.MeasureFast
	}
	report.Results = measure(ctx, n, path, dnscheck.FastCatalog, opts)
}

func (s *Server) dnsFastNet() dnscheck.FastNet {
	if s.dnsFastNetOf != nil {
		return s.dnsFastNetOf()
	}
	return newDNSFastNet()
}

func dnsFastUnavailableResults(entries []dnscheck.FastEntry) []dnscheck.FastResult {
	results := make([]dnscheck.FastResult, 0, len(entries))
	for _, entry := range entries {
		result := dnscheck.FastResult{ID: entry.ID}
		if entry.DoHPath != "" {
			result.Transports = append(result.Transports, dnscheck.FastTransport{Proto: "doh", Status: dnscheck.FastOther})
		}
		if entry.DoT {
			result.Transports = append(result.Transports, dnscheck.FastTransport{Proto: "dot", Status: dnscheck.FastOther})
		}
		results = append(results, result)
	}
	return results
}

// dnsFastVias takes a fresh view because a group's elected member and the router's interfaces can both
// change while the page is open. Only kernel links can bind a measurement socket; proxy outbounds cannot.
func (s *Server) dnsFastVias(prof *model.Profile) []dnscheck.FastVia {
	if s.dnsPlatform() == "" {
		return nil
	}
	vias := make([]dnscheck.FastVia, 0, dnsFastMaxVias)
	iface := ""
	if s.dnsCheckWANOf != nil {
		iface, _ = s.dnsCheckWANOf()
	} else {
		iface, _ = probeWANInterface()
	}
	if iface != "" {
		vias = append(vias, dnscheck.FastVia{ID: model.OutboundDirect, Label: "Provider", Kind: dnscheck.PathWAN, Iface: iface})
	}

	for i := range prof.Groups {
		if len(vias) == dnsFastMaxVias {
			return vias
		}
		group := &prof.Groups[i]
		memberIface, err := s.dnsFastGroupIface(prof, group)
		if err != nil || memberIface == "" || !s.dnsCheckInterfaceExists(memberIface) {
			continue
		}
		label := group.Name
		if label == "" {
			label = group.ID
		}
		vias = append(vias, dnscheck.FastVia{ID: group.ID, Label: label, Kind: dnscheck.PathTunnel, Iface: memberIface})
	}

	interfaces := kernelIfaceByEndpoint(prof, s.appliedKernelDevices())
	for i := range prof.Endpoints {
		if len(vias) == dnsFastMaxVias {
			break
		}
		endpoint := &prof.Endpoints[i]
		memberIface := interfaces[endpoint.ID]
		if !endpoint.Enabled || memberIface == "" || !s.dnsCheckInterfaceExists(memberIface) {
			continue
		}
		label := endpoint.Name
		if label == "" {
			label = endpoint.ID
		}
		vias = append(vias, dnscheck.FastVia{ID: endpoint.ID, Label: label, Kind: dnscheck.PathTunnel, Iface: memberIface})
	}
	return vias
}

func (s *Server) dnsFastGroupIface(prof *model.Profile, group *model.Group) (string, error) {
	if s.dnsFastGroupIfaceOf != nil {
		return s.dnsFastGroupIfaceOf(prof, group)
	}
	return s.groupFeedIface(prof, group)
}

func dnsFastDefault(prof *model.Profile, vias []dnscheck.FastVia) string {
	detour := dnsDetour(prof)
	if detour != "" && detour != model.OutboundDirect {
		if via, ok := dnsFastVia(vias, detour); ok {
			return via.ID
		}
	}
	for _, via := range vias {
		if via.Kind == dnscheck.PathTunnel {
			return via.ID
		}
	}
	for _, via := range vias {
		if via.ID == model.OutboundDirect {
			return via.ID
		}
	}
	return ""
}

func dnsFastVia(vias []dnscheck.FastVia, id string) (dnscheck.FastVia, bool) {
	for _, via := range vias {
		if via.ID == id {
			return via, true
		}
	}
	return dnscheck.FastVia{}, false
}
