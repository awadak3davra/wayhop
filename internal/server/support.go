package server

import (
	"encoding/json"
	"net/http"
	"runtime"

	"wayhop/internal/health"
	"wayhop/internal/version"
	"wayhop/internal/watchdog"
)

// supportBundleSchema is the schema marker of a diagnostics bundle.
const supportBundleSchema = 1

// supportEndpoint is a REDACTED endpoint summary — enough to diagnose a setup (which
// protocols/engines exist, on what port, enabled or not) WITHOUT any secret: no Params
// (private keys / passwords / PSKs) and no server address.
type supportEndpoint struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Engine    string `json:"engine,omitempty"`
	Port      int    `json:"port,omitempty"`
	Enabled   bool   `json:"enabled"`
	HasServer bool   `json:"has_server"`
}

// supportBundle is a SHAREABLE diagnostics snapshot: build info, non-secret config knobs, a
// redacted routing summary, kernel-PBR state, sing-box supervision, and per-endpoint health.
// Unlike /api/backup it carries NO secrets — no connection keys/passwords, no server addresses,
// no subscription token, no clash secret — so a user can attach it to a bug report safely.
type supportBundle struct {
	WayHopSupport int    `json:"wayhop_support"` // schema marker
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	Date          string `json:"date"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`

	Config struct {
		RoutingMode string `json:"routing_mode,omitempty"`
		Gateway     bool   `json:"gateway"`
		Offload     string `json:"offload,omitempty"`
		Demo        bool   `json:"demo"`
	} `json:"config"`

	Profile struct {
		Endpoints    []supportEndpoint `json:"endpoints"`
		Groups       int               `json:"groups"`
		Rules        int               `json:"rules"`
		RoutingLists int               `json:"routing_lists"`
		DeviceGroups int               `json:"device_groups"`
	} `json:"profile"`

	PBR struct {
		Installed  bool     `json:"installed"`
		Zones      int      `json:"zones"`
		Mode       string   `json:"mode"`
		MasqIfaces []string `json:"masq_ifaces,omitempty"`
	} `json:"pbr"`

	Watchdog watchdog.Stats `json:"watchdog"`
	Health   []health.View  `json:"health,omitempty"`
}

// buildSupportBundle gathers the redacted diagnostics snapshot.
func (s *Server) buildSupportBundle() supportBundle {
	c := s.config()
	p := s.store.Profile()

	b := supportBundle{
		WayHopSupport: supportBundleSchema,
		Version:       version.Version,
		Commit:        version.Commit,
		Date:          version.Date,
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
	}
	b.Config.RoutingMode = c.RoutingMode
	b.Config.Gateway = c.Gateway
	b.Config.Offload = c.Offload
	b.Config.Demo = c.Demo

	for i := range p.Endpoints {
		e := &p.Endpoints[i]
		b.Profile.Endpoints = append(b.Profile.Endpoints, supportEndpoint{
			ID: e.ID, Name: e.Name, Protocol: string(e.Protocol), Engine: string(e.Engine),
			Port: e.Port, Enabled: e.Enabled, HasServer: e.Server != "",
		})
	}
	b.Profile.Groups = len(p.Groups)
	b.Profile.Rules = len(p.Rules)
	b.Profile.RoutingLists = len(p.RoutingLists)
	b.Profile.DeviceGroups = len(p.DeviceGroups)

	s.pbrMu.Lock()
	b.PBR.Installed = s.pbrPlan != nil
	if s.pbrPlan != nil {
		b.PBR.Zones = len(s.pbrPlan.Zones)
		b.PBR.MasqIfaces = s.pbrPlan.MasqIfaces
	}
	s.pbrMu.Unlock()
	b.PBR.Mode = s.routingMode(c)

	if s.watchdog != nil {
		b.Watchdog = s.watchdog.Stats()
	}
	if s.monitor != nil {
		b.Health = s.monitor.Snapshot()
	}
	return b
}

// handleSupportBundle (GET /api/support-bundle) streams the redacted diagnostics bundle as a
// downloadable attachment, behind the same access gate as the rest of /api. Carries NO secrets,
// so it is safe to attach to a bug report (contrast /api/backup, which is a personal secret-bearing
// backup).
func (s *Server) handleSupportBundle(w http.ResponseWriter, r *http.Request) {
	data, err := json.MarshalIndent(s.buildSupportBundle(), "", "  ")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "marshal failed: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="wayhop-support.json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
