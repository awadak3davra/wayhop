package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// exitGeo is the geolocation of an exit IP: country (ISO-2 + name), the ISP/org,
// the AS number+name, and whether the address belongs to a hosting/datacenter
// range (expected for a VPS exit, NOT a warning). All fields are best-effort and
// omitted when no provider answered — geo never gates the exit check.
type exitGeo struct {
	CC      string `json:"cc,omitempty"`
	Country string `json:"country,omitempty"`
	ISP     string `json:"isp,omitempty"`
	ASN     string `json:"asn,omitempty"`
	Hosting bool   `json:"hosting,omitempty"`
}

func (g exitGeo) empty() bool { return g.CC == "" && g.Country == "" && g.ISP == "" && g.ASN == "" }

// exitIPState caches the public exit IP (the address the active proxy presents
// upstream) plus its geolocation so the Dashboard hero + Diagnostics battery can
// show them without an outbound call on every poll. Refreshed at most once per
// exitIPTTL (geo is cached alongside the IP, under the same TTL, to respect the
// free geo providers' rate limits across battery + per-row re-runs).
type exitIPState struct {
	mu  sync.Mutex
	ip  string
	geo exitGeo
	at  time.Time
}

const exitIPTTL = 60 * time.Second

// exitIPEchos are plain-text IP responders, tried in order through the active
// proxy until one returns a valid IP. (Not RU-blocked; reachable via the exits.)
var exitIPEchos = []string{
	"https://api.ipify.org",
	"https://ifconfig.co/ip",
	"https://icanhazip.com",
}

// handleExitIP returns the public IP the active proxy egresses from. It works
// both when WayHop MANAGES sing-box (probe through the local mixed proxy) and
// in MONITOR mode over an EXTERNALLY-managed core (Keenetic: the daemon's own
// sing-box isn't running, but a live core answers the Clash API and the device's
// default route IS the exit — so a DIRECT probe yields the real exit IP). Degrades
// to {available:false} in demo or when no core is up.
func (s *Server) handleExitIP(w http.ResponseWriter, r *http.Request) {
	if s.config().Demo {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	// Serve a fresh cached IP without any outbound call (and without the coreUp probe).
	s.exitIP.mu.Lock()
	if s.exitIP.ip != "" && time.Since(s.exitIP.at) < exitIPTTL {
		ip, geo := s.exitIP.ip, s.exitIP.geo
		s.exitIP.mu.Unlock()
		writeJSON(w, http.StatusOK, exitIPResponse(ip, geo, true))
		return
	}
	s.exitIP.mu.Unlock()

	// Refresh requires a live proxy core: the daemon's own sing-box OR an external one.
	if !s.coreUp() {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	mixed := s.config().Ports.Mixed
	ip := lookupExitIP(ctx, mixed)
	if ip == "" {
		// Monitor mode (no local mixed proxy): probe DIRECTLY — the daemon's request
		// follows the device's default route, which is the active exit tunnel.
		ip = lookupExitIP(ctx, 0)
	}
	if ip == "" {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	// Geo is a best-effort enrichment: a failed lookup leaves geo empty but the IP
	// (and available:true) still stand — never let geo turn a working exit "down".
	geo := lookupExitGeo(ctx, mixed, ip)
	s.exitIP.mu.Lock()
	s.exitIP.ip, s.exitIP.geo, s.exitIP.at = ip, geo, time.Now()
	s.exitIP.mu.Unlock()
	writeJSON(w, http.StatusOK, exitIPResponse(ip, geo, false))
}

// coreUp reports whether a proxy core is live: the daemon's OWN sing-box, or an
// EXTERNALLY-managed one answering the Clash API (monitor mode, e.g. on Keenetic
// where sing-box is run by the OS init, not WayHop). A 2s probe of the Clash
// controller's /version is the cheapest liveness signal that an external core is up.
func (s *Server) coreUp() bool {
	if s.singbox != nil && s.singbox.Running() {
		return true
	}
	ctrl := s.config().Clash.Controller
	if ctrl == "" {
		return false
	}
	cl := &http.Client{Timeout: 2 * time.Second}
	defer cl.CloseIdleConnections()
	resp, err := cl.Get("http://" + ctrl + "/version")
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// exitIPResponse merges the cached IP + geo into the wire shape. The base fields
// (available/ip/cached) are unchanged from before geo existed; geo fields are
// additive + omitempty, so older UI builds keep working.
func exitIPResponse(ip string, geo exitGeo, cached bool) map[string]any {
	m := map[string]any{"available": true, "ip": ip}
	if cached {
		m["cached"] = true
	}
	if geo.CC != "" {
		m["cc"] = geo.CC
	}
	if geo.Country != "" {
		m["country"] = geo.Country
	}
	if geo.ISP != "" {
		m["isp"] = geo.ISP
	}
	if geo.ASN != "" {
		m["asn"] = geo.ASN
	}
	if geo.Hosting {
		m["hosting"] = true
	}
	return m
}

// lookupExitIP GETs an IP echo and returns the first valid IP. With mixedPort>0 it
// routes through the local mixed (HTTP) proxy; with mixedPort<=0 it goes DIRECT (the
// daemon's request follows the device's default route — used in monitor mode where
// the active core is external and there is no local mixed proxy). Empty on failure.
func lookupExitIP(ctx context.Context, mixedPort int) string {
	transport := &http.Transport{}
	if mixedPort > 0 {
		pu, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
		if err != nil {
			return ""
		}
		transport.Proxy = http.ProxyURL(pu)
	}
	cl := &http.Client{Transport: transport, Timeout: 6 * time.Second}
	defer cl.CloseIdleConnections()
	for _, echo := range exitIPEchos {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, echo, nil)
		if err != nil {
			continue
		}
		resp, err := cl.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		_ = resp.Body.Close()
		if ip := parseExitIP(string(body)); ip != "" {
			return ip
		}
	}
	return ""
}

// parseExitIP trims + validates an echo response into an IP (or "").
func parseExitIP(body string) string {
	s := strings.TrimSpace(body)
	if net.ParseIP(s) != nil {
		return s
	}
	return ""
}

// lookupExitGeo resolves the country/ISP/AS of a known exit IP. The primary
// provider (ip-api.com) takes the IP explicitly, so it is route-independent and
// can use the daemon's default route. The fallback (ifconfig.co/json) reports the
// REQUESTER's geo, so it must egress through the proxy to describe the exit, not
// the router's WAN. Returns an empty exitGeo (never an error) on total failure —
// the caller treats missing geo as "unknown", not a fault.
func lookupExitGeo(ctx context.Context, mixedPort int, ip string) exitGeo {
	tls := &http.Client{Timeout: 5 * time.Second}
	defer tls.CloseIdleConnections()
	// Primary: explicit-IP lookup over HTTPS (ipwho.is is free, keyless, and route-independent).
	// This keeps the exit IP OFF the cleartext wire — the earlier ip-api.com primary was the one
	// non-localhost plaintext outbound in the daemon, sending the exit IP over the real WAN.
	whoURL := "https://ipwho.is/" + url.PathEscape(ip) + "?fields=success,country_code,country,connection"
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, whoURL, nil); err == nil {
		if resp, err := tls.Do(req); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			if g, ok := parseIPWho(body); ok {
				return g
			}
		}
	}
	// Fallback: requester-geo provider, through the proxy so it sees the exit.
	if mixedPort > 0 {
		if pu, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort)); err == nil {
			pcl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 6 * time.Second}
			defer pcl.CloseIdleConnections()
			if req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ifconfig.co/json", nil); err == nil {
				if resp, err := pcl.Do(req); err == nil {
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
					_ = resp.Body.Close()
					if g, ok := parseIfconfigGeo(body); ok {
						return g
					}
				}
			}
		}
	}
	// Last resort: ip-api.com over HTTP (its free tier is http-only). Only reached when both HTTPS
	// providers failed; the exit IP is a VPN's public egress, so this residual best-effort cleartext
	// lookup is acceptable as a fallback rather than the default path.
	uPlain := "http://ip-api.com/json/" + url.PathEscape(ip) + "?fields=status,countryCode,country,isp,as,hosting"
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, uPlain, nil); err == nil {
		if resp, err := tls.Do(req); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			if g, ok := parseIPAPI(body); ok {
				return g
			}
		}
	}
	return exitGeo{}
}

// parseIPWho maps an ipwho.is response into exitGeo. ok=false when the provider signalled failure
// (success:false) or the body was unparseable.
func parseIPWho(body []byte) (exitGeo, bool) {
	var v struct {
		Success     bool   `json:"success"`
		CountryCode string `json:"country_code"`
		Country     string `json:"country"`
		Connection  struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if err := json.Unmarshal(body, &v); err != nil || !v.Success {
		return exitGeo{}, false
	}
	as := ""
	if v.Connection.ASN > 0 {
		as = fmt.Sprintf("AS%d %s", v.Connection.ASN, v.Connection.Org)
	}
	isp := v.Connection.ISP
	if isp == "" {
		isp = v.Connection.Org
	}
	g := exitGeo{CC: strings.ToUpper(v.CountryCode), Country: v.Country, ISP: strings.TrimSpace(isp), ASN: strings.TrimSpace(as)}
	if g.empty() {
		return exitGeo{}, false
	}
	return g, true
}

// parseIPAPI maps an ip-api.com/json response into exitGeo. ok=false when the
// provider signalled failure or the body was unparseable.
func parseIPAPI(body []byte) (exitGeo, bool) {
	var v struct {
		Status      string `json:"status"`
		CountryCode string `json:"countryCode"`
		Country     string `json:"country"`
		ISP         string `json:"isp"`
		AS          string `json:"as"`
		Hosting     bool   `json:"hosting"`
	}
	if err := json.Unmarshal(body, &v); err != nil || v.Status != "success" {
		return exitGeo{}, false
	}
	g := exitGeo{CC: strings.ToUpper(v.CountryCode), Country: v.Country, ISP: v.ISP, ASN: v.AS, Hosting: v.Hosting}
	if g.empty() {
		return exitGeo{}, false
	}
	return g, true
}

// parseIfconfigGeo maps an ifconfig.co/json response into exitGeo (no hosting flag).
func parseIfconfigGeo(body []byte) (exitGeo, bool) {
	var v struct {
		Country    string `json:"country"`
		CountryISO string `json:"country_iso"`
		ASN        string `json:"asn"`
		ASNOrg     string `json:"asn_org"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return exitGeo{}, false
	}
	asn := strings.TrimSpace(v.ASN)
	if v.ASNOrg != "" {
		if asn != "" {
			asn += " "
		}
		asn += v.ASNOrg
	}
	g := exitGeo{CC: strings.ToUpper(v.CountryISO), Country: v.Country, ISP: v.ASNOrg, ASN: asn}
	if g.empty() {
		return exitGeo{}, false
	}
	return g, true
}
