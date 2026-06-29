package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"time"

	"wakeroute/internal/atomicfile"
	"wakeroute/internal/config"
	"wakeroute/internal/generator"
	"wakeroute/internal/importer"
	"wakeroute/internal/model"
	"wakeroute/internal/pbr"
	"wakeroute/internal/plugin"
)

// handleImport parses a share link / conf into an endpoint WITHOUT saving it
// (preview before the user confirms).
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	e, err := importer.Parse(body.Link)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.Profile())
}

// handleRestoreProfile replaces the ENTIRE routing profile (endpoints/groups/rules/lists) from an
// uploaded backup — the JSON that GET /api/profile returns. store.Replace validates it before it
// lands (a bad backup is rejected, the current profile untouched), and persists atomically; the
// change goes live on the next Apply (with the fail-safe net). The companion to handleConfigExport
// for the daemon config — together they let a user back up + restore or migrate a full WakeRoute
// setup. POST /api/profile.
func (s *Server) handleRestoreProfile(w http.ResponseWriter, r *http.Request) {
	var p model.Profile
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid profile JSON")
		return
	}
	if err := s.store.Replace(p); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid profile: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"restored": true, "endpoints": len(p.Endpoints), "groups": len(p.Groups),
		"rules": len(p.Rules), "lists": len(p.RoutingLists),
	})
}

func (s *Server) handleUpsertEndpoint(w http.ResponseWriter, r *http.Request) {
	var e model.Endpoint
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid endpoint JSON")
		return
	}
	if err := s.store.UpsertEndpoint(e); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) handleDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteEndpoint(id); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) handleUpsertGroup(w http.ResponseWriter, r *http.Request) {
	var g model.Group
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid group JSON")
		return
	}
	if err := s.store.UpsertGroup(g); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteGroup(id); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) handleUpsertRule(w http.ResponseWriter, r *http.Request) {
	var ru model.Rule
	if err := json.NewDecoder(r.Body).Decode(&ru); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid rule JSON")
		return
	}
	if err := s.store.UpsertRule(ru); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ru)
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteRule(id); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// --- Routing lists (the "Routing" page) ---

func (s *Server) handleUpsertRoutingList(w http.ResponseWriter, r *http.Request) {
	var rl model.RoutingList
	if err := json.NewDecoder(r.Body).Decode(&rl); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid routing list JSON")
		return
	}
	if err := s.store.UpsertRoutingList(rl); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rl)
}

func (s *Server) handleDeleteRoutingList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteRoutingList(id); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// handleRoutingCatalog returns the curated pre-defined rule-set presets.
func (s *Server) handleRoutingCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, model.RoutingPresets())
}

// handleRoutingStatus reports, per routing list, whether its remote rule-set source
// is reachable/downloadable — the signal the Routing UI shows as a green/red dot +
// error code under each list. Manual (no-source) lists are always ok. Probes run
// concurrently and reuse the SSRF-guarded fetch client.
func (s *Server) handleRoutingStatus(w http.ResponseWriter, r *http.Request) {
	prof := s.store.Profile()
	type st struct {
		ID     string `json:"id"`
		OK     bool   `json:"ok"`
		Status int    `json:"status,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	res := make([]st, len(prof.RoutingLists))
	client := s.subscriptionFetchClient()
	// Bound concurrent source fetches: a profile with many auto-refresh lists would
	// otherwise open one HTTP connection per list at once (each a 12s download),
	// spiking connections/FDs on a low-memory router. Slightly tighter than the exit
	// probe cap since each fetch holds a connection for longer.
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, rl := range prof.RoutingLists {
		if rl.Source == "" {
			res[i] = st{ID: rl.ID, OK: true} // manual list — nothing to download
			continue
		}
		wg.Add(1)
		go func(i int, id, src string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cur := st{ID: id}
			ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
			if err != nil {
				cur.Error = "bad url: " + err.Error()
				res[i] = cur
				return
			}
			req.Header.Set("User-Agent", "wakeroute")
			resp, err := client.Do(req)
			if err != nil {
				cur.Error = err.Error()
				res[i] = cur
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			cur.Status = resp.StatusCode
			cur.OK = resp.StatusCode >= 200 && resp.StatusCode < 400
			if !cur.OK {
				cur.Error = "HTTP " + resp.Status
			}
			res[i] = cur
		}(i, rl.ID, rl.Source)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, res)
}

// handleGenerate returns the sing-box config for the current profile (preview).
func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	p := s.store.Profile()
	res, err := generator.Generate(&p, s.genOptions(&p))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":  res.Config,
		"plugins": pluginSummary(res.Plugins),
	})
}

// syncPluginsFor (re)starts the engine plugins (AmneziaWG interfaces, olcRTC
// procs) required by a generated config. Idempotent; safe to call repeatedly.
func (s *Server) syncPluginsFor(res *generator.Result) {
	specs := make([]plugin.Spec, 0, len(res.Plugins))
	for _, pl := range res.Plugins {
		specs = append(specs, plugin.Spec{ID: pl.Endpoint.ID, Endpoint: pl.Endpoint, SOCKSPort: pl.SOCKSPort})
	}
	s.plugins.Sync(specs)
}

// SyncPlugins brings up the engine plugins the current profile needs AND, in hybrid
// mode, installs the kernel PBR plane. The daemon calls this on start so AmneziaWG/olcRTC
// tunnels + the kernel routes come up from boot — the watchdog only crash-restarts
// already-running plugins, and an Apply is otherwise required. The PBR install is FOLDED
// here (not a separate goroutine) so it runs AFTER the kernel interfaces are up in the
// same goroutine — `ip route ... dev awgX` fails if the device doesn't exist yet, and two
// bare `go` calls have no ordering. No-op in demo mode (must not touch host interfaces/nft).
func (s *Server) SyncPlugins() {
	c := s.config()
	if c.Demo {
		return
	}
	p := s.store.Profile()
	opts, newPlan := s.genOptionsWithPlan(&p, c)
	res, err := generator.Generate(&p, opts)
	if err != nil {
		// Boot path: a swallowed generate error here means the engine plugins + kernel PBR
		// plane never come up after a reboot, with no trace of why. Log it (the watchdog /
		// next Apply will retry); don't change the fail-soft behavior otherwise.
		log.Printf("wakeroute: boot SyncPlugins skipped — config generation failed (tunnels/PBR not brought up): %v", err)
		return
	}
	s.syncPluginsFor(res) // brings AmneziaWG/olcRTC interfaces UP first
	if newPlan != nil {
		// Hybrid OR fast/native-only: install the kernel plane now that the interfaces exist
		// (best-effort — a later Apply re-establishes; applyPBR records pbrPlan=nil on failure).
		pbrErr := s.applyPBR(newPlan)
		if pbrErr != nil {
			log.Printf("SyncPlugins: boot PBR apply failed: %v", pbrErr)
		}
		// Native-only boot arm: once the kernel plane is up, STOP the core so a stale
		// singbox.json the boot autostart (main.go) may have launched does not run a
		// redundant/black-holing TUN over the native datapath. Gated on a successful kernel
		// plane (pbrErr == nil) so we never drop the core onto a failed install; Stop() is a
		// no-op when the core isn't running and clears Desired() so the watchdog leaves it
		// down (§d). Recomputed here from the SAME (config, profile) that produced newPlan.
		if pbrErr == nil && s.datapathNativeOnly(c, &p) {
			if err := s.singbox.Stop(); err != nil {
				log.Printf("SyncPlugins: native-only sing-box stop failed: %v", err)
			}
		}
	} else if s.pbrRunner != nil {
		// Not hybrid/fast: clear any stale "wakeroute_pbr" table left by a prior hybrid era
		// (e.g. the user switched to tun via Settings and never Applied, then rebooted —
		// the in-memory pbrPlan is nil so there's nothing else to tear down). Idempotent.
		_ = (&pbr.Plan{Table: "wakeroute_pbr"}).Teardown(s.pbrRunner, pbr.Options{})
	}
}

// handleApply generates the config, validates it with sing-box (if available),
// atomically swaps it in, and reloads a running sing-box. Body {save:bool}:
// false (Apply) arms the fail-safe rollback window; true (Apply & Save) commits.
func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Save bool `json:"save"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	// Serialize applies: two concurrent applies would race on the shared
	// singbox.json.tmp path and on Backup()/Restore(), and could interleave the
	// fail-safe window.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	c := s.config() // one consistent snapshot of Demo/RoutingMode/SingBox.Config for this apply
	p := s.store.Profile()
	// genOptionsWithPlan compiles the hybrid Plan ONCE and returns it, so the kernel plane
	// (applyPBR below) and the TUN route_exclude in opts are the same compile — never desync.
	opts, newPlan := s.genOptionsWithPlan(&p, c)
	// Native-only verdict from the SAME (config, profile) the kernel plane is built from
	// (single source of truth, docs/NATIVE_P4_DESIGN.md §b). When true the kernel plane
	// (newPlan) provably carries everything and sing-box is droppable: we skip the
	// singbox.json write/check/rename + reload/start block entirely and STOP the core after
	// the kernel plane is up (§c, §g). Conservative: it is true only in fast mode with every
	// endpoint kernel-native and nothing surviving into sing-box — on any doubt it is false
	// and the path below is byte-identical to today (KEEP sing-box).
	nativeOnly := s.datapathNativeOnly(c, &p)

	res, err := generator.Generate(&p, opts)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	var backupErr, reloadErr, commitErr string
	checked := false
	reloaded := false
	path := c.SingBox.Config

	if !nativeOnly {
		data, err := json.MarshalIndent(res.Config, "", "  ")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		tmp := path + ".tmp"
		if err := atomicfile.WriteSynced(tmp, data, 0o600); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		if s.singbox.Available() {
			ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			defer cancel()
			if err := s.singbox.CheckConfig(ctx, tmp); err != nil {
				_ = os.Remove(tmp)
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
			checked = true
		}

		// Snapshot the pre-window config as the rollback baseline — but only at the
		// FIRST apply of a fail-safe window. A second apply while a window is still
		// open must NOT overwrite the baseline with the interim (unconfirmed, maybe
		// broken) config, or a later rollback would restore that instead of the last
		// known-good config.
		if !s.failsafe.Status().Pending {
			// A failed Backup means the fail-safe has no rollback target — surface + log it
			// (don't abort: the PBR-fail and connectivity paths below already degrade safely
			// when there's no .bak, and the user may still want to apply).
			if err := s.singbox.Backup(); err != nil {
				backupErr = err.Error()
				log.Printf("handleApply: backup (rollback snapshot) failed: %v — fail-safe may be unable to restore", err)
			}
			s.snapshotPBRBaseline()    // capture the pre-window kernel plan as the rollback target
			s.snapshotPluginBaseline() // capture the pre-window engine-plugin specs too
		}
		if err := os.Rename(tmp, path); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		atomicfile.SyncDir(filepath.Dir(path)) // make the rename durable across power loss

		if s.singbox.Running() {
			if err := s.singbox.Reload(); err != nil {
				reloadErr = err.Error()
				log.Printf("handleApply: sing-box reload failed: %v", err)
			} else {
				reloaded = true
			}
		} else if s.singbox.Available() {
			// Not running yet — bring it up so the new config takes effect (and the
			// watchdog starts supervising it).
			if err := s.singbox.Start(); err != nil {
				reloadErr = err.Error()
				log.Printf("handleApply: sing-box start failed: %v", err)
			} else {
				reloaded = true
			}
		}
	} else if !s.failsafe.Status().Pending {
		// Native-only: do NOT write/check/rename singbox.json or reload the core (the kernel
		// plane carries everything). The previous singbox.json is left untouched on disk so a
		// transition back to needs-core is instant; only the live process is stopped (below).
		// Still snapshot the rollback baseline (kept sing-box-independent): Backup() backs up
		// the existing config if one is present (no-op + nil error if not), and the kernel +
		// plugin baselines are the real rollback target for native-only.
		if err := s.singbox.Backup(); err != nil {
			backupErr = err.Error()
			log.Printf("handleApply: backup (rollback snapshot) failed: %v — fail-safe may be unable to restore", err)
		}
		s.snapshotPBRBaseline()
		s.snapshotPluginBaseline()
	}

	// (re)start engine plugins (AmneziaWG, olcRTC) for this config's chained outbounds.
	// In native-only this brings the kernel-native interfaces UP BEFORE the core is stopped
	// (§g: kernel plane up before TUN down → no traffic gap).
	s.syncPluginsFor(res)

	// Kernel PBR plane (hybrid only; newPlan is nil otherwise). Install the fwmark routes
	// for the CIDRs the generator route_excluded from the TUN, AFTER the sing-box reload so
	// the kernel catch exists as the TUN stops capturing those dests. Demo/non-router is a
	// no-op. On failure during a NON-save apply we ABORT to baseline: the default fail-safe
	// ping target (1.1.1.1) sits OUTSIDE every excluded zone, so a kernel-plane-only failure
	// would otherwise sail through the connectivity check and commit green while the
	// carve-out (e.g. a carrier VoWiFi range) is dead — the exact failure this mode exists to fix.
	var pbrErr error
	if !c.Demo {
		if pbrErr = s.applyPBR(newPlan); pbrErr != nil {
			log.Printf("handleApply: PBR apply failed: %v", pbrErr)
			if !body.Save {
				// Roll the sing-box config back to the pre-apply baseline and tear the
				// kernel plane back to its baseline. If there is NO rollback target (a
				// first-ever apply leaves no .bak, so Restore is a no-op), don't leave a
				// half-hybrid config running unwatched — stop sing-box so the router falls
				// back to plain WAN routing, which the user can then re-apply over.
				restoreErr := s.singbox.Restore()
				if restoreErr == nil {
					if s.singbox.Running() {
						_ = s.singbox.Reload()
					} else if s.singbox.Available() {
						_ = s.singbox.Start()
					}
				} else if s.singbox.Running() {
					_ = s.singbox.Stop()
				}
				s.restorePBRBaseline()
				msg := "hybrid PBR apply failed, rolled back: " + pbrErr.Error()
				if restoreErr != nil {
					msg = "hybrid PBR apply failed; no rollback target, sing-box stopped (plain WAN): " + pbrErr.Error()
				}
				writeErr(w, http.StatusInternalServerError, msg)
				return
			}
			// Save==true: the user explicitly committed; surface the error in the response
			// but keep the applied config (matches the no-abort posture after the rename).
		}
	}

	// Native-only: STOP the sing-box core now that the kernel plane is up (§c, §g). Ordering
	// is load-bearing — applyPBR (the kernel carve-outs + general→WAN) and the plugin sync
	// above are already live, so tearing the TUN/core down leaves no datapath gap. Gated on
	// pbrErr == nil: if the kernel plane FAILED to install we keep sing-box as the fallback
	// rather than drop the core onto a broken kernel plane (a non-save apply already rolled
	// back + returned above; a save apply keeps the core up here). Stop() is a no-op when the
	// core isn't running, clears Desired() so the watchdog won't fight it (§d), and SIGTERMs
	// for a clean TUN teardown.
	if nativeOnly && pbrErr == nil {
		if err := s.singbox.Stop(); err != nil {
			reloadErr = err.Error()
			log.Printf("handleApply: native-only sing-box stop failed: %v", err)
		}
	}

	if body.Save {
		if err := s.singbox.Commit(); err != nil {
			commitErr = err.Error()
			log.Printf("handleApply: commit (save baseline) failed: %v", err)
		}
		s.failsafe.Confirm()
	} else {
		// Pass the native-only verdict so the rollback window judges connectivity by the
		// kernel-plane ping, not by sing-box liveness (which is intentionally down here).
		s.armFailSafe(nativeOnly)
	}

	resp := map[string]any{
		"applied":     true,
		"saved":       body.Save,
		"checked":     checked,
		"reloaded":    reloaded,
		"config_path": path,
		"plugins":     pluginSummary(res.Plugins),
		"failsafe":    s.failsafe.Status(),
	}
	if pbrErr != nil {
		resp["pbr_error"] = pbrErr.Error() // only on failure → non-hybrid/demo responses stay byte-identical
	}
	// Surface the previously-swallowed apply errors ONLY when present, so a successful
	// apply keeps a byte-identical response (the UI + tests depend on the happy-path shape).
	if backupErr != "" {
		resp["backup_error"] = backupErr
	}
	if reloadErr != "" {
		resp["reload_error"] = reloadErr
	}
	if commitErr != "" {
		resp["commit_error"] = commitErr
	}
	// L5: warn (non-blocking) when fast mode has domain/geo rules that won't apply to LAN traffic
	// (no TUN). Only-when-present so a clean apply keeps a byte-identical response.
	if warn := fastModeDomainWarning(&p, s.routingMode(c)); warn != "" {
		resp["routing_warning"] = warn
	}
	writeJSON(w, http.StatusOK, resp)
}

// entryIsDomain reports whether a routing-list Manual entry is a domain (not an IP/CIDR), so a list
// carrying domain matchers the kernel/IP plane can't route can be detected.
func entryIsDomain(s string) bool {
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return false
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return false
	}
	return true
}

// fastModeDomainWarning (L5) returns a non-blocking warning when RoutingMode is "fast" and the
// profile has domain/geo-based routing rules. In fast mode there is NO TUN (genOptionsWithPlan sets
// TunEnabled=false), so sing-box serves only the local mixed-proxy inbound — domain/geo rules do NOT
// apply to transparently-routed LAN traffic (the kernel plane matches IP/CIDR only). A user adding a
// domain rule usually expects it to steer their devices' traffic, so surface the gap. Returns "" when
// there is nothing to warn about, so a clean apply response stays byte-identical.
func fastModeDomainWarning(p *model.Profile, mode string) string {
	if mode != "fast" || p == nil {
		return ""
	}
	n := 0
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Default {
			continue // a default rule's matcher fields are inert (it's the catch-all)
		}
		if len(r.Domain) > 0 || len(r.DomainSuffix) > 0 || len(r.GeoSite) > 0 || len(r.GeoIP) > 0 {
			n++
		}
	}
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if !rl.Enabled {
			continue
		}
		if rl.Source != "" { // a remote rule_set is sing-box-loaded → no LAN match without a TUN
			n++
			continue
		}
		for _, m := range rl.Manual {
			if entryIsDomain(m) {
				n++
				break
			}
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d domain/geo routing rule(s)/list(s) won't apply to LAN traffic in fast mode: "+
		"with no TUN, sing-box matches domains only for apps using the local proxy port, not "+
		"transparently-routed LAN devices. Use hybrid or tun mode for domain-based LAN routing, or an IP/CIDR list.", n)
}

// handleSubscription parses a subscription (pasted text or a fetched URL) into
// endpoints WITHOUT saving them, so the user can pick which to import.
func (s *Server) handleSubscription(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL  string `json:"url"`
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	text := body.Text
	name := "" // subscription display name, from the server's Profile-Title header (URL path only)
	if body.URL != "" {
		u, perr := url.Parse(body.URL)
		if perr != nil {
			writeErr(w, http.StatusBadRequest, "bad url: "+perr.Error())
			return
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			writeErr(w, http.StatusBadRequest, "subscription url must be an http(s) URL")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, body.URL, nil)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad url: "+err.Error())
			return
		}
		req.Header.Set("User-Agent", "wakeroute")
		resp, err := s.subscriptionFetchClient().Do(req)
		if err != nil {
			writeErr(w, http.StatusBadGateway, "fetch failed: "+err.Error())
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			writeErr(w, http.StatusBadGateway, "subscription returned status "+resp.Status)
			return
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		text = string(b)
		name = subscriptionTitle(resp.Header) // "" when the server sends no usable title
		// Remember the URL so the opt-in periodic refresh (SubscriptionRefreshLoop)
		// can re-fetch it later and add newly-rotated endpoints. This does NOT enable
		// refresh (RefreshHours stays untouched — opt-in); it only records the source.
		s.cfgMu.Lock()
		if s.cfg.Subscription.URL != body.URL {
			s.cfg.Subscription.URL = body.URL
			if err := s.cfg.Save(); err != nil {
				log.Printf("wakeroute: could not persist subscription URL for auto-refresh: %v", err)
			}
		}
		s.cfgMu.Unlock()
	}
	eps, errs := importer.ParseSubscription(text)
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": eps, "errors": errs, "name": name})
}

// subscriptionFetchClient is an http.Client for fetching a user-supplied
// subscription URL with an SSRF guard: it refuses to connect to loopback /
// private / link-local addresses (so the panel can't be used to reach the
// router's own Clash API, other LAN hosts, or cloud metadata). The check runs at
// DIAL time on the already-resolved IP, so it also covers redirects and
// DNS-rebinding. Redirects are capped. (allowInternalFetch disables the guard for
// tests that point at a loopback httptest server.)
func (s *Server) subscriptionFetchClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if !s.allowInternalFetch {
		dialer.Control = blockInternalDial
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}
}

// errInternalHost marks a target that an SSRF guard must refuse (resolves to an
// internal address). The TLS-probe guard (refuseInternalHost) returns it.
var errInternalHost = fmt.Errorf("refusing to reach an internal address")

// cgnatNet is the RFC 6598 carrier-grade NAT (shared address) range 100.64.0.0/10.
// net.IP.IsPrivate covers only RFC1918/ULA, so a host resolving into CGNAT would
// otherwise read as "external" and be dialed — letting a subscription URL / Reality
// probe reach a carrier-side or on-link CGNAT service. Parsed once at init.
var cgnatNet = mustCIDR("100.64.0.0/10")

// #11: IPv6 forms that EMBED an IPv4 address the To4()/IsPrivate family does NOT decode — NAT64
// (well-known prefix 64:ff9b::/96) and 6to4 (2002::/16). The SSRF guards must extract + re-check the
// embedded v4 so a hostname resolving to e.g. 64:ff9b::7f00:1 (127.0.0.1) can't reach an internal host.
var nat64Net = mustCIDR("64:ff9b::/96")
var sixToFourNet = mustCIDR("2002::/16")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("server: bad CIDR " + s + ": " + err.Error())
	}
	return n
}

// isInternalDialIP reports whether ip is one the SSRF guards must refuse: loopback,
// RFC1918/ULA private, RFC6598 CGNAT (100.64.0.0/10), link-local (unicast incl.
// 169.254.169.254 metadata, and multicast), or the unspecified address. Single source
// of truth shared by blockInternalDial (subscription-fetch dial guard) and
// refuseInternalHost (the Reality dest/SNI probe guard) so the two can never diverge.
func isInternalDialIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// Normalize IPv4-mapped-IPv6 to 4 bytes so the CGNAT /10 Contains check matches
	// consistently with the IsPrivate family above (which already handles the mapped form).
	if v4 := ip.To4(); v4 != nil {
		return cgnatNet.Contains(v4)
	}
	// #11: NAT64 / 6to4 embed an IPv4 that To4() above does NOT extract — decode it and re-check, so a
	// host like 64:ff9b::7f00:1 (127.0.0.1) or 2002:7f00:1:: can't slip an internal target past the guard.
	if ip16 := ip.To16(); ip16 != nil {
		if nat64Net.Contains(ip16) {
			return isInternalDialIP(net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15]))
		}
		if sixToFourNet.Contains(ip16) {
			return isInternalDialIP(net.IPv4(ip16[2], ip16[3], ip16[4], ip16[5]))
		}
	}
	return false
}

// blockInternalDial rejects a dial to a loopback/private/link-local/unspecified
// address. address is host:port with host already resolved to an IP literal.
func blockInternalDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("could not parse dial address %q", address)
	}
	if isInternalDialIP(ip) {
		return fmt.Errorf("refusing to fetch from internal address %s", ip)
	}
	return nil
}

// handleBulkEndpoints upserts many endpoints at once (subscription import).
func (s *Server) handleBulkEndpoints(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Endpoints []model.Endpoint `json:"endpoints"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// Skip content-duplicate imports: re-fetching a subscription (fresh IDs each time)
	// would otherwise pile up identical endpoints. An incoming endpoint whose ID already
	// exists is an in-place update, not a dupe, and is kept (see importer.DedupeNew).
	eps, dupes := importer.DedupeNew(s.store.Profile().Endpoints, body.Endpoints)
	// Non-fatal: each UpsertEndpoint persists immediately, so bailing on the Nth
	// error would leave 1..N-1 saved while reporting total failure. Accumulate
	// per-endpoint errors and always report the true saved count.
	saved := 0
	errs := []string{}
	for _, e := range eps {
		if e.ID == "" {
			errs = append(errs, "skipped an endpoint with no id")
			continue
		}
		if err := s.store.UpsertEndpoint(e); err != nil {
			errs = append(errs, e.ID+": "+err.Error())
			continue
		}
		saved++
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": saved, "duplicates": dupes, "errors": errs})
}

// routingMode resolves the effective routing mode from a config snapshot: "" derives
// from Gateway (back-compat — TUN when gateway is on, else mixed-proxy-only); an explicit
// value ("tun"/"hybrid"/"mixed") wins. One resolver shared by genOptionsWithPlan,
// handleApply, and SyncPlugins so the two planes never disagree on which mode is active.
func (s *Server) routingMode(c config.Config) string {
	mode := c.RoutingMode
	if mode == "" {
		if c.Gateway {
			mode = "tun"
		} else {
			mode = "mixed"
		}
	}
	return mode
}

// pbrCompileOptions builds the pbr.Options the kernel-PBR compiler is driven with for a
// config, so the read-only preview handler compiles the SAME plan the apply path does — in
// particular the flow-offload flowtable, which is baked into the plan at Compile time, so a
// bare Options{} would silently omit it from the preview (the preview would not match Apply).
// Offload applies to "fast" mode only (it accelerates the general kernel fast-path that
// exists only there; in hybrid, general traffic transits the capture-all TUN). The WAN+LAN
// host probe runs ONLY in the opt-in case: offload set, no explicit device list, not demo.
func (s *Server) pbrCompileOptions(c config.Config) pbr.Options {
	opts := pbr.Options{}
	if s.routingMode(c) != "fast" {
		return opts
	}
	opts.Offload = c.Offload
	devs := c.OffloadDevices
	if (c.Offload == "sw" || c.Offload == "hw") && len(devs) == 0 && !c.Demo {
		devs = probeOffloadDevices()
	}
	opts.OffloadDevices = devs
	return opts
}

// genOptionsWithPlan builds the generator options for the given profile AND returns the
// kernel-routing Plan it compiled (nil unless hybrid). handleApply and the boot sync use
// the SAME returned plan to install the kernel plane (applyPBR), so the TUN route_exclude
// set and the kernel routes are always ONE compile of ONE profile — they can never
// desync. The Plan is the single source of truth for the hybrid partition. NOT demo-gated
// (config generation is identical in demo); the demo guard lives only on the kernel side
// (applyPBR), so a demo daemon produces a byte-identical singbox.json without touching nft/ip.
func (s *Server) genOptionsWithPlan(p *model.Profile, c config.Config) (generator.Options, *pbr.Plan) {
	opts := generator.Options{
		MixedPort:   c.Ports.Mixed,
		ClashAddr:   c.Clash.Controller,
		ClashSecret: c.Clash.Secret,
		CacheFile:   filepath.Join(filepath.Dir(c.SingBox.Config), "cache.db"),
		TunEnabled:  c.Gateway,
		TunMTU:      c.GatewayMTU,
		TunAddr:     c.GatewayAddr,
	}
	mode := s.routingMode(c)
	if (mode != "hybrid" && mode != "fast") || p == nil {
		return opts, nil
	}
	// Flow-offload (fast mode only) is baked into the plan at Compile; see pbrCompileOptions.
	plan, _, err := pbr.Compile(p, s.pbrCompileOptions(c))
	if err != nil {
		// Fail-safe: never emit a half-hybrid config that excludes CIDRs nothing routes.
		// Fall back to the non-hybrid (TUN) shape and return no plan — both planes agree
		// (nothing excluded, nothing kernel-routed).
		log.Printf("genOptions: pbr.Compile failed, falling back to non-hybrid: %v", err)
		opts.TunEnabled = c.Gateway
		return opts, nil
	}
	opts.Hybrid = true
	if mode == "fast" {
		// "fast": no capture-all TUN. General LAN traffic stays on the kernel fast-path
		// (no userspace-TUN tax → near-line-rate); ONLY the pbr kernel plane (IP/CIDR
		// carve-outs like TG-calls/VoWiFi) steers LAN traffic via fwmark. Domain carve-outs
		// are inactive for LAN here (no TUN to sniff them) — they'd only affect the local
		// mixed-proxy inbound. No route_exclude needed (there is no TUN to exclude from);
		// the plan is still returned so handleApply installs the kernel routes. Phase 1b
		// will additionally enable HW flow-offload (excluding carve-out marks).
		opts.TunEnabled = false
		return opts, plan
	}
	opts.TunEnabled = true // hybrid always keeps the TUN, regardless of c.Gateway
	// Exclude the CIDRs the kernel plane routes — every zone EXCEPT blackhole — plus
	// the anti-loop bypass (peer server IPs). Block stays in the sing-box reject plane
	// in hybrid (the generator keeps block rules as reject actions), so its CIDRs must
	// NOT be excluded from the TUN: excluding them would let the now-dead reject be
	// bypassed and blocked traffic fall through to WAN. The kernel still models the
	// blackhole zone (for a future kernel-level drop) but it isn't part of the TUN
	// exclude contract here.
	blackhole := map[string]bool{}
	for _, e := range plan.Egresses {
		if e.Kind == pbr.EgressBlackhole {
			blackhole[e.Tag] = true
		}
	}
	for _, z := range plan.Zones {
		if blackhole[z.EgressTag] {
			continue
		}
		// Source-scoped zones (§6.4): the kernel marks this dest ONLY for the matching source.
		// Other sources' traffic to the same dest must still reach it via the TUN default, so its
		// dest CIDR must NOT be excluded from the TUN — excluding it would leave a non-matching
		// client with neither a kernel mark nor a TUN route, falling through to WAN (a leak).
		if z.SrcScoped {
			continue
		}
		opts.KernelExcludeV4 = append(opts.KernelExcludeV4, z.V4...)
		opts.KernelExcludeV6 = append(opts.KernelExcludeV6, z.V6...)
	}
	opts.KernelExcludeV4 = append(opts.KernelExcludeV4, plan.BypassV4...)
	opts.KernelExcludeV6 = append(opts.KernelExcludeV6, plan.BypassV6...)
	return opts, plan
}

// genOptions builds the generator options for the current config, discarding the plan.
// handleGenerate/SyncPlugins/preview use this; handleApply uses genOptionsWithPlan so it
// can drive the kernel plane from the same compile.
func (s *Server) genOptions(p *model.Profile) generator.Options {
	opts, _ := s.genOptionsWithPlan(p, s.config())
	return opts
}

// datapathNativeOnly is the authoritative "skip sing-box" verdict for an apply/sync. It
// resolves the SAME routing mode (s.routingMode) that genOptionsWithPlan uses to drive the
// pbr compile, then delegates the (conservative) decision to the pure shared predicate
// generator.DatapathNativeOnly. Computing it from the identical (config, profile) the kernel
// plane is built from keeps a single source of truth — the verdict can never disagree with
// which mode/plan handleApply + SyncPlugins actually install.
//
// Fail-safe by construction (see docs/NATIVE_P4_DESIGN.md §h): DatapathNativeOnly returns
// true ONLY when the kernel plane provably carries everything (fast mode, every endpoint
// kernel-native, default egress direct/WAN, nothing surviving into sing-box) — on ANY doubt
// it returns false and sing-box is KEPT. Skipping the core is the only change that can
// black-hole traffic; this predicate is the gate that makes the skip safe.
func (s *Server) datapathNativeOnly(c config.Config, p *model.Profile) bool {
	return generator.DatapathNativeOnly(p, s.routingMode(c))
}

// applyPBR installs newPlan as the kernel PBR plane, or tears the plane down when nil.
// One pbrMu-held transaction: Teardown the previously-installed plan first (the nft table
// is self-flushing on its fixed name, so this only matters to clear ip rules/routes in
// tables a SHRINKING plan no longer uses), then Apply the new plan. pbrMu is the single
// authority for s.pbrPlan + the nft/ip command stream, so a concurrent rollback or boot
// sync can't interleave. The nil-runner guard makes a Server built directly in a test
// (bypassing New()) a no-op instead of a panic.
func (s *Server) applyPBR(newPlan *pbr.Plan) error {
	s.pbrMu.Lock()
	defer s.pbrMu.Unlock()
	if s.pbrRunner == nil {
		return nil
	}
	// QW3 idempotency: if the new plan is identical to the one already installed, skip the whole
	// teardown+apply. Re-applying an unchanged plan would tear down and rebuild the live nft table +
	// ip rules for nothing, opening a brief routing gap (drops calls / stalls flows) on every config
	// save that doesn't actually change routing. Plan is pure data so reflect.DeepEqual is exact;
	// both-nil (no PBR) compares equal too. The pre-Teardown below is KEPT for the changed-plan case
	// — it clears ip rules/routes a SHRINKING plan no longer uses (see this func's doc), so it must
	// NOT be dropped (the nft self-flush only covers the nft table, not the ip rules).
	if reflect.DeepEqual(newPlan, s.pbrPlan) {
		return nil
	}
	if s.pbrPlan != nil {
		_ = s.pbrPlan.Teardown(s.pbrRunner, pbr.Options{})
	}
	if newPlan != nil {
		if err := newPlan.Apply(s.pbrRunner, pbr.Options{}); err != nil {
			// Apply is not transactional across nft+ip; tear the partial install back out
			// (best-effort) so no interim nft table / ip rules survive, and record an
			// indeterminate state so the next first-apply cleanly reinstalls.
			_ = newPlan.Teardown(s.pbrRunner, pbr.Options{})
			s.pbrPlan = nil
			return err
		}
	}
	s.pbrPlan = newPlan
	return nil
}

// snapshotPBRBaseline records the currently-installed plan as the rollback target. Called
// once at the FIRST apply of a fail-safe window (co-located with singbox.Backup), BEFORE
// applyPBR overwrites s.pbrPlan — so the baseline is the true pre-window kernel state.
func (s *Server) snapshotPBRBaseline() {
	s.pbrMu.Lock()
	defer s.pbrMu.Unlock()
	s.pbrBaseline = s.pbrPlan
}

// restorePBRBaseline restores the kernel PBR plane to the baseline snapshotted at the
// start of the fail-safe window: tear down whatever is installed now, then re-Apply the
// baseline (nil baseline = leave the plane down). Best-effort — errors are logged, not
// returned — so a secondary nft/ip failure never flips the fail-safe verdict (sing-box
// restore is the primary connectivity signal). Reads both fields at call time under pbrMu,
// so a multi-apply window restores the interim-teardown + the true pre-window baseline.
func (s *Server) restorePBRBaseline() {
	s.pbrMu.Lock()
	defer s.pbrMu.Unlock()
	if s.pbrRunner == nil {
		return
	}
	if s.pbrPlan != nil {
		_ = s.pbrPlan.Teardown(s.pbrRunner, pbr.Options{})
	}
	if s.pbrBaseline != nil {
		if err := s.pbrBaseline.Apply(s.pbrRunner, pbr.Options{}); err != nil {
			// Apply isn't transactional across nft+ip; tear the partial baseline install back
			// out (best-effort) so no orphan ip rules/routes survive to silently mis-route a
			// dst into a now-stale table — mirrors applyPBR's failure path. Record an
			// indeterminate state so the next first-apply cleanly reinstalls.
			_ = s.pbrBaseline.Teardown(s.pbrRunner, pbr.Options{})
			log.Printf("fail-safe: PBR baseline restore failed: %v", err)
			s.pbrPlan = nil
			return
		}
	}
	s.pbrPlan = s.pbrBaseline
}

// snapshotPluginBaseline records the engine-plugin specs currently running as the
// rollback target — taken at the FIRST apply of a fail-safe window (before
// syncPluginsFor switches them to the new config's set), co-located with the sing-box
// Backup + PBR baseline so all three roll back together.
func (s *Server) snapshotPluginBaseline() {
	s.pbrMu.Lock()
	defer s.pbrMu.Unlock()
	s.pluginBaseline = s.plugins.Specs()
}

// restorePluginBaseline re-Syncs the engine plugins to the pre-window set so a rolled-
// back sing-box config's bind_interface targets (awg devices) / chained SOCKS ports are
// the ones that config expects. Without this, rollback restores the config + kernel plane
// but leaves the plugins at the FAILED apply's set, so a restored outbound bound to an
// awg device the failed apply tore down (or a chained SOCKS on a port no longer served)
// runs dead. plugins.Sync is idempotent + internally locked; best-effort.
func (s *Server) restorePluginBaseline() {
	s.pbrMu.Lock()
	specs := append([]plugin.Spec(nil), s.pluginBaseline...)
	s.pbrMu.Unlock()
	s.plugins.Sync(specs)
}

func pluginSummary(ps []generator.Plugin) []map[string]any {
	out := make([]map[string]any, 0, len(ps))
	for _, p := range ps {
		out = append(out, map[string]any{
			"id":         p.Endpoint.ID,
			"protocol":   p.Endpoint.Protocol,
			"engine":     p.Endpoint.Engine,
			"socks_port": p.SOCKSPort,
		})
	}
	return out
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
