package server

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/generator"
	"wayhop/internal/importer"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
	"wayhop/internal/plugin"
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
	// The full profile carries EVERY endpoint's Params (WireGuard private keys, SS/Trojan/Hy2
	// passwords, VLESS/VMess/TUIC UUIDs, Reality keys) — strictly more secrets than any single
	// export — so it must not be disk-cached by the browser or an intermediary, matching the
	// no-store policy on backup/config-export/subscription/job-snapshot/endpoint-export.
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Query().Get("lite") == "1" {
		writeJSON(w, http.StatusOK, liteProfileOf(s.store.Profile(), s.cidrCheckedAt))
		return
	}
	writeJSON(w, http.StatusOK, s.store.Profile())
}

// liteList is a routing list without its feed cache, carrying the cache's SIZE instead.
//
// The panel reloads the profile on every page render and after every mutation — around thirty call
// sites — and the caches are by far the largest thing in it: on a live router one list held
// 15 866 CIDRs, and /api/profile answered 275 KB where the panel needed a few kilobytes of names,
// ids and toggles. Nothing in the UI reads the cache CONTENTS; two places read its length, to show
// "12 043 entries" and "not fetched yet". So the count is sent and the array is not.
// omitempty on both counts, because most lists have no feed at all: the stress profile carries 66
// lists and none of them a cache, where two always-present zero fields added 1.7 KB to a payload
// this exists to shrink. An absent count reads as zero, which is what it is.
type liteList struct {
	model.RoutingList
	CIDRCacheCount   int `json:"cidr_cache_count,omitempty"`
	DomainCacheCount int `json:"domain_cache_count,omitempty"`
	// CIDRCheckedAt is when this list's feed was last FETCHED, as opposed to CIDRRefreshed, which is
	// when the fetch last CHANGED anything. The two diverge by design: a fetch whose result equals
	// the cache is deliberately not written, so the router does not burn flash rewriting identical
	// bytes. The cost of that is a display that ages without bound — a list on a 12-hour cycle whose
	// upstream is stable reads as "refreshed 129 hours ago", which is indistinguishable from a broken
	// refresh. It misled the author of this field into reporting the refresh as failing; only the
	// code showed the fetch had succeeded every time. This one is in MEMORY, so stating it costs no
	// flash, and it resets to zero on restart — which is honest, not a defect: nothing was checked in
	// this process yet.
	CIDRCheckedAt int64 `json:"cidr_checked,omitempty"`
}

// liteProfile is the profile with lite lists. The embedded Profile supplies every other field, and
// RoutingLists at the outer level shadows the embedded one in the JSON output.
type liteProfile struct {
	model.Profile
	RoutingLists []liteList `json:"routing_lists"`
}

// liteProfileOf strips the feed caches, keeping their sizes.
//
// Deliberately opt-IN, on ?lite=1, rather than made the default: the JSON this route returns is also
// the BACKUP format that POST /api/profile restores. A default that dropped the caches would produce
// backups whose restore leaves every feed-backed list empty — and an empty cache on a list with a
// source is a hard Apply blocker (see unfetchedFeedFindings), so the router would come back from its
// own backup unable to apply until every feed was re-fetched.
// checkedAt reports when a list was last fetched, or 0 when that is unknown. Passed in rather than
// read from a global so the shape stays testable without a Server.
func liteProfileOf(p model.Profile, checkedAt func(id string) int64) liteProfile {
	out := liteProfile{Profile: p, RoutingLists: make([]liteList, 0, len(p.RoutingLists))}
	for _, rl := range p.RoutingLists {
		l := liteList{RoutingList: rl, CIDRCacheCount: len(rl.CIDRCache), DomainCacheCount: len(rl.DomainCache)}
		if checkedAt != nil {
			l.CIDRCheckedAt = checkedAt(rl.ID)
		}
		// Nil, not empty: `cidr_cache` is omitempty, so the key disappears rather than arriving as []
		// — which a client could otherwise read as "fetched, and it is empty".
		l.CIDRCache = nil
		l.DomainCache = nil
		out.RoutingLists = append(out.RoutingLists, l)
	}
	// The embedded copy must not also carry them: it is the source of every other field, and Go would
	// keep the big arrays alive behind a value the encoder never reaches.
	out.Profile.RoutingLists = nil
	return out
}

// handleRestoreProfile replaces the ENTIRE routing profile (endpoints/groups/rules/lists) from an
// uploaded backup — the JSON that GET /api/profile returns. store.Replace validates it before it
// lands (a bad backup is rejected, the current profile untouched), and persists atomically; the
// change goes live on the next Apply (with the fail-safe net). The companion to handleConfigExport
// for the daemon config — together they let a user back up + restore or migrate a full WayHop
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
	if code, msg := s.gateEndpoint(r.Context(), e); code != 0 {
		writeErr(w, code, msg)
		return
	}
	// Switching an exit OFF breaks a reference exactly as deleting it would, so it is answered the
	// same way: ?replace_with= moves what routed through it, ?detach=1 parks those dependents, and a
	// bare refusal carries the full set plus the outbounds they could move to instead of naming one
	// internal id and stopping. See handleDeleteEndpoint — same question, same two answers.
	if !e.Enabled {
		if r.URL.Query().Get("detach") == "1" {
			if err := s.store.SetEndpointDisabledDetaching(e); err != nil {
				writeErr(w, http.StatusConflict, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, e)
			return
		}
		if replacement := strings.TrimSpace(r.URL.Query().Get("replace_with")); replacement != "" {
			if err := s.store.SetEndpointDisabledReplacing(e, replacement); err != nil {
				writeErr(w, http.StatusConflict, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, e)
			return
		}
	}
	if err := s.store.UpsertEndpoint(e); err != nil {
		if !e.Enabled {
			if blockers := s.store.EndpointDisableBlockers(e.ID); len(blockers) != 0 {
				writeJSON(w, http.StatusConflict, map[string]any{
					"error":        err.Error(),
					"code":         "ENDPOINT_IN_USE",
					"dependents":   blockers,
					"replacements": s.store.EndpointDisableReplacements(e.ID),
				})
				return
			}
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// gateEndpoint refuses an ENABLED endpoint unless the host can execute the exact engine/protocol
// operation and roll it back. Native carriage alone never grants create/remove authority.
//
// The capability gate lived only at Apply. Everything before it accepted whatever was posted, so a
// protocol the core cannot run could be created, enabled, listed and reviewed, and the first honest
// answer arrived after the user had built a configuration around it. Worse, the gate could be
// side-stepped entirely by talking to the API directly, which is the path any script takes.
//
// Three outcomes, and the distinction between them is the point:
//
//   - not enabled: allowed. A draft carries no traffic, and refusing to SAVE one would stop someone
//     preparing a configuration for a router they are about to install a core on.
//   - evaluated and not usable: 422. This is not a validation problem the caller can rephrase, and
//     it is not overridable — the host cannot carry it, so accepting it would be storing a promise
//     the daemon knows it will break.
//   - evaluated as unknown: 503. Not knowing is not the same as knowing it is impossible, and
//     answering 422 to an unfinished probe would refuse something that may be perfectly fine.
//
// Missing capability ids are unknown and fail closed. This prevents a future protocol or engine
// from bypassing the activation gate merely because this build forgot to evaluate it.
func (s *Server) gateEndpoint(ctx context.Context, e model.Endpoint) (int, string) {
	if !e.Enabled {
		return 0, ""
	}
	if e.Engine == model.EngineExternal {
		// An adopted tunnel is already up and carrying traffic, brought up by the router itself; WayHop
		// only routes into it. Its Protocol field is descriptive (validate skips it for external), and
		// the capability being consulted here answers a different question — whether the PROXY CORE can
		// build that protocol — so applying it to an interface the core never touches would refuse a
		// tunnel the host is demonstrably running. Today the two lists happen not to overlap; the day
		// wireguard joins singboxRequired, the Native loop stops overriding it (an id already taken is
		// skipped) and every adopted native tunnel would become un-enableable.
		return 0, ""
	}
	requirements, err := endpointCapabilityRequirements(e)
	if err != nil {
		return http.StatusUnprocessableEntity, err.Error() +
			" Save it disabled if you need to retain it as a draft."
	}
	set := s.capabilitySet(ctx, false)
	// Get synthesizes unknown for an id this build does not evaluate. That is deliberate here: an
	// enabled future operation must not bypass the gate through an absent matrix entry.
	for _, requirement := range requirements {
		cap := set.Get(requirement)
		switch endpointActivationGateState(cap.State) {
		case 0:
			continue
		case http.StatusServiceUnavailable:
			return http.StatusServiceUnavailable, "this host has not verified capability " + requirement +
				", so enabling this connection would be a guess. Retry the capability check."
		}
		msg := "this host cannot activate this connection because " + requirement + " is unavailable"
		if cap.Detail != "" {
			msg += ": " + cap.Detail
		}
		if cap.Remedy != "" {
			msg += " " + cap.Remedy
		}
		return http.StatusUnprocessableEntity, msg +
			" Save it disabled if you are preparing a configuration for elsewhere."
	}
	return 0, ""
}

func endpointCapabilityRequirements(e model.Endpoint) ([]string, error) {
	proto := model.Protocol(strings.ToLower(strings.TrimSpace(string(e.Protocol))))
	if proto == "" {
		return nil, fmt.Errorf("endpoint protocol is empty")
	}
	switch proto {
	case model.ProtoWireGuard, model.ProtoAmneziaWG:
		if e.Engine != model.EngineSingBox && e.Engine != model.EngineAmneziaWG {
			return nil, fmt.Errorf("engine %q cannot create a native %s connection", e.Engine, proto)
		}
		return []string{
			platform.NativeOperationCapabilityID(string(proto), platform.NativeCreate),
			platform.NativeOperationCapabilityID(string(proto), platform.NativeRemove),
		}, nil
	case model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan, model.ProtoShadowsocks,
		model.ProtoHysteria2, model.ProtoTUIC, model.ProtoAnyTLS, model.ProtoSOCKS, model.ProtoHTTP:
		if e.Engine != model.EngineSingBox {
			return nil, fmt.Errorf("protocol %s requires the sing-box compatibility add-on", proto)
		}
		return []string{platform.CapEngineSingbox, platform.CapProtocolPrefix + string(proto)}, nil
	case model.ProtoOlcRTC:
		if e.Engine != model.EngineOlcRTC {
			return nil, fmt.Errorf("protocol %s requires the olcRTC engine", proto)
		}
		return []string{platform.CapEngineOlcRTC}, nil
	default:
		return nil, fmt.Errorf("protocol %q is not supported by this WayHop build", proto)
	}
}

// An enabled endpoint is an activation claim. Only proven-supported capabilities satisfy it;
// missing dependencies can still be stored as disabled drafts.
func endpointActivationGateState(st platform.CapState) int {
	if st.Usable() {
		return 0
	}
	if st == platform.CapUnknown {
		return http.StatusServiceUnavailable
	}
	return http.StatusUnprocessableEntity
}

// gateState is the one place the WRITE-time policy on a capability state lives, so the gates that
// share it cannot drift apart while each still words its own refusal. It returns the HTTP status a
// write should answer with, or 0 to allow.
//
// available-after-install and blocked-by-dependency are ALLOWED: not yet is not never, and refusing
// them would break the ordinary order of setting a router up — panel first, exits next, core last.
// The review gate still blocks Apply while the dependency is missing, so nothing unsupported reaches
// the datapath either way. The criterion is that unsupported cannot be ACTIVATED; saving is not
// activation. Unknown is not a verdict in either direction, so it asks the caller to come back.
func gateState(st platform.CapState) int {
	switch {
	case st.Usable(), st == platform.CapAvailableAfterInstall, st == platform.CapBlockedByDependency:
		return 0
	case st == platform.CapUnknown:
		return http.StatusServiceUnavailable
	default:
		return http.StatusUnprocessableEntity
	}
}

// handleDeleteEndpoint removes a connection, moving anything that routes through it onto a
// replacement the caller names via ?replace_with=.
//
// Without a replacement it still refuses when something depends on the endpoint — a dangling
// outbound fails Validate() and blocks every later Apply — but the refusal now carries the full
// dependent set and the outbounds they could move to. The previous behaviour named one blocker and
// said "repoint it first", which is a dead end: it does not say what to repoint to, and with several
// dependents the operator discovers them one refusal at a time.
func (s *Server) handleDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	replacement := strings.TrimSpace(r.URL.Query().Get("replace_with"))
	if r.URL.Query().Get("detach") == "1" {
		if err := s.store.DetachEndpointDependents(id); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id, "detached": true})
		return
	}
	if err := s.store.DeleteEndpointReplacing(id, replacement); err != nil {
		if dependents := s.store.EndpointDependents(id); replacement == "" && len(dependents) != 0 {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":        err.Error(),
				"code":         "ENDPOINT_IN_USE",
				"dependents":   dependents,
				"replacements": s.store.EndpointReplacements(id),
			})
			return
		}
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id, "moved_to": replacement})
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
		// Structured, like the endpoint path: the sentence alone left the panel with nothing to render
		// but the raw error. The panel asks its own question before offering the destructive confirm;
		// this is what it falls back to when that check has not learned about a condition yet.
		if blockers := s.store.GroupDeleteBlockers(id); len(blockers) != 0 {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":      err.Error(),
				"code":       "GROUP_IN_USE",
				"dependents": blockers,
			})
			return
		}
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
	// Bound the auto-refresh cadence at the write boundary (400), NOT in Validate — a hard Validate
	// failure would brick Apply for profiles persisted before the bounds existed. The ticker clamps
	// legacy values; new writes are rejected here.
	if !model.ValidRefreshHours(rl) {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("refresh_hours must be 0 (default 24h) or %d–%d hours for a CIDR-source list (flash protection)", model.MinCIDRRefreshHours, model.MaxCIDRRefreshHours))
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

// handleUpsertDeviceGroup adds/replaces a device group (named MAC/IP set that RoutingLists scope to).
// Validates the members at the boundary (400) so a malformed group can never brick Apply.
func (s *Server) handleUpsertDeviceGroup(w http.ResponseWriter, r *http.Request) {
	var g model.DeviceGroup
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid device group JSON")
		return
	}
	if err := model.ValidateDeviceGroup(g); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpsertDeviceGroup(g); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, g)
}

// handleDeleteDeviceGroup removes a device group; the store prunes its id from any list's scope.
func (s *Server) handleDeleteDeviceGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteDeviceGroup(id); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// routingCatalog{Once,JSON,ETag} memoize the marshaled preset catalog + its content ETag.
// model.RoutingPresets() is a build-constant (a hardcoded slice, no config/time/rand), so the
// JSON is identical for the whole process life — marshal it once and let the browser 304 it.
var (
	routingCatalogOnce sync.Once
	routingCatalogJSON []byte
	routingCatalogETag string
)

func routingCatalogCached() ([]byte, string) {
	routingCatalogOnce.Do(func() {
		b, err := json.Marshal(model.RoutingPresets())
		if err != nil {
			b = []byte("[]") // a static catalog can't really fail to marshal; degrade to empty
		}
		h := fnv.New64a()
		_, _ = h.Write(b)
		routingCatalogJSON = b
		routingCatalogETag = fmt.Sprintf(`W/"cat-%x"`, h.Sum64())
	})
	return routingCatalogJSON, routingCatalogETag
}

// handleRoutingCatalog returns the curated pre-defined rule-set presets. The catalog is
// build-constant, so it's served from a cached buffer with a content ETag: the Routing page
// revalidates cheaply (If-None-Match → 304) instead of re-marshaling the whole list each visit.
func (s *Server) handleRoutingCatalog(w http.ResponseWriter, r *http.Request) {
	body, etag := routingCatalogCached()
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache") // always revalidate, but a match is a body-less 304
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
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
			req.Header.Set("User-Agent", "wayhop")
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

// handleEndpointCheck validates ONE connection's config without touching the live setup. It builds an
// isolated single-endpoint profile, runs the generator, and — when the sing-box binary is present —
// runs `sing-box check` on the result (the same validation the Apply path does, scoped to one
// connection). It writes only a throwaway temp file in the system temp dir (tmpfs on the router, so no
// flash write) and deletes it. Always HTTP 200; the "ok" boolean carries the verdict and "error" the
// reason on failure, so the UI can surface a plain toast.
// Who actually produced a connection-check verdict. The two are not equivalent: the engine parses
// and validates the whole outbound, the generator only proves the model could be translated at all.
const (
	checkedBySingbox   = "sing-box"
	checkedByGenerator = "generator"
	checkedByInterface = "interface"
)

func (s *Server) handleEndpointCheck(w http.ResponseWriter, r *http.Request) {
	full := s.store.Profile()
	ep := full.EndpointByID(r.PathValue("id"))
	if ep == nil {
		writeErr(w, http.StatusNotFound, "connection not found")
		return
	}
	// Isolate this endpoint (forced enabled) with no groups/rules, and force a plain sing-box
	// generation (Hybrid off) so the endpoint always emits as an outbound that `sing-box check`
	// actually validates — a hybrid/native plan could omit a kernel-class outbound and check nothing.
	e := *ep
	e.Enabled = true
	mini := model.Profile{Endpoints: []model.Endpoint{e}}
	opts := s.genOptions(&mini)
	opts.Hybrid = false
	opts.KernelExcludeV4 = nil
	opts.KernelExcludeV6 = nil

	res, err := generator.Generate(&mini, opts)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error(), "checked_by": checkedByGenerator})
		return
	}

	// An endpoint routed through an interface WayHop does not manage is configured by exactly one
	// field — that interface name — and the engine never looks at it. Measured on a live
	// Keenetic: sing-box check -c with bind_interface "iface-that-does-not-exist" exits 0, the same
	// as with the real nwg1. So the engine's opinion of a config the engine does not carry (pbr
	// routes these, not sing-box) was reported as "configuration is valid" while the one field that
	// can actually be wrong went unexamined — a typo'd interface name checked out clean.
	//
	// EngineExternal only: netifd/NDM owns these, so the interface must already exist. An AmneziaWG
	// endpoint is WayHop-managed and its device legitimately does not exist until Apply brings it
	// up, so judging it here would fail every new connection before it was ever applied.
	if ep.Engine == model.EngineExternal && !s.config().Demo {
		iface, _ := ep.Params["interface"].(string)
		if _, ierr := net.InterfaceByName(iface); ierr != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "checked_by": checkedByInterface,
				"error": fmt.Sprintf("interface %q does not exist on this router, so nothing can route through this connection", iface)})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "checked_by": checkedByInterface, "iface": iface})
		return
	}
	// No sing-box binary (e.g. a native-only router): the generator accepting the endpoint is the
	// best available verdict — report ok rather than a misleading failure.
	if s.singbox != nil && s.singbox.Available() {
		data, err := json.MarshalIndent(res.Config, "", "  ")
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error(), "checked_by": checkedByGenerator})
			return
		}
		tmpf, err := os.CreateTemp("", "wayhop-check-*.json")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		tmp := tmpf.Name()
		defer os.Remove(tmp)
		_, werr := tmpf.Write(data)
		if cerr := tmpf.Close(); werr != nil || cerr != nil {
			writeErr(w, http.StatusInternalServerError, firstErr(werr, cerr).Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if err := s.singbox.CheckConfig(ctx, tmp); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error(), "checked_by": checkedBySingbox})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "checked_by": checkedBySingbox})
		return
	}
	// Without the engine binary the only thing that happened is that the generator accepted the
	// endpoint. That is a real but much weaker verdict, and returning a bare ok:true made it
	// indistinguishable from a full `sing-box check` — every connection on a native-only router
	// reported the same "OK" whether or not anything validated it. Name the checker so the panel
	// can say which question was actually answered.
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "checked_by": checkedByGenerator})
}

// firstErr returns the first non-nil error (tiny local helper for the two-error temp-file path).
func firstErr(a, b error) error {
	if a != nil {
		return a
	}
	return b
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
// profile has domain/geo-based routing rules that sing-box would have to match. In fast mode there
// is NO TUN (genOptionsWithPlan sets TunEnabled=false), so sing-box serves only the local
// mixed-proxy inbound — a domain/geo rule it owns does NOT apply to transparently-routed LAN
// traffic. A user adding a domain rule usually expects it to steer their devices' traffic, so
// surface the gap. Returns "" when there is nothing to warn about, so a clean apply response stays
// byte-identical.
//
// kernelCarriesDomains says the router matches domains WITHOUT sing-box, which makes the whole
// warning wrong rather than merely loud: see keeneticKernelCarriesDomains.
func fastModeDomainWarning(p *model.Profile, mode string, kernelCarriesDomains bool) string {
	if mode != "fast" || p == nil {
		return ""
	}
	n := 0
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Default {
			continue // a default rule's matcher fields are inert (it's the catch-all)
		}
		// Rule-level matchers are sing-box's own: the kernel plane has no equivalent for them, so a
		// wired resolver does not rescue these.
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
		// Names — typed or fetched — are what the resolver plane carries. With it wired they are
		// ipset members at query time and the kernel routes them; without it the list would route
		// nothing at all in fast mode, which is exactly what this warning exists to say.
		//
		// Measured on a live Keenetic: a list carrying teamviewer.com took its set from 15
		// to 22 members across three lookups and the set's MARK rule counted packets, in fast mode,
		// with no TUN anywhere. The warning fired anyway and advised switching routing mode to fix
		// something that already worked. Advice that talks a user out of a correct configuration is
		// worse than silence.
		if kernelCarriesDomains {
			continue
		}
		if rl.DomainSource != "" || len(rl.DomainCache) > 0 {
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
		req.Header.Set("User-Agent", "wayhop")
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
				log.Printf("wayhop: could not persist subscription URL for auto-refresh: %v", err)
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

	// The single-endpoint gate is worth nothing if the bulk path walks around it, and bulk is the
	// path a subscription import takes — the largest source of protocols this host may not have.
	//
	// Refusing the whole batch over one unsupported entry would make importing a fifty-exit
	// subscription an all-or-nothing bet on the weakest member, so a permanently unsupported
	// endpoint is stored DISABLED instead and named in the response. That keeps the import while
	// holding the same line as the single gate: nothing the host cannot carry arrives enabled.
	// Changing what the caller sent is only acceptable BECAUSE it is reported; a silent flip would
	// be its own defect.
	//
	// Unknown is different and refuses the batch: the host has not finished answering, so disabling
	// would be a guess in one direction and enabling a guess in the other.
	gated := make([]string, 0)
	for i := range eps {
		code, msg := s.gateEndpoint(r.Context(), eps[i])
		switch code {
		case 0:
			// nothing in the way
		case http.StatusServiceUnavailable:
			writeErr(w, http.StatusServiceUnavailable, "this host has not finished reporting what it can run, "+
				"so this import would be a guess: "+msg)
			return
		default:
			eps[i].Enabled = false
			gated = append(gated, eps[i].Name+" ("+string(eps[i].Protocol)+"): "+msg)
		}
	}
	// Persist the whole deduped set in ONE write. A per-endpoint UpsertEndpoint loop rewrites the
	// entire growing profile and fsyncs once per endpoint — O(N^2) bytes + a multi-minute wmu stall +
	// flash wear that an unauthenticated LAN client (or a large legit subscription) could trigger.
	// Endpoints with no ID are skipped and surfaced, mirroring the prior per-endpoint behavior.
	errs := []string{}
	skipped, err := s.store.UpsertEndpoints(eps)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "persist endpoints: "+err.Error())
		return
	}
	for range skipped {
		errs = append(errs, "skipped an endpoint with no id")
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": len(eps) - len(skipped), "duplicates": dupes,
		"errors": errs, "stored_disabled": gated})
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
// accelKind returns this host's forwarding-accelerator kind ("nft-flowtable" | "ppe" | ""),
// detected once and cached. It gates WayHop's nft flow-offload so a flowtable is compiled ONLY on a
// host whose kernel supports it — never on Keenetic (firmware PPE, no nftables) or a kernel without
// CONFIG_NF_FLOW_TABLE, where the best-effort offload transaction would just be rejected. Demo
// pretends to be a capable OpenWrt box so the demo UI can exercise the offload knobs.
func (s *Server) accelKind() string {
	s.detectAccel()
	return s.accelKindCached
}

// accelHW reports whether a HARDWARE fast path is present. Separate from accelKind because "auto"
// must distinguish a kernel that can only do software offload from one that can do both — resolving
// auto to "hw" on the former would compile a flowtable the kernel then rejects.
func (s *Server) accelHW() bool {
	s.detectAccel()
	return s.accelHWCached
}

// detectAccel probes once and caches both fields together, so kind and HW can never be read from
// two different detections.
func (s *Server) detectAccel() {
	s.accelOnce.Do(func() {
		if s.config().Demo {
			s.accelKindCached, s.accelHWCached = "nft-flowtable", true
			return
		}
		a := platform.DetectCapabilities().Accel
		s.accelKindCached, s.accelHWCached = a.Kind, a.HW
	})
}

// kernelPBRAvailable reports whether this host can run WayHop's nftables kernel-PBR plane. It CANNOT
// on Keenetic (KeeneticOS ships no nftables and the native routing backend is not yet wired into the
// apply path — see cmd/wayhop/main.go) or on any host without the `nft` binary. Detected once and
// cached. When false, the daemon skips the nft plane entirely — Apply proceeds in monitor/sing-box
// mode, and the reconcile loop + PBR health probe are no-ops — instead of exec-failing `nft` on every
// apply and every 30s reconcile (the P0 that made fast/hybrid unusable on Keenetic).
func (s *Server) kernelPBRAvailable() bool {
	s.pbrAvailOnce.Do(func() {
		// A test/mock runner (not the real ExecRunner) records commands without touching the host, so
		// the gate — which exists only to avoid exec-failing `nft` on a live router — does not apply:
		// the plane logic must run so tests observe it. Only the real ExecRunner path is gated.
		if _, isExec := s.pbrRunner.(pbr.ExecRunner); !isExec {
			s.pbrAvail = true
			return
		}
		switch {
		case s.config().Demo:
			s.pbrAvail = true // demo poses as a capable OpenWrt box (nft never actually runs)
		case platform.Detect() == platform.Keenetic:
			s.pbrAvail = keeneticKernelPBRPresent()
		default:
			_, err := exec.LookPath("nft")
			s.pbrAvail = err == nil
		}
	})
	return s.pbrAvail
}

func (s *Server) pbrCompileOptions(c config.Config) pbr.Options {
	opts := pbr.Options{}
	// KeeneticOS carries domain matchers through dnsmasq rather than the kernel: the resolver adds
	// each answer's address to the zone's ipset at query time, and the existing MARK rule then
	// matches by address. That is how keen-pbr did it, and it is the only way a domain reaches a
	// kernel plane at all — nftables/iptables cannot match names. Collecting the domains here is what
	// turns them into ipset= directives instead of a warning-and-drop.
	//
	// It is deliberately not conditioned on routing mode: the collection is pure, and a zone with no
	// domains renders nothing.
	if platform.Detect() == platform.Keenetic {
		opts.CollectDomainZones = true
	}
	if s.routingMode(c) != "fast" {
		return opts
	}
	// "auto" is resolved against the capability probe FIRST, so everything downstream sees a concrete
	// mode. Resolution is a pure function of the probe, so preview, apply and reconcile cannot
	// disagree about what auto meant on this host.
	opts.Offload = c.Offload
	if opts.Offload == "auto" {
		opts.Offload, _ = platform.ResolveOffload("auto", platform.Capabilities{Accel: platform.Accel{
			Kind: s.accelKind(), HW: s.accelHW(),
		}})
	}
	// Compile a flow-offload flowtable ONLY where the kernel supports it. On Keenetic (PPE, no
	// nftables) or a kernel without CONFIG_NF_FLOW_TABLE, force it off so preview/apply/reconcile
	// agree and the best-effort offload transaction has nothing to reject. The UI gates the selector
	// on the same capability, so this only ever silently drops a stale/API-set value on a box that
	// can't honor it — safe, and better than a flowtable that can never load.
	if (opts.Offload == "sw" || opts.Offload == "hw") && s.accelKind() != "nft-flowtable" {
		opts.Offload = ""
	}
	devs := c.OffloadDevices
	if (opts.Offload == "sw" || opts.Offload == "hw") && len(devs) == 0 && !c.Demo {
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
	mode := s.routingMode(c)
	opts := generator.Options{
		MixedPort:   c.Ports.Mixed,
		ClashAddr:   managedClashAddress(c),
		ClashSecret: c.Clash.Secret,
		CacheFile:   filepath.Join(filepath.Dir(c.SingBox.Config), "cache.db"),
		// Default download outbound for remote rule-sets ("" = direct). On a censored WAN direct
		// downloads fail/return block pages, and one failing rule-set aborts the whole core.
		RuleSetDetour: c.RuleSetDetour,
		// The TUN capture-all inbound is driven by the RESOLVED routing mode, not c.Gateway:
		// "tun"/"hybrid" need the TUN, "mixed"/"fast" do not. c.Gateway is only a mode INPUT
		// (routingMode derives "" from it), so keying TunEnabled off it directly meant an
		// explicit routing_mode="tun" with gateway=false emitted NO tun inbound (all LAN
		// traffic egressed clear), and routing_mode="mixed" with gateway=true wrongly emitted
		// one. fast/hybrid re-set this below from the same resolved mode.
		TunEnabled: mode == "tun" || mode == "hybrid",
		TunMTU:     c.GatewayMTU,
		TunAddr:    c.GatewayAddr,
	}
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
		// Fail SAFE, not open: capture everything through the TUN so nothing leaks while the
		// kernel plane is absent. We only reach here for hybrid/fast (past the early return);
		// keying this off c.Gateway could yield TunEnabled=false and silently egress the
		// censored traffic clear on a compile error.
		opts.TunEnabled = true
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
// Fail-safe by construction (see docs/NATIVE_P4_DESIGN.md §h) in the development repository:
// DatapathNativeOnly returns true ONLY when the kernel plane provably carries everything (fast
// mode, every endpoint kernel-native, default egress direct/WAN, nothing surviving into sing-box) —
// on ANY doubt it returns false and sing-box is KEPT. Skipping the core is the only change that can
// black-hole traffic; this predicate is the gate that makes the skip safe.
func (s *Server) datapathNativeOnly(c config.Config, p *model.Profile) bool {
	return generator.DatapathNativeOnly(p, s.routingMode(c))
}

// nativeOnlyCached is datapathNativeOnly for the read-only hot path (the ~5s /api/health
// poll). The verdict is a pure function of (profile, routing mode), so it's memoized on
// (store gen, mode): a hit returns instantly, skipping both the full Profile() clone and
// the profile walk. gen is read BEFORE the profile snapshot on a miss, so a mutation racing
// between the two only ever forces one extra recompute — never serves a stale verdict.
func (s *Server) nativeOnlyCached() bool {
	if s.store == nil {
		return false
	}
	gen := s.store.Gen()
	mode := s.routingMode(s.config())
	s.nativeOnlyMu.Lock()
	if s.nativeOnlyOK && s.nativeOnlyGen == gen && s.nativeOnlyMode == mode {
		v := s.nativeOnlyVal
		s.nativeOnlyMu.Unlock()
		return v
	}
	s.nativeOnlyMu.Unlock()

	p := s.store.Profile()
	// Ask the question the Apply review asks, not a differently-shaped one. datapathRequiresCore is
	// per-platform (on Keenetic it is keenetic.PlanRequiresCore); generator.DatapathNativeOnly is the
	// generic predicate, and it hard-requires routing mode "fast" in a sense KeeneticOS never
	// satisfies — so this answered false on a router whose datapath is entirely native, and the
	// dashboard called a working, routing router OFFLINE with "proxy core not running".
	v := !s.datapathRequiresCore(s.config(), p)

	s.nativeOnlyMu.Lock()
	s.nativeOnlyGen, s.nativeOnlyMode, s.nativeOnlyVal, s.nativeOnlyOK = gen, mode, v, true
	s.nativeOnlyMu.Unlock()
	return v
}

// failedPluginSummary lists the tracked plugins that are NOT running, with the reason the manager
// recorded. It is the counterpart to pluginSummary, which reports the set the generator WANTED —
// a desired-state list that reads identically whether every engine came up or none did.
func failedPluginSummary(st []plugin.Status) []map[string]any {
	out := make([]map[string]any, 0, len(st))
	for _, p := range st {
		if p.Running {
			continue
		}
		row := map[string]any{"id": p.ID, "engine": p.Engine, "needs_binary": p.NeedsBinary}
		if p.Reason != "" {
			row["reason"] = p.Reason
		}
		out = append(out, row)
	}
	return out
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

// handleRoutingReorder rewrites the routing-list order.
//
// Order is behaviour: the generator emits one route rule per list in slice order and sing-box takes
// the first match, so moving a list changes which one wins. The store refuses a body that does not
// name every list exactly once, because a reorder that silently drops a rule is worse than one that
// fails loudly.
func (s *Server) handleRoutingReorder(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid reorder JSON")
		return
	}
	if err := s.store.ReorderRoutingLists(body.IDs); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p := s.store.Profile()
	out := make([]string, 0, len(p.RoutingLists))
	for i := range p.RoutingLists {
		out = append(out, p.RoutingLists[i].ID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ids": out})
}
