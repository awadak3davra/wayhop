package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"wayhop/internal/config"
)

// config returns a value snapshot of the live config taken under cfgMu. ALL
// reads of s.cfg outside the write path must go through this, so they can't race
// handlePutConfig/subToken mutating the shared struct (a torn read of a string/
// slice header can crash). The copy is cheap and read-only for the caller.
// demoMode answers the one config question the handlers ask outside a fully-built Server.
//
// config() dereferences s.cfg unconditionally, which is right for the daemon — a Server without a
// config is not a thing that runs — but several handler tests construct a Server with only the field
// under test (&Server{updater: up}), and a handler that merely reports whether it is in demo mode
// should not be the reason such a test panics. Absent config means "not a demo": the demo is
// something you switch ON.
func (s *Server) demoMode() bool {
	if s == nil {
		return false
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	return s.cfg != nil && s.cfg.Demo
}

func (s *Server) config() config.Config {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	c := *s.cfg
	// A value copy ALIASES the Features map. Nothing writes it any more — the optional-module
	// (Plugins/IPTV) surface that did now sits in deferred/features/plugins-iptv/_go/ — but the field
	// stays for config-file compatibility, and the clone stays because aliasing a map across a
	// snapshot boundary is a bug waiting for the next writer, not a cost worth shaving
	// (under cfgMu). A caller that ranges/reads the aliased map after this lock is released would
	// then race that write — "concurrent map iteration and map write" is fatal. Clone it here (the
	// single read chokepoint) so every snapshot is truly independent; Features is tiny, the copy is cheap.
	if s.cfg.Features != nil {
		c.Features = make(map[string]config.FeatureConfig, len(s.cfg.Features))
		for k, v := range s.cfg.Features {
			c.Features[k] = v
		}
	}
	return c
}

// allowedHosts returns a copy of the live AllowedHosts list under cfgMu — a cheap read for the
// per-request hostAllowGuard. It avoids config()'s full-config snapshot (which clones the Features
// map on EVERY call), so the guard's disabled default (allowed_hosts unset) stays effectively
// zero-cost — just a lock + a len check + a nil return — as its contract promises, instead of
// allocating and copying the whole config purely to read one slice on every request.
func (s *Server) allowedHosts() []string {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if len(s.cfg.AllowedHosts) == 0 {
		return nil
	}
	return append([]string(nil), s.cfg.AllowedHosts...)
}

// allowAnyHost reports the explicit compatibility opt-out from the Host allow-list. It is read per
// request so clearing it takes effect without a restart.
func (s *Server) allowAnyHost() bool {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	return s.cfg.AllowAnyHost
}

// handleGetConfig returns the current daemon configuration. Settings can edit the
// Clash/webhook fields, but it never edits the imported subscription URL; exposing
// that provider credential here served no UI purpose. Keep it masked and use the
// dedicated /api/subscription/info display DTO for its redacted provider identity.
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	// The response still carries editable credential-bearing settings, so keep it out of any
	// browser/proxy cache, matching handleConfigExport / subscription / backup / job-snapshot.
	w.Header().Set("Cache-Control", "no-store")
	cfg := s.config()
	if cfg.Subscription.URL != "" {
		cfg.Subscription.URL = config.RedactedMark
	}
	if cfg.Auth.PasswordHash != "" {
		cfg.Auth.PasswordHash = config.RedactedMark
	}
	cfg.Telegram = cfg.Telegram.Redacted()
	writeJSON(w, http.StatusOK, cfg)
}

// handleConfigDefaults returns the configuration a fresh install would start with.
//
// The Settings index offers a "not default" filter, and there is no honest way to compute that in
// the browser: hard-coding a copy of the defaults there would drift from config.Default() the first
// time a default changed, and the page would then quietly mislabel settings as customised (or, worse,
// as untouched). Serving the real thing keeps one source of truth.
//
// Secrets are cleared rather than shipped. A default config carries no user secrets today, but a
// field added later would otherwise leak through this route, and a defaults endpoint has no reason
// to be credential-bearing.
// EVERY field is present, including the ones whose default is the zero value. Marshalling the struct
// directly does not do that: most fields carry `omitempty`, so a default of "" or 0 vanished from the
// payload — and the Settings index, which reads this to answer "is this still the default", could
// then only say "cannot be compared". Measured on a live router: `routing_mode`,
// `flow_offload` and `flow_offload_devices` were all absent, so the filter was blind to the routing
// mode, which is the most consequential setting on the page. Their defaults are not unknown; they are
// empty, and empty is an answer.
//
// The blanket rule also keeps the OTHER half working: a config path that is genuinely wrong (a typo
// in the page's metadata) is still absent from a complete payload, so it still reports honestly that
// it cannot be judged, instead of being silently compared against "".
func (s *Server) handleConfigDefaults(w http.ResponseWriter, r *http.Request) {
	d := config.Default()
	d.Clash.Secret = ""
	d.Watchdog.NotifyURL = ""
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, completeJSONFields(d))
}

// completeJSONFields renders a struct as a map holding every json-tagged field, recursing into nested
// structs and dereferencing pointers, so `omitempty` cannot hide a zero-valued default.
//
// Reflection rather than a hand-written mirror of config.Config: a second declaration of a hundred
// fields is a second thing to keep in step, and the whole point of serving the defaults from the
// daemon is that there is one source of truth for them.
func completeJSONFields(value any) any {
	return completeValue(reflect.ValueOf(value))
}

func completeValue(rv reflect.Value) any {
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		return completeValue(rv.Elem())
	case reflect.Struct:
		// time.Time and anything else that marshals itself must be left alone: walking its private
		// fields would produce an object where the JSON is a string.
		if rv.Type().Implements(reflect.TypeOf((*json.Marshaler)(nil)).Elem()) {
			return rv.Interface()
		}
		out := map[string]any{}
		t := rv.Type()
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if !field.IsExported() {
				continue
			}
			tag := field.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name := field.Name
			if comma := strings.IndexByte(tag, ','); comma >= 0 {
				if comma > 0 {
					name = tag[:comma]
				}
			} else if tag != "" {
				name = tag
			}
			// An embedded struct with no json name is inlined by encoding/json; mirror that, or its
			// fields would appear one level too deep and every path into them would break.
			if field.Anonymous && tag == "" {
				if inner, ok := completeValue(rv.Field(i)).(map[string]any); ok {
					for k, v := range inner {
						out[k] = v
					}
					continue
				}
			}
			out[name] = completeValue(rv.Field(i))
		}
		return out
	default:
		return rv.Interface()
	}
}

// handlePutConfig validates and saves a new configuration. The response reports
// whether a daemon restart is required for the change to take effect (see
// restartNeeded); hot fields apply on the next Apply or immediately.
func (s *Server) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	in, err := decodeConfigBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	old := s.config() // snapshot BEFORE persist (cfgMu is non-reentrant) for the restart diff
	if code, msg := s.gateRoutingMode(r.Context(), old, *in); code != 0 {
		writeErr(w, code, msg)
		return
	}
	if err := s.persistConfig(in); err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": true, "restart_needed": restartNeeded(old, *in)})
}

// gateRoutingMode refuses a SWITCH to a routing mode this host cannot run. The mode decides which
// planes Apply builds, and nothing on the server consulted the capability for it: a PUT (or a curl)
// naming hybrid on a box with no kernel PBR was stored 200, and the panel then showed a mode the
// datapath would never realise.
//
// The subject is the TRANSITION, not the stored value. A host that loses a capability — a package
// removed, a firmware downgrade — must still accept saves of every unrelated setting, or the mode it
// is already in would lock the operator out of Settings entirely.
func (s *Server) gateRoutingMode(ctx context.Context, old, next config.Config) (int, string) {
	// A demo instance configures nothing real — handlePBRApply short-circuits on the same flag before
	// it touches the kernel — so a capability verdict about the host running it is not the subject.
	// Enforcing it here would leave the demo panel unable to show the modes it exists to show. Only
	// while it STAYS a demo: a request that turns demo off is a request to start meaning it.
	if old.Demo && next.Demo {
		return 0, ""
	}
	from, to := s.routingMode(old), s.routingMode(next)
	if from == to {
		return 0, ""
	}
	cap, ok := s.capabilitySet(ctx, false).Items["routing.mode."+to]
	if !ok {
		return 0, "" // a mode this build does not evaluate has no verdict to enforce
	}
	switch gateState(cap.State) {
	case 0:
		return 0, ""
	case http.StatusServiceUnavailable:
		return http.StatusServiceUnavailable, "this host has not finished reporting whether it can run " +
			to + " routing, so switching to it now would be a guess. Retry once the capability probe completes."
	default:
		msg := "this host cannot run " + to + " routing"
		if cap.Detail != "" {
			msg += ": " + cap.Detail
		}
		if cap.Remedy != "" {
			msg += " " + cap.Remedy
		}
		return http.StatusUnprocessableEntity, msg
	}
}

// decodeConfigBody decodes, reconciles, and validates a config request body,
// returning a 400-worthy error for malformed JSON, a bad listen, or any value
// that would not start (config.Validate). Shared by PUT and import.
func decodeConfigBody(r *http.Request) (*config.Config, error) {
	var in config.Config
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return nil, fmt.Errorf("invalid JSON body")
	}
	if err := reconcileListen(&in); err != nil {
		return nil, err
	}
	if err := in.Validate(); err != nil {
		return nil, err
	}
	return &in, nil
}

// persistConfig applies in's user-settable fields onto the live config and saves
// it durably, under cfgMu so it can't race handleGetConfig() or the
// config.json.tmp file.
//
// applyConfigFields MUTATES the shared live config in place, but Save() can fail
// (full overlay / EROFS / IO). To avoid a memory/disk divergence — the live
// daemon using the new values while config.json on disk still holds the old ones,
// which a later reboot would silently revert to — we snapshot the live config
// BEFORE applying and restore it if Save() fails. A failed Save then leaves the
// live config UNCHANGED and consistent with the (atomically-untouched) disk file.
func (s *Server) persistConfig(in *config.Config) error {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	snap := cloneConfig(s.cfg)
	applyConfigFields(s.cfg, in)
	if err := s.cfg.Save(); err != nil {
		*s.cfg = snap // roll back the in-memory mutation: keep memory == disk
		return err
	}
	return nil
}

// cloneConfig returns a fully independent value copy of c suitable for restoring
// the live config after a failed Save. The struct value-copy carries every value
// field (and the unexported path); the reference fields that applyConfigFields
// replaces — OffloadDevices, AllowedHosts, and Updater.Mirrors — are deep-copied
// so the restored snapshot shares no backing array with c or with the incoming
// request config. (applyConfigFields only REPLACES these slices, so a plain
// value-copy would already restore correctly, but deep-copying keeps the snapshot
// self-contained and immune to any future element-wise mutation.)
func cloneConfig(c *config.Config) config.Config {
	snap := *c
	snap.OffloadDevices = cloneStrings(c.OffloadDevices)
	snap.AllowedHosts = cloneStrings(c.AllowedHosts)
	snap.Updater.Mirrors = cloneStrings(c.Updater.Mirrors)
	return snap
}

// cloneStrings returns a copy of s with its own backing array, preserving nil
// (so a round-tripped config marshals identically to the original).
func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}

// reconcileListen forces Listen's port to equal Ports.UI so the two encodings of
// the panel port can't diverge — editing the UI port in Settings MOVES the bind
// (the documented escape from the lighttpd :8088 conflict). Listen keeps its
// host/interface. A malformed Listen is rejected here, not at the next restart.
func reconcileListen(in *config.Config) error {
	host, _, err := net.SplitHostPort(in.Listen)
	if err != nil {
		return fmt.Errorf(`listen must be host:port (e.g. ":8088" or "192.168.50.1:8088")`)
	}
	in.Listen = net.JoinHostPort(host, strconv.Itoa(in.Ports.UI))
	return nil
}

// applyConfigFields copies the user-settable exported fields from in onto dst,
// preserving dst's unexported file path. Subscription is deliberately NOT copied:
// its token is rotated through its own path, never the bulk Settings PUT, so a
// Settings save can't invalidate a client's subscription URL.
// TestApplyConfigFields_CopiesEveryExportedField fails if a new exported config
// field is added without a copy line here (the silent-drop class that once hit
// the gateway flag and the offload fields).
func applyConfigFields(dst, in *config.Config) {
	dst.Listen = in.Listen
	dst.DataDir = in.DataDir
	dst.Demo = in.Demo
	dst.Gateway = in.Gateway
	dst.GatewayMTU = in.GatewayMTU
	dst.GatewayAddr = in.GatewayAddr
	dst.RoutingMode = in.RoutingMode
	dst.Offload = in.Offload
	dst.RuleSetDetour = in.RuleSetDetour
	dst.NativeFirewallZone = in.NativeFirewallZone
	dst.OffloadDevices = in.OffloadDevices
	dst.Ports = in.Ports
	dst.Clash = in.Clash
	dst.SingBox = in.SingBox
	dst.Updater = in.Updater
	dst.FailSafe = in.FailSafe
	dst.Watchdog = in.Watchdog
	dst.AllowedHosts = in.AllowedHosts
	dst.AllowAnyHost = in.AllowAnyHost
	dst.Backup = in.Backup
	// NOT copied: Telegram (its own /api/telegram/* endpoints and the bot's pairing write it; the
	// Settings page sends a masked token, so copying it would store "***" as the token).
	// NOT copied: Auth (credential setup/rotation only) + Subscription (managed by its import settings endpoint) + Features (per-plugin
	// toggles/settings persisted via PUT /api/features/{id}, never the bulk Settings PUT)
	// + IgnoredDrift (dismissed drift warnings, written by setIgnoredDrift). The Settings page
	// never sends `ignored_drift`, so copying it here would silently wipe every dismissal on the
	// next save of an unrelated setting — the same silent-drop class from the other direction.
}

// restartNeeded reports whether moving old->nw requires a daemon restart to take
// effect. Only fields consumed at startup — the bind, the reserved ports, the
// proxy-core wiring, and demo synthesis — need one; the rest (failsafe target,
// watchdog URL, updater mirrors, routing_mode, and allowed_hosts now that the
// host guard is evaluated per request) apply on the next Apply or immediately.
func restartNeeded(old, nw config.Config) bool {
	return old.Listen != nw.Listen ||
		old.Ports != nw.Ports ||
		old.SingBox != nw.SingBox ||
		old.Clash != nw.Clash ||
		old.Demo != nw.Demo
}

// validatePorts is retained as a thin wrapper over config.Ports.Validate for the
// existing port-validation test; new code validates via config.Validate.
func validatePorts(p config.Ports) error { return p.Validate() }

// handleConfigExport returns the daemon config as a downloadable JSON attachment.
// Secrets (clash secret, subscription URL, watchdog webhook) are REDACTED by
// default so a backup shared for support can't leak credentials; ?secrets=1
// includes them for a full personal backup. Read-only.
func (s *Server) handleConfigExport(w http.ResponseWriter, r *http.Request) {
	cfg := s.config()
	if r.URL.Query().Get("secrets") != "1" {
		cfg = cfg.Redacted()
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "marshal failed: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="wayhop-config.json"`)
	// With ?secrets=1 this is the unredacted config (clash secret, subscription URL, webhook);
	// keep it out of any browser/proxy cache, matching the QR/subscription/backup handlers.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleConfigImport replaces the daemon config from an uploaded backup. The body
// is reconciled/validated exactly like PUT, and a secret still equal to the
// redaction sentinel means "keep the current value" so importing a redacted
// backup doesn't wipe secrets. Most changes need a restart.
func (s *Server) handleConfigImport(w http.ResponseWriter, r *http.Request) {
	var in config.Config
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	old := s.config()
	// Un-redact: a sentinel secret means "unchanged" — don't persist the mask.
	if in.Clash.Secret == config.RedactedMark {
		in.Clash.Secret = old.Clash.Secret
	}
	if in.Watchdog.NotifyURL == config.RedactedMark {
		in.Watchdog.NotifyURL = old.Watchdog.NotifyURL
	}
	// Subscription is never applied (see applyConfigFields), so its sentinel is moot.
	if err := reconcileListen(&in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := in.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if code, msg := s.gateRoutingMode(r.Context(), old, in); code != 0 {
		writeErr(w, code, msg)
		return
	}
	if err := s.persistConfig(&in); err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": true, "restart_needed": restartNeeded(old, in)})
}

// handleConfigReset restores default settings while PRESERVING the fields that
// keep the operator reachable: the bind (Listen + Ports.UI) and Host allow-list.
// Without that carve-out a reset could move the UI port or strand the user with
// no way back into the panel. Most changes need a restart.
func (s *Server) handleConfigReset(w http.ResponseWriter, r *http.Request) {
	old := s.config()
	def := config.Default()
	def.Listen = old.Listen
	def.Ports.UI = old.Ports.UI
	def.AllowedHosts = old.AllowedHosts
	def.AllowAnyHost = old.AllowAnyHost
	def.Subscription = old.Subscription // moot (Subscription not copied) but explicit
	// Preserve the Clash-API secret: it authenticates the daemon's own Clash client to the
	// live (still-running, old-secret) sing-box, so regenerating it on reset would break the
	// Dashboard/health views until the next Apply+restart. It's an internal secret (not a
	// panel-access vector), so preserving it is invisible to the user and avoids that outage.
	def.Clash.Secret = old.Clash.Secret
	if err := reconcileListen(def); err != nil {
		def.Listen = fmt.Sprintf(":%d", def.Ports.UI) // old listen was malformed; fall back to default host + preserved port
	}
	// Reset is a recovery action, so it must always produce a VALID config. The only
	// preserved user-data that could be invalid is AllowedHosts (e.g. a blank entry
	// from a hand-edited config.json); if it makes the reset config invalid, drop it
	// rather than refuse to reset. A final Validate guards against any other surprise.
	if err := def.Validate(); err != nil {
		def.AllowedHosts = nil
		if err := def.Validate(); err != nil {
			writeErr(w, http.StatusInternalServerError, "reset produced an invalid config: "+err.Error())
			return
		}
	}
	if err := s.persistConfig(def); err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": true, "restart_needed": restartNeeded(old, *def)})
}
