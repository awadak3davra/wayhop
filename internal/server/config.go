package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"velinx/internal/config"
)

// config returns a value snapshot of the live config taken under cfgMu. ALL
// reads of s.cfg outside the write path must go through this, so they can't race
// handlePutConfig/subToken mutating the shared struct (a torn read of a string/
// slice header can crash). The copy is cheap and read-only for the caller.
func (s *Server) config() config.Config {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	return *s.cfg
}

// handleGetConfig returns the current daemon configuration (LAN tool — secrets
// are returned so the user can see/edit them).
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.config())
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
	if err := s.persistConfig(in); err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": true, "restart_needed": restartNeeded(old, *in)})
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
// it durably, under cfgMu so it can't race subToken()/handleGetConfig() or the
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
		return fmt.Errorf(`listen must be host:port (e.g. ":8088" or "192.168.1.1:8088")`)
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
	dst.OffloadDevices = in.OffloadDevices
	dst.Ports = in.Ports
	dst.Clash = in.Clash
	dst.SingBox = in.SingBox
	dst.Updater = in.Updater
	dst.FailSafe = in.FailSafe
	dst.Watchdog = in.Watchdog
	dst.AllowedHosts = in.AllowedHosts
	// NOT copied: Subscription (token protection — rotated via its own path).
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
// Secrets (clash secret, subscription token, watchdog webhook) are REDACTED by
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
	w.Header().Set("Content-Disposition", `attachment; filename="velinx-config.json"`)
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
	if err := s.persistConfig(&in); err != nil {
		writeErr(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": true, "restart_needed": restartNeeded(old, in)})
}

// handleConfigReset restores default settings while PRESERVING the fields that
// keep the operator reachable: the bind (Listen + Ports.UI), the Host allow-list,
// and the subscription token. Without that carve-out a reset could move the UI
// port or strand the user with no way back into the panel. Most changes need a
// restart.
func (s *Server) handleConfigReset(w http.ResponseWriter, r *http.Request) {
	old := s.config()
	def := config.Default()
	def.Listen = old.Listen
	def.Ports.UI = old.Ports.UI
	def.AllowedHosts = old.AllowedHosts
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
