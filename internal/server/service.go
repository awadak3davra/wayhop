package server

import "net/http"

// handleServiceRestart restarts the WHOLE WayHop service via the init system
// (procd on OpenWrt, busybox sysvinit on Entware). Restarting the daemon — not
// just reloading the proxy core — means this process exits and the init system
// brings up a fresh one, so the web panel briefly drops then returns. The actual
// restart command is platform-specific (restartCommand); it is detached so it
// survives this process being killed mid-restart. Where no init system is present
// (e.g. the Windows demo), restartCommand returns nil and we report 503 rather
// than tearing anything down.
func (s *Server) handleServiceRestart(w http.ResponseWriter, r *http.Request) {
	cmd := restartCommand()
	if cmd == nil {
		writeErr(w, http.StatusServiceUnavailable, "service restart is not available in this environment")
		return
	}
	if err := cmd.Start(); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start restart: "+err.Error())
		return
	}
	// Don't Wait — the command kills us as part of the restart. Respond first so
	// the 200 flushes before the connection drops.
	writeJSON(w, http.StatusOK, map[string]any{"restarting": true})
}
