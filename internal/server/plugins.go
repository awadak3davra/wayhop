package server

import "net/http"

// handlePlugins lists the engine plugins (AmneziaWG, olcRTC) and their state.
func (s *Server) handlePlugins(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.plugins.Status())
}
