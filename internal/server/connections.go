package server

import (
	"context"
	"net/http"
	"sort"
	"time"

	"wayhop/internal/clash"
)

// handleConnections exposes the live Clash /connections list for the Dashboard's
// connections table (host · chain · rule · up/down · age). Degrades to an empty list
// when the Clash controller is unreachable (sing-box not running / demo) so the UI
// shows a clean empty state. Capped server-side to the top-N by total bytes so the
// payload and the DOM stay bounded.
func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	empty := clash.Connections{Connections: []clash.Conn{}}
	if s.clash == nil {
		writeJSON(w, http.StatusOK, empty)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	conns, err := s.clash.Connections(ctx)
	if err != nil {
		writeJSON(w, http.StatusOK, empty)
		return
	}
	sort.Slice(conns.Connections, func(i, j int) bool {
		return conns.Connections[i].Upload+conns.Connections[i].Download >
			conns.Connections[j].Upload+conns.Connections[j].Download
	})
	const maxRows = 60
	if len(conns.Connections) > maxRows {
		conns.Connections = conns.Connections[:maxRows]
	}
	writeJSON(w, http.StatusOK, conns)
}
