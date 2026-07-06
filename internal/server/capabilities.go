package server

import (
	"net/http"

	"wayhop/internal/platform"
)

// handleNativeCapabilities reports what the host can route natively (kernel/firmware
// paths present NOW), which protocols are installable and via which package, and which
// proxy protocols still require sing-box. Read-only host probe; captures no secrets.
// The verdict is computed server-side (platform.DetectCapabilities) so every client agrees.
func (s *Server) handleNativeCapabilities(w http.ResponseWriter, r *http.Request) {
	caps := platform.DetectCapabilities()
	writeJSON(w, http.StatusOK, caps)
}
