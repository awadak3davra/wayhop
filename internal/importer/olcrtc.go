package importer

import (
	"errors"
	"strings"
)

// errOlcRTCRetired answers a pasted olcRTC config. WayHop carried olcRTC as a chained SOCKS engine
// until upstream (openlibrecommunity/olcrtc) was archived on 2026-09-30 with its author calling it
// end of life; the meet services it rides change without notice, so an unmaintained client is a
// connection that stops working with nobody to fix it. The config is still recognised so the
// operator learns why it is refused instead of reading it as an unknown format.
var errOlcRTCRetired = errors.New("olcRTC is no longer supported: the project ended (archived 2026-09-30) and WayHop removed it; use another protocol for this server")

// looksLikeOlcRTC heuristically detects a pasted olcRTC YAML config. Parse calls it only for input
// without a URI scheme, so a share link whose #fragment carries these words is never refused.
func looksLikeOlcRTC(s string) bool {
	low := strings.ToLower(s)
	return strings.Contains(low, "provider:") &&
		(strings.Contains(low, "crypto") || strings.Contains(low, "datachannel") ||
			strings.Contains(low, "jitsi") || strings.Contains(low, "telemost") || strings.Contains(low, "wbstream"))
}
