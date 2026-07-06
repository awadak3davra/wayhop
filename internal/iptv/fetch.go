package iptv

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// maxPlaylistBytes bounds a single source fetch so a malicious/huge upstream can't exhaust a router's
// RAM (Parse itself streams line-by-line, but the read is still capped defensively).
const maxPlaylistBytes = 16 << 20 // 16 MiB

// FetchPlaylist GETs url with the injected (SSRF-guarded) client and parses the M3U it returns,
// reading at most maxBytes (0 → 16 MiB). The client carries the security policy (allowed hosts,
// dial guard); this function only bounds size + status. A non-2xx status is an error so the caller
// keeps the list's last-good playlist rather than overwriting it with an error page.
func FetchPlaylist(ctx context.Context, client *http.Client, url string, maxBytes int64) (*Playlist, error) {
	if client == nil {
		return nil, fmt.Errorf("fetch %s: nil client", url)
	}
	if maxBytes <= 0 {
		maxBytes = maxPlaylistBytes
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "WayHop-IPTV/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	return Parse(io.LimitReader(resp.Body, maxBytes))
}
