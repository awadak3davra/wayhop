package importer

import (
	"net/url"
	"strings"

	"velinx/internal/model"
)

// looksLikeOlcRTC detects an olcRTC client YAML config (WebRTC-over-meet tunnel).
func looksLikeOlcRTC(s string) bool {
	low := strings.ToLower(s)
	return strings.Contains(low, "provider:") &&
		(strings.Contains(low, "crypto") || strings.Contains(low, "datachannel") ||
			strings.Contains(low, "jitsi") || strings.Contains(low, "telemost") || strings.Contains(low, "wbstream"))
}

// parseOlcRTC parses an olcRTC client YAML config into an endpoint. olcRTC runs
// as a chained SOCKS engine plugin (its traffic rides a Jitsi/Telemost/WbStream
// WebRTC session, so it bypasses IP whitelists). Fields: auth.provider, room.id,
// crypto.key, net.transport, net.dns.
func parseOlcRTC(text string) (*model.Endpoint, error) {
	provider := yamlVal(text, "auth", "provider")
	room := yamlVal(text, "room", "id")
	key := yamlVal(text, "crypto", "key")
	transport := yamlVal(text, "net", "transport")
	dns := yamlVal(text, "net", "dns")

	e := &model.Endpoint{
		Engine:   model.EngineOlcRTC,
		Protocol: model.ProtoOlcRTC,
		Params: map[string]any{
			"provider": provider,
			"room":     room,
			"key":      key,
		},
	}
	if transport != "" {
		e.Params["transport"] = transport
	}
	if dns != "" {
		e.Params["dns"] = dns
	}

	// olcRTC has no classic server:port (traffic goes via the meet room); use the
	// meet host so the model validates and the UI shows something meaningful.
	host := room
	if u, err := url.Parse(room); err == nil && u.Host != "" {
		host = u.Hostname()
	}
	e.Server = host
	e.Port = 443
	e.Name = "olcRTC " + provider
	return e, nil
}

// yamlVal reads `key:` under top-level `parent:` from a simple 2-space-indented
// YAML doc — enough for olcRTC configs, and avoids pulling in a YAML dependency.
func yamlVal(text, parent, key string) string {
	inParent := false
	for _, ln := range strings.Split(text, "\n") {
		if ln == "" {
			continue
		}
		indent := len(ln) - len(strings.TrimLeft(ln, " \t"))
		t := strings.TrimSpace(ln)
		if indent == 0 {
			inParent = strings.HasPrefix(t, parent+":")
			continue
		}
		if inParent && strings.HasPrefix(t, key+":") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, key+":")), `"'`)
		}
	}
	return ""
}
