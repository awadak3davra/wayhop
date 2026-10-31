package importer

import (
	"fmt"
	"strconv"
	"strings"

	"wayhop/internal/model"
)

// clashSnell maps a Clash / mihomo `type: snell` proxy. mihomo speaks Snell v1-v5 (no version means
// v1, and v5 is sent as v4); sing-box carries v4 and v6. So v4 and v5 import as v4, and v1-v3 are
// refused by version rather than stored as a connection the core cannot speak. mihomo's obfs-opts
// mode may be http or tls; sing-box's v4 obfuscation is HTTP only.
func clashSnell(p proxyMap, server string, port int, name string) (*model.Endpoint, error) {
	if port == 0 {
		return nil, fmt.Errorf("snell: missing/invalid port")
	}
	if p["psk"] == "" {
		return nil, fmt.Errorf("snell %s: missing psk", name)
	}
	version := 1
	if v := strings.TrimSpace(p["version"]); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("snell %s: version %q is not a number", name, v)
		}
		version = n
	}
	switch version {
	case 4, 5:
		version = 4
	default:
		return nil, fmt.Errorf("snell %s: version %d; sing-box carries Snell v4 and v6 only", name, version)
	}
	params := map[string]any{"version": version, "psk": p["psk"]}
	if p["reuse"] == "true" {
		params["reuse"] = true
	}
	// mihomo enables UDP only when asked; sing-box enables both unless told otherwise.
	if p["udp"] != "true" {
		params["network"] = "tcp"
	}
	switch mode := p["obfs-opts.mode"]; mode {
	case "", "none":
	case "http":
		params["obfs_mode"] = "http"
		if h := p["obfs-opts.host"]; h != "" {
			params["obfs_host"] = h
		}
	default:
		return nil, fmt.Errorf("snell %s: obfs mode %q; sing-box obfuscates Snell v4 with http only", name, mode)
	}
	return &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoSnell,
		Server:   server,
		Port:     port,
		Name:     name,
		Enabled:  true,
		Params:   params,
	}, nil
}
