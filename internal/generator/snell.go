package generator

import (
	"fmt"
	"strconv"

	"wayhop/internal/model"
)

// snellMinMinor is the first sing-box 1.x minor with the snell outbound.
const snellMinMinor = 14

// snellOutbound fills a sing-box snell outbound (1.14+). sing-box speaks Snell v4 (HTTP obfs) and v6
// (traffic shaping); v5 is v4 on the wire, which is what the importers store it as.
func snellOutbound(e *model.Endpoint, ob map[string]any) error {
	p := e.Params
	version := intp(p, "version")
	if version == 0 {
		version, _ = strconv.Atoi(str(p, "version"))
	}
	if version != 4 && version != 6 {
		return fmt.Errorf("snell version %d: sing-box carries v4 and v6", version)
	}
	ob["type"] = "snell"
	ob["version"] = version
	ob["psk"] = str(p, "psk")
	if k := str(p, "userkey"); k != "" {
		ob["userkey"] = k
	}
	if boolp(p, "reuse") {
		ob["reuse"] = true
	}
	if n := str(p, "network"); n == "tcp" || n == "udp" {
		ob["network"] = n
	}
	switch version {
	case 4:
		if str(p, "obfs_mode") == "http" {
			ob["obfs_mode"] = "http"
			if h := str(p, "obfs_host"); h != "" {
				ob["obfs_host"] = h
			}
		}
	case 6:
		if m := str(p, "mode"); m == "default" || m == "unshaped" || m == "unsafe-raw" {
			ob["mode"] = m
		}
	}
	return nil
}
