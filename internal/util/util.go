// Package util holds tiny stateless helpers shared across packages to avoid
// byte-for-byte duplication (see the audit's DRY findings). Intentionally minimal.
package util

import "strings"

// FirstNonEmpty returns the first non-empty argument, or "".
func FirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// LocalAddr renders a WireGuard/AmneziaWG "local_address" param — which may be a
// string, []string, or []any (from decoded JSON) — as a comma-joined string.
func LocalAddr(p map[string]any) string {
	switch t := p["local_address"].(type) {
	case []string:
		return strings.Join(t, ", ")
	case []any:
		var ss []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				ss = append(ss, s)
			}
		}
		return strings.Join(ss, ", ")
	case string:
		return t
	}
	return ""
}

// LocalAddrs returns the WireGuard/AmneziaWG interface addresses as a slice — the
// un-joined form of LocalAddr. Callers that add addresses one syscall at a time
// (`ip addr add`, which rejects a comma-joined argument) must use this so a
// dual-stack config ("10.0.0.2/32, fd00::2/128") gets BOTH addresses, not a
// single failed add. A legacy comma-joined string value is split on commas.
func LocalAddrs(p map[string]any) []string {
	clean := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, s := range in {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	switch t := p["local_address"].(type) {
	case []string:
		return clean(t)
	case []any:
		var ss []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				ss = append(ss, s)
			}
		}
		return clean(ss)
	case string:
		return clean(strings.Split(t, ","))
	}
	return nil
}

// WGAllowedIPs returns the WireGuard/AmneziaWG peer AllowedIPs for a full-tunnel export/config,
// chosen by the endpoint's local_address family: 0.0.0.0/0 when any IPv4 local address is present,
// with ::/0 appended when any IPv6 is — so a dual-stack or IPv6-only endpoint TUNNELS its IPv6 rather
// than leaking it outside the tunnel (or routing nothing at all). Defaults to 0.0.0.0/0 (the common
// IPv4 case) when no local address is configured.
func WGAllowedIPs(p map[string]any) string {
	v4, v6 := false, false
	for _, a := range LocalAddrs(p) {
		host := a
		if i := strings.IndexByte(host, '/'); i >= 0 {
			host = host[:i] // drop any CIDR suffix
		}
		if strings.Contains(host, ":") {
			v6 = true
		} else if host != "" {
			v4 = true
		}
	}
	switch {
	case v4 && v6:
		return "0.0.0.0/0, ::/0"
	case v6:
		return "::/0"
	default:
		return "0.0.0.0/0"
	}
}
