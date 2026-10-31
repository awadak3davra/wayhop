package generator

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"wayhop/internal/model"
)

// openconnectMinMinor is the first sing-box 1.x minor with the openconnect endpoint.
const openconnectMinMinor = 14

// openconnectFlavors are the server families sing-box's openconnect endpoint speaks.
var openconnectFlavors = map[string]bool{"anyconnect": true, "gp": true, "fortinet": true, "f5": true, "pulse": true, "nc": true}

// openconnectEndpointFor renders an OpenConnect connection as sing-box's openconnect endpoint
// (1.14+). There is no profile format to import, so the params are the connection form's: flavor,
// username, password, auth_group, totp_secret, server_cert (a fingerprint or pin, for a server whose
// certificate no public CA signs - ocserv's usual case) and no_udp. A router cannot answer an
// interactive prompt, so a server that insists on one beyond a password and a TOTP code will not
// connect; that is the operator's to know, and the form says so.
func openconnectEndpointFor(e *model.Endpoint, coreVersion string) (map[string]any, error) {
	if coreVersion != "" && coreMinor(coreVersion) < openconnectMinMinor {
		return nil, fmt.Errorf("OpenConnect needs sing-box 1.%d or newer; this core is %s", openconnectMinMinor,
			strings.TrimSpace(strings.SplitN(coreVersion, "\n", 2)[0]))
	}
	p := e.Params
	server := "https://" + e.Server
	if e.Port != 0 && e.Port != 443 {
		server = "https://" + net.JoinHostPort(e.Server, strconv.Itoa(e.Port))
	}
	ep := map[string]any{"type": "openconnect", "tag": e.ID, "server": server}
	if f := str(p, "flavor"); f != "" {
		if !openconnectFlavors[f] {
			return nil, fmt.Errorf("OpenConnect flavor %q is not one sing-box speaks", f)
		}
		ep["flavor"] = f
	}
	for param, field := range map[string]string{"username": "username", "password": "password", "auth_group": "auth_group"} {
		if v := str(p, param); v != "" {
			ep[field] = v
		}
	}
	if s := str(p, "totp_secret"); s != "" {
		ep["token"] = map[string]any{"mode": "totp", "secret": s}
	}
	if fp := str(p, "server_cert"); fp != "" {
		ep["tls"] = map[string]any{"peer_fingerprint": fp}
	}
	if boolp(p, "no_udp") {
		ep["no_udp"] = true
	}
	return ep, nil
}
