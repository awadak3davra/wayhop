package keenetic

import (
	"strings"

	"wayhop/internal/model"
)

// ResolveNDMName returns the KeeneticOS NDM interface name to target for a native managed
// toggle / state read of ep, and whether it is KNOWN. The name is taken ONLY from the
// explicitly-captured params["ndm_name"] (set at adoption from `show interface`, see
// server.endpointFromDiscovered) — it is NEVER guessed from the kernel iface.
//
// Why not derive it: on a hand-configured router the native interfaces were created by hand
// with arbitrary NDM names — the kernel name "nwg5" does NOT guarantee the NDM name is
// "Wireguard5". Deriving would risk toggling the WRONG interface and could bounce the family's
// working datapath. So when ndm_name is absent we return known=false and the caller must
// surface "re-adopt to capture the NDM name" rather than act blind.
//
// (When WayHop itself creates a native interface via the backend, that path assigns and
// records the NDM name directly, so it flows through params["ndm_name"] too — derivation is
// never needed there either.)
func ResolveNDMName(ep model.Endpoint) (string, bool) {
	if s, ok := ep.Params["ndm_name"].(string); ok {
		if s = strings.TrimSpace(s); s != "" {
			return s, true
		}
	}
	return "", false
}
