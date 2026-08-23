package keenetic

import (
	"strings"
)

// TeardownCommands returns the NDM `no …` commands that REMOVE everything this Plan added to
// the NDM config: each route (`no ip route <dst> <mask> <target>`) and then each native
// interface (`no interface WireguardN`). NDM config is additive, so a clean re-apply must
// first tear down the previously-applied plan — otherwise stale interfaces/routes linger.
//
// Routes are removed BEFORE interfaces (a route references its interface; dropping the
// interface first would auto-invalidate the route and a later `no` could mismatch). The
// route key is the identity portion only (the leading `ip route <dst> <mask> <target>` /
// `ipv6 route …`), with trailing auto/reject/!comment stripped so `no` matches by key.
//
// Pure — no device I/O. The strict transaction adapter consumes this exact teardown list after
// authenticating the prior execution artifact; it never asks the compiler to rediscover ownership.
func TeardownCommands(plan *Plan) []string {
	out := make([]string, 0, len(plan.Routes)+len(plan.Interfaces))
	for _, r := range plan.Routes {
		out = append(out, "no "+routeKey(r))
	}
	for _, block := range plan.Interfaces {
		if len(block) > 0 {
			out = append(out, "no "+block[0]) // block[0] == "interface WireguardN"
		}
	}
	return out
}

// routeKey trims a rendered route line to its identity tokens, dropping any trailing
// `auto`/`reject`/`!comment` so a `no` removal matches the route by key. The identity WIDTH is
// address-family-specific: v4 is "ip route <dst> <mask> <target>" (5 tokens); v6 is
// "ipv6 route <dst-cidr> <target>" (4 tokens — a slash-CIDR, no separate mask). Getting the v6
// width wrong would leave the trailing !comment attached, so the `no` never matches and the v6
// route is left LIVE.
func routeKey(line string) string {
	f := strings.Fields(line)
	n := 5
	if len(f) > 0 && f[0] == "ipv6" {
		n = 4
	}
	if len(f) > n {
		f = f[:n]
	}
	return strings.Join(f, " ")
}
