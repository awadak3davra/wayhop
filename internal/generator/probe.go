package generator

import (
	"crypto/sha256"
	"encoding/hex"
)

// The probe inbound lets the daemon send a request out ONE chosen exit, which the per-exit service
// check needs (competitor gap 3): the Clash API's delay test reaches a URL through an outbound but
// returns only a latency, never the answer, and a region-locked service says no in the answer.
//
// It is a mixed inbound on loopback with one user per exit; a route rule per user sends that user's
// connections to its exit, ahead of every other rule. The users share one password derived from the
// Clash API secret, so the daemon can rebuild it without storing anything new. Nothing outside the
// router can reach it, and a process on the router can already pick an exit through the Clash API.

// ProbeInboundTag names the probe inbound in the generated config.
const ProbeInboundTag = "probe-in"

// ProbeUser is the probe inbound's user name for an exit tag.
func ProbeUser(tag string) string { return "x-" + tag }

// ProbePassword is the probe inbound's password for a Clash API secret.
func ProbePassword(clashSecret string) string {
	sum := sha256.Sum256([]byte("wayhop-probe-in\x00" + clashSecret))
	return hex.EncodeToString(sum[:16])
}

// probeExitTags lists the exits the probe inbound can reach: every outbound and endpoint the config
// emits, plain direct included - in tun mode the daemon's own sockets may be captured by the TUN, so
// the WAN is asked through sing-box's direct outbound, which never is.
func probeExitTags(outbounds, endpoints []map[string]any) []string {
	var tags []string
	for _, list := range [][]map[string]any{outbounds, endpoints} {
		for _, o := range list {
			if t, _ := o["tag"].(string); t != "" {
				tags = append(tags, t)
			}
		}
	}
	return tags
}

// probeInbound is the inbound for the probe users, or nil when there is no port or no exit.
func probeInbound(opts Options, tags []string) map[string]any {
	if opts.ProbePort <= 0 || len(tags) == 0 {
		return nil
	}
	pw := ProbePassword(opts.ClashSecret)
	users := make([]map[string]any, 0, len(tags))
	for _, t := range tags {
		users = append(users, map[string]any{"username": ProbeUser(t), "password": pw})
	}
	return map[string]any{
		"type": "mixed", "tag": ProbeInboundTag, "listen": "127.0.0.1", "listen_port": opts.ProbePort,
		"users": users,
	}
}

// ProbeFor is the probe inbound and its route rules for a config Generate does not build (the
// KeeneticOS fallback core): the same users, password and rules, over that config's own outbounds and
// endpoints. The caller puts the rules ahead of its own; both are nil when port is 0 or there is no exit.
func ProbeFor(port int, clashSecret string, outbounds, endpoints []map[string]any) (map[string]any, []map[string]any) {
	opts := Options{ProbePort: port, ClashSecret: clashSecret}
	tags := probeExitTags(outbounds, endpoints)
	return probeInbound(opts, tags), probeRules(opts, tags)
}

// LeadingProbeRules counts the probe rules at the head of cfg's route rules, where Generate and the
// KeeneticOS fallback core both put them: for a config that arrives already built, they are the
// guards a core override's prepended route rules go after (see override.go).
func LeadingProbeRules(cfg map[string]any) int {
	route, _ := cfg["route"].(map[string]any)
	n, stop := 0, false
	forEachObject(route["rules"], func(r map[string]any) {
		if stop || !isProbeRule(r) {
			stop = true
			return
		}
		n++
	})
	return n
}

// isProbeRule reports whether a rule matches only the probe inbound, the way probeRules writes it,
// as built ([]string) or decoded ([]any).
func isProbeRule(r map[string]any) bool {
	switch in := r["inbound"].(type) {
	case []string:
		return len(in) == 1 && in[0] == ProbeInboundTag
	case []any:
		return len(in) == 1 && in[0] == ProbeInboundTag
	}
	return false
}

// probeRules route each probe user to its exit. They go first: no list, block-by-default or sniff
// rule may see a probe, or the check would measure the routing instead of the exit.
func probeRules(opts Options, tags []string) []map[string]any {
	if probeInbound(opts, tags) == nil {
		return nil
	}
	rules := make([]map[string]any, 0, len(tags))
	for _, t := range tags {
		rules = append(rules, map[string]any{
			"inbound": []string{ProbeInboundTag}, "auth_user": []string{ProbeUser(t)},
			"action": "route", "outbound": t,
		})
	}
	return rules
}
