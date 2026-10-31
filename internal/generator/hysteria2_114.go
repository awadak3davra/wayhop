package generator

import (
	"strings"
	"time"

	"wayhop/internal/model"
)

// hysteria2Extras adds the Hysteria2 options newer cores carry to an outbound outboundFor built.
//
//   - hop_interval (1.11, below WayHop's oldest core) is always emitted when set; hop_interval_max
//     (1.14) randomises it.
//   - gecko obfuscation (1.14) is the second QUIC obfuscator beside salamander. outboundFor knows
//     only salamander; this emits gecko for a 1.14+ core. An older core has no gecko, so the
//     connection is rendered without it and the Apply review names it (GeckoNeedsNewerCore).
//   - bbr_profile and disable_chrome_parrot (1.14). From 1.14 the client parrots Chrome's QUIC
//     handshake by default, and Chrome does not offer Ed25519, so a server with an Ed25519
//     certificate needs the parrot off. On an older core neither exists, and leaving them out is
//     exactly what they would mean there.
//   - realm (1.14): a server with no public address, reached through a Hysteria realm. outboundFor
//     has already left the server fields out; this adds the realm for a 1.14+ core. An older core
//     keeps the serverless outbound, which loads and cannot connect, and the Apply review names it
//     (RealmNeedsNewerCore).
func hysteria2Extras(e *model.Endpoint, ob map[string]any, coreVersion string) error {
	p := e.Params
	modern := coreMinor(coreVersion) >= 14
	// Nothing here fails the whole config: every endpoint shares one singbox.json, so an option this
	// connection cannot use is left out (the connection degrades) rather than refused (every
	// connection stops). A malformed duration is dropped the same way.
	realm := e.UsesRealm()
	if realm && modern {
		// Validate refuses a malformed realm on an enabled connection, so an error here is a profile
		// that skipped it; the outbound then stays serverless, as on an older core.
		if r, err := model.Hy2RealmOf(e); err == nil {
			ob["realm"] = hy2RealmJSON(r)
		}
	}
	// Hopping moves between server_ports, which a realm replaces.
	if v := str(p, "hop_interval"); v != "" && !realm {
		if _, err := time.ParseDuration(v); err == nil {
			ob["hop_interval"] = v
			if m := str(p, "hop_interval_max"); m != "" && modern {
				if _, err := time.ParseDuration(m); err == nil {
					ob["hop_interval_max"] = m
				}
			}
		}
	}
	if strings.EqualFold(str(p, "obfs"), "gecko") {
		pw := str(p, "obfs_password")
		if !modern || pw == "" {
			// Rendered without obfuscation, as before: this exit cannot reach its server, and the
			// review says so (GeckoNeedsNewerCore); refusing would hold every other change hostage.
			return nil
		}
		obfs := map[string]any{"type": "gecko", "password": pw}
		if n := intp(p, "obfs_min_packet_size"); n > 0 {
			obfs["min_packet_size"] = n
		}
		if n := intp(p, "obfs_max_packet_size"); n > 0 {
			obfs["max_packet_size"] = n
		}
		ob["obfs"] = obfs
	}
	if modern {
		if b := str(p, "bbr_profile"); b == "conservative" || b == "standard" || b == "aggressive" {
			ob["bbr_profile"] = b
		}
		if boolp(p, "disable_chrome_parrot") {
			ob["disable_chrome_parrot"] = true
		}
	}
	return nil
}

// GeckoNeedsNewerCore reports a Hysteria2 connection whose gecko obfuscation the known core cannot
// carry, so the review can say that exit will not come up. An unknown version says nothing.
func GeckoNeedsNewerCore(e *model.Endpoint, coreVersion string) bool {
	m := coreMinor(coreVersion)
	return e.Protocol == model.ProtoHysteria2 && strings.EqualFold(str(e.Params, "obfs"), "gecko") && m >= 0 && m < 14
}

// RealmNeedsNewerCore reports a Hysteria2 connection made through a realm on a known core older than
// 1.14, which has no realm: the connection is applied without a server and cannot come up, so the
// review says so. An unknown version says nothing.
func RealmNeedsNewerCore(e *model.Endpoint, coreVersion string) bool {
	m := coreMinor(coreVersion)
	return e.UsesRealm() && m >= 0 && m < 14
}

// hy2RealmDefaultSTUN are the STUN servers Hysteria's own client uses when none are configured
// (app/cmd/client.go, defaultRealmSTUNServers; the Realms docs list the same three). sing-box has no
// default: its docs mark stun_servers required, and `check` passes without them (1.14.4) while the
// client then has no way to learn its own address ("no STUN servers"). A realm that names none gets
// these and behaves as it would in Hysteria.
var hy2RealmDefaultSTUN = []string{"stun.nextcloud.com:3478", "stun.sip.us:3478", "global.stun.twilio.com:3478"}

// hy2RealmJSON is sing-box's hysteria2 `realm` object. The TLS server name is left to the
// connection's own tls block: unset, sing-box uses the rendezvous host, as Hysteria does.
func hy2RealmJSON(r *model.Hy2Realm) map[string]any {
	stun := r.STUN
	if len(stun) == 0 {
		stun = append([]string(nil), hy2RealmDefaultSTUN...)
	}
	out := map[string]any{"server_url": r.ServerURL(), "realm_id": r.ID, "stun_servers": stun}
	if r.Token != "" {
		out["token"] = r.Token
	}
	return out
}
