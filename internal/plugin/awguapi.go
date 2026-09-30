package plugin

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"

	"wayhop/internal/awg"
	"wayhop/internal/model"
	"wayhop/internal/util"
)

// awgUAPI renders an AmneziaWG endpoint as the UAPI set that configures amneziawg-go: the userspace
// path's counterpart of awgConfig, which renders the same endpoint for `awg setconf`.
//
// It follows amneziawg-tools' own UAPI writer (src/ipc-uapi.h at v3.1.20260812), which is what the
// tools send when they drive amneziawg-go: the same keys in the same order, keys in hex, booleans as
// 0 or 1. The difference is what gets checked first. amneziawg-go refuses some bad values with an
// errno, which after a partial apply means recreating the device; others it does not refuse at all:
// Jmin above Jmax makes it allocate a near-4 GiB junk packet on every handshake, and a negative tag
// length panics it. Both kinds are caught here, with the field named.
//
// The set is complete for a fresh device only. On a reused one, every key it does not mention keeps
// its old value - measured against the pinned build, a 3.1 config followed by a 2.0 one left the old
// header protection key, I1, RandomTrailers and DisableCookies running under the new config - so a
// changed config gets a new amneziawg-go, not a second set.
//
// endpoint is the peer's address, already resolved: UAPI takes only a numeric address (the tools
// resolve the name before they write), and resolving belongs to bring-up, which can retry it.
//
// The warnings are for the operator; none of them stops the tunnel.
func awgUAPI(e model.Endpoint, endpoint netip.AddrPort) (lines []awg.KV, warnings []string, err error) {
	p := e.Params
	add := func(k, v string) { lines = append(lines, awg.KV{Key: k, Value: v}) }

	priv, err := uapiKey(p, "private_key", "PrivateKey", true)
	if err != nil {
		return nil, nil, err
	}
	add("private_key", priv)
	add("replace_peers", "true")

	// Junk packets. The count is bounded by the kernel module's documented range (README, 1 <= Jc <=
	// 128; 0 turns junk off); the sizes by what one datagram carries. An unset value is 0 upstream,
	// so Jmin alone is Jmin above a Jmax of 0 - exactly the overflow.
	jc, jcSet, err := uapiUint(p, "jc", "Jc", 128)
	if err != nil {
		return nil, nil, err
	}
	jmin, jminSet, err := uapiUint(p, "jmin", "Jmin", awg.MaxDatagram)
	if err != nil {
		return nil, nil, err
	}
	jmax, jmaxSet, err := uapiUint(p, "jmax", "Jmax", awg.MaxDatagram)
	if err != nil {
		return nil, nil, err
	}
	if jc > 0 && jmin > jmax {
		return nil, nil, fmt.Errorf("junk packet sizes: Jmin %d is above Jmax %d, and amneziawg-go would try to allocate a near-4 GiB junk packet on every handshake", jmin, jmax)
	}
	for _, f := range []struct {
		key string
		v   uint64
		set bool
	}{{"jc", jc, jcSet}, {"jmin", jmin, jminSet}, {"jmax", jmax, jmaxSet}} {
		if f.set {
			add(f.key, strconv.FormatUint(f.v, 10))
		}
	}

	// Paddings: upstream parses them as 16-bit.
	var s [4]uint64
	for i := range s {
		v, set, err := uapiUint(p, fmt.Sprintf("s%d", i+1), fmt.Sprintf("S%d", i+1), math.MaxUint16)
		if err != nil {
			return nil, nil, err
		}
		s[i] = v
		if set {
			add(fmt.Sprintf("s%d", i+1), strconv.FormatUint(v, 10))
		}
	}
	// The kernel module's README: "S1 + 56 ≠ S2". An initiation (148 bytes) and a response (92)
	// padded to the same size are told apart by nothing but their headers.
	if s[0]+56 == s[1] {
		warnings = append(warnings, fmt.Sprintf("S1 + 56 = S2 (%d + 56 = %d): the handshake initiation and response come out the same size, which upstream's documentation rules out", s[0], s[1]))
	}

	// Headers. An unset H keeps its WireGuard message type (1..4 in device.go), so overlaps are
	// checked against those too: "H1 = 1-100" collides with the default H2 of 2.
	type span struct{ lo, hi uint32 }
	h := [4]span{{1, 1}, {2, 2}, {3, 3}, {4, 4}}
	hRange := false
	for i := range h {
		v := numStr(p[fmt.Sprintf("h%d", i+1)])
		if v == "" {
			continue
		}
		lo, hi, err := awg.ParseRange(v, math.MaxUint32)
		if err != nil {
			return nil, nil, fmt.Errorf("header range H%d: %v", i+1, err)
		}
		h[i] = span{lo, hi}
		hRange = hRange || lo < hi
		add(fmt.Sprintf("h%d", i+1), rangeStr(lo, hi))
	}
	for i := range h {
		for j := i + 1; j < len(h); j++ {
			if h[i].lo <= h[j].hi && h[j].lo <= h[i].hi {
				return nil, nil, fmt.Errorf("header ranges H%d and H%d overlap; every message type needs its own", i+1, j+1)
			}
		}
	}

	for i := 1; i <= 5; i++ {
		k := fmt.Sprintf("i%d", i)
		raw, isStr := p[k].(string)
		if !isStr {
			if p[k] != nil {
				warnings = append(warnings, fmt.Sprintf("I%d is not a string; not sent (awgConfig drops it on the kernel path too)", i))
			}
			continue
		}
		spec, note, err := awg.GoIPacket(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("special junk packet I%d: %v", i, err)
		}
		if note != "" {
			warnings = append(warnings, fmt.Sprintf("I%d: %s", i, note))
		}
		if spec != "" {
			add(k, spec)
		}
	}

	hpk, err := uapiKey(p, "header_protection_key", "HeaderProtectionKey", false)
	if err != nil {
		return nil, nil, err
	}
	if hpk != "" {
		// Both implementations refuse a protection key unless every padding holds its 12-byte nonce;
		// the check is made here to name the field (amneziawg-go's message counts them from S0).
		for i, v := range s {
			if v < 12 {
				return nil, nil, fmt.Errorf("padding S%d is %d; with a HeaderProtectionKey every S1-S4 must be at least 12, the size of the nonce it carries", i+1, v)
			}
		}
		add("header_protection_key", hpk)
	}

	for _, f := range []struct{ key, name string }{
		{"content_padding_addition", "ContentPaddingAddition"}, {"rekey_after_time", "RekeyAfterTime"},
		{"rekey_timeout", "RekeyTimeout"}, {"reject_after_time", "RejectAfterTime"},
		{"keepalive_timeout", "KeepaliveTimeout"}, {"max_handshake_attempts", "MaxHandshakeAttempts"},
	} {
		v := numStr(p[f.key])
		if v == "" {
			continue
		}
		lo, hi, err := awg.ParseRange(v, math.MaxUint16)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %v", f.name, err)
		}
		add(f.key, rangeStr(lo, hi))
	}

	rt, rtSet, err := uapiBool(p, "random_trailers", "RandomTrailers")
	if err != nil {
		return nil, nil, err
	}
	dc, dcSet, err := uapiBool(p, "disable_cookies", "DisableCookies")
	if err != nil {
		return nil, nil, err
	}
	if rtSet {
		add("random_trailers", boolUAPI(rt))
	}
	if dcSet {
		add("disable_cookies", boolUAPI(dc))
	}
	// Measured 2026-08-29 on 3.1.20260812, module and tools on both ends: RandomTrailers together with
	// junk packets, paddings and header ranges lost 37-55% of packets; drop any one of the four and
	// loss was 0. Not refused - the server decides whether trailers are on.
	if rt && jc > 0 && s != [4]uint64{} && hRange {
		warnings = append(warnings, "RandomTrailers with junk packets, S1-S4 paddings and H ranges lost 37-55% of packets in a measurement on upstream 3.1.20260812; if the tunnel drops packets, this combination is the first suspect")
	}

	pub, err := uapiKey(p, "peer_public_key", "PublicKey", true)
	if err != nil {
		return nil, nil, err
	}
	psk, err := uapiKey(p, "pre_shared_key", "PresharedKey", false)
	if err != nil {
		return nil, nil, err
	}
	if !endpoint.IsValid() || endpoint.Port() == 0 {
		return nil, nil, fmt.Errorf("the peer endpoint %q is not a resolved address and port", endpoint)
	}
	// A resolver can hand back an IPv4 address in its IPv6-mapped form; send the plain one.
	endpoint = netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
	kaLo, kaHi, err := awg.ParseRange(awgKeepalive(e), math.MaxUint16)
	if err != nil {
		return nil, nil, fmt.Errorf("PersistentKeepalive: %v", err)
	}
	add("public_key", pub)
	if psk != "" {
		add("preshared_key", psk)
	}
	add("endpoint", endpoint.String())
	add("persistent_keepalive_interval", rangeStr(kaLo, kaHi))
	add("replace_allowed_ips", "true")
	for _, a := range strings.Split(util.WGAllowedIPs(p), ",") {
		pfx, err := netip.ParsePrefix(strings.TrimSpace(a))
		if err != nil {
			return nil, nil, fmt.Errorf("allowed IP %q: %v", a, err)
		}
		add("allowed_ip", pfx.String())
	}
	return lines, warnings, nil
}

// rangeStr writes a range the way amneziawg-go's get prints it back ("5", not "5-5"), so what was
// set and what is running compare as strings.
func rangeStr(lo, hi uint32) string {
	if lo == hi {
		return strconv.FormatUint(uint64(lo), 10)
	}
	return strconv.FormatUint(uint64(lo), 10) + "-" + strconv.FormatUint(uint64(hi), 10)
}

// uapiKey reads a 32-byte key in any base64 spelling the config may carry - the same set
// normalizeWGKey accepts - and returns it in the hex UAPI takes. A key that does not decode is an
// error, not a pass-through: amneziawg-go would refuse it with an errno after applying the lines
// before it.
func uapiKey(p map[string]any, field, name string, required bool) (string, error) {
	raw := strings.TrimSpace(str(p, field))
	if raw == "" {
		if required {
			return "", fmt.Errorf("%s is missing", name)
		}
		return "", nil
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(raw); err == nil && len(b) == 32 {
			return hex.EncodeToString(b), nil
		}
	}
	return "", fmt.Errorf("%s is not a 32-byte base64 key", name)
}

// uapiUint reads a numeric parameter stored as a number or a string, as the importer and the API
// store them.
func uapiUint(p map[string]any, field, name string, max uint64) (uint64, bool, error) {
	s := numStr(p[field])
	if s == "" {
		return 0, false, nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v > max {
		return 0, false, fmt.Errorf("%s is %q; it takes a whole number from 0 to %d", name, s, max)
	}
	return v, true, nil
}

// uapiBool reads RandomTrailers/DisableCookies stored as a bool (the importer), a number or a string
// (the API).
func uapiBool(p map[string]any, field, name string) (value, set bool, err error) {
	switch v := p[field].(type) {
	case nil:
		return false, false, nil
	case bool:
		return v, true, nil
	case string:
		b, err := awg.ParseBool(v)
		if err != nil {
			return false, false, fmt.Errorf("%s: %v", name, err)
		}
		return b, true, nil
	default:
		if n := numStr(v); n != "" {
			b, err := awg.ParseBool(n)
			if err != nil {
				return false, false, fmt.Errorf("%s: %v", name, err)
			}
			return b, true, nil
		}
		return false, false, fmt.Errorf("%s has an unreadable value %v", name, v)
	}
}

func boolUAPI(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
