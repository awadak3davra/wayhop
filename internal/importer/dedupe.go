package importer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"wayhop/internal/model"
)

// ContentKey is a normalized identity signature for an endpoint: two endpoints with
// the same key describe the same upstream connection (same protocol/engine, host,
// port, and identifying credential) regardless of their WayHop ID or display
// name. Used to skip content-duplicate imports — re-fetching a subscription with
// fresh IDs would otherwise pile up identical endpoints.
func ContentKey(e model.Endpoint) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(string(e.Protocol)))
	b.WriteByte('|')
	b.WriteString(strings.ToLower(string(e.Engine)))
	b.WriteByte('|')
	b.WriteString(strings.ToLower(strings.TrimSpace(e.Server)))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(e.Port))
	// The credential(s) that distinguish one endpoint from another on the same
	// host:port — whichever the protocol uses. Missing ones contribute "".
	for _, k := range []string{"uuid", "password", "peer_public_key", "private_key", "method", "interface", "username"} {
		b.WriteByte('|')
		// An SSH exit's private key is typed in the form; no ssh:// link carries one. Counted, adding a
		// key made the next import of the same link a different connection, added beside the first.
		if k == "private_key" && e.Protocol == model.ProtoSSH {
			continue
		}
		b.WriteString(paramStr(e.Params, k))
	}
	// A realm connection has no host or port: its rendezvous and realm name are what it dials. Only
	// when present, so every other key stays as it was.
	if r := paramStr(e.Params, "realm"); r != "" {
		b.WriteString("|realm=")
		b.WriteString(r)
	}
	// An SSH exit's login is "user", not "username": two accounts on one server that sign in with a
	// key (no password in the key above until one is pasted) are two exits. Only when present, as above.
	if u := paramStr(e.Params, "user"); u != "" && e.Protocol == model.ProtoSSH {
		b.WriteString("|user=")
		b.WriteString(u)
	}
	// Dial-distinguishing transport + TLS fields. Two endpoints with the same
	// host:port:credential but a different stream transport (ws vs grpc) or TLS
	// mode (tls vs reality) dial DIFFERENTLY and must NOT collapse to one key —
	// otherwise the second is silently dropped on bulk import / never added on a
	// subscription transport-or-TLS rotation. Only stable normalized fields go in
	// here (never ID/name/tags) so a re-parsed identical share-link keeps its key.
	b.WriteByte('|')
	if t := e.Transport; t != nil {
		b.WriteString(strings.ToLower(strings.TrimSpace(t.Type)))
		b.WriteByte('|')
		b.WriteString(strings.TrimSpace(t.Path))
		b.WriteByte('|')
		b.WriteString(strings.ToLower(strings.TrimSpace(t.Host)))
		b.WriteByte('|')
		b.WriteString(strings.TrimSpace(t.ServiceName))
	} else {
		// nil transport == raw TCP; contributes the same empty signature.
		b.WriteString("|||")
	}
	b.WriteByte('|')
	if s := e.TLS; s != nil {
		if s.Enabled {
			b.WriteString("1")
		} else {
			b.WriteString("0")
		}
		b.WriteByte('|')
		b.WriteString(strings.ToLower(strings.TrimSpace(s.Type)))
		b.WriteByte('|')
		b.WriteString(strings.ToLower(strings.TrimSpace(s.SNI)))
		b.WriteByte('|')
		b.WriteString(strings.TrimSpace(s.PublicKey)) // Reality
		b.WriteByte('|')
		b.WriteString(strings.TrimSpace(s.ShortID)) // Reality
		b.WriteByte('|')
		// ALPN order is significant to the dial; join verbatim, lowercased.
		for i, a := range s.ALPN {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(strings.ToLower(strings.TrimSpace(a)))
		}
	} else {
		// nil TLS == plaintext; same empty signature as a disabled TLS block.
		b.WriteString("0|||||")
	}
	return b.String()
}

// paramStr renders a Params value as a stable string for the content key.
func paramStr(p map[string]any, k string) string {
	v, ok := p[k]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return fmt.Sprintf("%v", v)
}

// DedupeNew filters incoming endpoints against an existing set for a bulk import:
// it KEEPS an incoming endpoint when its ID already exists (that is an in-place
// update, not a new duplicate) or when its content is genuinely new, and DROPS it
// when its content matches an already-present endpoint (existing or earlier in the
// same batch) under a new ID. Order is preserved; the original slice is untouched.
// An in-place update is returned as Reimport makes it: the link's connection with what
// the user owns carried over, never the bare parse that would revert the user's edits.
// Returns the kept endpoints and the count dropped as content-duplicates.
func DedupeNew(existing, incoming []model.Endpoint) (unique []model.Endpoint, dupes int) {
	ids := make(map[string]int, len(existing)) // ID -> its index in existing
	cks := make([]string, len(existing))       // existing[i]'s ContentKey
	keys := make(map[string]bool, len(existing))
	// seenIDs is every ID that will exist after this merge — existing endpoints plus ones kept so far
	// this pass — so a freshly-minted ID can't collide with any of them.
	seenIDs := make(map[string]bool, len(existing)+len(incoming))
	for i := range existing {
		cks[i] = ContentKey(existing[i])
		ids[existing[i].ID] = i
		keys[cks[i]] = true
		seenIDs[existing[i].ID] = true
	}
	updated := make(map[string]bool)
	unique = make([]model.Endpoint, 0, len(incoming))
	for i := range incoming {
		e := incoming[i]
		ck := ContentKey(e)
		if e.ID != "" {
			// Keep as an in-place update ONLY when an existing endpoint shares both
			// the ID AND the content — the legitimate re-import-update path. If the
			// ID matches but the content differs, this is an import-generated ID
			// colliding with a DIFFERENT user-created endpoint; do NOT overwrite it
			// — fall through to content-dedup so it is treated as a new endpoint or
			// dropped as a content-duplicate.
			if at, ok := ids[e.ID]; ok && cks[at] == ck {
				if updated[e.ID] {
					dupes++ // the same link twice in one batch updates it once
					continue
				}
				updated[e.ID] = true
				unique = append(unique, Reimport(existing[at], e))
				continue
			}
		}
		if keys[ck] {
			dupes++
			continue
		}
		keys[ck] = true
		// Content is genuinely new. If its NON-EMPTY import-generated ID COLLIDES with a different
		// endpoint (an existing one, or one already kept this pass), re-slug it to a fresh unique ID —
		// otherwise the downstream ID-keyed UpsertEndpoint would OVERWRITE that other endpoint, the
		// exact data loss the ID-match guard above is meant to prevent. An empty ID is left untouched:
		// importers always assign IDs, and the caller (bulk handler) decides how to treat an empty one.
		if e.ID != "" {
			if seenIDs[e.ID] {
				e.ID = uniqueID(e.ID, seenIDs)
			} else {
				seenIDs[e.ID] = true
			}
		}
		unique = append(unique, e)
	}
	return unique, dupes
}

// userPins returns the pins in t that the user added rather than an import brought.
//
// Whole-certificate pins can be told apart: an importer marks the ones it brings (PinCertMayBeCA for
// Xray's pcs= and mihomo's fingerprint, PinCertBesideChain for Hysteria's pinSHA256, each naming its
// pins in the ...Of list when they are not all of them), and a pin typed in the form has neither mark.
// The one importer that does not mark its pins is a sing-box JSON config, so a pin from one reads as
// typed and is kept when the config drops it.
//
// Public-key pins carry no mark, and no share link carries one: they come from Set up Server, the form,
// or a sing-box JSON config. They are all kept, with the same exception.
func userPins(t *model.TLS) (cert, pub []string) {
	if t == nil {
		return nil, nil
	}
	imported := map[string]bool{}
	mark := func(on bool, of []string) {
		if !on {
			return
		}
		if len(of) == 0 {
			of = t.PinCertSHA256
		}
		for _, p := range of {
			imported[p] = true
		}
	}
	mark(t.PinCertMayBeCA, t.PinCertMayBeCAOf)
	mark(t.PinCertBesideChain, t.PinCertBesideChainOf)
	for _, p := range t.PinCertSHA256 {
		if !imported[p] {
			cert = append(cert, p)
		}
	}
	return cert, append([]string(nil), t.PinPubKeySHA256...)
}

// withUserPins is a TLS block holding the link's pins with the user's pins from have added. A link
// with no TLS has nothing to pin, so they go with it. The link's marks said "all of the certificate
// pins" by leaving their ...Of list empty; with a typed pin beside them they name the link's own.
func withUserPins(link, have *model.TLS) *model.TLS {
	cert, pub := userPins(have)
	if link == nil || len(cert)+len(pub) == 0 {
		return link
	}
	t := *link
	own := t.PinCertSHA256
	t.PinCertSHA256 = append([]string(nil), own...)
	t.PinPubKeySHA256 = append([]string(nil), t.PinPubKeySHA256...)
	added := false
	for _, p := range cert {
		if !containsPin(t.PinCertSHA256, p) {
			t.PinCertSHA256 = append(t.PinCertSHA256, p)
			added = true
		}
	}
	if added && len(own) > 0 {
		if t.PinCertMayBeCA && len(t.PinCertMayBeCAOf) == 0 {
			t.PinCertMayBeCAOf = append([]string(nil), own...)
		}
		if t.PinCertBesideChain && len(t.PinCertBesideChainOf) == 0 {
			t.PinCertBesideChainOf = append([]string(nil), own...)
		}
	}
	for _, p := range pub {
		if !containsPin(t.PinPubKeySHA256, p) {
			t.PinPubKeySHA256 = append(t.PinPubKeySHA256, p)
		}
	}
	return &t
}

func containsPin(pins []string, p string) bool {
	for _, q := range pins {
		if q == p {
			return true
		}
	}
	return false
}

// SameEndpoint reports whether two endpoints store the same thing: equal once encoded, which is how
// the profile keeps them, so a number that went through JSON compares equal to its decoded self.
func SameEndpoint(a, b model.Endpoint) bool {
	ab, err1 := json.Marshal(a)
	bb, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(ab, bb)
}
