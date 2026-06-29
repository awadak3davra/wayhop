package importer

import (
	"fmt"
	"strconv"
	"strings"

	"velinx/internal/model"
)

// ContentKey is a normalized identity signature for an endpoint: two endpoints with
// the same key describe the same upstream connection (same protocol/engine, host,
// port, and identifying credential) regardless of their Velinx ID or display
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
	for _, k := range []string{"uuid", "password", "peer_public_key", "private_key", "method", "interface"} {
		b.WriteByte('|')
		b.WriteString(paramStr(e.Params, k))
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
// Returns the kept endpoints and the count dropped as content-duplicates.
func DedupeNew(existing, incoming []model.Endpoint) (unique []model.Endpoint, dupes int) {
	ids := make(map[string]string, len(existing)) // ID -> its ContentKey
	keys := make(map[string]bool, len(existing))
	for i := range existing {
		ck := ContentKey(existing[i])
		ids[existing[i].ID] = ck
		keys[ck] = true
	}
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
			if existCK, ok := ids[e.ID]; ok && existCK == ck {
				unique = append(unique, e)
				continue
			}
		}
		if keys[ck] {
			dupes++
			continue
		}
		keys[ck] = true
		unique = append(unique, e)
	}
	return unique, dupes
}
