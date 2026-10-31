package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// EndpointRev, GroupRev and RoutingListRev are the revision of ONE stored connection, group or
// routing list: a hash of its stored form. An edit made from a copy sends the revision the copy was
// loaded at, and the save is refused when the stored object no longer has it (QA-152). It is per
// object so that a write to anything else - another connection, a new device group, a reorder, a
// subscription adding exits - never makes an open form stale.
//
// What the daemon writes on its own and no form edits is left out, or the form for that object
// would go stale whenever it ran: a routing list's feed caches and their refresh times, which the
// hourly feed refresh rewrites.
func EndpointRev(e Endpoint) string { return objectRev(e) }

// GroupRev is EndpointRev for a failover group.
func GroupRev(g Group) string { return objectRev(g) }

// RoutingListRev is EndpointRev for a routing list, without its feed caches and refresh times.
func RoutingListRev(rl RoutingList) string {
	rl.CIDRCache, rl.CIDRRefreshed = nil, 0
	rl.DomainCache, rl.DomainRefreshed = nil, 0
	return objectRev(rl)
}

// objectRev hashes v's JSON, the form the profile stores it in: map keys are sorted, so equal
// objects always hash alike.
func objectRev(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "" // unreachable for these types; "" is never a revision a client holds, so it never matches
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}
