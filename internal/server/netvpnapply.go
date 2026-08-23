package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"wayhop/internal/netvpn"
)

// planHash identifies the exact commands a client was shown. Both halves are hashed: a plan whose
// staged commands match but whose commit tail differs is not the same plan.
func planHash(p netvpn.Plan) string {
	h := sha256.New()
	fmt.Fprintf(h, "iface=%s\nzone=%s\nref=%s\n", p.Iface, p.Zone, p.ZoneRef)
	for _, c := range p.Commands {
		fmt.Fprintln(h, "cmd", c)
	}
	for _, c := range p.Commit {
		fmt.Fprintln(h, "commit", c)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
