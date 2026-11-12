//go:build !linux

package server

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
	"time"

	"wayhop/internal/dnscheck"
)

// Router DNS checks run on Linux. Tests inject Net directly; an off-router build has no real paths to
// bind and therefore creates no probe network.
func newDNSCheckNet() dnscheck.Net { return nil }

// Non-router tests use this small A/IN encoder to exercise the same wire shape without creating the
// engine's probe network. Production router checks use dnscheck.BuildQuery on Linux.
func dnsCheckQuery(name string) []byte {
	q := make([]byte, 12, 128)
	if _, err := rand.Read(q[:2]); err != nil {
		binary.BigEndian.PutUint16(q[:2], uint16(time.Now().UnixNano()))
	}
	q[2] = 1 // recursion desired
	binary.BigEndian.PutUint16(q[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1)
}
