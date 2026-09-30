//go:build linux

package server

import (
	"context"
	"net"
	"testing"
	"time"
)

// A socket that cannot be bound to its tunnel's interface does not go out some other way: the dial
// fails, so a speed test of one exit never measures the default route under the exit's name. The
// line's dialer binds nothing, and its mark is best-effort, so it connects even where the mark is
// not allowed.
func TestTunnelDialNeverFallsBackToAnotherPath(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := ifaceDial("wayhop-none0")(ctx, "tcp", ln.Addr().String()); err == nil {
		c.Close()
		t.Fatal("dialed out without the interface it was bound to")
	}
	c, err := bypassDial(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("the line's dialer: %v", err)
	}
	c.Close()
}
