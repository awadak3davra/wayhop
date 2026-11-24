//go:build linux

package server

import (
	"context"
	"net"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"

	"wayhop/internal/generator"
)

// OpenWrt stage 3: the download bound to a tunnel is not taken by the core's auto_redirect. The
// core's nat output chain redirects every TCP connection the router opens, bound to a device or
// not, unless the socket carries the mark the generator writes into the TUN inbound as
// auto_redirect_output_mark. The throughput download dials with ifaceDial, which sets the device and
// that mark and fails when either cannot be set: an unmarked socket would measure whatever outbound
// the core picked, under the tunnel's name.
func TestBoundDownloadSocketCarriesTheCoresBypassMark(t *testing.T) {
	if reflect.ValueOf(speedBindDial).Pointer() != reflect.ValueOf(ifaceDial).Pointer() {
		t.Fatal("the bound download no longer dials with ifaceDial")
	}
	if got := generator.AutoRedirectOutputMark; engineBypassMark != got {
		t.Fatalf("the bypass mark is %#x, the core's auto_redirect_output_mark is %#x", engineBypassMark, generator.AutoRedirectOutputMark)
	}
	// The dialer's own Control, on a socket of this test: nothing is connected, so the answer does
	// not depend on how the host routes a marked packet.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	raw, err := pc.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	err = egressControl("lo", engineBypassMark, true)("udp4", "", raw)
	if os.Geteuid() != 0 {
		// Neither the device nor the mark can be set without the capabilities, and the control says
		// so: the dial fails instead of leaving unbound or unmarked.
		if err == nil {
			t.Log("not root, and the socket options were allowed (a capability): the mark is read back below")
		} else {
			ln, lerr := net.Listen("tcp4", "127.0.0.1:0")
			if lerr != nil {
				t.Fatal(lerr)
			}
			defer ln.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if conn, derr := ifaceDial("lo")(ctx, "tcp4", ln.Addr().String()); derr == nil {
				conn.Close()
				t.Fatal("a socket that could not be bound and marked was dialed all the same")
			}
			return
		}
	} else if err != nil {
		t.Fatalf("bind and mark as root: %v", err)
	}
	mark, gerr := 0, error(nil)
	if err := raw.Control(func(fd uintptr) {
		mark, gerr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
	}); err != nil || gerr != nil {
		t.Fatalf("read SO_MARK: %v %v", err, gerr)
	}
	if mark != engineBypassMark {
		t.Fatalf("the download socket's mark is %#x, want %#x", mark, engineBypassMark)
	}
}
