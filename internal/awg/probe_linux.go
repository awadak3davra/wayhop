//go:build linux

package awg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// probeTimeout bounds the one netlink round trip. The controller answers at once on any working
// kernel; the bound only stops an odd one from hanging the panel request that asked.
const probeTimeout = 2 * time.Second

// ProbeHost measures what this router can do for AmneziaWG: which generation the loaded kernel module
// is, if any, and whether amneziawg-go could run instead.
func ProbeHost() Probe {
	p := Probe{TUN: tunAvailable()}
	v, m, err := queryFamily("amneziawg")
	switch {
	case errors.Is(err, errFamilyNotFound):
		// The module is not loaded. That is an answer (GenNone), not a probe failure.
	case err != nil:
		p.Err = err.Error()
	default:
		p.GenlVersion, p.GenlMaxAttr = v, m
	}
	p.Kernel = Classify(p.GenlVersion, p.GenlMaxAttr)
	return p
}

// tunAvailable is the one thing amneziawg-go needs from the kernel. A missing node or a regular file
// in its place both mean it cannot create its interface.
func tunAvailable() bool {
	fi, err := os.Stat("/dev/net/tun")
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// queryFamily asks the generic-netlink controller about one family. Raw syscalls on purpose: the
// question is a single request and reply, and pulling a netlink library into a binary that ships to
// 16 MB routers for it would cost more than the forty lines it replaces.
func queryFamily(name string) (version, maxAttr uint32, err error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_GENERIC)
	if err != nil {
		return 0, 0, fmt.Errorf("netlink socket: %w", err)
	}
	defer syscall.Close(fd)

	tv := syscall.NsecToTimeval(int64(probeTimeout))
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return 0, 0, fmt.Errorf("netlink bind: %w", err)
	}
	req := getFamilyRequest(binary.NativeEndian, 1, name)
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return 0, 0, fmt.Errorf("netlink send: %w", err)
	}
	// A family reply is a few hundred bytes (amneziawg registers two ops and one multicast group);
	// the buffer is generous so a truncated read cannot be mistaken for a whole one.
	buf := make([]byte, 16<<10)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("netlink receive: %w", err)
	}
	return parseGetFamilyReply(binary.NativeEndian, buf[:n])
}
