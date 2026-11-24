//go:build linux

package rtblackhole

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
	"time"
)

type netlinkTable struct {
	fd    int
	seq   uint32
	table uint32
	buf   []byte
}

// Open connects to rtnetlink for one routing table.
func Open(table int) (Table, error) {
	if table <= 0 {
		return nil, fmt.Errorf("routing table %d", table)
	}
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	// An ack or a dump that never comes must not hang the Apply that asked for it.
	tv := syscall.NsecToTimeval((3 * time.Second).Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	return &netlinkTable{fd: fd, seq: uint32(time.Now().Unix()), table: uint32(table), buf: make([]byte, 1<<16)}, nil
}

func (t *netlinkTable) send(msg []byte) error {
	return syscall.Sendto(t.fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
}

// wait reads until the kernel answers request seq, handing dumped routes to visit.
func (t *netlinkTable) wait(seq uint32, visit func(netip.Prefix)) (int32, error) {
	for {
		n, _, err := syscall.Recvfrom(t.fd, t.buf, 0)
		if err != nil {
			return 0, fmt.Errorf("netlink read: %w", err)
		}
		done, errno, perr := parseMessages(t.buf[:n], seq, t.table, visit)
		if perr != nil {
			return 0, perr
		}
		if done {
			return errno, nil
		}
	}
}

func (t *netlinkTable) List() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, fam := range []uint8{afInet, afInet6} {
		t.seq++
		if err := t.send(encodeDump(t.seq, fam)); err != nil {
			return nil, fmt.Errorf("send dump: %w", err)
		}
		errno, err := t.wait(t.seq, func(p netip.Prefix) { out = append(out, p) })
		if err != nil {
			return nil, err
		}
		if errno != 0 && !(fam == afInet6 && (syscall.Errno(-errno) == syscall.EAFNOSUPPORT || syscall.Errno(-errno) == syscall.EOPNOTSUPP)) {
			return nil, fmt.Errorf("dump refused: %w", syscall.Errno(-errno))
		}
	}
	return out, nil
}

func (t *netlinkTable) request(msgType uint16, p netip.Prefix) (int32, error) {
	return t.requestType(msgType, p, rtnBlackhole)
}

func (t *netlinkTable) requestType(msgType uint16, p netip.Prefix, rtype uint8) (int32, error) {
	t.seq++
	if err := t.send(encodeRouteType(msgType, t.seq, t.table, p, rtype)); err != nil {
		return 0, fmt.Errorf("netlink send: %w", err)
	}
	return t.wait(t.seq, nil)
}

// refusal is the error for a kernel answer errno to a route operation on p.
func refusal(p netip.Prefix, errno int32) error {
	e := syscall.Errno(-errno)
	if p.Addr().Is6() && (e == syscall.EOPNOTSUPP || e == syscall.EAFNOSUPPORT) {
		return fmt.Errorf("%w: %w", ErrFamilyUnsupported, e)
	}
	return e
}

func (t *netlinkTable) Add(p netip.Prefix) error {
	errno, err := t.request(rtmNewRoute, p)
	if err != nil {
		return err
	}
	if errno != 0 {
		return refusal(p, errno)
	}
	return nil
}

func (t *netlinkTable) Del(p netip.Prefix) error {
	errno, err := t.request(rtmDelRoute, p)
	if err != nil {
		return err
	}
	if errno != 0 && -errno != enoent && -errno != esrch {
		return refusal(p, errno)
	}
	return nil
}

func (t *netlinkTable) DelThrow(p netip.Prefix) error {
	errno, err := t.requestType(rtmDelRoute, p, rtnThrow)
	if err != nil {
		return err
	}
	if errno != 0 && -errno != enoent && -errno != esrch {
		return refusal(p, errno)
	}
	return nil
}

func (t *netlinkTable) Close() error { return syscall.Close(t.fd) }

// encodeDump builds an RTM_GETROUTE dump request for one family. Kernels before 4.20 ignore any
// table filter in a dump, so the table is filtered on the way back (parseDump).
func encodeDump(seq uint32, fam uint8) []byte {
	n := nlmsgHdrLen + rtmsgLen
	b := make([]byte, n)
	binary.NativeEndian.PutUint32(b[0:4], uint32(n))
	binary.NativeEndian.PutUint16(b[4:6], rtmGetRoute)
	binary.NativeEndian.PutUint16(b[6:8], nlmFRequest|nlmFDump)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	b[nlmsgHdrLen] = fam
	return b
}
