//go:build linux

package ctflush

import (
	"fmt"
	"syscall"
	"time"
)

const netlinkNetfilter = 12 // NETLINK_NETFILTER

// netlinkTable is the kernel's conntrack table over a NETLINK_NETFILTER socket.
type netlinkTable struct {
	fd  int
	seq uint32
	buf []byte
}

// Open connects to ctnetlink. It fails where nf_conntrack_netlink is absent.
func Open() (Table, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkNetfilter)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	// A dump or an ack that never comes must not hang the Apply that asked for it.
	tv := syscall.NsecToTimeval((3 * time.Second).Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	return &netlinkTable{fd: fd, seq: uint32(time.Now().Unix()), buf: make([]byte, 1<<16)}, nil
}

func (t *netlinkTable) send(msg []byte) error {
	return syscall.Sendto(t.fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
}

// Dump walks the table for one family, handing each entry to visit as it is read: the table is never
// held in memory (a busy router keeps tens of thousands of entries).
func (t *netlinkTable) Dump(family uint8, visit func(Entry)) error {
	t.seq++
	if err := t.send(dumpRequest(t.seq, family)); err != nil {
		return fmt.Errorf("send dump: %w", err)
	}
	for {
		n, _, err := syscall.Recvfrom(t.fd, t.buf, 0)
		if err != nil {
			return fmt.Errorf("read dump: %w", err)
		}
		done, errno, perr := readMessages(t.buf[:n], family, t.seq, visit)
		if perr != nil {
			return perr
		}
		if errno != 0 {
			if e := syscall.Errno(-errno); e == syscall.EINVAL || e == syscall.EOPNOTSUPP {
				// nfnetlink answers EINVAL when no subsystem serves the conntrack messages: the
				// nf_conntrack_netlink module is not loaded (a separate package on OpenWrt).
				return fmt.Errorf("%w (%v)", ErrNoModule, e)
			}
			return fmt.Errorf("dump refused: %w", syscall.Errno(-errno))
		}
		if done {
			return nil
		}
	}
}

// Delete removes one entry by its original tuple and waits for the kernel's answer to THIS request.
func (t *netlinkTable) Delete(e Entry) error {
	t.seq++
	msg, err := deleteRequest(t.seq, e)
	if err != nil {
		return err
	}
	if err := t.send(msg); err != nil {
		return fmt.Errorf("send delete: %w", err)
	}
	for {
		n, _, err := syscall.Recvfrom(t.fd, t.buf, 0)
		if err != nil {
			return fmt.Errorf("read ack: %w", err)
		}
		done, errno, perr := readMessages(t.buf[:n], e.Family, t.seq, nil)
		switch {
		case perr != nil:
			return perr
		case !done:
			continue // an earlier request's late reply
		case errno == -enoent:
			return errNoEntry
		case errno != 0:
			return syscall.Errno(-errno)
		}
		return nil
	}
}

func (t *netlinkTable) Close() error { return syscall.Close(t.fd) }
