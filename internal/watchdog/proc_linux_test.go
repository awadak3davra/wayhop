package watchdog

import (
	"os"
	"syscall"
	"testing"
)

// rtnetlinkSocket opens a real rtnetlink socket with the given groups and returns its inode. Joining
// these groups needs no privileges.
func rtnetlinkSocket(t *testing.T, groups uint32) uint64 {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: groups}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		t.Fatalf("fstat: %v", err)
	}
	return st.Ino
}

func TestReadNetlinkQueues_FindsThisProcesssSubscriptions(t *testing.T) {
	const routeGroups = 0x40 | 0x400 // RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE, the mask seen on a wedged sing-box
	subscribed := rtnetlinkSocket(t, routeGroups)
	query := rtnetlinkSocket(t, 0)

	queues, err := readNetlinkQueues(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if q, ok := queues[subscribed]; !ok || q.drops != 0 {
		t.Fatalf("subscription %d not found in %+v", subscribed, queues)
	}
	if _, ok := queues[query]; ok {
		t.Fatalf("query socket %d reported as a subscription", query)
	}
}

func TestReadCPUTicks_ReadsThisProcess(t *testing.T) {
	first, err := readCPUTicks(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	var sink uint64
	for i := uint64(0); ; i++ {
		sink += i
		if i%1000000 != 0 {
			continue
		}
		now, err := readCPUTicks(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		if now > first {
			break
		}
	}
	_ = sink
}

func TestReadNetlinkQueues_NoSuchProcess(t *testing.T) {
	if _, err := readNetlinkQueues(1 << 30); err == nil {
		t.Fatal("no error for a process that does not exist")
	}
}
