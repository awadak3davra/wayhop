package watchdog

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// clockTicksPerSecond is USER_HZ, the unit of utime and stime in /proc/<pid>/stat. The kernel fixes
// it at 100 on every architecture WayHop builds for, and reading it properly would take cgo.
const clockTicksPerSecond = 100

// netlinkQueue is what /proc/net/netlink says about one socket.
type netlinkQueue struct {
	rmem  int64 // bytes queued and not yet read
	drops int64 // messages lost to a full queue, ever
}

// readCPUTicks is the user plus system CPU time process pid has used, in clock ticks. Outside Linux
// there is no such file, so the error turns the guard off, which is what the demo wants.
func readCPUTicks(pid int) (uint64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	return parseStatTicks(b)
}

// parseStatTicks reads utime and stime out of a /proc/<pid>/stat line. Field 2 is the command name in
// parentheses and may itself hold spaces and parentheses, so counting starts after the last ')':
// the state, field 3, is first there, which puts utime and stime (14 and 15) at 11 and 12.
func parseStatTicks(b []byte) (uint64, error) {
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, fmt.Errorf("proc stat: no command name in %q", b)
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 13 {
		return 0, fmt.Errorf("proc stat: %d fields after the command name", len(f))
	}
	utime, err := strconv.ParseUint(f[11], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("proc stat utime: %w", err)
	}
	stime, err := strconv.ParseUint(f[12], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("proc stat stime: %w", err)
	}
	return utime + stime, nil
}

// readNetlinkQueues reports the rtnetlink subscription sockets process pid holds, by socket inode.
func readNetlinkQueues(pid int) (map[uint64]netlinkQueue, error) {
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	fds, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	inodes := make(map[uint64]bool, len(fds))
	for _, fd := range fds {
		link, err := os.Readlink(dir + "/" + fd.Name())
		if err != nil {
			continue // closed since the listing
		}
		rest, ok := strings.CutPrefix(link, "socket:[")
		if !ok {
			continue
		}
		if inode, err := strconv.ParseUint(strings.TrimSuffix(rest, "]"), 10, 64); err == nil {
			inodes[inode] = true
		}
	}
	table, err := os.ReadFile("/proc/net/netlink")
	if err != nil {
		return nil, err
	}
	return parseNetlinkQueues(table, inodes)
}

// parseNetlinkQueues picks the listed sockets out of /proc/net/netlink, keeping only those subscribed
// to rtnetlink groups: protocol 0 with a group set. A socket with no groups is a query socket whose
// replies are read on demand, so bytes sitting in it mean nothing (one held 33024 in the reproduction).
// Columns are found by name, so a table of another shape turns the guard off instead of being misread.
func parseNetlinkQueues(table []byte, inodes map[uint64]bool) (map[uint64]netlinkQueue, error) {
	lines := strings.Split(string(table), "\n")
	col := map[string]int{}
	for i, name := range strings.Fields(lines[0]) {
		col[name] = i
	}
	for _, name := range []string{"Eth", "Groups", "Rmem", "Drops", "Inode"} {
		if _, ok := col[name]; !ok {
			return nil, fmt.Errorf("proc netlink: no %s column in %q", name, lines[0])
		}
	}
	queues := make(map[uint64]netlinkQueue)
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) != len(col) {
			continue
		}
		inode, err := strconv.ParseUint(f[col["Inode"]], 10, 64)
		if err != nil || !inodes[inode] || f[col["Eth"]] != "0" {
			continue
		}
		groups, err := strconv.ParseUint(f[col["Groups"]], 16, 64)
		if err != nil || groups == 0 {
			continue
		}
		rmem, err := strconv.ParseInt(f[col["Rmem"]], 10, 64)
		if err != nil {
			continue
		}
		drops, err := strconv.ParseInt(f[col["Drops"]], 10, 64)
		if err != nil {
			continue
		}
		queues[inode] = netlinkQueue{rmem: rmem, drops: drops}
	}
	return queues, nil
}
