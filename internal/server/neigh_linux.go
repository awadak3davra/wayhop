//go:build linux

package server

import (
	"encoding/binary"
	"net"
	"strings"
	"syscall"
)

// Attributes of a neighbour message (linux/neighbour.h).
const (
	ndaDst    = 1 // NDA_DST: the neighbour's address
	ndaLladdr = 2 // NDA_LLADDR: its link-layer address
	ndmsgLen  = 12
)

// ipv6Neighbours maps the addresses in the kernel's IPv6 neighbour table to their link-layer
// addresses (lower case): how a LAN device's IPv6 traffic, which the DHCP leases and the ARP table
// know nothing of, is tied back to the device by its MAC. It asks the kernel over netlink, so no `ip`
// binary is needed; nil when the table cannot be read.
func ipv6Neighbours() map[string]string {
	raw, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_INET6)
	if err != nil {
		return nil
	}
	msgs, err := syscall.ParseNetlinkMessage(raw)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWNEIGH || len(m.Data) < ndmsgLen {
			continue
		}
		var ip net.IP
		var mac net.HardwareAddr
		for b := m.Data[ndmsgLen:]; len(b) >= 4; {
			n := int(binary.NativeEndian.Uint16(b[0:2]))
			if n < 4 || n > len(b) {
				break
			}
			switch v := b[4:n]; binary.NativeEndian.Uint16(b[2:4]) {
			case ndaDst:
				if len(v) == net.IPv6len {
					ip = net.IP(append([]byte(nil), v...))
				}
			case ndaLladdr:
				if len(v) == 6 {
					mac = net.HardwareAddr(append([]byte(nil), v...))
				}
			}
			if next := (n + 3) &^ 3; next < len(b) {
				b = b[next:]
			} else {
				break
			}
		}
		// The dump also holds the kernel's multicast entries (ff02::1 and the like, on 33:33-prefixed
		// multicast MACs), which no device is.
		if ip != nil && mac != nil && !ip.IsMulticast() {
			out[ip.String()] = strings.ToLower(mac.String())
		}
	}
	return out
}
