package server

import (
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// parseLeases maps client IP → hostname from dnsmasq's lease file. Pure (file-I/O-free),
// unit-tested. Line format: "<expiry> <mac> <ip> <hostname> <clientid>"; a "*" hostname
// (unknown) is dropped so the UI shows the bare IP instead.
func parseLeases(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		ip, name := f[2], f[3]
		if name != "" && name != "*" {
			out[ip] = name
		}
	}
	return out
}

// readLeases reads the dnsmasq lease file (OpenWrt path), or returns an empty map.
func readLeases() map[string]string {
	b, err := os.ReadFile("/tmp/dhcp.leases")
	if err != nil {
		return map[string]string{}
	}
	return parseLeases(string(b))
}

// deviceInfo is one LAN device from the DHCP lease file, for the source-rule device picker
// (source_ip_cidr / source_mac). MAC is lowercased; an unknown ("*") hostname is omitted.
type deviceInfo struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Hostname string `json:"hostname,omitempty"`
}

// dhcpDevices parses dnsmasq's lease file into the LAN device list (ip + mac + hostname). Reuses
// the same "<expiry> <mac> <ip> <hostname> <clientid>" format as parseLeases, but keeps the MAC so
// the UI can fill a source_mac rule. Malformed lines and entries with an unparseable IP/MAC are
// skipped; the result is sorted (named devices first, then by IP) for a stable picker.
func dhcpDevices(s string) []deviceInfo {
	var out []deviceInfo
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		mac, ip, name := f[1], f[2], f[3]
		if net.ParseIP(ip) == nil {
			continue
		}
		if _, err := net.ParseMAC(mac); err != nil {
			continue
		}
		d := deviceInfo{IP: ip, MAC: strings.ToLower(mac)}
		if name != "*" && name != "" {
			d.Hostname = name
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Hostname == "") != (out[j].Hostname == "") {
			return out[i].Hostname != "" // named devices before unnamed
		}
		if out[i].Hostname != out[j].Hostname {
			return out[i].Hostname < out[j].Hostname
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// parseARP reads /proc/net/arp into {ip, mac} devices — the cross-platform fallback (OpenWrt +
// Keenetic + any Linux) for the picker when there's no dnsmasq lease file (Keenetic) or for a device
// with no current lease. Keeps only COMPLETE entries (flag != 0x0) on a bridge ("br…") LAN device
// with a private/link-local IP, so WAN neighbours never pollute the LAN list. No hostname (leases
// supply those). Line format: "IP HWtype Flags HWaddr Mask Device" after a one-line header.
func parseARP(s string) []deviceInfo {
	var out []deviceInfo
	for i, line := range strings.Split(s, "\n") {
		if i == 0 {
			continue // header row
		}
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		ip, flags, mac, dev := f[0], f[2], f[3], f[5]
		if flags == "0x0" || !strings.HasPrefix(dev, "br") {
			continue // incomplete entry, or not a LAN bridge (skip WAN/tunnels)
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil || !(addr.IsPrivate() || addr.IsLinkLocalUnicast()) {
			continue
		}
		if _, err := net.ParseMAC(mac); err != nil || mac == "00:00:00:00:00:00" {
			continue
		}
		out = append(out, deviceInfo{IP: ip, MAC: strings.ToLower(mac)})
	}
	return out
}

// handleDevices lists LAN devices for the device picker (source-based routing / per-device list
// scoping) so the UI offers real devices instead of a hand-typed MAC/IP. Merges the dnsmasq lease
// file (ip/mac/hostname — OpenWrt) with /proc/net/arp (ip/mac — any platform, incl. Keenetic), deduped
// by MAC (a lease's hostname wins). Read-only host probe; both sources absent ⇒ an empty list. GET.
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	byMAC := map[string]int{}
	var devs []deviceInfo
	add := func(d deviceInfo) {
		if d.MAC == "" {
			return
		}
		if idx, ok := byMAC[d.MAC]; ok {
			if devs[idx].Hostname == "" && d.Hostname != "" {
				devs[idx].Hostname = d.Hostname
			}
			return
		}
		byMAC[d.MAC] = len(devs)
		devs = append(devs, d)
	}
	if b, err := os.ReadFile("/tmp/dhcp.leases"); err == nil {
		for _, d := range dhcpDevices(string(b)) {
			add(d)
		}
	}
	if b, err := os.ReadFile("/proc/net/arp"); err == nil {
		for _, d := range parseARP(string(b)) {
			add(d)
		}
	}
	sort.Slice(devs, func(i, j int) bool {
		if (devs[i].Hostname == "") != (devs[j].Hostname == "") {
			return devs[i].Hostname != "" // named devices before unnamed
		}
		if devs[i].Hostname != devs[j].Hostname {
			return devs[i].Hostname < devs[j].Hostname
		}
		return devs[i].IP < devs[j].IP
	})
	if devs == nil {
		devs = []deviceInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devs})
}
