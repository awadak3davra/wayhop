package server

import (
	"net"
	"net/http"
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

// handleDevices lists LAN devices from the DHCP leases (ip/mac/hostname) so the UI can offer a
// device picker for source-based routing rules instead of hand-typing a MAC/IP. Read-only host
// probe; an absent lease file (e.g. non-dnsmasq platform) yields an empty list. GET /api/devices.
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	devs := []deviceInfo{}
	if b, err := os.ReadFile("/tmp/dhcp.leases"); err == nil {
		devs = dhcpDevices(string(b))
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devs})
}
