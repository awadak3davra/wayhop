package generator

import "wayhop/internal/model"

// vpnDNSMinMinor is the first sing-box 1.x minor with the openvpn and openconnect DNS server types
// (docs/configuration/dns/server/openvpn.md and openconnect.md, "Since sing-box 1.14.0"; at v1.13.21
// neither file exists and constant/dns.go has no DNSTypeOpenVPN/DNSTypeOpenConnect). 1.12.17 and
// 1.13.21 refuse the whole config over one: "dns.servers[0]: unknown transport type: openvpn".
const vpnDNSMinMinor = 14

// VPNDNSCarried reports whether the core named by coreVersion takes the openvpn/openconnect DNS server
// types. An unknown version ("") renders them, as it renders the OpenVPN and OpenConnect endpoints they
// name (openvpnEndpointFor): a server of this type needs an enabled connection of the same protocol,
// and that connection cannot load on a core without them either.
func VPNDNSCarried(coreVersion string) bool {
	return coreVersion == "" || coreMinor(coreVersion) >= vpnDNSMinMinor
}

// VPNDNSNeedsNewerCore reports an enabled openvpn/openconnect DNS server that the known core cannot
// carry, so dnsFrom and ECHLookupFor leave it out. A valid profile never reaches it: such a server
// needs an enabled OpenVPN or OpenConnect connection, and Generate refuses that connection by name on
// the same cores, so the operator is told about the connection rather than about its resolver. It is
// the generator's own guard against handing an older core a config it would refuse whole.
func VPNDNSNeedsNewerCore(s *model.DNSServer, coreVersion string) bool {
	return s != nil && s.Enabled && model.IsVPNDNSType(s.Type) && !VPNDNSCarried(coreVersion)
}
