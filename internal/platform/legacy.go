package platform

// LegacyProtocolWarning maps a protocol to why using it is a security problem, for protocols the
// router can still carry but nobody should choose today.
//
// The spec is explicit that PPTP is to be supported "only as a legacy detected type, with a security
// warning". Detection without the warning is the worse outcome of the two: a protocol appearing in a
// capability list next to WireGuard reads as an endorsement, and a user picking it would reasonably
// assume it protects their traffic. It does not.
//
// The wording states the consequence rather than a severity label, because "insecure" is a word
// people have learned to skip past.
var LegacyProtocolWarning = map[string]string{
	"pptp": "PPTP's encryption (MS-CHAPv2/MPPE) is broken and has been for over a decade — captured " +
		"traffic can be decrypted offline, so this tunnel protects against nothing. It is detected " +
		"for compatibility with existing router configurations, not recommended for use.",
}

// IsLegacyProtocol reports whether proto carries a security warning.
func IsLegacyProtocol(proto string) bool {
	_, ok := LegacyProtocolWarning[proto]
	return ok
}
